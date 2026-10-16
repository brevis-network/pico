//! RISCV Phase-1 proving on the MLE/WHIR backend.
//!
//! Reuses the chips' `constraints.rs` (the MLE builders natively implement the
//! `ChipBuilder` stack, see `pico_mle_core::air::{symbolic, debug}`) and their
//! trace generation — no per-chip AIR re-implementation, and no trace field conversion (the whole
//! workspace shares one p3 version).
//!
//! The air list is the full RISCV chip set: 10 ALU + Cpu + memory (Local/RW/Init/Final) + Global
//! (GCS) + Poseidon2 + Syscall (Riscv/Precompile) + Byte/Program (preprocessed) + the compute
//! precompiles. Each AIR is optional — `build_ctx` includes a chip only when it's active for the
//! program (e.g. precompiles fire for reth, not fib), and inactive chips are omitted from the
//! proof and skipped in `complement`.

use std::{
    num::NonZeroUsize,
    sync::{Arc, Mutex, PoisonError},
};

use p3_field::PrimeCharacteristicRing;
use p3_koala_bear::KoalaBear;
use p3_maybe_rayon::prelude::*;

use super::air::{GcsBindAir, PrepAir, GCS_DIGEST_LEN};
use crate::{
    chips::{
        chips::{
            alu::{
                add::AddChip, addw::AddwChip, bitwise::BitwiseChip, divrem::DivRemChip, lt::LtChip,
                mul::MulChip, sll::SLLChip, sr::traces::ShiftRightChip, sub::SubChip,
                subw::SubwChip,
            },
            byte::ByteChip,
            riscv_cpu::CpuChip,
            riscv_ecall::EcallChip,
            riscv_memory::{
                initialize_finalize::{MemoryChipType, MemoryInitializeFinalizeChip},
                local::MemoryLocalChip,
                read_write::MemoryReadWriteChip,
            },
            riscv_poseidon2::FieldSpecificPoseidon2Chip,
            riscv_program::ProgramChip,
            syscall::{SyscallChip, SyscallChunkKind},
        },
        gadgets::{
            curves::{
                edwards::ed25519::{Ed25519, Ed25519Parameters},
                weierstrass::{
                    bls381::Bls381BaseField, bn254::Bn254BaseField, Bls12381, Bn254, Secp256k1,
                    Secp256r1,
                },
            },
            field::secp256k1::Secp256k1BaseField,
        },
        precompiles::{
            edwards::{EdAddAssignChip, EdDecompressChip},
            fptower::{fp::FpOpChip, fp2_addsub::Fp2AddSubChip, fp2_mul::Fp2MulChip},
            keccak256::{KeccakControlChip, KeccakPermuteChip},
            poseidon2::FieldSpecificPrecompilePoseidon2Chip,
            sha256::{
                compress::{ShaCompressChip, ShaCompressControlChip},
                extend::{ShaExtendChip, ShaExtendControlChip},
            },
            uint256::Uint256MulChip,
            weierstrass::{
                weierstrass_add::WeierstrassAddAssignChip,
                weierstrass_decompress::WeierstrassDecompressChip,
                weierstrass_double::WeierstrassDoubleAssignChip,
            },
        },
    },
    compiler::riscv::program::Program,
    configs::stark_config::KoalaBearPoseidon2,
    emulator::{
        opts::{EmulatorOpts, SnapshotMainMode},
        record::RecordBehavior,
        riscv::{
            emulator::{EmulationError, RiscvEmulator},
            record::EmulationRecord,
        },
        stdin::EmulatorStdin,
    },
    instances::chiptype::riscv_chiptype::RiscvChipType,
    machine::{
        chip::{ChipBehavior, MetaChip},
        report::EmulationReport,
        septic::{SepticCurve, SepticDigest, SepticExtension},
        witness::ProvingWitness,
    },
    primitives::consts::{MAX_NUM_PVS, RISCV_NUM_PVS},
    proverchain::riscv::{emulate_snapshot_pipeline_with, DeferredSplit},
};
use pico_mle_core::{
    config::{
        riscv_params_with_100_bits_security,
        soundness::{admit_production_vk, UnderBudgetError},
    },
    keygen::{compute_vk_pre_hash, types::MultiStarkVerifyingKey},
    proof::Proof,
    prover::{
        AirProvingContext, DeviceDataTransporter, DeviceMultiStarkProvingKey, ProvingContext,
    },
    verifier::VerifierError,
    AirRef, StarkEngine, StarkProtocolConfig,
};
use pico_mle_cpu::KoalaBearPoseidon2CpuEngine;

/// Base field for the KoalaBear RISCV proof.
pub type Kb = KoalaBear;
/// The MLE CPU engine (KoalaBear + Poseidon2 + WHIR).
pub type Engine = KoalaBearPoseidon2CpuEngine;
/// The `StarkProtocolConfig` of the engine.
pub type Sc = <Engine as StarkEngine>::SC;
/// The prover backend of the engine.
pub type Pb = <Engine as StarkEngine>::PB;

/// AIR-id constants for the core air set (slice index == AIR id in `ProvingContext`).
pub mod air_id {
    pub const ADD: usize = 0;
    pub const SUB: usize = 1;
    pub const MUL: usize = 2;
    pub const BITWISE: usize = 3;
    pub const LT: usize = 4;
    pub const SLL: usize = 5;
    pub const SR: usize = 6;
    pub const DIVREM: usize = 7;
    pub const ADDW: usize = 8;
    pub const SUBW: usize = 9;
    pub const CPU: usize = 10;
    pub const MEM_LOCAL: usize = 11;
    pub const MEM_RW: usize = 12;
    pub const SYSCALL_RISCV: usize = 13;
    pub const BYTE: usize = 14;
    pub const PROGRAM: usize = 15;
    pub const MEM_INIT: usize = 16;
    pub const MEM_FINAL: usize = 17;
    pub const GLOBAL: usize = 18;
    pub const POSEIDON2: usize = 19;
    // Precompile / SyscallPrecompile AIR ids (20..=44) are literal indices in `INCLUDED`.
    /// Dedicated Ecall chip; appended after the precompile block so the literal
    /// precompile indices stay valid.
    pub const ECALL: usize = 45;
    /// Keccak control sibling (syscall + memory, one row per permutation); appended after Ecall
    /// so the existing air ids do not move.
    pub const KECCAK_CONTROL: usize = 46;
    /// The poseidon2 precompile, returned to the machine after its canonicality and alignment
    /// fixes; appended last for the same reason as the two above.
    pub const POSEIDON2_PERMUTE: usize = 47;
    /// The two Ed25519 precompiles, returned to the machine on the RV64 memory layout; appended
    /// after the poseidon2 precompile, in the order the three came back.
    pub const ED_ADD: usize = 48;
    pub const ED_DECOMPRESS: usize = 49;
}

/// Maps brevis chip `name()` → AIR id for the core set. Chips not listed are excluded from both
/// the air list and `complement`.
const INCLUDED: &[(&str, usize)] = &[
    ("Add", air_id::ADD),
    ("Sub", air_id::SUB),
    ("Mul", air_id::MUL),
    ("Bitwise", air_id::BITWISE),
    ("LessThan", air_id::LT),
    ("ShiftLeft", air_id::SLL),
    ("ShiftRight", air_id::SR),
    ("DivRem", air_id::DIVREM),
    ("Addw", air_id::ADDW),
    ("Subw", air_id::SUBW),
    ("Cpu", air_id::CPU),
    ("MemoryLocal", air_id::MEM_LOCAL),
    ("MemoryReadWrite", air_id::MEM_RW),
    ("SyscallRiscv", air_id::SYSCALL_RISCV),
    ("Byte", air_id::BYTE),
    ("Program", air_id::PROGRAM),
    ("MemoryInitialize", air_id::MEM_INIT),
    ("MemoryFinalize", air_id::MEM_FINAL),
    ("Global", air_id::GLOBAL),
    ("RiscvKoalaBearPoseidon2", air_id::POSEIDON2),
    // Compute precompiles (air id == air_refs index). Active on programs that use them (reth);
    // brevis chip `constraints.rs` emit matching BYTE_BUS, so no byte_lookup skip is needed.
    ("KeccakPermute", 20),
    ("ShaExtend", 21),
    ("ShaExtendControl", 22),
    ("ShaCompress", 23),
    ("ShaCompressControl", 24),
    ("Uint256MulMod", 25),
    ("Secp256k1AddAssign", 26),
    ("Secp256k1DoubleAssign", 27),
    ("Secp256k1Decompress", 28),
    ("Secp256r1AddAssign", 29),
    ("Secp256r1DoubleAssign", 30),
    ("Secp256r1Decompress", 31),
    ("Bn254AddAssign", 32),
    ("Bn254DoubleAssign", 33),
    ("Bls12381AddAssign", 34),
    ("Bls12381DoubleAssign", 35),
    ("Bls12381Decompress", 36),
    ("Bn254FpOp", 37),
    ("Bn254Fp2AddSub", 38),
    ("Bn254Fp2Mul", 39),
    ("Bls381FpOp", 40),
    ("Bls381Fp2AddSub", 41),
    ("Bls381Fp2Mul", 42),
    ("Secp256k1FpOp", 43),
    ("SyscallPrecompile", 44),
    ("Ecall", air_id::ECALL),
    ("KeccakControl", air_id::KECCAK_CONTROL),
    ("Poseidon2Permute", air_id::POSEIDON2_PERMUTE),
    ("EdAddAssign", air_id::ED_ADD),
    ("EdDecompress", air_id::ED_DECOMPRESS),
];

pub fn air_id_for(name: &str) -> Option<usize> {
    INCLUDED.iter().find(|(n, _)| *n == name).map(|(_, id)| *id)
}

/// Reverse lookup of [`air_id`]: the chip name for an AIR id (tooling/logging).
pub fn air_name(air_id: usize) -> Option<&'static str> {
    INCLUDED
        .iter()
        .find(|(_, id)| *id == air_id)
        .map(|(n, _)| *n)
}

/// The stacked height the MLE riscv machine runs at, from `MLE_LOG_STACKED_HEIGHT`, defaulting
/// to the production operating point. The catch-all shapes put `Cpu` at 2^23, so a run below 23
/// cannot prove them — a trace taller than the stack does not pack.
///
/// Panics at startup on a value that does not parse or that the riscv preset refuses.
pub fn log_stacked_height_from_env() -> usize {
    let Ok(v) = std::env::var("MLE_LOG_STACKED_HEIGHT") else {
        return DEFAULT_LOG_STACKED_HEIGHT;
    };
    let h: usize = v
        .parse()
        .unwrap_or_else(|_| panic!("MLE_LOG_STACKED_HEIGHT {v:?} is not a stacked height"));
    if let Err(err) = pico_mle_core::config::try_riscv_params_with_100_bits_security(h) {
        panic!(
            "MLE_LOG_STACKED_HEIGHT {h} is not a height the backend can prove (maximum {}): {err}",
            pico_mle_core::config::MAX_RISCV_LOG_STACKED_HEIGHT
        );
    }
    h
}

/// Default for [`log_stacked_height_from_env`].
pub const DEFAULT_LOG_STACKED_HEIGHT: usize = 23;

/// The air ids a BUCKETED proof of this record will carry, after the same extra-record pass
/// `build_ctx` runs (extra events can activate more chips), sorted ascending. This is the
/// whitelist enumerator's input, so it goes through `bucketed_presence` rather than reading
/// `is_active` directly.
///
/// Shares `augmented_record` and `bucketed_presence` with `build_ctx`, so the enumerator cannot
/// drift from proving reality; the vk-map builder's self-validation is the safety net behind
/// that.
pub fn bucketed_air_ids(
    chips: &[MetaChip<Kb, RiscvChipType<Kb>>],
    record: &EmulationRecord,
) -> Vec<usize> {
    let record = augmented_record(chips, record);
    let mut ids: Vec<usize> = chips
        .iter()
        .filter(|chip| bucketed_presence(chip, &record))
        .filter_map(|chip| air_id_for(&chip.name()))
        .collect();
    ids.sort_unstable();
    ids
}

/// Whether `chip` is present in a BUCKETED proof of `record`: the canonical presence set for the
/// chunk kind, which for a CPU chunk is the whole core family and for a deferred chunk is the
/// event-driven set (see `shape::MLE_CORE_CANONICAL_PRESENCE`). `record` must not carry a shape
/// yet — this is what the shape is built from.
///
/// Single source of truth for the prover (`build_ctx`) and the whitelist enumerator
/// (`bucketed_air_ids`); the two drifting apart is what the vk-map builder's self-validation
/// catches.
fn bucketed_presence(chip: &MetaChip<Kb, RiscvChipType<Kb>>, record: &EmulationRecord) -> bool {
    let name = chip.name();
    if air_id_for(&name).is_none() {
        return false;
    }
    (record.is_cpu_chunk && crate::mle::machine::shape::is_core_canonical(&name))
        || chip.is_active(record)
}

/// AIRs whose preprocessed commitment is *application identity* (varies with the guest program):
/// exactly the program table. Their commitment values are excluded from the lean vk pre-hash
/// preimage (`compute_vk_pre_hash`), making the RISCV vk pre-hash app-independent; the program
/// commitment is bound separately (witnessed + consumed in-circuit; pinned by
/// [`verify_riscv`] / the apex against a trusted value). The byte table ignores the program
/// (machine constant) and stays in the preimage.
pub const RISCV_APP_PREP_AIR_IDS: &[usize] = &[air_id::PROGRAM];

/// The program-table preprocessed commitment of a RISCV verifying key — the app-identity
/// commitment excluded from the lean pre-hash. Panics if the vk carries no program table
/// (not a RISCV machine vk).
pub fn riscv_program_commit(
    vk: &MultiStarkVerifyingKey<Sc>,
) -> <Sc as StarkProtocolConfig>::Digest {
    vk.inner.per_air[air_id::PROGRAM]
        .preprocessed_data
        .as_ref()
        .expect("RISCV vk must carry a program-table preprocessed commitment")
        .commit
}

/// Default number of chunks [`RiscvMachine::prove`] proves concurrently. A single chunk prover is
/// itself rayon-parallel but leaves a large host underused (reth chunks measured ~30 of 124 busy
/// cores), so proving a few at once fills the machine; the bound caps peak memory (one full proving
/// working set per in-flight chunk). Override with the `PROVE_CONCURRENCY` env var; defaults to 4.
///
/// Consulted only when the machine was given no explicit [`RiscvMachine::with_concurrency`]: an
/// argument outranks the environment.
fn prove_concurrency() -> usize {
    std::env::var("PROVE_CONCURRENCY")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .filter(|&n| n >= 1)
        .unwrap_or(4)
}

/// An explicit concurrency wins; only its absence consults the environment.
fn resolved_concurrency(explicit: Option<NonZeroUsize>) -> usize {
    explicit.map_or_else(prove_concurrency, |n| n.get())
}

/// The machine's params-free constraint dump: one line per AIR plus an overall digest, covering
/// constraints, interactions, column widths, public-value counts and degrees — nothing that depends
/// on the operating point.
///
/// Shared by the example that writes the artifact and the gate that reproduces it, so the two
/// cannot drift apart.
///
/// Keygen only: the constraint DAG is already in the vk, so this needs no proving. It needs no real
/// ELF either — the program table feeds only the preprocessed commitment and its geometry, both
/// excluded from the digest, so one instruction suffices (`Program::default()` is rejected by the
/// program table's trace generator). `bucket` cannot move the result either, which is what makes
/// the artifact workload-independent.
pub fn riscv_constraint_dump(bucket: bool) -> String {
    use pico_mle_core::{
        config::riscv_params_with_100_bits_security, keygen::compute_constraint_dump,
    };

    // Any operating point works; the dump excludes `SystemParams`. Pinned rather than tied to the
    // e2e's default so that moving the operating point cannot silently change the artifact.
    let engine: Engine = StarkEngine::new(riscv_params_with_100_bits_security(22));
    let program = Program {
        instructions: vec![crate::compiler::riscv::instruction::Instruction::new(
            crate::compiler::riscv::opcode::Opcode::ADD,
            0,
            0,
            0,
            false,
            false,
        )]
        .into(),
        pc_start: 0,
        pc_base: 0,
        memory_image: Default::default(),
        preprocessed_shape: None,
    };
    let airs = mle_riscv_air_refs(Arc::new(program), bucket);
    let names: Vec<String> = airs.iter().map(|a| a.name()).collect();
    let (_, vk) = engine.keygen_with_app_prep(&airs, RISCV_APP_PREP_AIR_IDS);
    compute_constraint_dump(engine.config(), &vk.inner, &names).render()
}

/// Ordered RISCV air list for keygen/prove. `program` is the ELF (needed by the `ProgramChip`
/// preprocessed table; ignored by `ByteChip`).
pub fn mle_riscv_air_refs(program: Arc<Program>, bucket: bool) -> Vec<AirRef<Sc>> {
    // Coarse-bucket the program table so the vk's preprocessed GEOMETRY is app-independent
    // (see `shape`) — whitelist mode only; without it the natural program size keeps proofs
    // small and the vk per-app (the commitment VALUE is app identity either way).
    let program = if bucket {
        crate::mle::machine::shape::with_mle_preprocessed_shape(program)
    } else {
        program
    };
    vec![
        Arc::new(AddChip::<Kb>::default()) as AirRef<Sc>, // 0
        Arc::new(SubChip::<Kb>::default()),               // 1
        Arc::new(MulChip::<Kb>::default()),               // 2
        Arc::new(BitwiseChip::<Kb>::default()),           // 3
        Arc::new(LtChip::<Kb>::default()),                // 4
        Arc::new(SLLChip::<Kb>::default()),               // 5
        Arc::new(ShiftRightChip::<Kb>::default()),        // 6
        Arc::new(DivRemChip::<Kb>::default()),            // 7
        Arc::new(AddwChip::<Kb>::default()),              // 8
        Arc::new(SubwChip::<Kb>::default()),              // 9
        Arc::new(CpuChip::<Kb>::default()),               // 10
        Arc::new(MemoryLocalChip::<Kb>::default()),       // 11
        Arc::new(MemoryReadWriteChip::<Kb>::default()),   // 12
        Arc::new(SyscallChip::<Kb>::new(SyscallChunkKind::Riscv)), // 13
        Arc::new(PrepAir::new(ByteChip::<Kb>::default(), program.clone())), // 14
        Arc::new(PrepAir::new(ProgramChip::<Kb>::default(), program)), // 15
        Arc::new(MemoryInitializeFinalizeChip::<Kb>::new(
            MemoryChipType::Initialize,
        )), // 16
        Arc::new(MemoryInitializeFinalizeChip::<Kb>::new(
            MemoryChipType::Finalize,
        )), // 17
        Arc::new(GcsBindAir::<Kb>::default()),            // 18 (GlobalChip + GCS public values)
        Arc::new(FieldSpecificPoseidon2Chip::<Kb>::default()), // 19 (POSEIDON2_BUS receiver)
        // Compute precompiles: present in the verifying key. They activate on programs that
        // use them (omitted from a proof as optional AIRs when the chunk has no such events).
        Arc::new(KeccakPermuteChip::<Kb>::default()),
        Arc::new(ShaExtendChip::<Kb>::default()),
        Arc::new(ShaExtendControlChip::<Kb>::default()),
        Arc::new(ShaCompressChip::<Kb>::default()),
        Arc::new(ShaCompressControlChip::<Kb>::default()),
        Arc::new(Uint256MulChip::<Kb>::default()),
        Arc::new(WeierstrassAddAssignChip::<Kb, Secp256k1>::default()),
        Arc::new(WeierstrassDoubleAssignChip::<Kb, Secp256k1>::default()),
        Arc::new(WeierstrassDecompressChip::<Kb, Secp256k1>::default()),
        Arc::new(WeierstrassAddAssignChip::<Kb, Secp256r1>::default()),
        Arc::new(WeierstrassDoubleAssignChip::<Kb, Secp256r1>::default()),
        Arc::new(WeierstrassDecompressChip::<Kb, Secp256r1>::default()),
        Arc::new(WeierstrassAddAssignChip::<Kb, Bn254>::default()),
        Arc::new(WeierstrassDoubleAssignChip::<Kb, Bn254>::default()),
        Arc::new(WeierstrassAddAssignChip::<Kb, Bls12381>::default()),
        Arc::new(WeierstrassDoubleAssignChip::<Kb, Bls12381>::default()),
        Arc::new(WeierstrassDecompressChip::<Kb, Bls12381>::default()),
        Arc::new(FpOpChip::<Kb, Bn254BaseField>::default()),
        Arc::new(Fp2AddSubChip::<Kb, Bn254BaseField>::default()),
        Arc::new(Fp2MulChip::<Kb, Bn254BaseField>::default()),
        Arc::new(FpOpChip::<Kb, Bls381BaseField>::default()),
        Arc::new(Fp2AddSubChip::<Kb, Bls381BaseField>::default()),
        Arc::new(Fp2MulChip::<Kb, Bls381BaseField>::default()),
        Arc::new(FpOpChip::<Kb, Secp256k1BaseField>::default()),
        Arc::new(SyscallChip::<Kb>::new(SyscallChunkKind::Precompile)), // 44 (precompile ecalls)
        Arc::new(EcallChip::<Kb>::default()),                           // 45
        Arc::new(KeccakControlChip::<Kb>::default()),                   // 46
        Arc::new(FieldSpecificPrecompilePoseidon2Chip::<Kb>::default()), // 47
        Arc::new(EdAddAssignChip::<Kb, Ed25519>::default()),            // 48
        Arc::new(EdDecompressChip::<Kb, Ed25519Parameters>::default()), // 49
    ]
}

/// What one RISCV emulation produced.
pub struct EmulationOutput {
    /// Every record the run emitted, in emission order: one per chunk, followed by the records the
    /// deferred split emits once the guest halts. Not a chunk count — see [`Self::chunks`].
    pub records: Vec<EmulationRecord>,
    /// How many chunks the run took.
    pub chunks: u32,
    /// The bytes the guest committed, in commit order.
    pub committed_bytes: Vec<u8>,
    /// The emulator's final global clock.
    pub cycles: u64,
    /// One per `emulate_batch` call, in order — carrying that batch's `cycle_tracker` and
    /// `host_cycle_estimator` when `opts` asked for them.
    pub reports: Vec<EmulationReport>,
}

impl std::fmt::Debug for EmulationOutput {
    /// Lengths only: `records` holds every event of the run, which at reth scale is gigabytes.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmulationOutput")
            .field("records", &format_args!("{} record(s)", self.records.len()))
            .field("chunks", &self.chunks)
            .field(
                "committed_bytes",
                &format_args!("{} byte(s)", self.committed_bytes.len()),
            )
            .field("cycles", &self.cycles)
            .field("reports", &format_args!("{} report(s)", self.reports.len()))
            .finish()
    }
}

/// Why a RISCV emulation produced no [`EmulationOutput`].
#[derive(Debug, thiserror::Error)]
pub enum EmulateError {
    /// `snapshot_main` picks the emulator for `emulate_snapshot_pipeline`'s snapshot thread, which
    /// this path does not run. Ignoring it would run the interpreter and report success.
    #[error("emulate_with_opts drives one RiscvEmulator and cannot honour snapshot_main = {0:?}")]
    UnsupportedSnapshotMain(SnapshotMainMode),
    /// The snapshot pipeline splits the deferred pool once per chunk, so it runs one chunk per
    /// batch.
    #[error("emulate_with_pipeline needs chunk_batch_size = 1, not {0}")]
    UnsupportedChunkBatchSize(u32),
    /// `snapshot_main = Aot` with no AOT code to run: the `aot-emulator` feature is off, or no
    /// AOT program is registered.
    #[error("snapshot_main = Aot, but no AOT program is registered in this process")]
    AotUnavailable,
    /// The emulation itself failed — a guest fault, a limit in `opts`, or, on the pipeline, a
    /// worker count or a memory pool the machine cannot run it with.
    #[error(transparent)]
    Emulation(#[from] EmulationError),
}

/// Emulate to completion under `opts`, reading no environment variable.
///
/// `EmulatorOpts::default` reads `CHUNK_SIZE`, `CHUNK_BATCH_SIZE` and `SPLIT_THRESHOLD`, and
/// `EmulatorOpts::from_env_chunk_size` reads the first of those; a caller needing a determined
/// proof shape states the fields rather than starting from either.
///
/// The chunk size and the caller's `log_stacked_height` are one decision: a chunk holds one CPU row
/// per instruction, so a full chunk of `2^n` instructions needs a stacked height of at least `n`.
pub fn emulate_with_opts(
    program: Arc<Program>,
    stdin: &EmulatorStdin<Program, Vec<u8>>,
    opts: EmulatorOpts,
) -> Result<EmulationOutput, EmulateError> {
    if opts.snapshot_main != SnapshotMainMode::Interpreter {
        return Err(EmulateError::UnsupportedSnapshotMain(opts.snapshot_main));
    }
    let mut emulator = RiscvEmulator::new_single::<Kb>(program, opts, None);
    emulator.write_stdin(stdin);
    let mut records = Vec::new();
    let mut reports = Vec::new();
    loop {
        let report = emulator.emulate_batch(&mut |r| records.push(r))?;
        let done = report.done;
        reports.push(report);
        if done {
            break;
        }
    }
    Ok(EmulationOutput {
        records,
        chunks: emulator.state.current_chunk,
        committed_bytes: std::mem::take(&mut emulator.state.public_values_stream),
        cycles: emulator.state.global_clk,
        reports,
    })
}

/// [`emulate_with_opts`] through the snapshot pipeline: one snapshot thread, running the
/// interpreter or AOT code as `opts.snapshot_main` says, and `workers` interpreters replaying its
/// snapshots into the records. A run [`check_pipeline`](crate::proverchain::riscv::check_pipeline)
/// refuses is refused before anything runs, and `NUM_THREADS` does not size the pipeline. The AOT snapshot thread still
/// reads it, with `PROVER_COUNT` and `MLE_SPLIT_REPLAY`, to decide whether to cut a chunk's replay
/// into segments (`emulator::aot::split_segments`); the workers fold those back into one record.
///
/// The output is filled as `emulate_with_opts` fills it: the records in chunk order, the reports
/// sorted by `start_chunk` (the workers finish out of order), `chunks` counting the CPU-chunk
/// records, and `cycles` the snapshot thread's count.
///
/// Both paths split the deferred pool after every chunk, so they emit the same records in the same
/// order. A tail record's `start_pc` is read from the last CPU chunk's `next_pc` here and from the
/// emulator's `pc` there, and both name the instruction after the last one emulated.
pub fn emulate_with_pipeline(
    program: Arc<Program>,
    stdin: &EmulatorStdin<Program, Vec<u8>>,
    opts: EmulatorOpts,
    workers: NonZeroUsize,
) -> Result<EmulationOutput, EmulateError> {
    if opts.chunk_batch_size != 1 {
        return Err(EmulateError::UnsupportedChunkBatchSize(
            opts.chunk_batch_size,
        ));
    }
    #[cfg(feature = "aot-emulator")]
    let aot_ready = crate::emulator::aot::is_aot_factory_registered();
    #[cfg(not(feature = "aot-emulator"))]
    let aot_ready = false;
    if opts.snapshot_main == SnapshotMainMode::Aot && !aot_ready {
        return Err(EmulateError::AotUnavailable);
    }
    let witness = ProvingWitness::<KoalaBearPoseidon2, RiscvChipType<Kb>, Vec<u8>> {
        program: Some(program),
        vk_root: None,
        stdin: Some(stdin.clone()),
        flag_empty_stdin: false,
        config: None,
        opts: Some(opts),
        records: Vec::new(),
    };
    let records = Mutex::new(Vec::new());
    let (mut reports, cycles, committed_bytes) = emulate_snapshot_pipeline_with(
        &witness,
        workers,
        DeferredSplit::AfterEveryChunk,
        |record, _done| {
            records
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(record)
        },
    )?;
    reports.sort_by_key(|report| report.start_chunk);
    let records = records.into_inner().unwrap_or_else(PoisonError::into_inner);
    let chunks = records.iter().filter(|record| record.is_cpu_chunk).count() as u32;
    Ok(EmulationOutput {
        records,
        chunks,
        committed_bytes,
        cycles,
        reports,
    })
}

/// Build the MLE `ProvingContext` for one chunk.
///
/// `complement` runs the included chips' `extra_record` (in brevis `all_chips()` order, matching
/// The record tracegen actually reads: the emulator's, plus every active chip's `extra_record`
/// output appended back in.
///
/// A chip's `extra_record` can raise events another chip's trace is built from -- byte lookups
/// most of all, but ALU events too -- so the emulator's raw counts UNDER-report what the traces
/// will hold. Sizing a shape from them hands the prover a shape its own trace overflows, which
/// is why the shape is chosen from this record rather than from the one the emulator returned.
pub fn augmented_record(
    chips: &[MetaChip<Kb, RiscvChipType<Kb>>],
    record: &EmulationRecord,
) -> EmulationRecord {
    let mut record = record.clone();
    for chip in chips.iter() {
        if air_id_for(&chip.name()).is_none() {
            continue;
        }
        if chip.is_active(&record) {
            let mut extra = EmulationRecord::default();
            chip.extra_record(&record, &mut extra);
            record.append(&mut extra);
        }
    }
    record
}

/// Build the proving context of one record: the extra-record pass first (as
/// `Machine::complement_record` would, so synthetic ALU events and byte lookups are populated),
/// then, in whitelist mode, the shape the record proves under, then each included active chip's
/// `generate_main`. Excluded chips never run, so they contribute no orphan `byte_lookups`.
pub fn build_ctx(
    // Used only for the `ChipBehavior` methods; the FRI parts are dead. See `RiscvMachine::new`.
    chips: &[MetaChip<Kb, RiscvChipType<Kb>>],
    record: &EmulationRecord,
    bucket: bool,
) -> ProvingContext<Pb> {
    let mut record = augmented_record(chips, record);

    // Coarse-bucket normalization (see `shape`), whitelist mode only. The shape fixes both
    // halves of a chunk's proof shape: every chip in it pads to its bucket height, and the chip
    // set itself is the canonical presence set for the chunk kind rather than the set the
    // chunk's events happen to activate. A CPU chunk therefore declares the whole core family
    // (`MLE_CORE_CANONICAL_PRESENCE`), event-free members included; a deferred chunk keeps its
    // event-driven set, which already depends only on the chunk kind. `is_active` is evaluated
    // here BEFORE the shape is set, so it takes its event-driven branch — the bootstrap the
    // shape is then built from.
    assert!(
        record.shape.is_none(),
        "record already carries a shape; the FRI shape system and the MLE bucket must not mix"
    );
    if !bucket {
        return build_ctx_inner(chips, &record);
    }
    let present: Vec<String> = chips
        .iter()
        .filter(|chip| bucketed_presence(chip, &record))
        .map(|chip| chip.name())
        .collect();
    let natural = crate::mle::machine::shape::mle_natural_heights(&record);
    let inner =
        crate::mle::machine::shape::select_riscv_shape(&present, &natural, record.is_cpu_chunk)
            .into_iter()
            .collect();
    record.shape = Some(crate::instances::compiler::shapes::riscv_shape::RiscvPadShape { inner });
    build_ctx_inner(chips, &record)
}

/// Trace assembly over a (possibly shape-set) record: generate each active chip's main trace
/// and wrap with the public values.
fn build_ctx_inner(
    chips: &[MetaChip<Kb, RiscvChipType<Kb>>],
    record: &EmulationRecord,
) -> ProvingContext<Pb> {
    // RISCV public values. Cpu and Ecall read the first RISCV_NUM_PVS; MemInit/MemFinal read a
    // MAX_NUM_PVS-sized array (the tail is recursion-padding, zero here).
    let raw_pvs: Vec<Kb> = record.public_values::<Kb>();
    let pvs_riscv: Vec<Kb> = raw_pvs.iter().copied().take(RISCV_NUM_PVS).collect();
    let mut pvs_max = raw_pvs;
    pvs_max.resize(MAX_NUM_PVS, Kb::ZERO);

    let mut per_trace: Vec<(usize, AirProvingContext<Pb>)> = Vec::new();
    let mut dummy = EmulationRecord::default();
    for chip in chips.iter() {
        if !chip.is_active(record) {
            continue;
        }
        let Some(id) = air_id_for(&chip.name()) else {
            // An active chip with no AIR in the list would emit interactions with no matching
            // receiver/sender, breaking bus balance deep in proving. Fail loudly instead.
            panic!(
                "active chip `{}` is not in the RISCV air list (program uses an unsupported chip)",
                chip.name()
            );
        };
        let trace = chip.generate_main(record, &mut dummy);
        let ctx = match id {
            air_id::CPU | air_id::ECALL => AirProvingContext::simple(trace, pvs_riscv.clone()),
            air_id::MEM_INIT | air_id::MEM_FINAL => {
                AirProvingContext::simple(trace, pvs_max.clone())
            }
            air_id::GLOBAL => {
                // Per-chunk GCS: the last-row cumulative_sum (trailing GCS_DIGEST_LEN columns),
                // bound to these public values by `GcsBindAir` — followed by the riscv
                // PublicValues copy (the Global air is every chunk's always-present carrier;
                // see `GcsBindAir::num_public_values`).
                let w = trace.width;
                let h = trace.values.len() / w;
                let mut pvs: Vec<Kb> = (0..GCS_DIGEST_LEN)
                    .map(|i| trace.values[(h - 1) * w + (w - GCS_DIGEST_LEN + i)])
                    .collect();
                pvs.extend_from_slice(&pvs_max);
                AirProvingContext::simple(trace, pvs)
            }
            _ => AirProvingContext::simple_no_pis(trace),
        };
        per_trace.push((id, ctx));
    }
    ProvingContext::new(per_trace)
}

/// Run the MLE debug checker (constraints + interactions/bus balance) over every chunk of
/// `records`. Panics on the first failure; returns cleanly when all chunks pass.
pub fn debug_records(
    program: Arc<Program>,
    records: &[EmulationRecord],
    log_stacked_height: usize,
    bucket: bool,
) {
    let engine: Engine = StarkEngine::new(riscv_params_with_100_bits_security(log_stacked_height));
    let airs = mle_riscv_air_refs(program, bucket);
    // Keygen once and reuse across chunks — `debug` would otherwise re-run it per record.
    let (pk, _) = engine.keygen_with_app_prep(&airs, RISCV_APP_PREP_AIR_IDS);
    let chips = RiscvChipType::<Kb>::all_chips();
    for (i, record) in records.iter().enumerate() {
        let ctx = build_ctx(&chips, record, bucket);
        engine.debug_with_pk(&airs, &ctx, &pk);
        tracing::info!("chunk {i}: MLE debug (constraints + interactions) OK");
    }
}

/// Reconstruct a per-chunk `SepticDigest` from `GcsBindAir`'s public values (x = first 7, y = last
/// 7 of the [`GCS_DIGEST_LEN`] elements).
fn gcs_from_pvs(pvs: &[Kb]) -> SepticDigest<Kb> {
    assert!(
        pvs.len() >= GCS_DIGEST_LEN,
        "GlobalChip public values ({}) too short for a {GCS_DIGEST_LEN}-element GCS digest",
        pvs.len()
    );
    SepticDigest(SepticCurve {
        x: SepticExtension(std::array::from_fn(|i| pvs[i])),
        y: SepticExtension(std::array::from_fn(|i| pvs[GCS_DIGEST_LEN / 2 + i])),
    })
}

/// A RISCV Phase-1 proof bundle: the shared verifying key plus one chunk proof per record.
///
/// `vk` is `Arc`-wrapped so downstream consumers can share a single verifying key across many shapes
/// without cloning; `chunk_proofs` are in record order. Decoupling prove from verify lets a caller
/// serialize, inspect, or independently re-verify the proofs.
pub struct RiscvProof {
    /// Verifying key for the full RISCV air set, shared across all chunks.
    pub vk: Arc<MultiStarkVerifyingKey<Sc>>,
    /// One proof per emulation record, in order.
    pub chunk_proofs: Vec<Proof<Sc>>,
}

impl RiscvProof {
    /// Decompose into `(vk, chunk_proofs)`.
    pub fn into_parts(self) -> (Arc<MultiStarkVerifyingKey<Sc>>, Vec<Proof<Sc>>) {
        (self.vk, self.chunk_proofs)
    }
}

/// Failure modes of [`verify_riscv`] / [`RiscvMachine::verify`].
#[derive(Debug, thiserror::Error)]
pub enum VerifyRiscvError {
    /// The bundle's verifying-key body does not hash to the trusted `expected_vk_pre_hash`.
    /// `verify_riscv` recomputes `hash(proof.vk.inner)` (not the self-reported `pre_hash` field,
    /// which is attacker-settable) to reject a deserialized bundle carrying a vk of the prover's
    /// choosing.
    #[error("verifying key body does not hash to the expected pre-hash")]
    UnexpectedVerifyingKey,
    /// Chunk `chunk`'s proof failed per-chunk verification.
    #[error("chunk {chunk}: {source}")]
    Chunk {
        chunk: usize,
        source: VerifierError<<Sc as StarkProtocolConfig>::EF>,
    },
    /// The trusted initial GCS plus the per-chunk global cumulative sums do not cancel: cross-chunk
    /// memory is inconsistent.
    #[error("cross-chunk global cumulative sum != 0 (memory inconsistency)")]
    CrossChunkMemoryInconsistency,
    /// An app-identity preprocessed commitment in the bundle's vk body (e.g. the program table)
    /// does not match the trusted value. The lean pre-hash deliberately does not cover these
    /// commitments, so this explicit check is what binds the bundle to the trusted program.
    #[error(
        "app-identity preprocessed commitment (air {air_id}) does not match the trusted value"
    )]
    UnexpectedAppCommitment { air_id: usize },
}

/// Why a RISCV chunk could not be proved.
///
/// The backend's own prover error is generic over the engine, which would put an engine type into
/// every signature that propagates this one; the message is the actionable part, so it is carried
/// as text.
#[derive(Debug, thiserror::Error)]
pub enum ProveRiscvError {
    /// The backend failed to produce a proof for chunk `chunk`.
    #[error("chunk {chunk}: MLE prove failed: {message}")]
    Prove { chunk: usize, message: String },
    /// A freshly produced chunk proof failed the inline verification `prove_chunk` was asked for.
    #[error("chunk {chunk}: freshly proved chunk failed verification: {source}")]
    SelfVerify {
        chunk: usize,
        source: VerifierError<<Sc as StarkProtocolConfig>::EF>,
    },
    /// Keygen produced a verifying key below the production soundness budget.
    #[error(transparent)]
    UnderBudget(#[from] UnderBudgetError),
}

/// Stateful, reusable RISCV prover/verifier for the MLE/WHIR backend.
///
/// Keygen + device transport run once in [`RiscvMachine::new`]; the engine, device-resident proving
/// key, verifying key, and chip set are then shared read-only. Each [`Self::prove_chunk`] builds its
/// own proving context + Fiat-Shamir transcript, so proving concurrently from `&self` is sound.
///
/// The free functions [`prove_riscv`] / [`verify_riscv`] are thin wrappers over it.
pub struct RiscvMachine {
    engine: Engine,
    d_pk: DeviceMultiStarkProvingKey<Pb>,
    vk: MultiStarkVerifyingKey<Sc>,
    // Used only for the `ChipBehavior` methods; the FRI parts are dead. See `RiscvMachine::new`.
    chips: Vec<MetaChip<Kb, RiscvChipType<Kb>>>,
    /// Whitelist-mode shape bucketing (see `shape`); off = natural heights, dynamic shapes.
    bucket: bool,
    /// Chunk proving concurrency; `None` falls back to [`prove_concurrency`].
    concurrency: Option<NonZeroUsize>,
}

impl RiscvMachine {
    /// Keygen once: build the engine from `log_stacked_height`, keygen the RISCV air set, transport
    /// the proving key to the device, and materialize the chip set for trace generation.
    pub fn new(
        program: Arc<Program>,
        log_stacked_height: usize,
        bucket: bool,
    ) -> Result<Self, UnderBudgetError> {
        Self::from_airs(
            mle_riscv_air_refs(program, bucket),
            log_stacked_height,
            bucket,
        )
    }

    /// [`Self::new`] for a caller that has already built the air set — and, in `bucket` mode, has
    /// already paid for the shape-padded program inside it. Building it twice is the whole cost
    /// this exists to avoid, so `airs` must be [`mle_riscv_air_refs`]'s output for the same
    /// program and the same `bucket`.
    pub fn from_airs(
        airs: Vec<AirRef<Sc>>,
        log_stacked_height: usize,
        bucket: bool,
    ) -> Result<Self, UnderBudgetError> {
        let engine: Engine =
            StarkEngine::new(riscv_params_with_100_bits_security(log_stacked_height));
        let (pk, vk) = engine.keygen_with_app_prep(&airs, RISCV_APP_PREP_AIR_IDS);
        admit_production_vk("riscv", "cpu", &vk)?;
        let d_pk = engine.device().transport_pk_to_device(&pk);
        // The MLE backend uses these chips only for their `ChipBehavior` methods
        // (`name`/`is_active`/`extra_record`/`generate_main`). `MetaChip::new` is a FRI constructor:
        // it runs a full symbolic AIR eval per chip and builds the `VirtualPairLookup`s /
        // `log_quotient_degree` that the MLE path immediately discards and re-derives in
        // `engine.keygen(&airs)` above.
        //
        // TODO(fri-removal): carry bare `RiscvChipType<Kb>` enums (they impl `ChipBehavior`
        // directly) instead of `MetaChip`, here and throughout the MLE glue. Until then the FRI-only
        // `VirtualPairLookup` / `symbolic_to_virtual_pair` (`vm/src/machine/lookup.rs`) can't be
        // deleted, since the MLE path builds one per chip on every `RiscvMachine::new`.
        let chips = RiscvChipType::<Kb>::all_chips();
        Ok(Self {
            engine,
            d_pk,
            vk,
            chips,
            bucket,
            concurrency: None,
        })
    }

    /// Fix the chunk proving concurrency, overriding `PROVE_CONCURRENCY`.
    ///
    /// The bound caps peak memory (one full proving working set per in-flight chunk), so a caller
    /// sizing a host has to be able to state it rather than hope the environment agrees.
    pub fn with_concurrency(mut self, concurrency: NonZeroUsize) -> Self {
        self.concurrency = Some(concurrency);
        self
    }

    /// Prove one chunk. Takes `&self` so a worker pool can prove chunks concurrently. When `verify`
    /// is set, the fresh proof is verified inline; the cross-chunk GCS check is a whole-proof
    /// property and lives in [`Self::verify`], not here.
    ///
    /// `chunk` names the record in errors only.
    pub fn prove_chunk(
        &self,
        record: &EmulationRecord,
        chunk: usize,
        verify: bool,
    ) -> Result<Proof<Sc>, ProveRiscvError> {
        let ctx = build_ctx(&self.chips, record, self.bucket);
        let proof = self
            .engine
            .prove(&self.d_pk, ctx)
            .map_err(|e| ProveRiscvError::Prove {
                chunk,
                message: format!("{e:?}"),
            })?;
        if verify {
            self.engine
                .verify(&self.vk, &proof)
                .map_err(|source| ProveRiscvError::SelfVerify { chunk, source })?;
        }
        Ok(proof)
    }

    /// Prove the whole program into a serializable bundle: one [`Proof`] per record, in order, plus
    /// the shared verifying key.
    ///
    /// Chunks are proved in bounded-concurrency batches (see [`prove_concurrency`]):
    /// [`Self::prove_chunk`] takes `&self` and builds its own proving context + transcript, so
    /// proving concurrently is sound; the batch bound caps peak memory since every in-flight
    /// chunk holds a full proving working set.
    pub fn prove(&self, records: &[EmulationRecord]) -> Result<RiscvProof, ProveRiscvError> {
        let conc = resolved_concurrency(self.concurrency);
        let mut chunk_proofs = Vec::with_capacity(records.len());
        for (batch_idx, batch) in records.chunks(conc).enumerate() {
            let base = batch_idx * conc;
            let batch_proofs: Vec<Proof<Sc>> = batch
                .par_iter()
                .enumerate()
                .map(|(j, record)| {
                    let proof = self.prove_chunk(record, base + j, false)?;
                    tracing::info!("chunk {}: MLE prove OK", base + j);
                    Ok(proof)
                })
                .collect::<Result<_, ProveRiscvError>>()?;
            chunk_proofs.extend(batch_proofs);
        }
        Ok(RiscvProof {
            vk: Arc::new(self.vk.clone()),
            chunk_proofs,
        })
    }

    /// Verify a bundle against this machine's *trusted* verifying key: per-chunk `engine.verify` +
    /// the cross-chunk `initial_gcs + Σ per-chunk gcs == 0` memory-consistency check. Because the
    /// machine keygen'd `self.vk`, no `expected_vk_pre_hash` argument is needed; the stateless
    /// [`verify_riscv`] takes one for deserialized bundles whose vk is untrusted.
    pub fn verify(
        &self,
        proof: &RiscvProof,
        initial_gcs: SepticDigest<Kb>,
    ) -> Result<(), VerifyRiscvError> {
        verify_chunks_and_gcs(&self.engine, &self.vk, &proof.chunk_proofs, initial_gcs)
    }

    /// The canonical verifying key.
    pub fn vk(&self) -> &MultiStarkVerifyingKey<Sc> {
        &self.vk
    }
}

/// Shared verify core: per-chunk `engine.verify(vk, ..)` + the cross-chunk
/// `initial_gcs + Σ per-chunk gcs == 0` memory-consistency check. Passing `SepticDigest::zero()` as
/// `initial_gcs` is equivalent to omitting the term (the septic `Sum` treats it as the identity).
fn verify_chunks_and_gcs(
    engine: &Engine,
    vk: &MultiStarkVerifyingKey<Sc>,
    chunk_proofs: &[Proof<Sc>],
    initial_gcs: SepticDigest<Kb>,
) -> Result<(), VerifyRiscvError> {
    // The initial-memory term comes from the trusted argument, never from the bundle.
    let mut gcs_terms: Vec<SepticDigest<Kb>> = vec![initial_gcs];
    for (i, chunk_proof) in chunk_proofs.iter().enumerate() {
        engine
            .verify(vk, chunk_proof)
            .map_err(|source| VerifyRiscvError::Chunk { chunk: i, source })?;
        gcs_terms.push(gcs_from_pvs(&chunk_proof.public_values[air_id::GLOBAL]));
        tracing::info!("chunk {i}: MLE verify OK");
    }

    let total: SepticDigest<Kb> = gcs_terms.into_iter().sum();
    if !total.is_zero() {
        return Err(VerifyRiscvError::CrossChunkMemoryInconsistency);
    }
    tracing::info!("cross-chunk global cumulative sum == 0 ✓");
    Ok(())
}

/// Keygen the RISCV air set, transport the proving key, and prove every chunk on the MLE/WHIR
/// backend. Thin wrapper over [`RiscvMachine`]: no verification and no environment hooks, so the
/// returned [`RiscvProof`] can be serialized, inspected, or verified later by [`verify_riscv`].
pub fn prove_riscv(
    program: Arc<Program>,
    records: &[EmulationRecord],
    log_stacked_height: usize,
    bucket: bool,
) -> Result<RiscvProof, ProveRiscvError> {
    RiscvMachine::new(program, log_stacked_height, bucket)?.prove(records)
}

/// Verify a *deserialized* bundle whose verifying key is untrusted (e.g. after a wire round-trip),
/// and check cross-chunk memory consistency: `initial_gcs + Σ per-chunk gcs == 0`. When you already
/// hold the machine, prefer [`RiscvMachine::verify`].
///
/// `expected_vk_pre_hash`, `expected_app_commits`, and `initial_gcs` are **trusted inputs** —
/// never taken from the bundle. `expected_app_commits` lists `(air_id, trusted commitment)` for
/// every app-identity preprocessed table (for a RISCV bundle:
/// `[(air_id::PROGRAM, <trusted program commitment>)]`); the SAME air-id set must have been
/// marked at keygen, since the lean pre-hash recomputation excludes exactly those commitments
/// and this explicit comparison is what binds them instead. The engine is rebuilt from
/// `proof.vk.inner.params`, so no height argument is needed.
pub fn verify_riscv(
    proof: &RiscvProof,
    expected_vk_pre_hash: <Sc as StarkProtocolConfig>::Digest,
    expected_app_commits: &[(usize, <Sc as StarkProtocolConfig>::Digest)],
    initial_gcs: SepticDigest<Kb>,
) -> Result<(), VerifyRiscvError> {
    // Reconstruct the engine from the vk's (untrusted) system params. The KoalaBear hasher is
    // param-independent, so the recomputation below is canonical regardless.
    let engine: Engine = StarkEngine::new(proof.vk.inner.params.clone());

    // Bind the vk BODY (machine + shape) to the trusted pre-hash: recompute the lean
    // `hash(inner)` rather than trust the self-reported `pre_hash` field, and require it to
    // equal both the trusted hash and that field.
    let app_ids: Vec<usize> = expected_app_commits.iter().map(|(id, _)| *id).collect();
    let computed_pre_hash = compute_vk_pre_hash(engine.config(), &proof.vk.inner, &app_ids);
    if computed_pre_hash != expected_vk_pre_hash || proof.vk.pre_hash != computed_pre_hash {
        return Err(VerifyRiscvError::UnexpectedVerifyingKey);
    }

    // Bind the app-identity commitments the lean pre-hash deliberately excludes: each must
    // equal its trusted value. Without this, a bundle could swap the program table while
    // keeping a valid (app-independent) pre-hash.
    for &(air_id, expected_commit) in expected_app_commits {
        let got = proof
            .vk
            .inner
            .per_air
            .get(air_id)
            .and_then(|avk| avk.preprocessed_data.as_ref())
            .map(|p| p.commit);
        if got != Some(expected_commit) {
            return Err(VerifyRiscvError::UnexpectedAppCommitment { air_id });
        }
    }

    verify_chunks_and_gcs(&engine, &proof.vk, &proof.chunk_proofs, initial_gcs)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use p3_field::PrimeCharacteristicRing;

    use super::*;
    use crate::{
        compiler::riscv::{instruction::Instruction, opcode::Opcode, program::Program},
        machine::septic::{SepticCurve, SepticDigest, SepticExtension},
        mle::machine::air::GCS_DIGEST_LEN,
    };

    /// Prebuilt RV64 fibonacci guest committing `(n, F(n), F(n+1))` as three 32-byte big-endian
    /// words, byte-identical to `perf/bench_data/rv64/fib-elf`. Keep it prebuilt: a rebuild, from
    /// `examples/fibonacci/app` or anywhere else, is a different ELF with a different program id.
    const RV64_FIB_ELF: &[u8] = include_bytes!("../../compiler/test_elf/fib-elf");

    /// An explicit concurrency outranks `PROVE_CONCURRENCY`; without one the environment decides.
    ///
    /// Asserted in a child process, because `set_var` in a live test binary races every other
    /// thread's `getenv`.
    #[test]
    fn an_explicit_concurrency_outranks_the_environment() {
        const MARKER: &str = "[env-probe] an explicit concurrency outranked PROVE_CONCURRENCY";
        const CHILD_VAR: &str = "PICO_CONCURRENCY_ENV_PROBE";
        const TEST_NAME: &str =
            "mle::machine::riscv::tests::an_explicit_concurrency_outranks_the_environment";

        if std::env::var(CHILD_VAR).is_ok() {
            assert_eq!(
                resolved_concurrency(None),
                7,
                "the child's env was not applied"
            );
            assert_eq!(
                resolved_concurrency(Some(std::num::NonZeroUsize::new(2).unwrap())),
                2,
                "PROVE_CONCURRENCY outranked an explicit argument"
            );
            println!("{MARKER}");
            return;
        }

        let exe = std::env::current_exe().expect("test binary path");
        let out = std::process::Command::new(exe)
            .args(["--exact", TEST_NAME, "--nocapture"])
            .env(CHILD_VAR, "1")
            .env("PROVE_CONCURRENCY", "7")
            .output()
            .expect("re-run this test binary");
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success(),
            "child failed: {stdout}{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            stdout.contains(MARKER),
            "child ran no assertion (a stale --exact name matches nothing and still exits 0): \
             {stdout}"
        );
    }

    /// `(F(n), F(n+1))` in wrapping `u32`, recomputed here so the assertions compare against a
    /// derived value rather than a recorded byte string.
    fn host_fib_u32(n: u32) -> (u32, u32) {
        let (mut a, mut b) = (0u32, 1u32);
        for _ in 0..n {
            let next = a.wrapping_add(b);
            a = b;
            b = next;
        }
        (a, b)
    }

    /// Decode the guest's commit stream: three 32-byte big-endian words.
    fn decode_fib_commit(committed: &[u8]) -> (u32, u32, u32) {
        assert_eq!(
            committed.len(),
            96,
            "expected three 32-byte words from the fib guest, got {} byte(s) — if this is 0 the \
             ELF was rebuilt from a guest that does not commit",
            committed.len()
        );
        let word = |i: usize| -> u32 {
            let w = &committed[i * 32..(i + 1) * 32];
            assert!(
                w[..28].iter().all(|b| *b == 0),
                "word {i} does not fit in u32: {w:02x?}"
            );
            u32::from_be_bytes([w[28], w[29], w[30], w[31]])
        };
        (word(0), word(1), word(2))
    }

    fn fib_stdin(n: u32) -> EmulatorStdin<Program, Vec<u8>> {
        let mut builder = EmulatorStdin::<Program, Vec<u8>>::new_builder::<
            crate::configs::stark_config::KoalaBearPoseidon2,
        >();
        builder.write(&n);
        builder.finalize()
    }

    fn fib_program() -> Arc<Program> {
        crate::compiler::riscv::compiler::Compiler::new(
            crate::compiler::riscv::compiler::SourceType::RISCV,
            RV64_FIB_ELF,
        )
        .expect("failed to parse the prebuilt RV64 fib ELF")
        .compile()
    }

    /// Every field stated: `EmulatorOpts::default` reads `CHUNK_SIZE`, `CHUNK_BATCH_SIZE` and
    /// `SPLIT_THRESHOLD`, so a `..Default::default()` here would leave these tests measuring the
    /// environment they are meant to be independent of.
    fn fixed_opts(chunk_size: u32) -> EmulatorOpts {
        EmulatorOpts {
            chunk_size,
            chunk_batch_size: 1,
            split_opts: crate::emulator::opts::SplitOpts::new(chunk_size as usize >> 2),
            max_cycles: Some(1 << 32),
            cycle_tracker: false,
            cost_estimator: false,
            snapshot_main: SnapshotMainMode::Interpreter,
        }
    }

    /// The committed bytes come back and decode to what the host computed.
    #[test]
    fn emulate_returns_the_guests_committed_bytes() {
        for n in [10u32, 20, 90] {
            let out = emulate_with_opts(fib_program(), &fib_stdin(n), fixed_opts(1 << 22))
                .expect("fib emulation");

            assert!(
                !out.committed_bytes.is_empty(),
                "n={n}: the guest committed nothing — a test against a non-committing guest \
                 asserts nothing"
            );
            assert!(!out.records.is_empty(), "n={n}: no records");
            assert!(out.cycles > 0, "n={n}: zero cycles emulated");

            let (got_n, got_a, got_b) = decode_fib_commit(&out.committed_bytes);
            let (want_a, want_b) = host_fib_u32(n);
            assert_eq!(got_n, n, "n={n}: guest echoed the wrong input");
            assert_eq!(
                got_a, want_a,
                "n={n}: committed F(n) disagrees with the host"
            );
            assert_eq!(
                got_b, want_b,
                "n={n}: committed F(n+1) disagrees with the host"
            );
        }
    }

    /// An option this path cannot honour is reported, not ignored and not fatal.
    #[test]
    fn emulate_with_opts_refuses_an_option_it_cannot_honour() {
        let opts = fixed_opts(1 << 22).with_snapshot_main(SnapshotMainMode::Aot);
        let err = emulate_with_opts(fib_program(), &fib_stdin(10), opts)
            .expect_err("Aot must not be accepted");
        assert!(matches!(err, EmulateError::UnsupportedSnapshotMain(_)));
    }

    /// An option this path *does* accept is honoured, not drained and dropped.
    #[test]
    fn emulate_with_opts_returns_the_tracking_it_was_asked_for() {
        let stdin = fib_stdin(10);

        let off = emulate_with_opts(fib_program(), &stdin, fixed_opts(1 << 22)).expect("off");
        assert!(off.reports.iter().all(|r| r.cycle_tracker.is_none()));
        assert!(off.reports.iter().all(|r| r.host_cycle_estimator.is_none()));

        let on = emulate_with_opts(
            fib_program(),
            &stdin,
            fixed_opts(1 << 22)
                .with_cycle_tracker()
                .with_cost_estimator(),
        )
        .expect("on");
        assert!(
            on.reports.iter().all(|r| r.cycle_tracker.is_some()),
            "cycle_tracker was accepted, paid for and discarded"
        );
        assert!(
            on.reports.iter().all(|r| r.host_cycle_estimator.is_some()),
            "cost_estimator was accepted, paid for and discarded"
        );
    }

    /// An emulation failure is returned, not fatal: `max_cycles` is usable as a bound.
    #[test]
    fn emulate_with_opts_reports_a_failed_emulation() {
        let opts = EmulatorOpts {
            max_cycles: Some(64),
            ..fixed_opts(1 << 22)
        };
        let err = emulate_with_opts(fib_program(), &fib_stdin(90), opts)
            .expect_err("64 cycles cannot finish fib");
        assert!(matches!(
            err,
            EmulateError::Emulation(EmulationError::ExceededCycleLimit(_))
        ));
    }

    /// The caller's `chunk_size` decides the chunking, and chunking does not change the output.
    #[test]
    fn emulate_with_opts_honours_the_callers_chunk_size() {
        let stdin = fib_stdin(10);
        let whole =
            emulate_with_opts(fib_program(), &stdin, fixed_opts(1 << 22)).expect("one chunk");
        let split = emulate_with_opts(fib_program(), &stdin, fixed_opts(2048)).expect("split");

        assert_eq!(whole.chunks, 1, "a 2^22 chunk holds this whole run");
        assert!(
            split.chunks > whole.chunks,
            "a 2048-cycle chunk should split a {}-cycle run: {} vs {} chunk(s)",
            split.cycles,
            split.chunks,
            whole.chunks
        );
        // `records` also carries the deferred records the split emits at the end, so it runs ahead
        // of the chunk count on both arms.
        assert!(split.records.len() >= split.chunks as usize);
        assert_eq!(
            whole.committed_bytes, split.committed_bytes,
            "chunking must not change what the guest committed"
        );
        assert_eq!(
            whole.cycles, split.cycles,
            "chunking must not change cycles"
        );
    }

    /// `CHUNK_SIZE` must not reach `emulate_with_opts`.
    ///
    /// Asserted in a child process, because `set_var` in a live test binary races every other
    /// thread's `getenv`.
    #[test]
    fn chunk_size_env_does_not_reach_emulate_with_opts() {
        const MARKER: &str = "[env-probe] emulate_with_opts ignored CHUNK_SIZE";
        const CHILD_VAR: &str = "PICO_EMULATE_ENV_PROBE";
        const TEST_NAME: &str =
            "mle::machine::riscv::tests::chunk_size_env_does_not_reach_emulate_with_opts";

        if std::env::var(CHILD_VAR).is_ok() {
            // 2048 would split this run into several chunks if the environment were read.
            let out = emulate_with_opts(fib_program(), &fib_stdin(10), fixed_opts(1 << 22))
                .expect("fib emulation");
            assert_eq!(out.chunks, 1, "CHUNK_SIZE reached emulate_with_opts");
            println!("{MARKER}");
            return;
        }

        let exe = std::env::current_exe().expect("test binary path");
        let child = std::process::Command::new(exe)
            .args(["--exact", TEST_NAME, "--nocapture"])
            .env("CHUNK_SIZE", "2048")
            .env(CHILD_VAR, "1")
            .output()
            .expect("re-run this test binary");
        let stdout = String::from_utf8_lossy(&child.stdout);
        assert!(
            child.status.success(),
            "child failed:\n{stdout}{}",
            String::from_utf8_lossy(&child.stderr)
        );
        // `--exact` against a stale name matches nothing and still exits 0.
        assert!(
            stdout.contains(MARKER),
            "child did not run the body — is TEST_NAME still this test's path?\n{stdout}"
        );
    }

    /// Minimal non-empty program: enough for the ProgramChip preprocessed table (keygen-only
    /// tests; never emulated).
    fn test_program() -> Program {
        Program {
            instructions: vec![Instruction::new(Opcode::ADD, 0, 0, 0, false, false)].into(),
            pc_start: 0,
            pc_base: 0,
            memory_image: Default::default(),
            preprocessed_shape: None,
        }
    }
    use pico_mle_core::{
        codec::{Decode, Encode},
        keygen::types::{LinearConstraint, MultiStarkVerifyingKey},
        proof::Proof,
        test_utils::{test_system_params_small, FibFixture, TestFixture},
        StarkEngine,
    };

    /// A small, self-consistent single-chunk bundle proven on the **CPU engine** — the exact engine
    /// [`verify_riscv`] reconstructs from the vk params, so an untampered proof verifies and only
    /// tampering breaks it. The bundle carries one dummy AIR, not the RISCV set, so it exercises only
    /// `verify_riscv`'s early-exit paths (vk-trust + per-chunk verify), both of which short-circuit
    /// before `gcs_from_pvs` ever indexes `public_values[air_id::GLOBAL]`.
    fn small_cpu_bundle() -> RiscvProof {
        let engine: Engine = StarkEngine::new(test_system_params_small(2, 5, 3));
        let (vk, proof) = FibFixture::new(0, 1, 1 << 5).keygen_and_prove(&engine);
        engine
            .verify(&vk, &proof)
            .expect("fixture proof must verify under the CPU engine");
        RiscvProof {
            vk: Arc::new(vk),
            chunk_proofs: vec![proof],
        }
    }

    /// A bundle whose vk does not match the trusted `expected_vk_pre_hash` is rejected with
    /// `UnexpectedVerifyingKey` before any proof byte is inspected — the guard that stops a
    /// deserialized bundle from shipping a self-consistent vk of the prover's choosing.
    #[test]
    fn verify_riscv_rejects_wrong_vk() {
        let bundle = small_cpu_bundle();
        let mut wrong = bundle.vk.pre_hash;
        wrong[0] += Kb::ONE; // Digest = [Kb; DIGEST_SIZE]; perturb one limb
        assert!(matches!(
            verify_riscv(&bundle, wrong, &[], SepticDigest::zero()),
            Err(VerifyRiscvError::UnexpectedVerifyingKey)
        ));
    }

    /// The substitution attack proper: the bundle's `pre_hash` field *and* the trusted `expected`
    /// both hold the honest value, but the vk **body** is tampered. `verify_riscv` must recompute
    /// `hash(inner)` and reject — a guard that trusted the self-reported `pre_hash` field alone would
    /// wrongly accept this.
    #[test]
    fn verify_riscv_rejects_vk_body_substitution() {
        let honest = small_cpu_bundle();
        let expected = honest.vk.pre_hash; // trusted honest hash

        // Tamper the vk body (any change flips hash(inner)) while pinning `pre_hash` to `expected`.
        let mut inner = honest.vk.inner.clone();
        inner.trace_height_constraints.push(LinearConstraint {
            coefficients: vec![0],
            threshold: 1,
        });
        let forged = RiscvProof {
            vk: Arc::new(MultiStarkVerifyingKey {
                inner,
                pre_hash: expected,
            }),
            chunk_proofs: honest.chunk_proofs.clone(),
        };
        assert!(matches!(
            verify_riscv(&forged, expected, &[], SepticDigest::zero()),
            Err(VerifyRiscvError::UnexpectedVerifyingKey)
        ));
    }

    /// A decodable-but-invalid chunk proof surfaces as `Chunk { chunk, .. }`, making that variant
    /// test-reachable. The proof is first round-tripped through the versioned codec (a live
    /// `Proof::decode`), then one commitment is perturbed so the proof *shape* stays valid but
    /// Fiat-Shamir no longer agrees. (Raw malformed-byte decode rejection is covered by the codec
    /// tests.)
    #[test]
    fn verify_riscv_rejects_tampered_chunk() {
        let bundle = small_cpu_bundle();
        let bytes = bundle.chunk_proofs[0].encode_to_vec().unwrap();
        let mut proof = Proof::<Sc>::decode_from_bytes(&bytes).unwrap();
        assert_eq!(
            proof, bundle.chunk_proofs[0],
            "codec round-trip must be exact"
        );
        proof.common_main_commit[0] += Kb::ONE; // well-formed, but no longer a valid commitment
        let vk = bundle.vk.clone();
        let vk_hash = vk.pre_hash;
        let tampered = RiscvProof {
            vk,
            chunk_proofs: vec![proof],
        };
        assert!(matches!(
            verify_riscv(&tampered, vk_hash, &[], SepticDigest::zero()),
            Err(VerifyRiscvError::Chunk { chunk: 0, .. })
        ));
    }

    /// Lean pre-hash semantics on a real RISCV keygen: mutating the **program-table** commitment
    /// (app identity, excluded from the preimage) leaves the pre-hash unchanged, while mutating
    /// the **byte-table** commitment or the program table's geometry (machine/shape data, kept in
    /// the preimage) changes it. Also pins the unmarked semantics: with no app marks, the
    /// program commitment IS covered.
    #[test]
    fn lean_pre_hash_excludes_exactly_the_app_commitment() {
        let engine: Engine = StarkEngine::new(riscv_params_with_100_bits_security(22));
        let airs = mle_riscv_air_refs(Arc::new(test_program()), false);
        let (_, vk) = engine.keygen_with_app_prep(&airs, RISCV_APP_PREP_AIR_IDS);

        let base = compute_vk_pre_hash(engine.config(), &vk.inner, RISCV_APP_PREP_AIR_IDS);
        assert_eq!(base, vk.pre_hash, "keygen must use the same lean SSOT");

        // Program commitment (app identity): excluded → pre-hash unchanged.
        let mut inner = vk.inner.clone();
        inner.per_air[air_id::PROGRAM]
            .preprocessed_data
            .as_mut()
            .unwrap()
            .commit[0] += Kb::ONE;
        assert_eq!(
            compute_vk_pre_hash(engine.config(), &inner, RISCV_APP_PREP_AIR_IDS),
            base,
            "program commitment must NOT be covered by the lean pre-hash"
        );
        // ... but with no app marks it IS covered (per-air machine-table semantics).
        assert_ne!(
            compute_vk_pre_hash(engine.config(), &inner, &[]),
            compute_vk_pre_hash(engine.config(), &vk.inner, &[]),
            "unmarked per-air commitments must be covered"
        );

        // Byte-table commitment (machine constant): kept → pre-hash changes.
        let mut inner = vk.inner.clone();
        inner.per_air[air_id::BYTE]
            .preprocessed_data
            .as_mut()
            .unwrap()
            .commit[0] += Kb::ONE;
        assert_ne!(
            compute_vk_pre_hash(engine.config(), &inner, RISCV_APP_PREP_AIR_IDS),
            base,
            "byte-table commitment must be covered"
        );

        // Program-table geometry (shape data): kept → pre-hash changes.
        let mut inner = vk.inner.clone();
        inner.per_air[air_id::PROGRAM]
            .preprocessed_data
            .as_mut()
            .unwrap()
            .hypercube_dim += 1;
        assert_ne!(
            compute_vk_pre_hash(engine.config(), &inner, RISCV_APP_PREP_AIR_IDS),
            base,
            "program-table geometry must be covered"
        );
    }

    /// The substitution the lean pre-hash deliberately does not catch: swap the program-table
    /// commitment in the vk body while keeping the (app-independent) `pre_hash` field honest.
    /// `verify_riscv` must reject it via the explicit `expected_app_commits` comparison — the
    /// check that carries the program binding the pre-hash deliberately does not.
    #[test]
    fn verify_riscv_rejects_program_commit_substitution() {
        let engine: Engine = StarkEngine::new(riscv_params_with_100_bits_security(22));
        let airs = mle_riscv_air_refs(Arc::new(test_program()), false);
        let (_, vk) = engine.keygen_with_app_prep(&airs, RISCV_APP_PREP_AIR_IDS);
        let trusted_pre_hash = vk.pre_hash;
        let trusted_program_commit = riscv_program_commit(&vk);

        // Honest empty-chunk bundle passes (gcs total = zero initial term alone).
        let honest = RiscvProof {
            vk: Arc::new(vk.clone()),
            chunk_proofs: vec![],
        };
        verify_riscv(
            &honest,
            trusted_pre_hash,
            &[(air_id::PROGRAM, trusted_program_commit)],
            SepticDigest::zero(),
        )
        .expect("honest bundle must pass");

        // Swap the program commitment; the lean pre-hash stays valid — only the explicit
        // app-commitment check can catch this.
        let mut inner = vk.inner.clone();
        inner.per_air[air_id::PROGRAM]
            .preprocessed_data
            .as_mut()
            .unwrap()
            .commit[0] += Kb::ONE;
        let forged = RiscvProof {
            vk: Arc::new(MultiStarkVerifyingKey {
                inner,
                pre_hash: trusted_pre_hash,
            }),
            chunk_proofs: vec![],
        };
        assert!(matches!(
            verify_riscv(
                &forged,
                trusted_pre_hash,
                &[(air_id::PROGRAM, trusted_program_commit)],
                SepticDigest::zero(),
            ),
            Err(VerifyRiscvError::UnexpectedAppCommitment {
                air_id: air_id::PROGRAM
            })
        ));
    }

    /// A single dummy AIR through the full production chain: keygen → prove → codec round-trip →
    /// verify on the CPU engine. Pins that a proof survives versioned (de)serialization and still
    /// verifies.
    #[test]
    fn single_air_full_chain_prove_codec_verify() {
        let engine: Engine = StarkEngine::new(test_system_params_small(2, 5, 3));
        let fixture = FibFixture::new(0, 1, 1 << 5);
        let (pk, vk) = fixture.keygen(&engine);
        let proof = fixture.prove(&engine, &pk);

        let bytes = proof.encode_to_vec().expect("encode");
        let decoded = Proof::<Sc>::decode_from_bytes(&bytes).expect("decode");
        assert_eq!(decoded, proof, "codec round-trip must be exact");

        engine
            .verify(&vk, &decoded)
            .expect("decoded proof must verify");
    }

    /// `gcs_from_pvs` splits the GLOBAL public values into the septic-curve `(x, y)` halves and
    /// ignores any trailing recursion-padding values.
    #[test]
    fn gcs_from_pvs_splits_x_and_y_halves() {
        let pvs: Vec<Kb> = (0..GCS_DIGEST_LEN).map(|i| Kb::from_usize(i + 1)).collect();
        let want = SepticDigest(SepticCurve {
            x: SepticExtension(std::array::from_fn(|i| pvs[i])),
            y: SepticExtension(std::array::from_fn(|i| pvs[GCS_DIGEST_LEN / 2 + i])),
        });
        assert_eq!(gcs_from_pvs(&pvs), want);

        // Extra public values beyond the digest (recursion padding) are ignored.
        let mut padded = pvs;
        padded.push(Kb::from_usize(999));
        assert_eq!(gcs_from_pvs(&padded), want);
    }

    /// `gcs_from_pvs` panics loudly when the public values are too short for a full digest.
    #[test]
    #[should_panic(expected = "too short")]
    fn gcs_from_pvs_panics_on_short_pvs() {
        let _ = gcs_from_pvs(&[Kb::ZERO; GCS_DIGEST_LEN - 1]);
    }

    /// The RISCV air table is position-indexed (`INCLUDED[i].1 == i`), chip names round-trip through
    /// `air_id_for`, the named `air_id::*` constants agree with their table rows, and
    /// `mle_riscv_air_refs` yields exactly one air ref per table row — the positional invariant
    /// `build_ctx` relies on to map an active chip's name to its AIR id.
    #[test]
    fn included_air_table_is_position_indexed() {
        for (i, (name, id)) in INCLUDED.iter().enumerate() {
            assert_eq!(*id, i, "INCLUDED[{i}] id must equal its position");
            assert_eq!(
                air_id_for(name),
                Some(i),
                "air_id_for({name}) must be Some({i})"
            );
        }
        // Named core-set constants agree with their table positions.
        assert_eq!(INCLUDED[air_id::ADD].1, air_id::ADD);
        assert_eq!(INCLUDED[air_id::GLOBAL].1, air_id::GLOBAL);
        assert_eq!(INCLUDED[air_id::POSEIDON2].1, air_id::POSEIDON2);
        // One air ref per table row, in order (constructed cheaply from an empty program).
        let airs = mle_riscv_air_refs(Arc::new(Program::default()), false);
        assert_eq!(airs.len(), INCLUDED.len());
    }

    /// Every chip the emulator can activate has a row in the air table, so the host prover's
    /// `UnsupportedChip` refusal (`check_chips_provable` in `sdk/prover`) has nothing to refuse. A
    /// chip added to the pool without an AIR makes that refusal reachable again, and it then wants a
    /// guest that reaches it in `sdk/prover/src/tests/precompiles.rs`.
    #[test]
    fn every_chip_the_emulator_serves_has_an_air() {
        let missing: Vec<String> = RiscvChipType::<Kb>::all_chip_variants()
            .into_iter()
            .map(|chip| chip.name())
            .filter(|name| air_id_for(name).is_none())
            .collect();
        assert!(
            missing.is_empty(),
            "chips with no MLE RISC-V air: {missing:?}"
        );
    }
}
