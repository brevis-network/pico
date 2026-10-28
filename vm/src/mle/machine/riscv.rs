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
//!
//! The engine is CPU by default and GPU under the `cuda` feature (a compile-time swap of the
//! [`Engine`] alias). Traces are always built on the host ([`build_ctx`] → [`HostPb`]) and bridged
//! to the engine backend by [`ctx_to_engine`] (identity on CPU, H2D transport on GPU); the GPU
//! path additionally offers on-device trace generation via [`build_ctx_gpu`].

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
    compiler::{program::ProgramBehavior, riscv::program::Program},
    configs::stark_config::KoalaBearPoseidon2,
    emulator::{
        opts::{EmulatorOpts, SnapshotMainMode},
        record::RecordBehavior,
        riscv::{
            alu_event_pool::{
                init_alu_event_buffer_pool, is_alu_pool_initialized, ALU_EVENT_BUFFER_CAPACITY,
            },
            cpu_event_pool::{
                init_cpu_event_buffer_pool, is_pool_initialized, CPU_EVENT_BUFFER_CAPACITY,
            },
            emulator::{EmulationError, RiscvEmulator},
            event_pool::use_growable_event_buffers,
            public_values::RecordFinalPvsState,
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
use pico_mle_cpu::{CpuBackend, KoalaBearPoseidon2CpuEngine};

/// Base field for the KoalaBear RISCV proof.
pub type Kb = KoalaBear;
/// The MLE engine (KoalaBear + Poseidon2 + WHIR): CPU by default, GPU with the `cuda`
/// feature. Both share the same `StarkProtocolConfig` (`Sc`), so keys/proofs are interchangeable
/// at the type level; only the prover backend differs.
#[cfg(not(feature = "cuda"))]
pub type Engine = KoalaBearPoseidon2CpuEngine;
#[cfg(feature = "cuda")]
pub type Engine = cuda_mle::KoalaBearPoseidon2GpuEngine;
/// The `StarkProtocolConfig` of the engine.
pub type Sc = <Engine as StarkEngine>::SC;
/// The prover backend of the engine.
pub type Pb = <Engine as StarkEngine>::PB;
/// The host (CPU) backend traces are built on: [`build_ctx`] always produces a host context
/// (`chip.generate_main` yields host row-major matrices); [`ctx_to_engine`] bridges it to the
/// engine's backend (identity on CPU, H2D transport on GPU).
pub type HostPb = CpuBackend<Sc>;

/// The default GPU device — card 0. Single-card runs pin one visible card via
/// `CUDA_VISIBLE_DEVICES`, making this the only target; multi-card runs bind each worker thread to
/// its card (`cuda_mle::runtime::context::set_device`) and the machine layer resolves the device
/// from the calling thread via [`bound_device`] instead of this constant.
pub const MLE_GPU_DEVICE: usize = 0;

/// The device the calling thread is bound to. The machine layer runs on per-card threads (each
/// bound at spawn), so "current device" is the correct card for trace-gen and keygen — no device
/// parameter needs threading through the machines.
#[cfg(feature = "cuda")]
pub(crate) fn bound_device() -> usize {
    // Surfaced rather than defaulted to card 0: proving on one card while allocating against
    // another card's pool surfaces as an unrelated OOM much later. `cudaGetDevice` succeeds
    // (reading card 0) on a thread that never bound, so a missed binding is caught by the stream
    // pool's device assert instead.
    cuda_mle::runtime::context::get_device().expect("cudaGetDevice failed") as usize
}

/// Bridge a host-built proving context to the engine's backend. Identity on CPU (the backend is
/// already `HostPb`); the GPU path never builds host contexts — it generates traces on-device via
/// [`build_ctx_gpu`] — so no `cuda` variant exists.
#[cfg(not(feature = "cuda"))]
#[inline]
fn ctx_to_engine(ctx: ProvingContext<HostPb>) -> ProvingContext<Pb> {
    ctx
}

/// Initialize process-wide GPU memory-pool sharing for MLE proving: create pico's global memory
/// pool for `device_id` and register it as cuda-mle's external pool, so the MLE prover and
/// pico's GPU trace-gen draw from one pool. Idempotent, and called at the top of every block the
/// pipeline proves — the pool itself is created once (`create_ctx`'s `OnceLock`); what repeats is
/// the read-back and the lines below. It must run **before** any MLE prover is constructed
/// (enforced by an assert in [`RiscvMachine::new`]).
#[cfg(feature = "cuda")]
pub fn init_mle_gpu_pool(device_id: usize) {
    crate::cuda_adaptor::create_mem_pool(device_id);
    // The chips' GPU trace-gen path also needs the per-device global stream pool.
    crate::cuda_adaptor::create_stream(device_id);
    // `.0` is a `CudaOwnedMemPool`; deref to the borrowed `CudaMemPool` to extract the raw handle.
    let pool: &cudart::memory_pools::CudaMemPool =
        &crate::cuda_adaptor::get_global_mem_pool(device_id).0;
    let raw: cudart_sys::cudaMemPool_t = pool.into();
    unsafe {
        cuda_mle::runtime::memory_manager::set_external_pool(
            device_id,
            raw as *mut std::ffi::c_void,
        )
        .expect("registering pico's memory pool with cuda-mle failed");
    }
    // The `.cu` scratch allocators bypass the pool registered above and draw from the device
    // default pool, so that one needs the same retaining threshold. Establish it here rather than
    // relying on `set_external_pool` reaching `manager_for`, then read the threshold back *from
    // the driver* — a cached "we called the setter" bool cannot tell a retaining pool from a
    // failed set, and this line is the only evidence a run carries of which state it proved in.
    cuda_mle::runtime::memory_manager::ensure_default_pool_retains(device_id);
    let threshold =
        match cuda_mle::runtime::memory_manager::default_pool_release_threshold(device_id) {
            Ok(t) if t == u64::MAX => "max (retaining)".to_owned(),
            Ok(0) => "0 (NOT retaining)".to_owned(),
            Ok(t) => format!("{t} (retaining)"),
            Err(e) => format!("unreadable: {e}"),
        };
    tracing::info!(
        target: "bench",
        "MLE pool: card {device_id} default-pool release threshold={threshold}"
    );
    // Its own line: this is the stream pool, not the memory pool, and a reader filtering for one
    // should not have to parse the other. The hand-back runs inside the proving window, so what it
    // costs is a number every run carries rather than an argument. Cumulative per card; a sweep
    // reads the per-block difference.
    let (recycled, recycle_us) = crate::cuda_adaptor::release_stats(device_id);
    tracing::info!(
        target: "bench",
        "MLE streams: card {device_id} recycled={recycled}, recycle_us={recycle_us}"
    );
}

/// A chunk packaged for proving: the record plus, on GPU, its FFI-precomputed events. Built by
/// [`prepare_chunk`] on the preparer thread and consumed by [`RiscvMachine::prove_chunk`]; the
/// orchestration layer never needs backend cfg.
pub struct PreparedChunk {
    pub record: EmulationRecord,
    #[cfg(feature = "cuda")]
    pub prepared: crate::instances::preparer::PreparedGpuEvents,
}

/// Package a record for proving (on GPU: `precompute_event_size` + `PreparedGpuEvents::new` feed
/// the trace-gen orchestrator; on CPU: pass-through).
pub fn prepare_chunk(record: EmulationRecord) -> PreparedChunk {
    #[cfg(feature = "cuda")]
    {
        use crate::instances::preparer::{precompute_event_size, PreparedGpuEvents};
        let counter = precompute_event_size::<Kb>(&record);
        let prepared = PreparedGpuEvents::new(&record, counter);
        PreparedChunk { record, prepared }
    }
    #[cfg(not(feature = "cuda"))]
    PreparedChunk { record }
}

/// [`prepare_chunk`] with the whitelist shape decided first when `bucket` is on. The shape comes
/// from the GPU event counter the packaging computes anyway
/// (`mle_natural_heights_from_counter`), so no chunk pays the record clone and the host
/// extra-record pass of [`shape_record`]. `MLE_SHAPE_CROSSCHECK=1` runs that path too and
/// asserts the shapes agree.
pub fn prepare_chunk_shaped(
    chips: &[MetaChip<Kb, RiscvChipType<Kb>>],
    #[cfg_attr(not(feature = "cuda"), allow(unused_mut))] mut record: EmulationRecord,
    bucket: bool,
) -> PreparedChunk {
    #[cfg(feature = "cuda")]
    {
        use crate::instances::preparer::{precompute_event_size, PreparedGpuEvents};
        // MLE_PREP_PROF=1: one line per chunk with the three steps' times, for the preparer lane.
        let prof = crate::mle::env_flag("MLE_PREP_PROF");
        let t0 = std::time::Instant::now();
        let counter = precompute_event_size::<Kb>(&record);
        let t_counter = t0.elapsed();
        if crate::mle::env_flag("SHAPE_PROBE_NATURAL") {
            log_natural_shape_probe(&record, &counter);
        }
        let t1 = std::time::Instant::now();
        if bucket && record.shape.is_none() {
            let shape = select_shape_from_counter(chips, &record, &counter);
            if crate::mle::env_flag("MLE_SHAPE_CROSSCHECK") {
                let augmented = augmented_record(chips, &record);
                let want = select_shape_for_augmented(chips, &augmented);
                assert_eq!(
                    shape.inner, want.inner,
                    "the counter-derived shape differs from the augmented-record shape"
                );
            }
            record.shape = Some(shape);
        }
        let t_shape = t1.elapsed();
        let t2 = std::time::Instant::now();
        let prepared = PreparedGpuEvents::new(&record, counter);
        if prof {
            tracing::info!(
                "[prepprof] chunk={} cpu={} counter={}us shape={}us package={}us",
                record.chunk_index().saturating_sub(1),
                record.is_cpu_chunk,
                t_counter.as_micros(),
                t_shape.as_micros(),
                t2.elapsed().as_micros()
            );
        }
        PreparedChunk { record, prepared }
    }
    // The CPU build leaves the shape to `build_ctx`, which picks it from the augmented record
    // it builds anyway.
    #[cfg(not(feature = "cuda"))]
    {
        let _ = (chips, bucket);
        PreparedChunk { record }
    }
}

impl PreparedChunk {
    /// Prove this chunk. Consumes self, so the record's pooled event buffers are released as the
    /// prove pipeline finishes with them.
    pub fn prove(self, prover: &RiscvMachine, verify: bool) -> Proof<Sc> {
        prover.prove_chunk(&self, verify)
    }

    /// [`Self::prove`] with the trace-gen hook of [`RiscvMachine::prove_chunk_hooked`]. Same drop
    /// point for the pooled event buffers: the chunk is released when this returns, exactly as in
    /// [`Self::prove`].
    pub fn prove_hooked(
        self,
        prover: &RiscvMachine,
        verify: bool,
        after_tracegen: Option<&(dyn Fn(Vec<Option<usize>>) + Send + Sync)>,
    ) -> Proof<Sc> {
        prover.prove_chunk_hooked(&self, verify, after_tracegen)
    }
}

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
    /// for the same reason.
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

/// Per-AIR log-heights, in `vk.inner.per_air` order, of a shape given as `(chip name, log
/// height)` pairs; `None` for the airs the shape leaves out. The vector form
/// `extract_recursion_vk_layout_from_heights` and [`RiscvMachine::ctx_per_air_log_heights`]
/// speak, so a whitelist shape can be turned into its convert layout without a proof.
pub fn per_air_log_heights_of(shape: &[(&str, usize)], n_airs: usize) -> Vec<Option<usize>> {
    let mut out = vec![None; n_airs];
    for (name, log) in shape {
        let id = air_id_for(name)
            .unwrap_or_else(|| panic!("shape lists `{name}`, which is not in the RISCV air list"));
        out[id] = Some(*log);
    }
    out
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

/// Instructions per chunk, from `CHUNK_SIZE`, defaulting to what the stacked height itself
/// holds (a chunk carries one CPU row per instruction). Setting it lower splits a program into
/// more, smaller chunks WITHOUT lowering the stacked height — which is the only way to get a
/// deep recursion tree out of a workload that would otherwise fit in one chunk, now that the
/// catch-all puts Cpu at the stacked height and a chunk can hold millions of instructions.
pub fn chunk_size_from_env(log_stacked_height: usize) -> u32 {
    let cap = 1u32 << log_stacked_height;
    let n = std::env::var("CHUNK_SIZE")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(cap);
    assert!(
        n > 0 && n <= cap,
        "CHUNK_SIZE must be in 1..=2^{log_stacked_height}, got {n}"
    );
    n
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

/// Number of chunks [`RiscvMachine::prove`] proves concurrently. A single chunk prover is itself
/// rayon-parallel but leaves a large host underused (reth chunks measured ~30 of 124 busy cores),
/// so proving a few at once fills the machine; the bound caps peak memory (one full proving
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
/// constraints, interactions, column widths, public-value counts and degrees, and nothing that
/// depends on the operating point.
///
/// Shared by `examples/mle_constraint_dump.rs` (which writes the artifact) and the
/// `riscv_constraint_parity` gate (which reproduces it), so the pinned value and the tool that
/// produces it cannot drift apart.
///
/// Keygen only — the constraint DAG is already in the vk, so this needs no proving and no GPU. It
/// also needs no ELF: the program table feeds only the preprocessed commitment and its geometry,
/// both excluded from the digest, so a one-instruction program suffices (`Program::default()` is
/// rejected by the program table's trace generator). `bucket` likewise cannot move the result,
/// which is what makes the artifact workload-independent.
pub fn riscv_constraint_dump(bucket: bool) -> String {
    use pico_mle_core::{
        config::riscv_params_with_100_bits_security, keygen::compute_constraint_dump,
    };

    // Any operating point works: the dump excludes `SystemParams` and everything derived from it.
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
///
/// Every record is held until the caller drops the output, so this switches the process's pinned
/// event buffers from the fixed pools to growable ones; [`emulate_each`] streams instead.
pub fn emulate_with_opts(
    program: Arc<Program>,
    stdin: &EmulatorStdin<Program, Vec<u8>>,
    opts: EmulatorOpts,
) -> Result<EmulationOutput, EmulateError> {
    if opts.snapshot_main != SnapshotMainMode::Interpreter {
        return Err(EmulateError::UnsupportedSnapshotMain(opts.snapshot_main));
    }
    hold_records_in_growable_buffers();
    let final_pvs_state = Arc::new(RecordFinalPvsState::default());
    let mut emulator = RiscvEmulator::new_single::<Kb>(program, final_pvs_state, opts, None);
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

/// Switches the process's pinned event buffers from the fixed pools, which a caller holding every
/// record would run dry, to growable ones, and claims the pools empty before an emulator would
/// fill them with full-size buffers it never uses.
fn hold_records_in_growable_buffers() {
    use_growable_event_buffers();
    if !is_pool_initialized() {
        init_cpu_event_buffer_pool(
            0,
            crate::emulator::riscv::event_pool::HostAllocFlags::DEFAULT,
        );
    }
    if !is_alu_pool_initialized() {
        init_alu_event_buffer_pool(
            0,
            crate::emulator::riscv::event_pool::HostAllocFlags::DEFAULT,
        );
    }
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
    hold_records_in_growable_buffers();
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

/// Emulate the program to completion, collecting one [`EmulationRecord`] per chunk.
///
/// `chunk_size` and the caller's `log_stacked_height` are one decision: a chunk holds one CPU row
/// per instruction, so a full chunk of `2^n` instructions needs a stacked height of at least `n`.
/// `None` inherits the emulator's RAM-derived default, which then decides the proof shape;
/// `CHUNK_SIZE` wins over both.
pub fn emulate(
    program: Arc<Program>,
    stdin: EmulatorStdin<Program, Vec<u8>>,
    chunk_size: Option<u32>,
) -> Vec<EmulationRecord> {
    emulate_with_committed_bytes(program, stdin, chunk_size).0
}

/// [`emulate`], also returning the bytes the guest committed: the preimage of the
/// `committed_value_digest` its proof carries, and what an on-chain verifier is called with.
pub fn emulate_with_committed_bytes(
    program: Arc<Program>,
    stdin: EmulatorStdin<Program, Vec<u8>>,
    chunk_size: Option<u32>,
) -> (Vec<EmulationRecord>, Vec<u8>) {
    let mut records = Vec::new();
    let committed = emulate_each(program, stdin, chunk_size, |r| records.push(r));
    (records, committed)
}

/// [`emulate`], handing each record to `on_record` as the emulator yields it instead of collecting
/// them, and returning the committed bytes. A record holds pinned CPU/ALU event buffers from fixed
/// pools until it is dropped, so a run with more chunks than the pools hold blocks in [`emulate`];
/// here it does not, as long as `on_record` drops what it is given.
pub fn emulate_each(
    program: Arc<Program>,
    stdin: EmulatorStdin<Program, Vec<u8>>,
    chunk_size: Option<u32>,
    mut on_record: impl FnMut(EmulationRecord),
) -> Vec<u8> {
    // The chunk size also sizes the pinned CPU/ALU event buffers, which read `CHUNK_SIZE` and
    // expose no other seam for the CPU pool. Set the variable rather than `opts.chunk_size`, or a
    // chunk larger than the buffers overflows them mid-emulation ("Buffer is full").
    if let (Some(n), None) = (chunk_size, std::env::var_os("CHUNK_SIZE")) {
        std::env::set_var("CHUNK_SIZE", n.to_string());
    }
    let mut opts = EmulatorOpts::default();
    // The buffers can still come out smaller than the chunk: `ALU_EVENT_BUFFER_SIZE` overrides
    // `CHUNK_SIZE` for the ALU pool, and a caller that named no size inherits a RAM-derived chunk
    // that can exceed the 2^22 default. Clamp rather than panic, but say so — it silently shrinks
    // the chunk a caller asked for.
    let buffer_cap = u32::try_from((*CPU_EVENT_BUFFER_CAPACITY).min(*ALU_EVENT_BUFFER_CAPACITY))
        .unwrap_or(u32::MAX);
    if opts.chunk_size > buffer_cap {
        tracing::warn!(
            "chunk size {} exceeds the pinned event buffers ({buffer_cap}); clamping",
            opts.chunk_size
        );
        opts.chunk_size = buffer_cap;
    }
    let final_pvs_state = Arc::new(RecordFinalPvsState::default());
    let mut emulator = RiscvEmulator::new_single::<Kb>(program, final_pvs_state, opts, None);
    emulator.write_stdin(&stdin);
    loop {
        let report = emulator
            .emulate_batch(&mut |r| on_record(r))
            .expect("emulate_batch failed");
        if report.done {
            break;
        }
    }
    std::mem::take(&mut emulator.state.public_values_stream)
}

/// RISCV public values for a chunk: `(pvs_riscv, pvs_max)`. Cpu and Ecall read the first
/// `RISCV_NUM_PVS`; MemInit / MemFinal / GLOBAL read the `MAX_NUM_PVS`-padded array (the tail is
/// recursion-padding, zero here). Shared by the host [`build_ctx`] and GPU [`build_ctx_gpu`] paths.
fn pvs_for_record(record: &EmulationRecord) -> (Vec<Kb>, Vec<Kb>) {
    let raw_pvs: Vec<Kb> = record.public_values::<Kb>();
    let pvs_riscv: Vec<Kb> = raw_pvs.iter().copied().take(RISCV_NUM_PVS).collect();
    let mut pvs_max = raw_pvs;
    pvs_max.resize(MAX_NUM_PVS, Kb::ZERO);
    (pvs_riscv, pvs_max)
}

/// Row-major offset of the first of the trailing `GCS_DIGEST_LEN` cells on the last row of an
/// `h`×`w` trace — where `GcsBindAir` writes the per-chunk global cumulative sum.
#[inline]
fn gcs_last_row_offset(h: usize, w: usize) -> usize {
    (h - 1) * w + (w - GCS_DIGEST_LEN)
}

/// Read the per-chunk GCS digest from the trailing cells of the last row of a host row-major trace.
fn read_gcs_from_host(values: &[Kb], h: usize, w: usize) -> Vec<Kb> {
    let off = gcs_last_row_offset(h, w);
    (0..GCS_DIGEST_LEN).map(|i| values[off + i]).collect()
}

/// The GLOBAL air's public values: `[gcs ‖ pvs_max]` — the per-chunk cumulative sum followed by the
/// riscv PublicValues copy, matching `GcsBindAir::num_public_values`.
fn global_pvs(gcs: Vec<Kb>, pvs_max: &[Kb]) -> Vec<Kb> {
    let mut pvs = gcs;
    pvs.extend_from_slice(pvs_max);
    pvs
}

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
) -> ProvingContext<HostPb> {
    let mut record = augmented_record(chips, record);

    // Coarse-bucket normalization (see `shape`), whitelist mode only. The shape fixes both
    // halves of a chunk's proof shape: every chip in it pads to its bucket height, and the chip
    // set itself is the canonical presence set for the chunk kind rather than the set the
    // chunk's events happen to activate. A CPU chunk therefore declares the whole core family
    // (`MLE_CORE_CANONICAL_PRESENCE`), event-free members included; a deferred chunk keeps its
    // event-driven set, which already depends only on the chunk kind. `is_active` is evaluated
    // here BEFORE the shape is set, so it takes its event-driven branch — the bootstrap the
    // shape is then built from.
    if !bucket {
        assert!(
            record.shape.is_none(),
            "record already carries a shape; the FRI shape system and the MLE bucket must not mix"
        );
        return build_ctx_inner(chips, &record);
    }
    // A record that reached the GPU path already carries the shape `shape_record` chose for it;
    // choose it here otherwise (the CPU path, and the trace-compare probe).
    if record.shape.is_none() {
        record.shape = Some(select_shape_for_augmented(chips, &record));
    }
    build_ctx_inner(chips, &record)
}

/// The whitelist shape of an ALREADY AUGMENTED record (see [`augmented_record`]): the presence
/// set by [`bucketed_presence`], the natural heights, then the ladder / enumeration match.
fn select_shape_for_augmented(
    chips: &[MetaChip<Kb, RiscvChipType<Kb>>],
    record: &EmulationRecord,
) -> crate::instances::compiler::shapes::riscv_shape::RiscvPadShape {
    let natural = crate::mle::machine::shape::mle_natural_heights(record);
    shape_of(chips, record, &natural)
}

/// `SHAPE_PROBE_NATURAL=1`: one line per chunk with the natural (event-driven) log-heights, in
/// the format `mle_shape_probe` prints -- `[shape] chunk=<i> <air_id>:<log2> ...` over the airs
/// the chunk activates, plus the Byte and Program tables -- so a ladder can be fitted from a
/// pipeline run instead of a host emulation of every block.
#[cfg(feature = "cuda")]
fn log_natural_shape_probe(
    record: &EmulationRecord,
    counter: &crate::instances::preparer::EventCounter,
) {
    use crate::emulator::record::RecordBehavior;
    // Trace heights, as the probe prints them: a trace never goes below 2^l_skip rows.
    let l_skip = crate::mle::machine::shape::MLE_MIN_LOG_HEIGHT as u32;
    let log2 =
        |rows: usize| (usize::BITS - rows.next_power_of_two().leading_zeros() - 1).max(l_skip);
    let mut cells: Vec<(usize, u32)> =
        crate::mle::machine::shape::mle_natural_heights_from_counter(record, counter)
            .into_iter()
            .filter(|(_, rows)| *rows > 0)
            .filter_map(|(name, rows)| air_id_for(&name).map(|id| (id, log2(rows))))
            .collect();
    cells.push((
        air_id::BYTE,
        log2(crate::chips::chips::byte::traces::NUM_ROWS),
    ));
    cells.push((
        air_id::PROGRAM,
        log2(record.program.instructions.len().max(1)),
    ));
    cells.sort_unstable();
    let cells: Vec<String> = cells
        .iter()
        .map(|(id, log)| format!("{id}:{log}"))
        .collect();
    // The emulator numbers chunks from 1; the probe and the per-chunk bench lines count from 0.
    tracing::info!(
        "[shape] chunk={} {}",
        record.chunk_index().saturating_sub(1),
        cells.join(" ")
    );
}

/// The whitelist shape of a chunk from the GPU preparer's event counter (see
/// [`crate::mle::machine::shape::mle_natural_heights_from_counter`]). Presence is read off the
/// raw record: the canonical core set covers every chip an extra-record pass could activate in a
/// core chunk, and the chips extra-record output feeds elsewhere (Global, Poseidon2, Byte,
/// Program) are unconditionally active.
#[cfg(feature = "cuda")]
fn select_shape_from_counter(
    chips: &[MetaChip<Kb, RiscvChipType<Kb>>],
    record: &EmulationRecord,
    counter: &crate::instances::preparer::EventCounter,
) -> crate::instances::compiler::shapes::riscv_shape::RiscvPadShape {
    let natural = crate::mle::machine::shape::mle_natural_heights_from_counter(record, counter);
    shape_of(chips, record, &natural)
}

/// Presence from the record, the ladder / enumeration match on `natural`, and the GPU catch-all
/// refusal.
fn shape_of(
    chips: &[MetaChip<Kb, RiscvChipType<Kb>>],
    record: &EmulationRecord,
    natural: &std::collections::BTreeMap<String, usize>,
) -> crate::instances::compiler::shapes::riscv_shape::RiscvPadShape {
    let present: Vec<String> = chips
        .iter()
        .filter(|chip| bucketed_presence(chip, record))
        .map(|chip| chip.name())
        .collect();
    let inner =
        crate::mle::machine::shape::select_riscv_shape(&present, natural, record.is_cpu_chunk);
    // The catch-all core shape pads to m = 31 (a 64 GiB GKR leaf buffer): no 32 GB card holds
    // it. A GPU build refuses the chunk here, legibly, instead of dying in a device allocation.
    if cfg!(feature = "cuda")
        && record.is_cpu_chunk
        && crate::mle::machine::shape::is_core_catch_all(&inner)
    {
        panic!(
            "core chunk selects the catch-all whitelist shape, which no GPU holds (m = 31); \
             prove this chunk on the CPU path or extend the ladder. natural heights: {}",
            natural
                .iter()
                .map(|(name, rows)| format!("{name}={rows}"))
                .collect::<Vec<_>>()
                .join(" ")
        );
    }
    crate::instances::compiler::shapes::riscv_shape::RiscvPadShape {
        inner: inner.into_iter().collect(),
    }
}

/// Whitelist mode: pin the record's proof shape before it is packaged for the GPU. The device
/// trace generator pads every chip to `record.shape` and, with the shape set, generates the
/// chips the shape lists even when they have no events (`BaseProver::gpu_generate_extra_record_and_main`),
/// so setting it here is what makes a GPU-proved chunk take a whitelist shape. Idempotent on a
/// record that already carries a shape.
pub fn shape_record(chips: &[MetaChip<Kb, RiscvChipType<Kb>>], record: &mut EmulationRecord) {
    if record.shape.is_some() {
        return;
    }
    let augmented = augmented_record(chips, record);
    record.shape = Some(select_shape_for_augmented(chips, &augmented));
}

/// Trace assembly over a (possibly shape-set) record: generate each active chip's main trace
/// and wrap with the public values. Produces a host (CPU) context; the GPU path builds on-device
/// via [`build_ctx_gpu`] instead.
fn build_ctx_inner(
    chips: &[MetaChip<Kb, RiscvChipType<Kb>>],
    record: &EmulationRecord,
) -> ProvingContext<HostPb> {
    let (pvs_riscv, pvs_max) = pvs_for_record(record);

    let mut per_trace: Vec<(usize, AirProvingContext<HostPb>)> = vec![];
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
                // Per-chunk GCS (last-row trailing cells, bound by `GcsBindAir`) followed by the
                // riscv PublicValues copy — the Global air is every chunk's always-present carrier.
                let w = trace.width;
                let h = trace.values.len() / w;
                let gcs = read_gcs_from_host(&trace.values, h, w);
                AirProvingContext::simple(trace, global_pvs(gcs, &pvs_max))
            }
            _ => AirProvingContext::simple_no_pis(trace),
        };
        per_trace.push((id, ctx));
    }
    ProvingContext::new(per_trace)
}

/// GPU trace generation for one chunk: run pico's GPU trace-gen orchestrator
/// (`BaseProver::gpu_generate_extra_record_and_main`) and bridge its row-major device traces into
/// an MLE GPU proving context.
///
/// The bridge does three things per trace: chip-name → AIR-id mapping (the `INCLUDED` table),
/// an on-device row-major → col-major transpose into a fresh pool buffer, and public-value
/// assembly (GLOBAL's GCS is read from the trailing cells of the last row, then followed by the
/// riscv PublicValues copy to match `GcsBindAir`'s `[gcs ‖ pvs_max]` layout).
///
/// `chips` must be in `gpu_generate_extra_record_and_main_chips()` order, not `all_chips()` order:
/// the orchestrator indexes it by position.
#[cfg(feature = "cuda")]
pub fn build_ctx_gpu(
    record: &EmulationRecord,
    prepared: &crate::instances::preparer::PreparedGpuEvents,
    chips: &[MetaChip<Kb, RiscvChipType<Kb>>],
) -> ProvingContext<Pb> {
    use crate::{
        chips::trace::TraceData, configs::stark_config::KoalaBearPoseidon2 as FriSc,
        machine::prover::BaseProver,
    };
    use cuda_mle::runtime::{
        copy::cuda_memcpy, d_buffer::DeviceBuffer, stream::current_stream_sync,
    };
    use std::{ffi::c_void, mem::ManuallyDrop};

    // Both orderings are same-typed and both are in the caller's scope, so passing the wrong one
    // compiles and then mis-binds every positional event buffer. Assert rather than trust. Not a
    // `debug_assert`: the prover runs in release, where that would never fire, and one name
    // comparison per chunk is nothing.
    assert_eq!(
        chips.first().map(|c| c.name()).as_deref(),
        Some("Cpu"),
        "build_ctx_gpu needs the orchestrator chip ordering, not all_chips()"
    );
    let named = BaseProver::<FriSc, RiscvChipType<Kb>>::new().gpu_generate_extra_record_and_main(
        bound_device(),
        chips,
        record,
        prepared,
    );

    // Public values from the host record (same construction as `build_ctx`).
    let (pvs_riscv, pvs_max) = pvs_for_record(record);

    let mut per_trace: Vec<(usize, AirProvingContext<Pb>)> = vec![];
    // Keep the orchestrator's pool allocations alive until the transposes are synchronized:
    // dropping enqueues a stream-ordered free that could otherwise race the per-thread-stream
    // transpose kernels reading them.
    let mut live_allocs = vec![];

    for (name, trace) in named {
        let Some(id) = air_id_for(&name) else {
            panic!("GPU trace-gen produced chip `{name}` which is not in the RISCV air list");
        };
        let h = trace.height();
        let w = trace.width();
        // AIR-width audit probe (`MLE_AREA_DEBUG=1`, default silent): per-chip trace dims per
        // chunk, to decompose cells/instr by chip.
        if std::env::var("MLE_AREA_DEBUG").is_ok() {
            tracing::info!(
                target: "bench",
                "[air-dims] chip={} h={} w={} cells={}",
                name,
                h,
                w,
                (h as u64) * (w as u64)
            );
        }
        let (matrix, gcs) = match trace {
            TraceData::Gpu(_, alloc) => {
                // GLOBAL's per-chunk GCS lives in the trailing GCS_DIGEST_LEN cells of the last
                // row — read it from the row-major device buffer before transposing.
                // NOTE: this D2H is async (per-thread stream). Moving the Vec into `pv` below is
                // fine (the heap buffer address is stable); the values must not be *read* until
                // the `current_stream_sync()` at the end of this function has run.
                let gcs = (id == air_id::GLOBAL).then(|| {
                    let mut host = vec![Kb::ZERO; GCS_DIGEST_LEN];
                    let offset = gcs_last_row_offset(h, w);
                    unsafe {
                        cuda_memcpy::<true, false>(
                            host.as_mut_ptr() as *mut c_void,
                            alloc.as_ptr().add(offset) as *const c_void,
                            GCS_DIGEST_LEN * std::mem::size_of::<Kb>(),
                        )
                        .expect("GCS extraction D2H failed");
                    }
                    host
                });
                // Borrow the pool allocation as a cuda-mle DeviceBuffer (ManuallyDrop: the buffer
                // must not free a pointer it does not own).
                let input = ManuallyDrop::new(unsafe {
                    DeviceBuffer::from_raw_parts(alloc.as_ptr() as *mut Kb, h * w)
                });
                let output = DeviceBuffer::<Kb>::with_capacity(h * w);
                unsafe {
                    cuda_mle::matrix_transpose_fp_any(&output, &input, w, h)
                        .expect("row-major → col-major transpose failed");
                }
                live_allocs.push(alloc);
                (
                    cuda_mle::base::DeviceMatrix::new(Arc::new(output), h, w),
                    gcs,
                )
            }
            TraceData::Cpu(m) => {
                // CPU fallback chip: extract GCS on host, then reuse the existing H2D+transpose.
                let gcs = (id == air_id::GLOBAL).then(|| read_gcs_from_host(&m.values, h, w));
                let matrix = cuda_mle::data_transporter::transport_matrix_h2d_row_major(&m)
                    .expect("CPU-fallback trace H2D failed");
                (matrix, gcs)
            }
            TraceData::Debug(..) => unreachable!("debug trace variant in production path"),
        };
        let pv = match id {
            air_id::CPU | air_id::ECALL => pvs_riscv.clone(),
            air_id::MEM_INIT | air_id::MEM_FINAL => pvs_max.clone(),
            air_id::GLOBAL => global_pvs(gcs.expect("GLOBAL gcs extracted above"), &pvs_max),
            _ => Vec::new(),
        };
        per_trace.push((id, AirProvingContext::new(vec![], matrix, pv)));
    }

    // One sync covers all per-thread-stream work (transposes + GCS D2H); after it the
    // orchestrator's allocations can be returned to the pool.
    current_stream_sync().expect("sync after GPU trace bridge");
    drop(live_allocs);

    per_trace.sort_by_key(|(id, _)| *id);
    ProvingContext::new(per_trace)
}

/// The permutation-comparison `unit` for a trace: one row, except Poseidon2 packs
/// `RISCV_NUM_POSEIDON2_VALUE_COLS` slots per row (reordered events repack across row boundaries,
/// so the sound unit is one slot).
#[cfg(feature = "cuda")]
fn trace_compare_unit(id: usize, w: usize) -> usize {
    if id == air_id::POSEIDON2 {
        use crate::{
            chips::chips::riscv_poseidon2::columns::RISCV_NUM_POSEIDON2_VALUE_COLS,
            primitives::consts::KoalaBearConfig,
        };
        RISCV_NUM_POSEIDON2_VALUE_COLS::<KoalaBearConfig>
    } else {
        w
    }
}

/// A GPU-only air (CPU inactive — the family-level GPU activity predicate emitted an all-padding
/// trace) must be pure padding: every row equals row 0. Padding rows send nothing on the bus, so
/// this is sound; a non-uniform trace is a real divergence.
#[cfg(feature = "cuda")]
fn assert_gpu_only_padding(id: usize, host: &[Kb], h: usize, w: usize) {
    let uniform_rows = (1..h).all(|r| (0..w).all(|c| host[c * h + r] == host[c * h]));
    assert!(
        uniform_rows,
        "air {id}: GPU-only (CPU inactive) but trace is not pure padding — real divergence"
    );
    tracing::warn!(
        "[trace-compare] air {id}: GPU-only all-padding trace ({h}x{w}) — sound \
         (family-level GPU activity predicate)"
    );
}

/// GPU/CPU traces disagree element-wise at `(r, c)`. Accept iff they are a unit-permutation of each
/// other (GPU may emit events in a different order — sound for per-unit constraints + multiset
/// interactions), or differ only in padding (dummy) rows (GPU bakes `RISCV_DUMMY_ROW_KB`, CPU recomputes
/// its dummy; both are `is_real = 0`). Otherwise panic with the first-diff location.
#[cfg(feature = "cuda")]
fn assert_permutation_or_padding_diff(
    id: usize,
    r: usize,
    c: usize,
    h: usize,
    w: usize,
    host: &[Kb],
    cpu_values: &[Kb],
) {
    use p3_field::PrimeField32;

    let unit = trace_compare_unit(id, w);
    assert_eq!(
        w % unit,
        0,
        "air {id}: width {w} not a multiple of unit {unit}"
    );
    let units_per_row = w / unit;
    let mut gpu_rows: Vec<Vec<Kb>> = (0..h)
        .flat_map(|row| {
            (0..units_per_row).map(move |u| {
                (u * unit..(u + 1) * unit)
                    .map(|col| host[col * h + row])
                    .collect::<Vec<Kb>>()
            })
        })
        .collect();
    let mut cpu_rows: Vec<Vec<Kb>> = cpu_values.chunks_exact(unit).map(|s| s.to_vec()).collect();
    let key = |row: &Vec<Kb>| row.iter().map(|x| x.as_canonical_u32()).collect::<Vec<_>>();
    gpu_rows.sort_by_key(key);
    cpu_rows.sort_by_key(key);
    if gpu_rows == cpu_rows {
        tracing::warn!(
            "[trace-compare] air {id}: rows are a permutation of CPU rows (first diff \
             at row {r} col {c}) — sound, but not byte-identical"
        );
        return;
    }
    // Not a permutation: accept iff the disagreeing rows on each side are copies of one single row
    // (each side's dummy), in equal number; anything else is a real divergence.
    let mut only_gpu: Vec<&Vec<Kb>> = Vec::new();
    let mut only_cpu: Vec<&Vec<Kb>> = Vec::new();
    let (mut i, mut j) = (0, 0);
    while i < gpu_rows.len() || j < cpu_rows.len() {
        match (gpu_rows.get(i), cpu_rows.get(j)) {
            (Some(g), Some(cvals)) if g == cvals => {
                i += 1;
                j += 1;
            }
            (Some(g), Some(cvals)) if key(g) < key(cvals) => {
                only_gpu.push(g);
                i += 1;
            }
            (Some(_), Some(_)) => {
                only_cpu.push(&cpu_rows[j]);
                j += 1;
            }
            (Some(g), None) => {
                only_gpu.push(g);
                i += 1;
            }
            (None, Some(_)) => {
                only_cpu.push(&cpu_rows[j]);
                j += 1;
            }
            (None, None) => break,
        }
    }
    let uniform = |rows: &[&Vec<Kb>]| rows.windows(2).all(|p| p[0] == p[1]);
    assert!(
        only_gpu.len() == only_cpu.len()
            && !only_gpu.is_empty()
            && uniform(&only_gpu)
            && uniform(&only_cpu),
        "air {id}: trace mismatch at row {r} col {c} (GPU={} CPU={}) — {} GPU-only \
         vs {} CPU-only distinct rows; NOT a padding-row-only difference — real \
         divergence",
        host[c * h + r],
        cpu_values[r * w + c],
        only_gpu.len(),
        only_cpu.len(),
    );
    tracing::warn!(
        "[trace-compare] air {id}: differs only in {} padding (dummy) rows — sound \
         (is_real = 0, no bus messages)",
        only_gpu.len()
    );
}

/// `MLE_TRACE_COMPARE=1` correctness harness: build the same chunk's context on CPU
/// (`build_ctx`) and compare every GPU trace element against it (after undoing the col-major
/// layout). Reports mismatches at air/row/col granularity — locates trace-bridge bugs that
/// `verify` would only report as an opaque failure.
#[cfg(feature = "cuda")]
fn compare_gpu_ctx_against_cpu(
    chips: &[MetaChip<Kb, RiscvChipType<Kb>>],
    record: &EmulationRecord,
    gpu_ctx: &ProvingContext<Pb>,
) {
    use cuda_mle::runtime::copy::MemCopyD2H;
    use pico_mle_core::poly::matrix::MatrixDimensions;

    // A whitelist-mode record already carries its shape; the host build must pad to it too.
    let cpu_ctx = build_ctx(chips, record, record.shape.is_some());
    let cpu: std::collections::HashMap<usize, _> = cpu_ctx.per_trace.into_iter().collect();
    let gpu_ids: std::collections::HashSet<usize> =
        gpu_ctx.per_trace.iter().map(|(id, _)| *id).collect();
    // A CPU-active air missing from the GPU context would drop bus messages — fatal.
    let missing: Vec<usize> = cpu
        .keys()
        .copied()
        .filter(|id| !gpu_ids.contains(id))
        .collect();
    assert!(
        missing.is_empty(),
        "airs {missing:?} active on CPU but missing from GPU trace-gen — real divergence"
    );

    for (id, gpu_air) in &gpu_ctx.per_trace {
        let Some(cpu_air) = cpu.get(id) else {
            // GPU-only air (CPU inactive): must be pure padding (see `assert_gpu_only_padding`).
            let (h, w) = (gpu_air.common_main.height(), gpu_air.common_main.width());
            let host = gpu_air
                .common_main
                .buffer()
                .to_host()
                .expect("gpu-only air D2H");
            assert_gpu_only_padding(*id, &host, h, w);
            continue;
        };
        let cpu_trace = &cpu_air.common_main;
        let w = cpu_trace.width;
        let h = cpu_trace.values.len() / w;
        assert_eq!(
            (gpu_air.common_main.height(), gpu_air.common_main.width()),
            (h, w),
            "air {id}: dimensions differ"
        );
        let host = gpu_air
            .common_main
            .buffer()
            .to_host()
            .expect("trace D2H for compare");
        let mismatch = (0..h)
            .flat_map(|r| (0..w).map(move |c| (r, c)))
            .find(|&(r, c)| host[c * h + r] != cpu_trace.values[r * w + c]);
        if let Some((r, c)) = mismatch {
            assert_permutation_or_padding_diff(*id, r, c, h, w, &host, &cpu_trace.values);
        }
        assert_eq!(
            gpu_air.public_values, cpu_air.public_values,
            "air {id}: public values differ"
        );
        tracing::info!("[trace-compare] air {id}: {h}x{w} OK");
    }
    tracing::info!("[trace-compare] all {} airs identical ✓", gpu_ids.len());
}

/// Run the MLE debug checker (constraints + interactions/bus balance) over every chunk of
/// `records`. Panics on the first failure; returns cleanly when all chunks pass.
///
/// Constraint debugging is a host-side tool (`check_constraints` walks host matrices), so it
/// always uses the CPU engine regardless of the `cuda` feature. Same `Sc`, so the air
/// list is shared.
pub fn debug_records(
    program: Arc<Program>,
    records: &[EmulationRecord],
    log_stacked_height: usize,
    bucket: bool,
) {
    let engine: KoalaBearPoseidon2CpuEngine =
        StarkEngine::new(riscv_params_with_100_bits_security(log_stacked_height));
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

/// Negative-test hook (NOT public API): bump the value of one MemoryFinalize event (`addr >=
/// 0x1000`, clear of the x0 row the chip pins) in a single record. The record's traces are all
/// built from its events, so the chunk stays internally consistent and its per-chunk proof
/// remains valid; but the Global receive its MemoryFinalize row now carries has no matching send
/// from the chunk that produced the word's final state, so `Σ gcs != 0`. Returns `true` if a
/// finalize event was found and corrupted.
///
/// Finalize only: a main-memory word whose initial value is zero has no MemoryInitialize event
/// at all (`riscv_memory/event.rs`), so a "bump a matching init/final pair" form would find
/// nothing to tamper in most memory records.
///
/// `pub` only so the `distributed-vm` orchestrator can drive the `CORRUPT_MEMORY` negative test at
/// runtime; `#[doc(hidden)]` marks it as test scaffolding, not part of the prover's surface.
#[doc(hidden)]
pub fn corrupt_one_record(rec: &mut EmulationRecord) -> bool {
    // Skip low addresses (registers / reserved).
    let Some(e) = rec
        .memory_finalize_events
        .iter_mut()
        .find(|e| e.addr >= 0x1000)
    else {
        return false;
    };
    e.value = e.value.wrapping_add(1);
    let addr = e.addr;
    tracing::warn!("CORRUPT_MEMORY: tampered finalize value at addr={addr:#x}");
    true
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

/// Stateful, reusable RISCV prover/verifier for the MLE/WHIR backend (CPU or GPU per the
/// `cuda` feature).
///
/// Keygen + device transport run once in [`RiscvMachine::new`]; the engine, device-resident proving
/// key, verifying key, and chip set are then shared read-only. Each [`Self::prove_chunk`] builds its
/// own proving context + Fiat-Shamir transcript, so proving concurrently from `&self` is sound.
/// Per-chunk `SepticDigest` GCS terms are accumulated internally (seeded with the program's initial
/// GCS) and checked by [`Self::assert_cross_chunk_gcs_zero`] — the streaming single-node path.
///
/// The free functions [`prove_riscv`] / [`verify_riscv`] are thin wrappers over the batch API.
pub struct RiscvMachine {
    engine: Engine,
    d_pk: DeviceMultiStarkProvingKey<Pb>,
    vk: MultiStarkVerifyingKey<Sc>,
    // Used only for the `ChipBehavior` methods (see `RiscvMachine::new`).
    chips: Vec<MetaChip<Kb, RiscvChipType<Kb>>>,
    /// The same chips in the **orchestrator's** ordering — a different permutation from `chips`
    /// above, and the orchestrator indexes by position, so the two are not interchangeable.
    /// Held here because the constructor takes no arguments: its result cannot depend on the chunk.
    #[cfg(feature = "cuda")]
    orchestrator_chips: Vec<MetaChip<Kb, RiscvChipType<Kb>>>,
    /// Accumulated per-chunk GCS digests — **chunk terms only**; the program's initial cumulative
    /// sum lives in [`Self::initial_gcs`] beside it. Every [`Self::prove_chunk`] pushes here,
    /// including the batch [`Self::prove`] path; only [`Self::assert_cross_chunk_gcs_zero`] (the
    /// streaming single-node path) consumes it. The batch [`Self::verify`] path ignores this field
    /// and recomputes GCS independently from the bundle, so the accumulation is simply unused there.
    gcs_terms: std::sync::Mutex<Vec<SepticDigest<Kb>>>,
    /// The program's initial cumulative sum, held **apart from the chunk terms above** so that a
    /// drain can add it without consuming it.
    ///
    /// It used to be term zero of `gcs_terms`, which is correct for a process that proves one
    /// block and exits: `drain_cross_chunk_gcs_over` takes the whole vector and the seed goes with
    /// it. A resident process that proves block after block off one machine needs the seed to
    /// survive the drain, or block 2 sums chunk terms against no seed and fails the `Σ == 0`
    /// assertion with a message that reads exactly like a memory-consistency bug.
    ///
    /// Re-seeding per block would be the obvious alternative and is wrong: **which** machine owns
    /// the seed is decided once, at construction time, from two-machine role state
    /// (`keeps_initial_gcs_seed()` in the orchestrator). Re-seeding "card 0, every block"
    /// double-counts the seed on a two-machine secondary from block 2 onward while block 1 still
    /// passes, because block 1's ownership came from the constructor. One decision point, not one
    /// per block.
    initial_gcs: std::sync::Mutex<Option<SepticDigest<Kb>>>,
    /// Whitelist-mode shape bucketing (see `shape`); off = natural heights, dynamic shapes.
    /// Read only on the CPU `prove_chunk` path; the GPU path generates traces on-device and does
    /// not bucket, so the field is unused under `cuda`.
    #[cfg_attr(feature = "cuda", allow(dead_code))]
    bucket: bool,
    /// Chunk proving concurrency of [`Self::prove`]; `None` falls back to [`prove_concurrency`].
    concurrency: Option<NonZeroUsize>,
}

impl RiscvMachine {
    /// Keygen once: build the engine from `log_stacked_height`, keygen the RISCV air set, transport
    /// the proving key to the device, and materialize the chip set for trace generation. Seeds the
    /// GCS accumulator with the program's initial cumulative sum.
    pub fn new(
        program: Arc<Program>,
        log_stacked_height: usize,
        bucket: bool,
    ) -> Result<Self, UnderBudgetError> {
        let machine = Self::from_airs(
            mle_riscv_air_refs(program.clone(), bucket),
            log_stacked_height,
            bucket,
        )?;
        let initial_gcs = if crate::mle::env_flag("SKIP_INITIAL_GCS") {
            tracing::warn!("SKIP_INITIAL_GCS set: omitting initial GCS (negative test)");
            None
        } else {
            Some(program.initial_global_cumulative_sum())
        };
        *machine.initial_gcs.lock().expect("gcs mutex poisoned") = initial_gcs;
        Ok(machine)
    }

    /// [`Self::new`] for a caller that has already built the air set — and, in `bucket` mode, has
    /// already paid for the shape-padded program inside it. Building it twice is the whole cost
    /// this exists to avoid, so `airs` must be [`mle_riscv_air_refs`]'s output for the same
    /// program and the same `bucket`.
    ///
    /// Without the program the GCS accumulator is not seeded, so the streaming
    /// [`Self::assert_cross_chunk_gcs_zero`] needs [`Self::new`]; the batch [`Self::verify`] takes
    /// the initial GCS as an argument and is unaffected.
    pub fn from_airs(
        airs: Vec<AirRef<Sc>>,
        log_stacked_height: usize,
        bucket: bool,
    ) -> Result<Self, UnderBudgetError> {
        // The GPU prover must share pico's memory pool; pool registration is a process-level
        // concern owned by the entry point — fail loudly instead of silently allocating from the
        // device default pool.
        #[cfg(feature = "cuda")]
        assert!(
            cuda_mle::runtime::memory_manager::external_pool_is_set(bound_device()),
            "GPU MLE proving requires the shared pico memory pool; call `init_mle_gpu_pool` \
             for this card at process entry"
        );
        #[allow(unused_mut)]
        let mut engine: Engine =
            StarkEngine::new(riscv_params_with_100_bits_security(log_stacked_height));
        // Do not cache the RS codeword: at 2^22 it holds ~9.2GiB resident that would OOM a 32GB
        // card, and WHIR simply recomputes it from the traces (~0.1s/chunk).
        #[cfg(feature = "cuda")]
        engine.device_mut().set_cache_rs_code_matrix(false);
        let (pk, vk) = engine.keygen_with_app_prep(&airs, RISCV_APP_PREP_AIR_IDS);
        admit_production_vk(
            "riscv",
            if cfg!(feature = "cuda") { "gpu" } else { "cpu" },
            &vk,
        )?;
        let d_pk = engine.device().transport_pk_to_device(&pk);
        // Eagerly nvrtc-compile all JIT kernels here, on the main thread, before the prove worker /
        // emulate-pipeline / rayon threads spawn. Lazy JIT compilation from a prove-worker thread
        // mid-proof deadlocks libnvrtc's internal threading in the heavily-threaded prover; warming
        // them in this quiescent context avoids it. No-op when G1_JIT/Z1_JIT are off (no jit_source).
        #[cfg(feature = "cuda")]
        cuda_mle::warmup_jit_kernels(&d_pk);
        // These chips are used only for their `ChipBehavior` methods
        // (`name`/`is_active`/`extra_record`/`generate_main`); keygen re-derives everything else.
        let chips = RiscvChipType::<Kb>::all_chips();
        // The orchestrator's ordering, built once here for the same reason `chips` is (see the field).
        #[cfg(feature = "cuda")]
        let orchestrator_chips = RiscvChipType::<Kb>::gpu_generate_extra_record_and_main_chips();

        Ok(Self {
            engine,
            d_pk,
            vk,
            chips,
            #[cfg(feature = "cuda")]
            orchestrator_chips,
            gcs_terms: std::sync::Mutex::new(Vec::new()),
            initial_gcs: std::sync::Mutex::new(None),
            bucket,
            concurrency: None,
        })
    }

    /// Fix the chunk proving concurrency of [`Self::prove`], overriding `PROVE_CONCURRENCY`.
    ///
    /// The bound caps peak memory (one full proving working set per in-flight chunk), so a caller
    /// sizing a host has to be able to state it rather than hope the environment agrees.
    pub fn with_concurrency(mut self, concurrency: NonZeroUsize) -> Self {
        self.concurrency = Some(concurrency);
        self
    }

    /// Prove one prepared chunk on the MLE/WHIR backend (optionally verifying it), accumulating the
    /// chunk's GCS digest. Takes `&self` so a worker pool can prove concurrently: each call builds
    /// its own context + transcript. On GPU, traces are generated on-device (no host build + H2D);
    /// on CPU, `build_ctx` runs on the host.
    pub fn prove_chunk(&self, chunk: &PreparedChunk, verify: bool) -> Proof<Sc> {
        self.prove_chunk_hooked(chunk, verify, None)
    }

    /// [`Self::prove_chunk`] with a callback fired the moment trace-gen has fixed this chunk's
    /// per-AIR committed log-heights, and before commit starts.
    ///
    /// **Why this boundary exists as a hook.** The heights are the *only* thing the convert
    /// layer takes from a riscv proof (`recursion/layout.rs:157-173`), and they are final here:
    /// `build_ctx_gpu` pushes each trace at the height the kernel produced and
    /// `mle-core/src/prover/mod.rs` puts `log2_strict_usize` of that same integer into
    /// `Proof::trace_vdata` — a pure log, never a re-pad. So a caller given this vector can
    /// derive the chunk's convert layout exactly, early in the prove, and spend the rest of it
    /// building the convert verify program off the critical path
    /// (`GpuConvertMachine::prebuild_program`).
    ///
    /// The callback runs **on the proving thread**, so it must not block: its only sanctioned use
    /// is to hand the vector to another thread. Anything expensive done here lands squarely in
    /// the middle of a riscv prove.
    pub fn prove_chunk_hooked(
        &self,
        chunk: &PreparedChunk,
        verify: bool,
        after_tracegen: Option<&(dyn Fn(Vec<Option<usize>>) + Send + Sync)>,
    ) -> Proof<Sc> {
        let ctx = self.chunk_ctx(chunk);
        if let Some(cb) = after_tracegen {
            cb(self.ctx_per_air_log_heights(&ctx));
        }
        let index = chunk.record.chunk_index().saturating_sub(1);
        self.try_prove_ctx(ctx, index, verify)
            .unwrap_or_else(|e| panic!("{e}"))
    }

    /// [`Self::prove_chunk`] returning the failure instead of panicking. `index` names the chunk
    /// in the error only.
    #[cfg(feature = "cuda")]
    fn try_prove_chunk(
        &self,
        chunk: &PreparedChunk,
        index: usize,
        verify: bool,
    ) -> Result<Proof<Sc>, ProveRiscvError> {
        let ctx = self.chunk_ctx(chunk);
        self.try_prove_ctx(ctx, index, verify)
    }

    /// The chunk's proving context: GPU trace-gen under `cuda`, host `build_ctx` otherwise.
    fn chunk_ctx(&self, chunk: &PreparedChunk) -> ProvingContext<Pb> {
        #[cfg(feature = "cuda")]
        {
            // `MLE_BREAKDOWN` times GPU trace-gen here; the other three phases
            // (commit / rap_constraints / openings) record themselves inside `engine.prove`, and
            // the worker loop reads `breakdown::take()` once this chunk is proved. Inert unless
            // the env flag is set, so the added `Instant::now()` costs nothing by default.
            let _nv = cuda_mle::nvtx::range("trace_gen");
            let _bt = cuda_mle::breakdown::start();
            let ctx = self.build_chunk_ctx(chunk);
            cuda_mle::breakdown::stop_tracegen(_bt);
            ctx
        }
        #[cfg(not(feature = "cuda"))]
        ctx_to_engine(build_ctx(&self.chips, &chunk.record, self.bucket))
    }

    /// Per-AIR committed log-heights in `vk.inner.per_air` index order; `None` = absent from this
    /// chunk. Identical by construction to what `extract_recursion_vk_layout` later reads off the
    /// finished proof's `trace_vdata` — `ProvingContext::per_trace`'s `usize` *is* the vk's AIR
    /// index (`mle-core/src/prover/types.rs:78-81`, "with respect to the vkey ordering").
    pub fn ctx_per_air_log_heights(&self, ctx: &ProvingContext<Pb>) -> Vec<Option<usize>> {
        let n_airs = self.vk.inner.per_air.len();
        let mut out = vec![None; n_airs];
        for (air_id, trace_ctx) in &ctx.per_trace {
            if *air_id < n_airs {
                let h = trace_ctx.height();
                if h > 0 {
                    out[*air_id] = Some(p3_util::log2_strict_usize(h));
                }
            }
        }
        out
    }

    /// Build a chunk's proving context (GPU trace-gen + bridge), inline from
    /// [`Self::prove_chunk`].
    #[cfg(feature = "cuda")]
    pub fn build_chunk_ctx(&self, chunk: &PreparedChunk) -> ProvingContext<Pb> {
        let ctx = build_ctx_gpu(&chunk.record, &chunk.prepared, &self.orchestrator_chips);
        if crate::mle::env_flag("MLE_TRACE_COMPARE") {
            compare_gpu_ctx_against_cpu(&self.chips, &chunk.record, &ctx);
        }
        ctx
    }

    /// Shared prove tail: engine prove (+ optional self-verify) + GCS accumulation.
    fn try_prove_ctx(
        &self,
        ctx: ProvingContext<Pb>,
        chunk: usize,
        verify: bool,
    ) -> Result<Proof<Sc>, ProveRiscvError> {
        // Phase tag for the shared GPU prove path: the prover thread alternates riscv, convert
        // and combine proves, and the bench spans attribute by it.
        #[cfg(feature = "cuda")]
        cuda_mle::set_prove_phase("riscv");
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
        let gcs = gcs_from_pvs(&proof.public_values[air_id::GLOBAL]);
        self.gcs_terms.lock().expect("gcs mutex poisoned").push(gcs);
        Ok(proof)
    }

    /// Remove the initial-GCS seed this constructor planted. Multi-card runs one machine per
    /// card, and every constructor seeds the program's initial cumulative sum — but the
    /// cross-card aggregate must count it exactly ONCE, so the orchestrator unseeds every card
    /// but the first, right after construction. Calling this after a prove has pushed terms
    /// would silently drop a chunk's digest, hence the assert.
    /// Permanent, not per-block: once a card is not the seed holder it never becomes one, so a
    /// resident process calls this exactly once per card at construction and never again.
    pub fn unseed_initial_gcs(&self) {
        let terms = self.gcs_terms.lock().expect("gcs mutex poisoned");
        assert!(
            terms.is_empty(),
            "unseed_initial_gcs must run before any chunk is proven ({} chunk terms present)",
            terms.len()
        );
        drop(terms);
        *self.initial_gcs.lock().expect("gcs mutex poisoned") = None;
    }

    /// Assert cross-chunk memory consistency for the streaming path: `Σ per-chunk gcs + initial ==
    /// 0`. Call once after all chunks have been proven via [`Self::prove_chunk`].
    pub fn assert_cross_chunk_gcs_zero(&self) {
        Self::assert_cross_chunk_gcs_zero_over([self]);
    }

    /// Multi-machine form of [`Self::assert_cross_chunk_gcs_zero`]: with one machine per GPU card,
    /// each accumulates only its own chunks' terms, and only the sum over ALL of them closes to
    /// zero. Drains every machine's terms.
    pub fn assert_cross_chunk_gcs_zero_over<'a>(machines: impl IntoIterator<Item = &'a Self>) {
        let total = Self::drain_cross_chunk_gcs_over(machines);
        assert!(
            total.is_zero(),
            "cross-chunk global cumulative sum is not zero (memory inconsistency)"
        );
        tracing::info!("cross-chunk global cumulative sum == 0 ✓");
    }

    /// The partial sum over these machines, drained but NOT asserted.
    ///
    /// Two-machine needs this: neither process's own chunks close to zero on their own, only the
    /// sum over both does, so the secondary computes its partial here and ships it to the primary
    /// to finish the reduction. A `SepticDigest<Kb>` is two septic extension elements — 56 bytes —
    /// so the exchange is free next to the proof traffic, which is why the cheap early detector is
    /// worth keeping across the link rather than falling back to the root proof's in-circuit
    /// closure alone.
    ///
    /// Drains the **chunk** terms, like the assert it backs: they are single-shot per block, so
    /// callers must collect the remote partial BEFORE draining the local one.
    ///
    /// The initial-GCS seed is *added but not taken*. It belongs to the program, not to the block,
    /// so a resident process proving block after block off one machine needs it to still be there
    /// next time — see [`Self::initial_gcs`] for why re-seeding per block is the wrong fix.
    pub fn drain_cross_chunk_gcs_over<'a>(
        machines: impl IntoIterator<Item = &'a Self>,
    ) -> SepticDigest<Kb> {
        machines
            .into_iter()
            .flat_map(|m| {
                let chunks = std::mem::take(&mut *m.gcs_terms.lock().expect("gcs mutex poisoned"));
                let seed = *m.initial_gcs.lock().expect("gcs mutex poisoned");
                chunks.into_iter().chain(seed)
            })
            .sum()
    }

    /// Prove the whole program into a serializable bundle: one [`Proof`] per record, in order, plus
    /// the shared verifying key.
    ///
    /// Chunks are proved in bounded-concurrency batches (see [`prove_concurrency`]); each record is
    /// wrapped via [`prepare_chunk`] before [`Self::prove_chunk`]. The batch bound caps peak memory
    /// since every in-flight chunk holds a full proving working set.
    /// Whitelist mode: pin `record`'s proof shape before it is packaged for the GPU (see
    /// [`shape_record`]). A no-op with the whitelist off.
    pub fn shape_record(&self, record: &mut EmulationRecord) {
        if self.bucket {
            shape_record(&self.chips, record);
        }
    }

    /// [`prepare_chunk_shaped`] with this machine's chips and mode: the one packaging step a
    /// pipeline calls per record.
    pub fn prepare_chunk_shaped(&self, record: EmulationRecord) -> PreparedChunk {
        prepare_chunk_shaped(&self.chips, record, self.bucket)
    }

    pub fn prove(&self, records: &[EmulationRecord]) -> Result<RiscvProof, ProveRiscvError> {
        let conc = resolved_concurrency(self.concurrency);
        let mut chunk_proofs = Vec::with_capacity(records.len());
        for (batch_idx, batch) in records.chunks(conc).enumerate() {
            let base = batch_idx * conc;
            let batch_proofs: Vec<Proof<Sc>> = batch
                .par_iter()
                .enumerate()
                .map(|(j, record)| {
                    // Only the GPU staging needs the record owned; the CPU build proves it borrowed.
                    #[cfg(feature = "cuda")]
                    let proof = self.try_prove_chunk(
                        &self.prepare_chunk_shaped(record.clone()),
                        base + j,
                        false,
                    )?;
                    #[cfg(not(feature = "cuda"))]
                    let proof = self.try_prove_ctx(
                        ctx_to_engine(build_ctx(&self.chips, record, self.bucket)),
                        base + j,
                        false,
                    )?;
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

    /// The vk's app-independent pre-hash (see [`compute_vk_pre_hash`]) — this machine's keygen
    /// identity. The orchestrator uses it to assert that per-card keygens of the same program
    /// agree.
    pub fn vk_pre_hash(&self) -> <Sc as pico_mle_core::StarkProtocolConfig>::Digest {
        compute_vk_pre_hash(self.engine.config(), &self.vk.inner, RISCV_APP_PREP_AIR_IDS)
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
    // The CPU-engine verify tests below (and their fixtures/codec helpers) are compiled out under
    // `cuda`, leaving several of these imports unused in that configuration only.
    #[cfg_attr(feature = "cuda", allow(unused_imports))]
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
    ///
    /// CPU-only: exercises the pure-verify guards, which need no GPU backend.
    #[cfg(not(feature = "cuda"))]
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
    #[cfg(not(feature = "cuda"))]
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
    #[cfg(not(feature = "cuda"))]
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
    #[cfg(not(feature = "cuda"))]
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
    #[cfg(not(feature = "cuda"))]
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

    /// Every chip the emulator can activate has a row in the air table. A chip added to the pool
    /// without one is a guest that emulates and then cannot be proved: `build_ctx` and the host
    /// prover's `check_chips_provable` (`sdk/prover`) stop on it by name. Such a chip also needs a
    /// guest in `sdk/prover/src/tests/precompiles.rs` that reaches it. The GPU path has no such
    /// check, which is what the next test is for.
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

    /// The GPU trace generator runs its own chip list
    /// (`RiscvChipType::gpu_generate_extra_record_and_main_chips`), not the air table, and it has
    /// no by-name guard: a chip left off the list is never generated, so its air is silently
    /// missing from every chunk whose shape or events need it, and the proof fails far from the
    /// cause. Every air in the table has to be on the list, and nothing else -- `build_ctx_gpu`
    /// panics on a trace it cannot place.
    ///
    /// The list is also positional: `BaseProver::gpu_generate_extra_record_and_main` indexes it
    /// with hard-coded constants, and the entries appended after the precompile block are pinned
    /// here so a reordering shows up as a test failure rather than as the wrong chip running.
    #[test]
    fn the_gpu_trace_generator_covers_the_air_table() {
        let listed: Vec<String> = RiscvChipType::<Kb>::gpu_generate_extra_record_and_main_chips()
            .iter()
            .map(|chip| chip.name())
            .collect();
        let unique: std::collections::BTreeSet<&str> = listed.iter().map(String::as_str).collect();
        assert_eq!(
            unique.len(),
            listed.len(),
            "a chip is listed twice: {listed:?}"
        );

        let never_generated: Vec<&str> = INCLUDED
            .iter()
            .map(|(name, _)| *name)
            .filter(|name| !unique.contains(name))
            .collect();
        assert!(
            never_generated.is_empty(),
            "airs the GPU trace generator never produces: {never_generated:?}"
        );
        let unplaceable: Vec<&str> = unique
            .iter()
            .copied()
            .filter(|name| air_id_for(name).is_none())
            .collect();
        assert!(
            unplaceable.is_empty(),
            "GPU-generated chips with no MLE RISC-V air: {unplaceable:?}"
        );

        // `BYTE_CHIP_INDEX`, `ECALL_CHIP_INDEX` and `HOST_TRACEGEN_PRECOMPILE_INDICES`.
        assert_eq!(
            listed[45..],
            [
                "Byte",
                "Ecall",
                "Poseidon2Permute",
                "EdAddAssign",
                "EdDecompress"
            ],
            "the orchestrator's positional tail moved"
        );
    }
}
