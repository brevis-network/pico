//! Negative test for the commit tally: an output word the guest never COMMITs must not reach the
//! root.
//!
//! The Ecall air pins a `committed_value_digest` word only on the COMMIT row that names it. Before
//! the fix the combine merge only locked a non-zero digest to its successors, so a word no COMMIT
//! names was free in every chunk, and a prover could make the root claim any value for it. The
//! SDK's halt commits all eight words, so SDK guests were not exposed; a guest that issues its own
//! ecalls was.
//!
//! The guests are built from instructions, so no ELF is needed. Each runs one keygen, then each
//! case proves the chunks — with the public values doctored or not — verifies the riscv proof, and
//! converts and combines to a root whose digest it checks:
//!
//! | guest                     | case             | unpatched                | patched (all-or-nothing) |
//! |---------------------------|------------------|--------------------------|--------------------------|
//! | commits all 8 words       | baseline         | root digest = honest     | root digest = honest     |
//! |                           | control          | riscv verify rejects     | riscv verify rejects     |
//! | commits no word           | baseline         | root digest = 0          | root digest = 0          |
//! |                           | forged           | root carries the forgery | rejected, or digest = 0  |
//! | commits words 0..4        | baseline         | root digest = honest     | rejected                 |
//! |                           | forged           | root carries the forgery | rejected                 |
//!
//! `control` changes a committed word, which the Ecall air pins: it shows the harness can see a
//! forgery at all, so the `forged` cases mean what they say. `forged` sets the uncommitted word
//! `FORGED_WORD` to `FORGED_VALUE` in every public-value copy of every chunk — byte-valued limbs,
//! so nothing that range-checks them could object.
//!
//! "Patched" is the fix, mirroring the deferred digest: a chunk contributes its digest only if it
//! committed all eight words once each, and a chunk that committed some but not all does not
//! prove. `G1_EXPECT=unpatched` states what a tree from before the fix does.
//!
//! Usage (from the repo root):
//!   cargo run --release -p pico-vm --example test_cvd_uncommitted
//!   G1_EXPECT=unpatched cargo run --release -p pico-vm --example test_cvd_uncommitted
//!
//! The process exits 0 only when every case matched its expectation.

use std::{env, panic, sync::Arc};

use p3_field::{PrimeCharacteristicRing, PrimeField32};
use pico_mle_core::{
    config::{recursion_params_with_128_bits_security, riscv_params_with_128_bits_security},
    prover::DeviceDataTransporter,
    StarkEngine,
};
use pico_vm::{
    compiler::{
        program::ProgramBehavior,
        riscv::{instruction::Instruction, opcode::Opcode, program::Program},
    },
    configs::stark_config::KoalaBearPoseidon2,
    emulator::{
        record::RecordBehavior,
        recursion::public_values::RECURSION_PUBLIC_VALUES_COL_MAP,
        riscv::{record::EmulationRecord, syscalls::SyscallCode},
        stdin::EmulatorStdin,
    },
    instances::chiptype::riscv_chiptype::RiscvChipType,
    machine::logger::setup_logger,
    mle::machine::{
        air::GCS_DIGEST_LEN,
        combine::CombineMachine,
        convert::ConvertMachine,
        exe::RiscvVmVk,
        riscv::{
            self, air_id, build_ctx, ctx_to_engine, mle_riscv_air_refs, Engine, Kb, RiscvProof,
            RISCV_APP_PREP_AIR_IDS,
        },
    },
    primitives::consts::{PV_DIGEST_NUM_WORDS, RECURSION_NUM_PVS},
};

const LOG_STACKED_HEIGHT: usize = 23;
const BUCKET: bool = false;
/// `committed_value_digest` is the first `4 * PV_DIGEST_NUM_WORDS` slots of the riscv
/// `PublicValues` layout: eight words of four byte limbs.
const NUM_DIGEST_LIMBS: usize = 4 * PV_DIGEST_NUM_WORDS;
/// The word the `forged` cases set: one the partial guest does not commit.
const FORGED_WORD: usize = 5;
/// Four byte-valued limbs, 0x42424242.
const FORGED_VALUE: [u32; 4] = [0x42; 4];
/// Where the hand-built guests live: two u16 limbs, inside the guest range like a real program.
const PC_BASE: u64 = 0x1000_0000;

/// A guest that COMMITs `words` (word `i` gets the value `0x700 + i`) and then halts with exit
/// code 0. The ecall ABI: syscall code in t0 (x5), arguments in a0 (x10) and a1 (x11). The values
/// stay below 2^11 so that each is a plain ADDI immediate.
fn guest(words: &[usize]) -> Program {
    let addi = |rd: u8, imm: u64| Instruction::new(Opcode::ADD, rd, 0, imm, false, true);
    let ecall = Instruction::new(Opcode::ECALL, 5, 10, 11, false, false);
    let mut instructions = Vec::new();
    for &i in words {
        instructions.push(addi(5, u64::from(SyscallCode::COMMIT.syscall_id())));
        instructions.push(addi(10, i as u64));
        instructions.push(addi(11, 0x700 + i as u64));
        instructions.push(ecall);
    }
    instructions.push(addi(5, u64::from(SyscallCode::HALT.syscall_id())));
    instructions.push(addi(10, 0));
    instructions.push(ecall);
    Program::new(instructions, PC_BASE, PC_BASE)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Case {
    Baseline,
    /// A committed word changed: the Ecall air must reject it.
    Control,
    /// `FORGED_WORD` set to `FORGED_VALUE`.
    Forged,
}

impl Case {
    fn name(self) -> &'static str {
        match self {
            Case::Baseline => "baseline",
            Case::Control => "control",
            Case::Forged => "forged",
        }
    }

    fn doctor(self, digest: &mut [Kb]) {
        match self {
            Case::Baseline => {}
            // Still a byte, so only the Ecall equality can catch it.
            Case::Control => digest[0] = Kb::from_u32(digest[0].as_canonical_u32() ^ 1),
            Case::Forged => {
                for (j, &b) in FORGED_VALUE.iter().enumerate() {
                    digest[4 * FORGED_WORD + j] = Kb::from_u32(b);
                }
            }
        }
    }
}

/// Offset of the digest limbs inside each AIR's public-value vector, or `None` for AIRs that
/// carry no `PublicValues` copy. Every copy is doctored, as a real prover would: the convert
/// layer ties them together, so doctoring fewer would be caught for the wrong reason.
fn digest_base(air: usize) -> Option<usize> {
    match air {
        air_id::CPU | air_id::ECALL | air_id::MEM_INIT | air_id::MEM_FINAL => Some(0),
        air_id::GLOBAL => Some(GCS_DIGEST_LEN),
        _ => None,
    }
}

/// What a case ended with: the riscv verify's verdict, then the root's digest or the error that
/// stopped convert/combine.
enum Outcome {
    RiscvRejected(String),
    Root(Vec<u32>),
    TreeFailed(String),
}

#[allow(clippy::too_many_arguments)]
fn run_case(
    case: Case,
    program: &Arc<Program>,
    records: &[EmulationRecord],
    engine: &Engine,
    d_pk: &pico_mle_core::prover::DeviceMultiStarkProvingKey<pico_vm::mle::machine::riscv::Pb>,
    vk: &Arc<
        pico_mle_core::keygen::types::MultiStarkVerifyingKey<pico_vm::mle::machine::riscv::Sc>,
    >,
    vm_vk: &RiscvVmVk,
    chips: &[pico_vm::machine::chip::MetaChip<Kb, RiscvChipType<Kb>>],
) -> Outcome {
    let proofs: Vec<_> = records
        .iter()
        .map(|record| {
            let mut ctx = build_ctx(chips, record, BUCKET);
            for (air, air_ctx) in ctx.per_trace.iter_mut() {
                if let Some(base) = digest_base(*air) {
                    case.doctor(&mut air_ctx.public_values[base..base + NUM_DIGEST_LIMBS]);
                }
            }
            engine
                .prove(d_pk, ctx_to_engine(ctx))
                .expect("riscv prove failed")
        })
        .collect();
    let bundle = RiscvProof {
        vk: Arc::clone(vk),
        chunk_proofs: proofs,
    };
    if let Err(e) = riscv::verify_riscv(
        &bundle,
        bundle.vk.pre_hash,
        &[(air_id::PROGRAM, riscv::riscv_program_commit(&bundle.vk))],
        program.initial_global_cumulative_sum(),
    ) {
        return Outcome::RiscvRejected(format!("{e}"));
    }

    let root = panic::catch_unwind(panic::AssertUnwindSafe(|| -> Result<_, String> {
        let convert = ConvertMachine::new(
            Arc::clone(vk),
            vm_vk.clone(),
            &bundle.chunk_proofs,
            recursion_params_with_128_bits_security(),
            false,
        )
        .map_err(|e| format!("{e:?}"))?;
        let children = convert
            .prove_with_vks(&bundle.chunk_proofs)
            .map_err(|e| format!("{e}"))?;
        let mut combine = CombineMachine::new(
            recursion_params_with_128_bits_security(),
            vm_vk.clone(),
            false,
        );
        let root = combine.prove_tree(children).map_err(|e| format!("{e}"))?;
        combine.verify(&root).map_err(|e| format!("{e}"))?;
        Ok(root)
    }))
    .unwrap_or_else(|p| {
        Err(p
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| p.downcast_ref::<&str>().map(|s| (*s).to_string()))
            .unwrap_or_else(|| "panic with no message".into()))
    });
    match root {
        Err(e) => Outcome::TreeFailed(e),
        Ok(root) => {
            let pvs = root
                .0
                .public_values
                .iter()
                .find(|p| p.len() == RECURSION_NUM_PVS)
                .expect("root proof carries no recursion public values");
            Outcome::Root(
                RECURSION_PUBLIC_VALUES_COL_MAP
                    .committed_value_digest
                    .iter()
                    .flat_map(|word| word.0.iter())
                    .map(|&idx| pvs[idx].as_canonical_u32())
                    .collect(),
            )
        }
    }
}

/// The digest limbs an honest run of `guest(words)` commits.
fn honest_digest(words: &[usize]) -> Vec<u32> {
    let mut d = vec![0u32; NUM_DIGEST_LIMBS];
    for &i in words {
        d[4 * i..4 * i + 4].copy_from_slice(&(0x700u32 + i as u32).to_le_bytes().map(u32::from));
    }
    d
}

fn main() {
    setup_logger();
    // The GPU riscv prover allocates from the shared pool; a CPU build has none to set up.
    #[cfg(feature = "cuda")]
    riscv::init_mle_gpu_pool(riscv::MLE_GPU_DEVICE);
    let patched = match env::var("G1_EXPECT")
        .unwrap_or_else(|_| "patched".into())
        .as_str()
    {
        "patched" => true,
        "unpatched" => false,
        other => panic!("G1_EXPECT must be `patched` or `unpatched`, got `{other}`"),
    };

    let all: Vec<usize> = (0..PV_DIGEST_NUM_WORDS).collect();
    let partial: Vec<usize> = (0..4).collect();
    assert!(!partial.contains(&FORGED_WORD));
    let guests: [(&str, Vec<usize>, Vec<Case>); 3] = [
        ("commits all 8", all, vec![Case::Baseline, Case::Control]),
        ("commits none", vec![], vec![Case::Baseline, Case::Forged]),
        ("commits 0..4", partial, vec![Case::Baseline, Case::Forged]),
    ];

    let engine: Engine = StarkEngine::new(riscv_params_with_128_bits_security(LOG_STACKED_HEIGHT));
    let chips = RiscvChipType::<Kb>::all_chips();
    let mut failures = 0;
    for (label, words, cases) in guests {
        let program = Arc::new(guest(&words));
        let stdin = EmulatorStdin::new_builder::<KoalaBearPoseidon2>();
        let chunk_size = riscv::chunk_size_from_env(LOG_STACKED_HEIGHT);
        let records = riscv::emulate(Arc::clone(&program), stdin.finalize(), Some(chunk_size));
        let honest = honest_digest(&words);
        // The guest's own commits must reach the record, or the cases below test nothing.
        let emulated: Vec<u32> = records
            .iter()
            .rev()
            .map(|r| r.public_values::<Kb>()[..NUM_DIGEST_LIMBS].to_vec())
            .find(|d| d.iter().any(|&b| b != Kb::ZERO))
            .unwrap_or_else(|| vec![Kb::ZERO; NUM_DIGEST_LIMBS])
            .iter()
            .map(|b| b.as_canonical_u32())
            .collect();
        assert_eq!(
            emulated, honest,
            "{label}: the emulator did not commit what the guest did"
        );

        let airs = mle_riscv_air_refs(Arc::clone(&program), BUCKET);
        let (pk, vk) = engine.keygen_with_app_prep(&airs, RISCV_APP_PREP_AIR_IDS);
        let d_pk = engine.device().transport_pk_to_device(&pk);
        let vk = Arc::new(vk);
        let vm_vk = RiscvVmVk::from_program_and_vk(&program, &vk);

        for case in cases {
            let outcome = run_case(
                case, &program, &records, &engine, &d_pk, &vk, &vm_vk, &chips,
            );
            let mut forged = honest.clone();
            Case::Forged.doctor_u32(&mut forged);
            let committed = words.len();
            let matched = match (&outcome, case) {
                // Only the Ecall air can see a changed committed word.
                (Outcome::RiscvRejected(_), Case::Control) => true,
                (_, Case::Control) => false,
                // A riscv rejection elsewhere means the harness broke, not the fix.
                (Outcome::RiscvRejected(_), _) => false,
                (Outcome::Root(d), Case::Baseline) => {
                    *d == honest && (!patched || committed == 0 || committed == PV_DIGEST_NUM_WORDS)
                }
                (Outcome::TreeFailed(_), Case::Baseline) => {
                    patched && committed != 0 && committed != PV_DIGEST_NUM_WORDS
                }
                (Outcome::Root(d), Case::Forged) => {
                    if patched {
                        committed == 0 && *d == honest
                    } else {
                        *d == forged
                    }
                }
                (Outcome::TreeFailed(_), Case::Forged) => patched,
            };
            let what = match &outcome {
                Outcome::RiscvRejected(e) => format!("riscv verify rejected: {e}"),
                Outcome::Root(d) if *d == forged && case == Case::Forged => {
                    "root proved and verified, carrying the forged word".to_string()
                }
                Outcome::Root(d) if *d == honest => {
                    "root proved and verified, honest digest".into()
                }
                Outcome::Root(d) => format!("root proved and verified, digest {d:?}"),
                Outcome::TreeFailed(e) => format!("convert/combine failed: {e}"),
            };
            if matched {
                tracing::info!("{label} / {}: as expected — {what}", case.name());
            } else {
                tracing::error!("{label} / {}: WRONG — {what}", case.name());
                failures += 1;
            }
        }
    }

    assert_eq!(failures, 0, "{failures} case(s) did not match expectation");
    tracing::info!(
        "uncommitted output words ({}): every case matched ✓",
        if patched { "patched" } else { "unpatched" }
    );
}

impl Case {
    /// [`Case::doctor`] on canonical limbs, to state what a forged root would carry.
    fn doctor_u32(self, digest: &mut [u32]) {
        let mut f: Vec<Kb> = digest.iter().map(|&b| Kb::from_u32(b)).collect();
        self.doctor(&mut f);
        for (d, x) in digest.iter_mut().zip(f) {
            *d = x.as_canonical_u32();
        }
    }
}
