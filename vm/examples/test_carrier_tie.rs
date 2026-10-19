//! The convert layer must bind the recursion's riscv public-value carrier to the Ecall air's copy.
//!
//! Each riscv AIR that declares public values gets its own vector in the chunk proof, and the
//! verifier never equates them. The Ecall air is the one that constrains `committed_value_digest`
//! (and `exit_code`, `deferred_proofs_digest`); the Cpu air leaves those fields free, and the
//! Global air's copy — the carrier the whole recursion tree reads — is unconstrained. So the only
//! thing that stops a prover from handing the recursion an output the guest never committed is
//! the convert layer tying the carrier to Ecall's copy.
//!
//! Three cases over one fib run, one keygen:
//!   * `baseline` — honest public values. The riscv proofs MUST verify, and convert + combine
//!     MUST give a root whose `committed_value_digest` is the guest's.
//!   * `padding-control` — one slot of the unread padding after the riscv public values changed in
//!     the Global, MemInit and MemFinal copies alike. MUST prove, with the honest digest: the
//!     doctoring path on its own does not break the tree, so the next case fails for its field.
//!   * `forged-carrier` — one digest byte changed in every copy EXCEPT Ecall's, in each chunk that
//!     carries the digest. The riscv proofs MUST still verify: the riscv layer cannot see the
//!     change. Convert + combine must then FAIL (`TIE_EXPECT=patched`, the default), or, on a tree
//!     without the tie, prove a root carrying the forged digest (`TIE_EXPECT=unpatched`).
//!
//! Usage (from the repo root):
//!   cargo run --release -p pico-vm --example test_carrier_tie
//!
//! The process exits 0 only when every case matched its expectation.

use std::{env, panic, sync::Arc};

use p3_field::{PrimeCharacteristicRing, PrimeField32};
use pico_mle_core::{
    config::{recursion_params_with_100_bits_security, riscv_params_with_100_bits_security},
    prover::DeviceDataTransporter,
    StarkEngine,
};
use pico_vm::{
    compiler::{
        program::ProgramBehavior,
        riscv::{
            compiler::{Compiler, SourceType},
            program::Program,
        },
    },
    configs::stark_config::KoalaBearPoseidon2,
    emulator::{
        opts::EmulatorOpts, record::RecordBehavior,
        recursion::public_values::RECURSION_PUBLIC_VALUES_COL_MAP, stdin::EmulatorStdin,
    },
    instances::chiptype::riscv_chiptype::RiscvChipType,
    machine::logger::setup_logger,
    mle::machine::{
        air::GCS_DIGEST_LEN,
        combine::CombineMachine,
        convert::ConvertMachine,
        exe::RiscvVmVk,
        recursion::recursion_public_values,
        riscv::{
            self, air_id, build_ctx, mle_riscv_air_refs, Engine, Kb, RiscvProof,
            RISCV_APP_PREP_AIR_IDS,
        },
    },
    primitives::consts::{MAX_NUM_PVS, PV_DIGEST_NUM_WORDS, RISCV_NUM_PVS},
};

const LOG_STACKED_HEIGHT: usize = 23;
const BUCKET: bool = false;
/// `committed_value_digest` is the first `4 * PV_DIGEST_NUM_WORDS` slots of the riscv
/// `PublicValues` layout.
const NUM_DIGEST_LIMBS: usize = 4 * PV_DIGEST_NUM_WORDS;
// The padding control needs a slot past the riscv public values.
const _: () = assert!(MAX_NUM_PVS > RISCV_NUM_PVS);

#[derive(Clone, Copy, PartialEq, Eq)]
enum Case {
    Baseline,
    PaddingControl,
    ForgedCarrier,
}

impl Case {
    fn name(self) -> &'static str {
        match self {
            Case::Baseline => "baseline",
            Case::PaddingControl => "padding-control",
            Case::ForgedCarrier => "forged-carrier",
        }
    }

    /// The slot this case changes inside `air`'s public values, if any: relative to the riscv
    /// `PublicValues` copy, which sits after the GCS prefix in the Global air.
    fn slot(self, air: usize) -> Option<usize> {
        let base = match air {
            air_id::GLOBAL => GCS_DIGEST_LEN,
            air_id::MEM_INIT | air_id::MEM_FINAL => 0,
            air_id::CPU if self == Case::ForgedCarrier => 0,
            _ => return None,
        };
        match self {
            Case::Baseline => None,
            // The first padding slot: MemInit/MemFinal/Global carry `MAX_NUM_PVS`, Cpu and Ecall
            // only `RISCV_NUM_PVS`, and nothing reads past the riscv values.
            Case::PaddingControl => Some(base + RISCV_NUM_PVS),
            // The first digest byte.
            Case::ForgedCarrier => Some(base),
        }
    }
}

fn main() {
    setup_logger();
    let patched = match env::var("TIE_EXPECT")
        .unwrap_or_else(|_| "patched".into())
        .as_str()
    {
        "patched" => true,
        "unpatched" => false,
        other => panic!("TIE_EXPECT must be `patched` or `unpatched`, got `{other}`"),
    };

    let elf = std::fs::read("./perf/bench_data/rv64/fib-elf")
        .expect("run from the repo root: ./perf/bench_data/rv64/fib-elf not found");
    let mut stdin = EmulatorStdin::<Program, Vec<u8>>::new_builder::<KoalaBearPoseidon2>();
    stdin.write(&10u32);
    let program = Compiler::new(SourceType::RISCV, &elf)
        .expect("failed to parse ELF")
        .compile();
    let opts = EmulatorOpts::from_env_chunk_size(1 << LOG_STACKED_HEIGHT);
    assert!(
        (opts.chunk_size as u64) <= (1u64 << LOG_STACKED_HEIGHT),
        "chunk_size {} exceeds 2^{LOG_STACKED_HEIGHT}",
        opts.chunk_size
    );
    let records = riscv::emulate_with_opts(Arc::clone(&program), &stdin.finalize(), opts)
        .expect("emulation failed")
        .records;

    let engine: Engine = StarkEngine::new(riscv_params_with_100_bits_security(LOG_STACKED_HEIGHT));
    let airs = mle_riscv_air_refs(Arc::clone(&program), BUCKET);
    let (pk, vk) = engine.keygen_with_app_prep(&airs, RISCV_APP_PREP_AIR_IDS);
    let d_pk = engine.device().transport_pk_to_device(&pk);
    let vk = Arc::new(vk);
    let chips = RiscvChipType::<Kb>::all_chips();
    let vm_vk = RiscvVmVk::from_program_and_vk(&program, &vk);

    let mut failures = 0;
    for case in [Case::Baseline, Case::PaddingControl, Case::ForgedCarrier] {
        let name = case.name();
        let mut honest = None;
        let mut forged = None;
        let proofs: Vec<_> = records
            .iter()
            .map(|record| {
                let mut ctx = build_ctx(&chips, record, BUCKET);
                // Only chunks carrying the digest are forged: a chunk before the commit carries
                // zero, and a forged non-zero value there would be caught by the merge's
                // consistency check with or without the tie.
                let carries_digest = record.public_values::<Kb>()[..NUM_DIGEST_LIMBS]
                    .iter()
                    .any(|&b| b != Kb::ZERO);
                for (air, air_ctx) in ctx.per_trace.iter_mut() {
                    if *air == air_id::ECALL && carries_digest {
                        honest = Some(air_ctx.public_values[..NUM_DIGEST_LIMBS].to_vec());
                    }
                    if case == Case::ForgedCarrier && !carries_digest {
                        continue;
                    }
                    if let Some(slot) = case.slot(*air) {
                        // Still a byte, so nothing that range-checks the limbs could object.
                        let v = &mut air_ctx.public_values[slot];
                        *v = Kb::from_u32(v.as_canonical_u32() ^ 1);
                        if case == Case::ForgedCarrier {
                            forged.get_or_insert_with(|| {
                                air_ctx.public_values[slot..slot + NUM_DIGEST_LIMBS].to_vec()
                            });
                        }
                    }
                }
                engine.prove(&d_pk, ctx).expect("riscv prove failed")
            })
            .collect();
        // Without a COMMIT the Ecall constraints are vacuous and this harness tests nothing.
        let honest = honest.expect("no chunk committed a digest: pick an ELF that commits");

        let bundle = RiscvProof {
            vk: Arc::clone(&vk),
            chunk_proofs: proofs,
        };
        let riscv_ok = riscv::verify_riscv(
            &bundle,
            bundle.vk.pre_hash,
            &[(air_id::PROGRAM, riscv::riscv_program_commit(&bundle.vk))],
            program.initial_global_cumulative_sum(),
        );
        if let Err(e) = riscv_ok {
            tracing::error!("case {name}: riscv verify rejected ({e}) — the harness tests nothing");
            failures += 1;
            continue;
        }

        let root = panic::catch_unwind(panic::AssertUnwindSafe(|| -> Result<_, String> {
            let convert = ConvertMachine::new(
                Arc::clone(&vk),
                vm_vk.clone(),
                &bundle.chunk_proofs,
                recursion_params_with_100_bits_security(),
                false,
            )
            .map_err(|e| format!("{e:?}"))?;
            let children = convert
                .prove_with_vks(&bundle.chunk_proofs)
                .map_err(|e| format!("{e}"))?;
            let mut combine = CombineMachine::new(
                recursion_params_with_100_bits_security(),
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

        let root_cvd = root.as_ref().ok().map(|root| {
            let pvs = recursion_public_values(&root.0.public_values).expect("root public values");
            RECURSION_PUBLIC_VALUES_COL_MAP
                .committed_value_digest
                .iter()
                .flat_map(|word| word.0.iter())
                .map(|&idx| pvs[idx])
                .collect::<Vec<_>>()
        });
        let matched = match (case, root_cvd) {
            // The tie's failure: release builds skip the convert emulator's assert, so the broken
            // convert proof first fails at the root's STARK verify. Any other error is not it.
            (Case::ForgedCarrier, None) => {
                patched
                    && root
                        .as_ref()
                        .is_err_and(|e| e.contains("root combine proof failed STARK verify"))
            }
            (Case::ForgedCarrier, Some(cvd)) => !patched && Some(cvd) == forged,
            (_, Some(cvd)) => cvd == honest,
            (_, None) => false,
        };
        let outcome = match &root {
            Ok(_) => "root proved and verified".to_string(),
            Err(e) => e.clone(),
        };
        if matched {
            tracing::info!("case {name}: as expected — {outcome}");
        } else {
            tracing::error!("case {name}: WRONG — {outcome}");
            failures += 1;
        }
    }

    assert_eq!(failures, 0, "{failures} case(s) did not match expectation");
    tracing::info!("carrier tie: every case matched ✓");
}
