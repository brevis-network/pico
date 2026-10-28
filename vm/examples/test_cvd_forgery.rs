//! Positive control for the `committed_value_digest` (cvd) limb-binding forgery.
//!
//! Runs one real MLE/WHIR prove+verify per case over a real RISC-V fib chunk, doctoring the
//! chunk's public values between trace generation and proving. Nothing else changes: the traces,
//! the program, the vk and the register value the guest actually committed are bit-identical
//! across all cases. Only the 32 public-value limbs move.
//!
//! Cases (all in one process, one keygen):
//!   * `baseline` — honest public values. MUST PROVE + VERIFY.
//!   * `control` — `pv[0] += 1`. MUST FAIL VERIFY. This is the harness's detection-power check:
//!     if the control verifies, the harness is worthless and every other result in this run is
//!     meaningless.
//!   * `attack-k` — `pv[2j] -= 256k`, `pv[2j+1] += k` for all 16 limb pairs, k in {1, 7, 1000000}.
//!     The two packed equalities in `vm/src/chips/chips/riscv_ecall/constraints.rs`
//!     (`b0 + 256*b1 == digest_word[0]`, `b2 + 256*b3 == digest_word[1]`) are invariant under this
//!     map, and nothing else bounds a limb, so on an UNPATCHED tree these VERIFY. On a tree that
//!     range-checks the limbs to [0,256) they MUST FAIL.
//!
//! Every case also runs the MLE debug constraint checker (`engine.debug_with_pk`) as an
//! independent second signal, reported next to the real verify result.
//!
//! Expected outcome is selected with `CVD_EXPECT`:
//!   `CVD_EXPECT=unpatched` (default) — attack cases must VERIFY (bug present).
//!   `CVD_EXPECT=patched`             — attack cases must FAIL (bug fixed).
//! The process exits 0 only when every case matches its expectation, 1 otherwise.
//!
//! Usage (from the repo root):
//!   cargo run --profile fast -p pico-vm --example test_cvd_forgery
//!   CVD_EXPECT=patched cargo run --profile fast -p pico-vm --example test_cvd_forgery
//!
//! Knobs: `CVD_N` (fib input, default 10), `CVD_SCOPE=all|cpu` (which AIRs' public-value copies
//! get doctored; default `all`, i.e. what a real prover would do).

use std::{env, panic, sync::Arc};

use p3_field::{PrimeCharacteristicRing, PrimeField32};
use pico_mle_core::{
    config::riscv_params_with_100_bits_security, prover::DeviceDataTransporter, StarkEngine,
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
    emulator::{record::RecordBehavior, riscv::record::EmulationRecord, stdin::EmulatorStdin},
    instances::chiptype::riscv_chiptype::RiscvChipType,
    machine::logger::setup_logger,
    mle::machine::{
        air::GCS_DIGEST_LEN,
        riscv::{
            self, air_id, build_ctx, ctx_to_engine, mle_riscv_air_refs, Engine, Kb, RiscvProof,
            RISCV_APP_PREP_AIR_IDS,
        },
    },
    primitives::consts::PV_DIGEST_NUM_WORDS,
};

/// The operating point the prover ships, matching `test_mle_e2e`: the forgery is only worth
/// demonstrating against the shape that actually deploys.
const LOG_STACKED_HEIGHT: usize = 23;
/// Natural heights, matching `test_mle_riscv`'s positive path.
const BUCKET: bool = false;
/// `committed_value_digest` is `[Word<F>; 8]` and `Word` is 4 limbs, so the digest occupies the
/// first 32 slots of the RISCV `PublicValues` layout (`emulator/riscv/public_values.rs:16`,
/// `compiler/word.rs:16`, `primitives/consts.rs:55`).
const NUM_DIGEST_LIMBS: usize = 4 * PV_DIGEST_NUM_WORDS;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Doctor {
    /// Honest public values.
    None,
    /// `pv[0] += 1` — breaks `b0 + 256*b1 == digest_word[0]`.
    Control,
    /// `(b0, b1) -> (b0 - 256k, b1 + k)` on all 16 limb pairs — kernel of the packed equalities.
    Attack(u64),
}

impl Doctor {
    fn name(&self) -> String {
        match self {
            Doctor::None => "baseline".to_string(),
            Doctor::Control => "control(pv[0]+=1)".to_string(),
            Doctor::Attack(k) => format!("attack(k={k})"),
        }
    }

    /// Apply the doctoring in place to the `NUM_DIGEST_LIMBS` limbs starting at `base`.
    fn apply(&self, pvs: &mut [Kb], base: usize) {
        match *self {
            Doctor::None => {}
            Doctor::Control => pvs[base] += Kb::ONE,
            Doctor::Attack(k) => {
                let k_f = Kb::from_u64(k);
                let k256 = k_f * Kb::from_u32(256);
                for j in 0..NUM_DIGEST_LIMBS / 2 {
                    pvs[base + 2 * j] -= k256;
                    pvs[base + 2 * j + 1] += k_f;
                }
            }
        }
    }
}

/// Offset of the digest limbs inside each AIR's public-value vector, or `None` for AIRs that carry
/// no `PublicValues` copy. See `mle/machine/riscv.rs:387-434` (`build_ctx_inner`).
fn digest_base(air: usize, scope_all: bool) -> Option<usize> {
    match air {
        // `AirProvingContext::simple(trace, pvs_riscv)` — RISCV PublicValues at offset 0.
        //
        // ECALL belongs here too: 0913a7c86 hoisted the digest constraints out of the Cpu chip
        // into the dedicated Ecall chip, and `build_ctx_inner` hands both the same `pvs_riscv`
        // (`mle/machine/riscv.rs`: `air_id::CPU | air_id::ECALL => simple(trace, pvs_riscv)`).
        // Doctoring only CPU leaves the chip that actually evaluates the equalities looking at
        // honest public values, which is exactly what the control caught: `pv[0] += 1` verified.
        air_id::CPU | air_id::ECALL => Some(0),
        // `pvs_max` — same layout, MAX_NUM_PVS long.
        air_id::MEM_INIT | air_id::MEM_FINAL if scope_all => Some(0),
        // `[gcs (GCS_DIGEST_LEN) || pvs_max]`.
        air_id::GLOBAL if scope_all => Some(GCS_DIGEST_LEN),
        _ => None,
    }
}

/// Read the honest digest limbs out of a record, for reporting / the vacuity guard.
fn honest_digest(record: &EmulationRecord) -> Vec<u32> {
    record.public_values::<Kb>()[..NUM_DIGEST_LIMBS]
        .iter()
        .map(|f| f.as_canonical_u32())
        .collect()
}

struct CaseResult {
    name: String,
    debug_ok: bool,
    prove_ok: bool,
    verify_ok: bool,
    detail: String,
    /// First chunk's doctored digest limbs, for the report.
    limbs: Vec<u32>,
}

#[allow(clippy::too_many_arguments)]
fn run_case(
    doctor: Doctor,
    program: Arc<Program>,
    records: &[EmulationRecord],
    engine: &Engine,
    airs: &[pico_mle_core::AirRef<pico_vm::mle::machine::riscv::Sc>],
    pk: &pico_mle_core::keygen::types::MultiStarkProvingKey<pico_vm::mle::machine::riscv::Sc>,
    d_pk: &pico_mle_core::prover::DeviceMultiStarkProvingKey<pico_vm::mle::machine::riscv::Pb>,
    vk: &pico_mle_core::keygen::types::MultiStarkVerifyingKey<pico_vm::mle::machine::riscv::Sc>,
    chips: &[pico_vm::machine::chip::MetaChip<Kb, RiscvChipType<Kb>>],
    scope_all: bool,
) -> CaseResult {
    let name = doctor.name();
    let mut limbs = Vec::new();

    // Build one doctored context per chunk, twice: the debug checker consumes a context by
    // reference but proving moves it, and `ProvingContext` is not `Clone`.
    let make_ctxs = || -> Vec<_> {
        records
            .iter()
            .map(|record| {
                let mut ctx = build_ctx(chips, record, BUCKET);
                for (air, air_ctx) in ctx.per_trace.iter_mut() {
                    if let Some(base) = digest_base(*air, scope_all) {
                        assert!(
                            air_ctx.public_values.len() >= base + NUM_DIGEST_LIMBS,
                            "air {air} public values too short for the digest window"
                        );
                        doctor.apply(&mut air_ctx.public_values, base);
                    }
                }
                ctx_to_engine(ctx)
            })
            .collect()
    };

    // --- signal 1: the MLE debug constraint checker (panics on violation) ---
    let debug_ctxs = make_ctxs();
    for (air, air_ctx) in debug_ctxs[0].per_trace.iter() {
        if *air == air_id::CPU {
            limbs = air_ctx.public_values[..NUM_DIGEST_LIMBS]
                .iter()
                .map(|f| f.as_canonical_u32())
                .collect();
        }
    }
    let debug_ok = panic::catch_unwind(panic::AssertUnwindSafe(|| {
        for ctx in debug_ctxs.iter() {
            engine.debug_with_pk(airs, ctx, pk);
        }
    }))
    .is_ok();

    // --- signal 2: real prove + real verify ---
    // Built outside the unwind guard: a failed upload must abort, not read as a rejected forgery.
    drop(debug_ctxs);
    let prove_ctxs = make_ctxs();
    let proved = panic::catch_unwind(panic::AssertUnwindSafe(|| {
        prove_ctxs
            .into_iter()
            .map(|ctx| engine.prove(d_pk, ctx).expect("prove failed"))
            .collect::<Vec<_>>()
    }));

    let (prove_ok, verify_ok, detail) = match proved {
        Err(_) => (false, false, "prover panicked/errored".to_string()),
        Ok(chunk_proofs) => {
            let bundle = RiscvProof {
                vk: Arc::new(vk.clone()),
                chunk_proofs,
            };
            let res = riscv::verify_riscv(
                &bundle,
                bundle.vk.pre_hash,
                &[(air_id::PROGRAM, riscv::riscv_program_commit(&bundle.vk))],
                program.initial_global_cumulative_sum(),
            );
            match res {
                Ok(()) => (true, true, "verify_riscv OK".to_string()),
                Err(e) => (true, false, format!("verify_riscv rejected: {e}")),
            }
        }
    };

    CaseResult {
        name,
        debug_ok,
        prove_ok,
        verify_ok,
        detail,
        limbs,
    }
}

fn main() {
    setup_logger();
    // The GPU riscv prover allocates from the shared pool; a CPU build has none to set up.
    #[cfg(feature = "cuda")]
    riscv::init_mle_gpu_pool(riscv::MLE_GPU_DEVICE);

    let patched = match env::var("CVD_EXPECT")
        .unwrap_or_else(|_| "unpatched".into())
        .as_str()
    {
        "patched" => true,
        "unpatched" => false,
        other => panic!("CVD_EXPECT must be `patched` or `unpatched`, got `{other}`"),
    };
    let scope_all = env::var("CVD_SCOPE").unwrap_or_else(|_| "all".into()) != "cpu";
    let n: u32 = env::var("CVD_N")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(10);

    // Same ELF + stdin as `test_mle_riscv --elf fib --n <n>` (which that example no longer
    // recommends -- its forgery table needs a precompile workload).
    let elf = std::fs::read("./perf/bench_data/rv64/fib-elf")
        .expect("run from the repo root: ./perf/bench_data/rv64/fib-elf not found");
    let mut stdin = EmulatorStdin::<Program, Vec<u8>>::new_builder::<KoalaBearPoseidon2>();
    stdin.write(&n);
    let stdin = stdin.finalize();

    let program = Compiler::new(SourceType::RISCV, &elf)
        .expect("failed to parse ELF")
        .compile();
    // Paired with `LOG_STACKED_HEIGHT`: a chunk of 2^23 instructions needs a stacked height of 23,
    // so a larger `CHUNK_SIZE` would prove a different shape than this test pins; refuse it.
    let chunk_size = riscv::chunk_size_from_env(LOG_STACKED_HEIGHT);
    let records = riscv::emulate(program.clone(), stdin, Some(chunk_size));

    let honest = honest_digest(&records[0]);
    println!("\n=== cvd forgery positive control ===");
    println!("chunks             : {}", records.len());
    println!("honest cvd limbs   : {honest:?}");
    println!(
        "expectation        : attack must {} (CVD_EXPECT={})",
        if patched { "FAIL" } else { "VERIFY" },
        if patched { "patched" } else { "unpatched" }
    );
    println!(
        "doctoring scope    : {}\n",
        if scope_all {
            "CPU+MemInit+MemFinal+Global"
        } else {
            "CPU only"
        }
    );

    // Vacuity guard: if the guest never committed anything, `commit_cond` is identically zero and
    // both the control and the attack would trivially "pass" — the run would prove nothing.
    assert!(
        honest.iter().any(|&b| b != 0),
        "committed_value_digest is all zero: the guest never ran a COMMIT ecall, so the ecall \
         constraints are vacuous and this harness has NO detection power. Pick an ELF that commits."
    );

    // Keygen once, reuse across every case (keygen is the expensive part and is case-independent).
    let engine: Engine = StarkEngine::new(riscv_params_with_100_bits_security(LOG_STACKED_HEIGHT));
    let airs = mle_riscv_air_refs(program.clone(), BUCKET);
    let (pk, vk) = engine.keygen_with_app_prep(&airs, RISCV_APP_PREP_AIR_IDS);
    let d_pk = engine.device().transport_pk_to_device(&pk);
    let chips = RiscvChipType::<Kb>::all_chips();

    // Keep the expected-failure cases from dumping panic spam over the report.
    let default_hook = panic::take_hook();
    panic::set_hook(Box::new(|info| {
        let msg = info
            .payload()
            .downcast_ref::<&str>()
            .map(|s| s.to_string())
            .or_else(|| info.payload().downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "<non-string panic>".into());
        eprintln!("  [caught] {msg}");
    }));

    let cases = [
        Doctor::None,
        Doctor::Control,
        Doctor::Attack(1),
        Doctor::Attack(7),
        Doctor::Attack(1_000_000),
    ];
    let results: Vec<CaseResult> = cases
        .iter()
        .map(|d| {
            eprintln!("--- running case: {} ---", d.name());
            run_case(
                *d,
                program.clone(),
                &records,
                &engine,
                &airs,
                &pk,
                &d_pk,
                &vk,
                &chips,
                scope_all,
            )
        })
        .collect();

    panic::set_hook(default_hook);

    println!("\n=== results ===");
    let mut harness_ok = true;
    for (case, r) in cases.iter().zip(results.iter()) {
        // What this case MUST do for the harness to be believed.
        let want_verify = match case {
            Doctor::None => true,
            Doctor::Control => false,
            Doctor::Attack(_) => !patched,
        };
        let ok = r.verify_ok == want_verify;
        harness_ok &= ok;
        println!(
            "{:<20} debug={:<4} prove={:<4} verify={:<4} want_verify={:<5} [{}]  {}",
            r.name,
            if r.debug_ok { "OK" } else { "FAIL" },
            if r.prove_ok { "OK" } else { "FAIL" },
            if r.verify_ok { "OK" } else { "FAIL" },
            want_verify,
            if ok { "as expected" } else { "MISMATCH" },
            r.detail,
        );
        println!(
            "{:<20} cvd limbs (cpu air): {:?}",
            "",
            &r.limbs[..8.min(r.limbs.len())]
        );
    }

    // The control is load-bearing: call it out separately and loudly.
    let control = &results[1];
    if control.verify_ok {
        println!(
            "\n!!! THE CONTROL VERIFIED. The harness has NO detection power — pv[0]+=1 breaks the \
             packed recomposition and MUST be rejected. Every other line above is meaningless."
        );
    } else {
        println!("\ncontrol rejected as required -> the harness has detection power.");
    }

    if harness_ok {
        println!("\nRESULT: PASS (every case matched its expectation)");
    } else {
        println!("\nRESULT: FAIL (see MISMATCH above)");
        std::process::exit(1);
    }
}
