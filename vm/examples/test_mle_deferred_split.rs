//! Where the chunk cut lands in the guest's COMMIT_DEFERRED_PROOFS run.
//!
//! The deferred digest is bound only on the eight COMMIT_DEFERRED_PROOFS rows the SDK's halt runs,
//! and the prover chooses where chunks end. The recursion takes the digest only from the chunk that
//! ran all eight words, and the emulator holds the cut while that run is in flight. Over fib, which
//! defers nothing (its honest digest is zero):
//!
//!   * `halt-only` — a cut right before HALT, which the hold does not prevent (the run is whole by
//!     then). The HALT-only chunk and every later one run no deferred commit, so their copies of the
//!     digest are free: each is set to the end of a real deferred chain, with that chain's nodes at
//!     the head of the tree. The riscv proofs still verify. MUST FAIL at the root
//!     (`SPLIT_EXPECT=patched`, the default); on a tree that took an executing chunk's copy, it
//!     proves a root claiming deferrals the guest never made (`SPLIT_EXPECT=unpatched`). The same
//!     cut unforged must prove.
//!   * `partial-run` — a cut inside the eight COMMIT_DEFERRED_PROOFS ecalls, made with the hold
//!     off (`CHUNK_COMMIT_TAIL_HOLD_OFF=1`), honest otherwise. MUST FAIL at the root: a chunk that
//!     ran some of the words but not all of them does not prove.
//!   * `guarded` — chunk sizes that end a chunk inside the run, searched near the halt below 2^15
//!     (the hold spends clk past the ceiling) and above (it spends a reserve below it): each cuts
//!     the run with the hold off, and with the hold on every chunk runs none or all eight of the
//!     words. A run at one of them proves.
//!
//! Usage (from the repo root):
//!   cargo run --release -p pico-vm --example test_mle_deferred_split
//!
//! The process exits 0 only when every case matched its expectation.

use std::{env, panic, sync::Arc};

use p3_field::PrimeCharacteristicRing;
use pico_mle_core::{
    config::{recursion_params_with_100_bits_security, riscv_params_with_100_bits_security},
    prover::DeviceDataTransporter,
    StarkEngine,
};
use pico_vm::{
    chips::chips::riscv_cpu::event::CpuEvent,
    compiler::{
        program::ProgramBehavior,
        riscv::{
            compiler::{Compiler, SourceType},
            program::Program,
        },
    },
    configs::stark_config::KoalaBearPoseidon2,
    emulator::{
        opts::EmulatorOpts,
        recursion::public_values::RECURSION_PUBLIC_VALUES_COL_MAP,
        riscv::{record::EmulationRecord, syscalls::SyscallCode},
        stdin::EmulatorStdin,
    },
    instances::chiptype::riscv_chiptype::RiscvChipType,
    machine::logger::setup_logger,
    mle::machine::{
        air::GCS_DIGEST_LEN,
        deferred::DeferredMachine,
        exe::RiscvVmVk,
        recursion::{recursion_public_values, Kb},
        riscv::{self, air_id, build_ctx, mle_riscv_air_refs, Engine, RISCV_APP_PREP_AIR_IDS},
    },
    primitives::consts::{DIGEST_SIZE, PV_DIGEST_NUM_WORDS},
};
use tracing::{error, info};

#[path = "common/tree.rs"]
mod tree;
use tree::build_tree;

const FIB_ELF: &str = "./perf/bench_data/rv64/fib-elf";
const LOG_STACKED_HEIGHT: usize = 23;
/// `deferred_proofs_digest` follows the 32 digest bytes in the riscv `PublicValues` layout.
const DEFERRED_OFFSET: usize = 4 * PV_DIGEST_NUM_WORDS;
/// Below this the emulator reserves nothing for the commit tail (`4 * chunk_size < 64 * 2048`).
const GUARDED_CHUNK_SIZE: u32 = 32_768;

fn syscall(e: &CpuEvent) -> Option<u32> {
    e.instruction
        .is_ecall_instruction()
        .then(|| (e.op_a_prev_value() & 0xFF) as u32)
}

fn deferred_commits(record: &EmulationRecord) -> usize {
    let id = SyscallCode::COMMIT_DEFERRED_PROOFS.syscall_id();
    record
        .cpu_events
        .iter()
        .filter(|e| syscall(e) == Some(id))
        .count()
}

fn halts(record: &EmulationRecord) -> bool {
    let id = SyscallCode::HALT.syscall_id();
    record.cpu_events.iter().any(|e| syscall(e) == Some(id))
}

fn emulate(program: &Arc<Program>, n: u32, chunk_size: u32) -> Vec<EmulationRecord> {
    let mut stdin = EmulatorStdin::<Program, Vec<u8>>::new_builder::<KoalaBearPoseidon2>();
    stdin.write(&n);
    let mut opts = EmulatorOpts::from_env_chunk_size(chunk_size);
    opts.chunk_size = chunk_size;
    riscv::emulate_with_opts(Arc::clone(program), &stdin.finalize(), opts)
        .expect("emulation")
        .records
}

/// Run `f` with the emulator's commit-tail hold off.
fn with_hold_off<T>(f: impl FnOnce() -> T) -> T {
    env::set_var("CHUNK_COMMIT_TAIL_HOLD_OFF", "1");
    let out = f();
    env::remove_var("CHUNK_COMMIT_TAIL_HOLD_OFF");
    out
}

/// Whether some chunk runs part of the deferred commit, and whether exactly one runs all of it.
fn run_is_whole(records: &[EmulationRecord]) -> bool {
    let counts: Vec<usize> = records.iter().map(deferred_commits).collect();
    counts.iter().all(|&c| c == 0 || c == DIGEST_SIZE)
        && counts.iter().filter(|&&c| c == DIGEST_SIZE).count() == 1
}

/// The run's instruction count, from one emulation in a single chunk.
fn emulate_cycles(program: &Arc<Program>, n: u32) -> u64 {
    let mut stdin = EmulatorStdin::<Program, Vec<u8>>::new_builder::<KoalaBearPoseidon2>();
    stdin.write(&n);
    let mut opts = EmulatorOpts::from_env_chunk_size(1 << 22);
    opts.chunk_size = 1 << 22;
    riscv::emulate_with_opts(Arc::clone(program), &stdin.finalize(), opts)
        .expect("emulation")
        .cycles
}

/// The first chunk size `range` yields whose records satisfy `hit`.
fn search(
    program: &Arc<Program>,
    n: u32,
    range: impl Iterator<Item = u32>,
    hit: impl Fn(&[EmulationRecord]) -> bool,
) -> Option<u32> {
    range.into_iter().find(|&cs| hit(&emulate(program, n, cs)))
}

struct Riscv {
    engine: Engine,
    d_pk: pico_mle_core::prover::DeviceMultiStarkProvingKey<riscv::Pb>,
    vk: Arc<pico_mle_core::keygen::types::MultiStarkVerifyingKey<riscv::Sc>>,
    vm_vk: RiscvVmVk,
}

impl Riscv {
    fn new(program: &Arc<Program>) -> Self {
        let engine: Engine =
            StarkEngine::new(riscv_params_with_100_bits_security(LOG_STACKED_HEIGHT));
        let airs = mle_riscv_air_refs(Arc::clone(program), false);
        let (pk, vk) = engine.keygen_with_app_prep(&airs, RISCV_APP_PREP_AIR_IDS);
        let d_pk = engine.device().transport_pk_to_device(&pk);
        let vm_vk = RiscvVmVk::from_program_and_vk(program, &vk);
        Self {
            engine,
            d_pk,
            vk: Arc::new(vk),
            vm_vk,
        }
    }

    /// Prove every record, first setting every public-value copy's deferred digest to `forged` in
    /// the records from index `from` on — the carrier is tied to each copy, so a forger fills them
    /// alike.
    fn prove(
        &self,
        records: &[EmulationRecord],
        from: usize,
        forged: [Kb; DIGEST_SIZE],
    ) -> Vec<pico_mle_core::protocol::proof::Proof<riscv::Sc>> {
        let chips = RiscvChipType::<Kb>::all_chips();
        records
            .iter()
            .enumerate()
            .map(|(i, record)| {
                let mut ctx = build_ctx(&chips, record, false);
                if i >= from {
                    for (air, air_ctx) in ctx.per_trace.iter_mut() {
                        let base = match *air {
                            air_id::CPU | air_id::ECALL | air_id::MEM_INIT | air_id::MEM_FINAL => 0,
                            air_id::GLOBAL => GCS_DIGEST_LEN,
                            _ => continue,
                        };
                        let at = base + DEFERRED_OFFSET;
                        air_ctx.public_values[at..at + DIGEST_SIZE].copy_from_slice(&forged);
                    }
                }
                self.engine.prove(&self.d_pk, ctx).expect("riscv prove")
            })
            .collect()
    }
}

impl Riscv {
    /// Whether the riscv layer accepts the chunk proofs: a doctored copy has to get past it for
    /// the recursion's rejection to mean anything.
    fn verifies(
        &self,
        program: &Arc<Program>,
        proofs: &[pico_mle_core::protocol::proof::Proof<riscv::Sc>],
    ) -> bool {
        let bundle = riscv::RiscvProof {
            vk: Arc::clone(&self.vk),
            chunk_proofs: proofs.to_vec(),
        };
        riscv::verify_riscv(
            &bundle,
            bundle.vk.pre_hash,
            &[(air_id::PROGRAM, riscv::riscv_program_commit(&bundle.vk))],
            program.initial_global_cumulative_sum(),
        )
        .is_ok()
    }
}

/// Build the tree, catching a panic as a failure; `Ok` carries the root's deferred digest.
fn tree(
    riscv: &Riscv,
    proofs: &[pico_mle_core::protocol::proof::Proof<riscv::Sc>],
    chain: [Kb; DIGEST_SIZE],
    prefix: &[pico_vm::mle::machine::convert::ProofWithVk],
) -> Result<[Kb; DIGEST_SIZE], String> {
    let root = panic::catch_unwind(panic::AssertUnwindSafe(|| {
        build_tree(&riscv.vk, &riscv.vm_vk, proofs, chain, prefix).map_err(|e| format!("{e}"))
    }))
    .unwrap_or_else(|p| {
        Err(p
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| p.downcast_ref::<&str>().map(|s| (*s).to_string()))
            .unwrap_or_else(|| "panic with no message".into()))
    })?;
    let pvs = recursion_public_values(&root.0.public_values).expect("root public values");
    Ok(std::array::from_fn(|j| {
        pvs[RECURSION_PUBLIC_VALUES_COL_MAP.deferred_proofs_digest[j]]
    }))
}

fn report(name: &str, ok: bool, detail: &str) -> bool {
    if ok {
        info!("case {name}: as expected — {detail}");
    } else {
        error!("case {name}: WRONG — {detail}");
    }
    ok
}

fn main() {
    setup_logger();
    let patched = match env::var("SPLIT_EXPECT")
        .unwrap_or_else(|_| "patched".into())
        .as_str()
    {
        "patched" => true,
        "unpatched" => false,
        other => panic!("SPLIT_EXPECT must be `patched` or `unpatched`, got `{other}`"),
    };
    let elf = std::fs::read(FIB_ELF).expect("fib elf");
    let program = Compiler::new(SourceType::RISCV, &elf)
        .expect("parse elf")
        .compile();
    let riscv = Riscv::new(&program);
    let n = 10;
    let mut failures = 0;

    // A real deferred chain to forge with: one node over fib's own honest root.
    let honest = emulate(&program, n, 1 << 22);
    let sub_root = build_tree(
        &riscv.vk,
        &riscv.vm_vk,
        &riscv.prove(&honest, usize::MAX, [Kb::ZERO; DIGEST_SIZE]),
        [Kb::ZERO; DIGEST_SIZE],
        &[],
    )
    .expect("honest tree");
    let mut deferred = DeferredMachine::new(
        recursion_params_with_100_bits_security(),
        riscv.vm_vk.clone(),
        false,
    );
    let (nodes, chain_end) = deferred
        .prove_chain(std::slice::from_ref(&sub_root))
        .expect("deferred chain");

    // ── halt-only ────────────────────────────────────────────────────────────────────────────
    let halt_only = |rs: &[EmulationRecord]| {
        rs.iter()
            .any(|r| halts(r) && deferred_commits(r) == 0 && !r.cpu_events.is_empty())
    };
    let cs = search(&program, n, (256..GUARDED_CHUNK_SIZE).rev(), halt_only)
        .expect("no chunk size puts HALT in a chunk of its own");
    let records = emulate(&program, n, cs);
    info!("halt-only: chunk size {cs}, {} records", records.len());
    let halt_chunk = records
        .iter()
        .position(|r| halts(r) && deferred_commits(r) == 0)
        .expect("the halt-only chunk");
    let proofs = riscv.prove(&records, halt_chunk, chain_end);
    let riscv_ok = riscv.verifies(&program, &proofs);
    let outcome = tree(&riscv, &proofs, chain_end, &nodes);
    let ok = riscv_ok
        && match (&outcome, patched) {
            (Err(e), true) => e.contains("root combine proof failed STARK verify"),
            (Ok(d), false) => *d == chain_end,
            _ => false,
        };
    let detail = match &outcome {
        Ok(d) => format!("root proved, deferred digest forged = {}", *d == chain_end),
        Err(e) => e.chars().take(120).collect(),
    };
    if !report(
        "halt-only",
        ok,
        &format!("riscv verifies: {riscv_ok}; {detail}"),
    ) {
        failures += 1;
    }
    let honest_cut = tree(
        &riscv,
        &riscv.prove(&records, usize::MAX, [Kb::ZERO; DIGEST_SIZE]),
        [Kb::ZERO; DIGEST_SIZE],
        &[],
    );
    if !report(
        "halt-only-unforged",
        matches!(honest_cut, Ok(d) if d == [Kb::ZERO; DIGEST_SIZE]),
        "the same cut, honest",
    ) {
        failures += 1;
    }

    // ── partial-run ──────────────────────────────────────────────────────────────────────────
    let partial = |rs: &[EmulationRecord]| {
        rs.iter().any(|r| {
            let c = deferred_commits(r);
            c > 0 && c < DIGEST_SIZE
        })
    };
    let (cs, records) = with_hold_off(|| {
        let cs = search(&program, n, (256..GUARDED_CHUNK_SIZE).rev(), partial)
            .expect("no chunk size cuts the deferred commit run");
        (cs, emulate(&program, n, cs))
    });
    info!("partial-run: chunk size {cs}, {} records", records.len());
    let proofs = riscv.prove(&records, usize::MAX, [Kb::ZERO; DIGEST_SIZE]);
    let riscv_ok = riscv.verifies(&program, &proofs);
    let outcome = tree(&riscv, &proofs, [Kb::ZERO; DIGEST_SIZE], &[]);
    let ok = riscv_ok
        && match (&outcome, patched) {
            (Err(e), true) => e.contains("root combine proof failed STARK verify"),
            // Without the all-or-nothing rule an honest zero digest split across chunks closes.
            (Ok(_), false) => true,
            _ => false,
        };
    let detail = match &outcome {
        Ok(_) => "root proved".to_string(),
        Err(e) => e.chars().take(120).collect(),
    };
    if !report(
        "partial-run",
        ok,
        &format!("riscv verifies: {riscv_ok}; {detail}"),
    ) {
        failures += 1;
    }

    // ── guarded ──────────────────────────────────────────────────────────────────────────────
    if patched {
        // Below 2^15 the hold spends clk past the ceiling; above, a reserve below it. A chunk holds
        // a little under `chunk_size` instructions, so a size that ends the k-th chunk near the
        // halt sits just above `instructions / k`; each band is searched there for sizes that cut
        // the run with the hold off — the ones the hold has to save — and those must keep it
        // whole with the hold on, and prove.
        for (label, n, band) in [
            ("short chunks", 10u32, 4_096u32..GUARDED_CHUNK_SIZE),
            ("long chunks", 20_000, GUARDED_CHUNK_SIZE..(1 << 18)),
        ] {
            let total = emulate_cycles(&program, n);
            let targets: Vec<u32> = (1..=64u64)
                .map(|k| (total / k) as u32)
                .filter(|cs| band.contains(cs))
                .collect();
            let cut: Vec<u32> = with_hold_off(|| {
                targets
                    .iter()
                    .flat_map(|&t| t.saturating_sub(64)..t + 2_048)
                    .filter(|cs| band.contains(cs))
                    .filter(|&cs| !run_is_whole(&emulate(&program, n, cs)))
                    .take(8)
                    .collect()
            });
            let broken: Vec<u32> = cut
                .iter()
                .copied()
                .filter(|&cs| !run_is_whole(&emulate(&program, n, cs)))
                .collect();
            let ok = !cut.is_empty() && broken.is_empty();
            let detail = format!(
                "{label}: without the hold the run is cut at {cut:?}; with it, at {broken:?}"
            );
            if !report("guarded", ok, &detail) {
                failures += 1;
            }
            let Some(&cs) = cut.first() else { continue };
            let records = emulate(&program, n, cs);
            let proofs = riscv.prove(&records, usize::MAX, [Kb::ZERO; DIGEST_SIZE]);
            let outcome = tree(&riscv, &proofs, [Kb::ZERO; DIGEST_SIZE], &[]);
            let ok = matches!(outcome, Ok(d) if d == [Kb::ZERO; DIGEST_SIZE]);
            let detail = format!("{label}: {} records at chunk size {cs}", records.len());
            if !report("guarded-proof", ok, &detail) {
                failures += 1;
            }
        }
    }

    assert_eq!(failures, 0, "{failures} case(s) did not match expectation");
    info!("deferred split: every case matched ✓");
}
