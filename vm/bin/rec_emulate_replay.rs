//! Replay one dumped recursion emulation, off the box, as many times as asked.
//!
//! `MLE_REC_EMULATE_DUMP=<dir>` on a proving run writes the interpreter's entire input — the
//! program, the witness stream, and the child ranges the program does not serialize — for one
//! convert or combine node. This runs it through `Runtime::run()`, and through
//! `Runtime::run_split()` when the node has two children, reporting both.
//!
//! Why it exists: a combine node's emulation is the biggest single item on the combine tree's
//! serial carry chain (82 ms at the median in-prover — see `emulator/recursion/emulator/
//! profile.rs` for what that was measured on), and the whole tail is a few per cent of E2E. An
//! effect that size is invisible against E2E's ~9 % single-reading noise, so an interpreter
//! change cannot be judged by proving a block. Here the same
//! program runs on the same input with nothing else on the machine, at n=30, which resolves a few
//! per cent — and it needs no GPU, so it does not queue behind the card lock.
//!
//! ```text
//! cargo run --release --bin rec-emulate-replay -- <dump.bin> [iters]
//! ```
//!
//! Every replay's record is digested and all digests must agree, so on a combine dump this is
//! also the cheap gate for a change to how the program is interpreted. It is not the whole gate:
//! it says the two paths agree on this input, not that the proof is sound — that is a real
//! `MLE_VERIFY=1` run.

use std::{sync::Arc, time::Instant};

use p3_field::{Field, PackedValue, PrimeCharacteristicRing};
use p3_symmetric::Permutation;
use pico_mle_core::config::koala_bear_poseidon2::{default_koalabear_poseidon2_16, EF};
use pico_vm::{
    compiler::recursion::{ir::Block, program::RecursionProgram},
    emulator::recursion::emulator::Runtime,
    mle::machine::riscv::Kb,
    primitives::consts::KOALABEAR_S_BOX_DEGREE,
};

/// What one Poseidon2 permutation costs on this machine, with nothing else around it.
///
/// The permutation is over half of a combine emulation, so its floor decides whether that half
/// is worth attacking at all. Chained (each output feeds the next input) to keep the CPU from
/// overlapping iterations, which is also how the interpreter meets them.
fn bench_perm(n: usize) {
    let perm = default_koalabear_poseidon2_16();
    let mut state: [Kb; 16] = std::array::from_fn(|i| Kb::from_u32(i as u32 + 1));
    let t = Instant::now();
    for _ in 0..n {
        state = perm.permute(state);
    }
    let ns = t.elapsed().as_secs_f64() * 1e9 / n as f64;
    // Printed so the loop cannot be optimised away.
    println!(
        "perm: n = {n}, {ns:.1} ns/permutation, state[0] = {}",
        state[0]
    );
}

/// The same permutation over the machine's packed field: N independent instances at once.
///
/// It priced the batching idea — reuse the packed implementation on permutations the program
/// leaves independent — and that idea is closed: the program's mean batch width is 1.69 and does
/// not widen with the lookahead, because the work is a duplex sponge and a sponge is a chain.
/// Nothing reads this figure any more; it is kept as the measured ceiling that verdict rests on.
fn bench_perm_packed(n: usize) {
    type Packed = <Kb as Field>::Packing;
    let lanes = Packed::WIDTH;
    let perm = default_koalabear_poseidon2_16();
    let mut state: [Packed; 16] = std::array::from_fn(|i| Packed::from(Kb::from_u32(i as u32 + 1)));
    let batches = n / lanes;
    let t = Instant::now();
    for _ in 0..batches {
        state = perm.permute(state);
    }
    let ns = t.elapsed().as_secs_f64() * 1e9 / (batches * lanes) as f64;
    println!(
        "perm packed: lanes = {lanes}, batches = {batches}, {ns:.1} ns/permutation, state[0] = {:?}",
        state[0].as_slice()[0]
    );
}

/// What `MLE_REC_EMULATE_DUMP` writes: the interpreter's whole input, plus the child ranges that
/// `RecursionProgram` does not serialize.
type Dump = (
    RecursionProgram<Kb>,
    std::collections::VecDeque<Block<Kb>>,
    Vec<(usize, usize)>,
);

fn main() {
    // The profile knob reports through `tracing`, so a subscriber has to exist here or its line
    // is silently dropped. `RUST_LOG` defaults to the prover's own bench filter.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn,bench=info")),
        )
        .with_target(false)
        .init();

    let mut args = std::env::args().skip(1);
    let Some(path) = args.next() else {
        eprintln!(
            "usage: rec-emulate-replay <dump.bin> [iters]   |   rec-emulate-replay --perm [n]"
        );
        std::process::exit(2);
    };
    if path == "--perm" {
        let n = args.next().map_or(1_000_000, |v| v.parse().expect("n"));
        // The packed arm runs `n / lanes` batches, and a machine's lane count is not knowable
        // here; below it the batch count is zero and the per-permutation figure comes out NaN.
        if n < 64 {
            eprintln!("--perm n must be at least 64");
            std::process::exit(2);
        }
        bench_perm(n);
        bench_perm_packed(n);
        return;
    }
    let iters: usize = args.next().map_or(10, |v| v.parse().expect("iters"));
    if iters == 0 {
        eprintln!("iters must be at least 1");
        std::process::exit(2);
    }

    let t_load = Instant::now();
    let file = std::io::BufReader::new(std::fs::File::open(&path).expect("open dump"));
    // `child_spans` is `#[serde(skip)]` on the program, so the dump carries it beside and it is
    // restored here — without it the emulator has no boundary to cut at and stays serial.
    let (mut program, witness_stream, child_spans): Dump =
        bincode::deserialize_from(file).expect("decode dump");
    program.child_spans = child_spans;
    let program = Arc::new(program);
    println!(
        "loaded {path} in {:?}: instructions = {}, total_memory = {}, witness_blocks = {}, \
         child_spans = {:?}",
        t_load.elapsed(),
        program.instructions.len(),
        program.total_memory,
        witness_stream.len(),
        program.child_spans,
    );

    // A fresh `Runtime` per iteration: `run()` drains the witness stream and fills the memory
    // table and the record, so a reused one would neither replay the same work nor even succeed.
    // Construction is charged separately for the same reason the prover's `emulate_ms` starts
    // after it — the allocation of a `total_memory`-sized table is not what is being optimised.
    // Both paths every iteration, and the order flipped on odd ones: the split is only worth
    // anything if it produces the same record, and the two timings are only comparable if they
    // see the same machine. Fixed order would hand whichever ran second a warm allocator and a
    // warm page cache — with the serial arm always first, that flattered the split.
    let mut serial_ms = Vec::with_capacity(iters);
    let mut split_ms = Vec::with_capacity(iters);
    let mut split_taken = false;
    let mut digests: Vec<u64> = Vec::with_capacity(iters * 2);
    for i in 0..iters {
        // One arm, timed. The digest is taken outside the timer: it serialises ~10 MB and is
        // not what is being measured. It is the gate for any change to *how* the program is
        // interpreted — the record is the only thing that leaves `run()`, so an unchanged digest
        // means an unchanged proof input.
        let arm = |split: bool| -> (f64, u64, bool, usize) {
            let perm = default_koalabear_poseidon2_16();
            let mut rt =
                Runtime::<Kb, EF, _, _, KOALABEAR_S_BOX_DEGREE>::new(Arc::clone(&program), perm);
            rt.witness_stream = witness_stream.clone();
            rt.dump_label = "replay";
            let t = Instant::now();
            let took = if split {
                rt.run_split().expect("split recursion runtime failed")
            } else {
                rt.run().expect("replayed recursion runtime failed");
                false
            };
            (
                t.elapsed().as_secs_f64() * 1e3,
                rt.record.digest(),
                took,
                rt.timestamp,
            )
        };

        let ((ms, digest, _, cycles), (sms, sdigest, took, scycles)) = if i % 2 == 0 {
            let a = arm(false);
            (a, arm(true))
        } else {
            let b = arm(true);
            (arm(false), b)
        };
        serial_ms.push(ms);
        split_ms.push(sms);
        split_taken = took;
        digests.push(digest);
        digests.push(sdigest);

        println!(
            "iter {i}: serial {ms:.2} ms / {} {sms:.2} ms ({:+.1}%), cycles {} vs {}, \
             record {digest:#018x} vs {sdigest:#018x}{}",
            // A convert node carries one child range and cannot split, so it runs serially in
            // both arms — worth saying, since the timings then measure nothing but the noise.
            if took { "split" } else { "serial again" },
            100.0 * (sms - ms) / ms,
            cycles,
            scycles,
            if digest == sdigest {
                ""
            } else {
                "   <-- MISMATCH"
            },
        );
    }

    // One input, one answer: every serial and every split record must agree, or the split is
    // producing a different proof and no timing it reports means anything.
    let distinct: std::collections::BTreeSet<u64> = digests.iter().copied().collect();
    assert_eq!(
        distinct.len(),
        1,
        "record digest differed across replays of one input: {distinct:#018x?}"
    );

    // Min and median, not the mean: the floor is the reading a quiet box converges to, and the
    // median survives one descheduled iteration. A mean over 30 does not.
    let stat = |v: &[f64]| {
        let mut s = v.to_vec();
        s.sort_by(f64::total_cmp);
        (s[0], s[s.len() / 2], s[s.len() - 1])
    };
    let (smin, smed, smax) = stat(&serial_ms);
    let (pmin, pmed, pmax) = stat(&split_ms);
    println!(
        "\nrecord identical across {} runs: {:#018x}{}",
        digests.len(),
        digests[0],
        if split_taken {
            ""
        } else {
            "   (one child range: both arms ran serially, so this agreement is trivial)"
        }
    );
    let arm = if split_taken { "split " } else { "serial2" };
    println!(
        "serial: n = {}, min {smin:.2}, median {smed:.2}, max {smax:.2} ms",
        serial_ms.len()
    );
    println!(
        "{arm}: n = {}, min {pmin:.2}, median {pmed:.2}, max {pmax:.2} ms",
        split_ms.len()
    );
    println!(
        "{arm} vs serial: median {:+.1}%, min {:+.1}%",
        100.0 * (pmed - smed) / smed,
        100.0 * (pmin - smin) / smin,
    );
}
