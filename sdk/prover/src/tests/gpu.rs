//! The `cuda` build's `Phase::Combine` through the GPU pipeline.
//!
//! Run on a GPU host with `cargo test --release -p pico-prover --features cuda -- --ignored
//! --test-threads=1 --nocapture tests::gpu`.

use super::fixture::{
    assert_is_fib_output, run_child, shipped_whitelist, FIB_ELF, N, OTHER_ELF, POSEIDON2_ELF,
};
use crate::{prover::WHITELIST_LOG_STACKED_HEIGHT, Phase, ProveError, Prover, Stdin};

const CHILD_VAR: &str = "PICO_PROVER_GPU_POISON_CHILD";
const POISON_MARKER: &str = "[gpu] the prove after a failed one was refused as poisoned";

/// The poseidon2 guest reads its round count.
const POSEIDON2_ROUNDS: u32 = 1;

fn whitelist_prover(elf: &[u8]) -> Prover {
    let (map, root) = shipped_whitelist();
    Prover::builder(elf)
        .log_stacked_height(WHITELIST_LOG_STACKED_HEIGHT)
        .verify_keys(true)
        .vk_map(map)
        .trusted_vk_root(root)
        .build()
        .expect("whitelist prover")
}

/// Bytes in use on card 0, pool reservations included.
fn card0_used() -> usize {
    use pico_vm::mle::cuda_mle::runtime::{context::set_device, memory_manager::device_mem_info};
    set_device(0).expect("bind card 0");
    let (free, total) = device_mem_info();
    total - free
}

#[test]
#[ignore = "needs a GPU"]
fn the_gpu_root_verifies_and_binds_the_output() {
    let mut prover = whitelist_prover(FIB_ELF);
    let proof = prover.prove(Stdin::from(&N)).expect("GPU combine");
    assert!(matches!(proof.phase(), Phase::Combine));
    assert!(proof.binds_complete_execution());
    assert_eq!(proof.program_id(), prover.program_id());
    assert_is_fib_output(proof.committed().as_bytes(), N);
}

/// Full `2^23`-instruction chunks, the size a history slot is laid out for, prove with `CHUNK_SIZE`
/// unset, as a library caller has it. A reth block, because fib's chunks outgrow the whitelist's
/// `Add` shapes long before that.
#[test]
#[ignore = "needs a GPU"]
fn full_chunks_prove_with_chunk_size_unset() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../perf/bench_data/rv64");
    let elf = std::fs::read(format!("{dir}/reth-elf")).expect("reth ELF");
    let input = std::fs::read(format!("{dir}/reth-18884864.bin")).expect("reth block");
    let mut stdin = Stdin::new();
    stdin.write_bytes(&input);
    assert!(
        std::env::var_os("CHUNK_SIZE").is_none(),
        "CHUNK_SIZE would set the chunk size"
    );
    let mut prover = whitelist_prover(&elf);
    assert!(prover.chunk_size() > 1 << 22);
    let executed = prover.execute_chunked(stdin.clone()).expect("execute");
    assert!(executed.chunks > 1, "{} chunk(s)", executed.chunks);
    let proof = prover.prove(stdin).expect("GPU combine");
    assert!(proof.binds_complete_execution());
    assert_eq!(proof.committed().as_bytes(), executed.committed_bytes);
}

/// The interpreted AOT runtime, which a `cuda` build emulates with by default, runs the run the
/// VM's interpreter runs. On guests covering the runtime's precompile backends (BN254 and
/// BLS12-381 field and curve ops, secp256k1, keccak, SHA-256, poseidon2): the same execution
/// (bytes, cycles, chunks, precompile calls) and cost estimate. On three of them, both GPU roots
/// verify and bind the same bytes.
#[test]
#[ignore = "needs a GPU"]
fn the_interpreted_aot_runtime_matches_the_interpreter() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../perf/bench_data/rv64");
    let hello = || Stdin::from(&"hello world".to_string());
    let guests: [(&str, fn() -> Stdin, bool); 8] = [
        ("bn254-fp-elf", Stdin::new, true),
        ("bls12381-fp-elf", Stdin::new, true),
        ("k256-elf", Stdin::new, true),
        ("bn254-elf-ws-add-double", Stdin::new, false),
        ("bls12381-elf-ws-add-double-decompress", Stdin::new, false),
        ("tiny-keccak-elf", hello, false),
        ("sha2-elf", hello, false),
        ("coprocessor-elf", Stdin::new, false),
    ];
    for (guest, stdin, prove) in guests {
        let elf = std::fs::read(format!("{dir}/{guest}")).expect("guest ELF");
        let builder = |aot_runtime: bool| {
            let (map, root) = shipped_whitelist();
            Prover::builder(&elf)
                .log_stacked_height(WHITELIST_LOG_STACKED_HEIGHT)
                .verify_keys(true)
                .vk_map(map)
                .trusted_vk_root(root)
                .interpreted_aot_runtime(aot_runtime)
        };
        let (aot, plain) = (builder(true), builder(false));

        let executed = aot.execute_chunked(stdin()).expect("execute");
        let expected = plain.execute_chunked(stdin()).expect("execute");
        assert!(
            !executed.precompile_calls.is_empty(),
            "{guest}: no precompile"
        );
        assert_eq!(
            executed.committed_bytes, expected.committed_bytes,
            "{guest}"
        );
        assert_eq!(executed.cycles, expected.cycles, "{guest}");
        assert_eq!(executed.chunks, expected.chunks, "{guest}");
        assert_eq!(
            executed.precompile_calls, expected.precompile_calls,
            "{guest}"
        );
        assert_eq!(
            aot.estimate_cost(stdin()).expect("cost"),
            plain.estimate_cost(stdin()).expect("cost"),
            "{guest}"
        );
        println!("[gpu] {guest}: {:?}", executed.precompile_calls);
        if !prove {
            continue;
        }

        let proved = aot
            .build()
            .expect("whitelist prover")
            .prove(stdin())
            .expect("GPU combine, AOT runtime");
        let reference = plain
            .build()
            .expect("whitelist prover")
            .prove(stdin())
            .expect("GPU combine, interpreter");
        assert!(proved.binds_complete_execution());
        assert_eq!(
            proved.committed().as_bytes(),
            reference.committed().as_bytes()
        );
        assert_eq!(proved.committed().as_bytes(), executed.committed_bytes);
    }
}

/// History slots that would pin more than half the host, or a count other than the one this
/// process pinned, are refused before anything runs, so the process can still prove. Named to sort after the
/// child-process tests: its prover keeps card memory in this process.
#[test]
#[ignore = "needs a GPU"]
fn pinning_past_half_the_host_is_refused_up_front() {
    use std::num::NonZeroUsize;

    let (map, root) = shipped_whitelist();
    let mut prover = Prover::builder(FIB_ELF)
        .log_stacked_height(WHITELIST_LOG_STACKED_HEIGHT)
        .verify_keys(true)
        .vk_map(map)
        .trusted_vk_root(root)
        .gpu_event_pool_size(NonZeroUsize::new(1 << 20).unwrap())
        .build()
        .expect("whitelist prover");
    for _ in 0..2 {
        let err = prover
            .prove(Stdin::from(&N))
            .expect_err("a pool past half the host");
        assert!(
            matches!(&err, ProveError::Gpu(m) if m.contains("would pin")),
            "got {err}"
        );
    }

    // Once a prove has pinned the slots, a prover asking for another count is refused the same
    // way, and the process can still prove at the pinned count.
    let build = |slots: Option<NonZeroUsize>| {
        let (map, root) = shipped_whitelist();
        let builder = Prover::builder(FIB_ELF)
            .log_stacked_height(WHITELIST_LOG_STACKED_HEIGHT)
            .verify_keys(true)
            .vk_map(map)
            .trusted_vk_root(root);
        match slots {
            Some(n) => builder.gpu_event_pool_size(n),
            None => builder,
        }
        .build()
        .expect("whitelist prover")
    };
    let pinned = match pico_vm::emulator::riscv::record_slots::bound_in_force() {
        Ok(Some(pinned)) => pinned,
        _ => {
            let n = distributed_vm::mle::embed::default_event_pool_size();
            build(Some(n))
                .prove(Stdin::from(&N))
                .expect("a prove at the default count");
            n
        }
    };
    let other = pinned.checked_add(1).unwrap();
    for _ in 0..2 {
        let err = build(Some(other))
            .prove(Stdin::from(&N))
            .expect_err("another count than the pinned one");
        assert!(
            matches!(&err, ProveError::Gpu(m) if m.contains("already pinned")),
            "got {err}"
        );
    }
    build(Some(pinned))
        .prove(Stdin::from(&N))
        .expect("a prove at the pinned count");
}

/// A whitelist prover latches its cards' memory tier at build, so an execute before its first
/// prove splits records for that tier rather than locking in the default.
#[test]
#[ignore = "needs a GPU"]
fn build_latches_the_cards_memory_tier_before_any_execute() {
    use pico_vm::emulator::riscv::record::{get_prover_hardware_config, gpu_memory_tier_from_env};

    let prover = whitelist_prover(FIB_ELF);
    prover.execute_chunked(Stdin::from(&N)).expect("execute");
    let cards = distributed_vm::mle::embed::gpu_resources().expect("cards");
    let expected = gpu_memory_tier_from_env().unwrap_or(cards.memory_tier());
    println!("[gpu] {cards:?}: tier {expected:?}");
    assert_eq!(get_prover_hardware_config().tier(), expected);
}

const ESTIMATE_FIRST_VAR: &str = "PICO_PROVER_GPU_ESTIMATE_FIRST_CHILD";
const ESTIMATE_FIRST_MARKER: &str = "[gpu] estimate before build latched the cards' tier";

/// A builder's `estimate_cost` before `build` latches the cards' tier, not the default, and the
/// prover built after it proves. In a child process, so nothing earlier has latched a tier.
///
/// Named to sort before every in-process GPU test: a parent that has built a prover keeps its card
/// memory pool, and the child would run out of memory.
#[test]
#[ignore = "needs a GPU"]
fn an_estimate_before_build_latches_the_cards_tier() {
    use pico_vm::emulator::riscv::record::{get_prover_hardware_config, gpu_memory_tier_from_env};

    if std::env::var(ESTIMATE_FIRST_VAR).is_err() {
        run_child(
            "tests::gpu::an_estimate_before_build_latches_the_cards_tier",
            ESTIMATE_FIRST_MARKER,
            &[(ESTIMATE_FIRST_VAR, "1".to_string())],
        );
        return;
    }

    let (map, root) = shipped_whitelist();
    let builder = Prover::builder(FIB_ELF)
        .log_stacked_height(WHITELIST_LOG_STACKED_HEIGHT)
        .verify_keys(true)
        .vk_map(map)
        .trusted_vk_root(root);
    builder.estimate_cost(Stdin::from(&N)).expect("estimate");

    let cards = distributed_vm::mle::embed::gpu_resources().expect("cards");
    let expected = gpu_memory_tier_from_env().unwrap_or(cards.memory_tier());
    println!("[gpu] {cards:?}: tier {expected:?}");
    assert_eq!(get_prover_hardware_config().tier(), expected);

    let mut prover = builder.build().expect("whitelist prover");
    let proof = prover.prove(Stdin::from(&N)).expect("GPU combine");
    assert!(proof.binds_complete_execution());
    assert_is_fib_output(proof.committed().as_bytes(), N);
    println!("{ESTIMATE_FIRST_MARKER}");
}

const EXECUTE_FIRST_VAR: &str = "PICO_PROVER_GPU_EXECUTE_FIRST_CHILD";
const EXECUTE_FIRST_MARKER: &str = "[gpu] an execute before a GPU prove left its slots bounded";

/// Peak resident memory of this process, from `/proc/self/status`.
fn peak_rss_gib() -> f64 {
    let status = std::fs::read_to_string("/proc/self/status").expect("read /proc/self/status");
    let kib: f64 = status
        .lines()
        .find_map(|l| l.strip_prefix("VmHWM:"))
        .and_then(|v| v.trim().trim_end_matches("kB").trim().parse().ok())
        .expect("VmHWM");
    kib / (1u64 << 20) as f64
}

/// An `execute`, whose emulation lifts the bound on records held only while it runs, does not
/// leave a later GPU prove in the same process unbounded: the prove pins its option's history
/// slots, and an execute after it leaves them bounding the next prove. In a child process, so no
/// earlier prove has pinned the slots.
#[test]
#[ignore = "needs a GPU"]
fn an_execute_before_a_gpu_prove_leaves_its_slots_bounded() {
    use std::num::NonZeroUsize;

    use pico_vm::emulator::riscv::record_slots::{bound_in_force, slots_outstanding};

    if std::env::var(EXECUTE_FIRST_VAR).is_err() {
        run_child(
            "tests::gpu::an_execute_before_a_gpu_prove_leaves_its_slots_bounded",
            EXECUTE_FIRST_MARKER,
            &[(EXECUTE_FIRST_VAR, "1".to_string())],
        );
        return;
    }

    const POOL: usize = 8;
    let (map, root) = shipped_whitelist();
    let builder = Prover::builder(FIB_ELF)
        .log_stacked_height(WHITELIST_LOG_STACKED_HEIGHT)
        .verify_keys(true)
        .vk_map(map)
        .trusted_vk_root(root)
        .gpu_event_pool_size(NonZeroUsize::new(POOL).unwrap());
    builder.execute_chunked(Stdin::from(&N)).expect("execute");
    // The emulation pinned nothing.
    assert_eq!(slots_outstanding(), None);

    let mut prover = builder.build().expect("whitelist prover");
    let proof = prover.prove(Stdin::from(&N)).expect("GPU combine");
    assert_is_fib_output(proof.committed().as_bytes(), N);
    assert_eq!(bound_in_force(), Ok(NonZeroUsize::new(POOL)));

    // The execute after the prove lifts the bound only while it runs.
    prover
        .execute_chunked(Stdin::from(&N))
        .expect("execute after the prove");
    assert_eq!(bound_in_force(), Ok(NonZeroUsize::new(POOL)));
    let again = prover.prove(Stdin::from(&N)).expect("second GPU combine");
    assert_is_fib_output(again.committed().as_bytes(), N);
    assert_eq!(slots_outstanding(), Some(0));

    let rss = peak_rss_gib();
    println!("[gpu] peak RSS {rss:.1} GiB with {POOL} history slots");
    assert!(rss < 64.0, "peak RSS {rss:.1} GiB");
    println!("{EXECUTE_FIRST_MARKER}");
}

/// One process proves A, then B, then A again: each root is for its own program, and the third
/// run does not hold more device memory than the first.
#[test]
#[ignore = "needs a GPU"]
fn switching_programs_rebuilds_the_machines_without_growing() {
    let mut a = whitelist_prover(FIB_ELF);
    let mut b = whitelist_prover(POSEIDON2_ELF);
    assert_ne!(a.program_id(), b.program_id());

    let first = a.prove(Stdin::from(&N)).expect("A");
    assert_eq!(first.program_id(), a.program_id());
    let after_first = card0_used();

    let second = b.prove(Stdin::from(&POSEIDON2_ROUNDS)).expect("B");
    assert_eq!(second.program_id(), b.program_id());
    let after_second = card0_used();

    let third = a.prove(Stdin::from(&N)).expect("A again");
    assert_eq!(third.program_id(), a.program_id());
    let after_third = card0_used();

    let mib = |b: usize| b >> 20;
    println!(
        "[gpu] card 0 used after A {} MiB, B {} MiB, A {} MiB",
        mib(after_first),
        mib(after_second),
        mib(after_third)
    );
    assert!(
        after_third <= after_first + (1 << 30),
        "card 0 grew by {} MiB over one switch and back",
        mib(after_third.saturating_sub(after_first))
    );
}

/// A pipeline failure that is not the guest's poisons the process: the next prove is refused with
/// a clear error rather than hanging or panicking on the leftover pipeline state. The failure is
/// `CORRUPT_MEMORY`'s tampered record, which no proof can close. Runs in a child process, since the
/// poisoning outlives the test.
#[test]
#[ignore = "needs a GPU"]
fn a_failed_gpu_prove_poisons_later_proves() {
    if std::env::var(CHILD_VAR).is_err() {
        run_child(
            "tests::gpu::a_failed_gpu_prove_poisons_later_proves",
            POISON_MARKER,
            &[
                (CHILD_VAR, "1".to_string()),
                ("CORRUPT_MEMORY", "1".to_string()),
            ],
        );
        return;
    }

    let mut fib = whitelist_prover(FIB_ELF);
    let first = fib.prove(Stdin::from(&N)).expect_err("a tampered run");
    assert!(matches!(first, ProveError::Gpu(_)), "got {first}");

    let second = fib.prove(Stdin::from(&N)).expect_err("a poisoned process");
    assert!(matches!(second, ProveError::GpuPoisoned), "got {second}");
    println!("{POISON_MARKER}");
}

const GUEST_CHILD_VAR: &str = "PICO_PROVER_GPU_GUEST_FAILURE_CHILD";
const GUEST_MARKER: &str = "[gpu] a failing guest left the process able to prove";

/// A guest whose emulation fails is an ordinary error on the GPU path too: the run drains, every
/// history slot and pooled emulator memory comes back, and the next prove in the process works.
/// The same program on bad input, as a caller retrying with fixed input would see it, so the
/// resident machines and their per-run state carry over; then another program's failure. In a
/// child process, so no earlier test's slots or poisoning are in the way.
#[test]
#[ignore = "needs a GPU"]
fn a_failing_guest_leaves_the_process_able_to_prove() {
    use pico_vm::{
        emulator::riscv::{
            emulator::EmulationError, memory::memory_pool_free, record_slots::slots_outstanding,
        },
        mle::machine::riscv::EmulateError,
    };

    if std::env::var(GUEST_CHILD_VAR).is_err() {
        run_child(
            "tests::gpu::a_failing_guest_leaves_the_process_able_to_prove",
            GUEST_MARKER,
            &[(GUEST_CHILD_VAR, "1".to_string())],
        );
        return;
    }

    // Free emulator memories once the recyclers have put back what a run used: unchanged for a
    // second, and at least `at_least`.
    let settled_memory_pool = |at_least: usize| {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
        let mut last = memory_pool_free();
        loop {
            std::thread::sleep(std::time::Duration::from_secs(1));
            let now = memory_pool_free();
            if (now == last && now >= at_least) || std::time::Instant::now() > deadline {
                return now;
            }
            last = now;
        }
    };
    let assert_drained = |baseline: usize| {
        assert!(
            matches!(slots_outstanding(), None | Some(0)),
            "{:?} history slots still held",
            slots_outstanding()
        );
        let free = settled_memory_pool(baseline);
        assert!(free >= baseline, "{free} memories free, {baseline} before");
    };
    let mut fib = whitelist_prover(FIB_ELF);
    let proof = fib.prove(Stdin::from(&N)).expect("fib");
    assert_is_fib_output(proof.committed().as_bytes(), N);
    let baseline = settled_memory_pool(0);

    for _ in 0..2 {
        // Fib reads its input, and there is none.
        let err = fib.prove(Stdin::new()).expect_err("fib without its input");
        assert!(
            matches!(err, ProveError::Emulate(EmulateError::Emulation(_))),
            "got {err}"
        );
        assert_drained(baseline);
        let proof = fib.prove(Stdin::from(&N)).expect("fib after a failing run");
        assert_is_fib_output(proof.committed().as_bytes(), N);
    }

    // Another program, which halts with exit code 1 on fib's input.
    let mut failing = whitelist_prover(OTHER_ELF);
    let err = failing.prove(Stdin::from(&N)).expect_err("a failing guest");
    assert!(
        matches!(
            err,
            ProveError::Emulate(EmulateError::Emulation(
                EmulationError::AbnormalTermination(_)
            ))
        ),
        "got {err}"
    );
    assert_drained(baseline);
    let proof = fib
        .prove(Stdin::from(&N))
        .expect("fib after another guest failed");
    assert_is_fib_output(proof.committed().as_bytes(), N);
    println!("{GUEST_MARKER}");
}
