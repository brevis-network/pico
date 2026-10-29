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

/// Full `2^23`-instruction chunks, twice the pinned event buffers' environment default, prove: the
/// GPU prove sizes its buffers from the chunks it cuts. `CHUNK_SIZE` is unset, as a library caller
/// has it. A reth block, because fib's chunks outgrow the whitelist's `Add` shapes long before that.
#[test]
#[ignore = "needs a GPU"]
fn chunks_past_the_default_event_buffers_prove() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../perf/bench_data/rv64");
    let elf = std::fs::read(format!("{dir}/reth-elf")).expect("reth ELF");
    let input = std::fs::read(format!("{dir}/reth-18884864.bin")).expect("reth block");
    let mut stdin = Stdin::new();
    stdin.write_bytes(&input);
    assert!(
        std::env::var_os("CHUNK_SIZE").is_none(),
        "CHUNK_SIZE would size the buffers"
    );
    let mut prover = whitelist_prover(&elf);
    assert!(prover.chunk_size() > 1 << 22);
    let executed = prover.execute(stdin.clone()).expect("execute");
    assert!(executed.chunks > 1, "{} chunk(s)", executed.chunks);
    let proof = prover.prove(stdin).expect("GPU combine");
    assert!(proof.binds_complete_execution());
    assert_eq!(proof.committed().as_bytes(), executed.committed_bytes);
}

/// An event pool that would pin more than half the host, or that cannot hold one record, is
/// refused before anything runs, so it leaves the process able to prove. Named to sort after the
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

    // A pool that cannot hold one record is refused the same way.
    let (map, root) = shipped_whitelist();
    let mut prover = Prover::builder(FIB_ELF)
        .log_stacked_height(WHITELIST_LOG_STACKED_HEIGHT)
        .verify_keys(true)
        .vk_map(map)
        .trusted_vk_root(root)
        .gpu_event_pool_size(NonZeroUsize::MIN)
        .build()
        .expect("whitelist prover");
    for _ in 0..2 {
        let err = prover
            .prove(Stdin::from(&N))
            .expect_err("a pool of one");
        assert!(
            matches!(&err, ProveError::Gpu(m) if m.contains("event buffers")),
            "got {err}"
        );
    }
}

/// A whitelist prover latches its cards' memory tier at build, so an execute before its first
/// prove splits records for that tier rather than locking in the default.
#[test]
#[ignore = "needs a GPU"]
fn build_latches_the_cards_memory_tier_before_any_execute() {
    use pico_vm::emulator::riscv::record::{get_prover_hardware_config, gpu_memory_tier_from_env};

    let prover = whitelist_prover(FIB_ELF);
    prover.execute(Stdin::from(&N)).expect("execute");
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
const EXECUTE_FIRST_MARKER: &str = "[gpu] an execute before a GPU prove left its pools bounded";

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

/// An `execute`, whose emulation holds its records in growable buffers, does not leave a later GPU
/// prove in the same process unbounded: the prove sizes the event pools to its option, and an
/// execute after it still runs. In a child process, so no earlier prove has sized the pools.
#[test]
#[ignore = "needs a GPU"]
fn an_execute_before_a_gpu_prove_leaves_its_pools_bounded() {
    use std::num::NonZeroUsize;

    use pico_vm::emulator::riscv::{
        alu_event_pool::alu_event_buffer_pool_size, cpu_event_pool::cpu_event_buffer_pool_size,
    };

    if std::env::var(EXECUTE_FIRST_VAR).is_err() {
        run_child(
            "tests::gpu::an_execute_before_a_gpu_prove_leaves_its_pools_bounded",
            EXECUTE_FIRST_MARKER,
            &[(EXECUTE_FIRST_VAR, "1".to_string())],
        );
        return;
    }

    const POOL: usize = 40;
    let (map, root) = shipped_whitelist();
    let builder = Prover::builder(FIB_ELF)
        .log_stacked_height(WHITELIST_LOG_STACKED_HEIGHT)
        .verify_keys(true)
        .vk_map(map)
        .trusted_vk_root(root)
        .gpu_event_pool_size(NonZeroUsize::new(POOL).unwrap());
    builder.execute(Stdin::from(&N)).expect("execute");
    // The emulation claimed the pools empty rather than pinning full-size buffers.
    assert_eq!(cpu_event_buffer_pool_size(), Some(0));
    assert_eq!(alu_event_buffer_pool_size(), Some(0));

    let mut prover = builder.build().expect("whitelist prover");
    let proof = prover.prove(Stdin::from(&N)).expect("GPU combine");
    assert_is_fib_output(proof.committed().as_bytes(), N);
    assert_eq!(cpu_event_buffer_pool_size(), Some(POOL));
    assert_eq!(alu_event_buffer_pool_size(), Some(POOL));

    // Growable again for an emulation after the prove, and bounded again for the next prove.
    prover
        .execute(Stdin::from(&N))
        .expect("execute after the prove");
    let again = prover.prove(Stdin::from(&N)).expect("second GPU combine");
    assert_is_fib_output(again.committed().as_bytes(), N);
    assert_eq!(cpu_event_buffer_pool_size(), Some(POOL));

    let rss = peak_rss_gib();
    println!("[gpu] peak RSS {rss:.1} GiB with {POOL} event buffers per pool");
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

/// A failed GPU prove poisons the process: the next prove is refused with a clear error rather
/// than hanging or panicking on the leftover pipeline state. Runs in a child process, since the
/// poisoning outlives the test.
#[test]
#[ignore = "needs a GPU"]
fn a_failed_gpu_prove_poisons_later_proves() {
    if std::env::var(CHILD_VAR).is_err() {
        run_child(
            "tests::gpu::a_failed_gpu_prove_poisons_later_proves",
            POISON_MARKER,
            &[(CHILD_VAR, "1".to_string())],
        );
        return;
    }

    // This guest halts with exit code 1 on fib's input.
    let mut failing = whitelist_prover(OTHER_ELF);
    let mut fib = whitelist_prover(FIB_ELF);
    let first = failing.prove(Stdin::from(&N)).expect_err("a failing guest");
    assert!(matches!(first, ProveError::Gpu(_)), "got {first}");

    let second = fib.prove(Stdin::from(&N)).expect_err("a poisoned process");
    assert!(matches!(second, ProveError::GpuPoisoned), "got {second}");
    println!("{POISON_MARKER}");
}
