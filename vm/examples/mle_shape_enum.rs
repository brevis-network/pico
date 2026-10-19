//! The riscv-stage shape space, enumerated and counted.
//!
//! The shapes come from a generator, not a stored enumeration, so this walks the generator and
//! reports what it produces, family by family. The counts feed the Merkle depth.
//!
//! Usage:
//!   cargo run --release -p pico-vm --example mle_shape_enum
//!   cargo run --release -p pico-vm --example mle_shape_enum -- --verbose

use std::collections::BTreeMap;

use pico_vm::mle::machine::shape::{
    bucket_log_height, mle_precompile_shapes, mle_riscv_shapes, MLE_MIN_LOG_HEIGHT,
};

fn main() {
    let verbose = std::env::args().any(|a| a == "--verbose");

    let shapes = mle_precompile_shapes();
    let mut per_kind: BTreeMap<String, Vec<_>> = BTreeMap::new();
    for s in &shapes {
        per_kind.entry(s.kind.clone()).or_default().push(s.clone());
    }
    println!("== precompile family ==");
    println!(
        "{:<22} {:>4} {:>7} {:>7}  shapes per height",
        "kind", "cap", "heights", "shapes"
    );
    for (kind, group) in &per_kind {
        let mut per_height: BTreeMap<usize, usize> = BTreeMap::new();
        for s in group {
            *per_height.entry(s.kind_log_height).or_default() += 1;
        }
        let counts: Vec<String> = per_height.values().map(|v| v.to_string()).collect();
        println!(
            "{:<22} {:>4} {:>7} {:>7}  {}",
            kind,
            bucket_log_height(kind, false),
            per_height.len(),
            group.len(),
            counts.join(",")
        );
    }
    println!("\n{} kinds, {} shapes", per_kind.len(), shapes.len());

    if verbose {
        println!("\n-- every shape (kind:h control:h syscall memory_local global poseidon2) --");
        for s in &shapes {
            let ctl = s
                .control
                .as_ref()
                .map(|(n, h)| format!(" {n}:{h}"))
                .unwrap_or_default();
            println!(
                "[pshape] {}:{}{} SyscallPrecompile:{} MemoryLocal:{} Global:{} Poseidon2:{}",
                s.kind,
                s.kind_log_height,
                ctl,
                s.syscall_precompile,
                s.memory_local,
                s.global,
                s.poseidon2
            );
        }
    }

    // The whole whitelist, as the generator emits it, counted by family label.
    let all = mle_riscv_shapes();
    let count = |prefix: &str| all.iter().filter(|(l, _)| l.starts_with(prefix)).count();
    let (core, memory, precompile) = (count("core:"), count("memory:"), count("precompile:"));
    println!("\n== memory family ==");
    println!(
        "MemoryInitialize and MemoryFinalize each absent or {}..={}, Global {}..={}, less the \
         both-absent slice: {memory} shapes",
        MLE_MIN_LOG_HEIGHT,
        bucket_log_height("MemoryInitialize", false),
        MLE_MIN_LOG_HEIGHT,
        bucket_log_height("Global", false)
    );
    println!("\n== core family ==");
    println!("{} ladder entries + 1 catch-all = {core} shapes", core - 1);
    assert_eq!(
        precompile,
        shapes.len(),
        "the two precompile views disagree"
    );

    let total = all.len();
    let depth = total.next_power_of_two().ilog2() as usize;
    println!("\n== total ==");
    println!("core {core} + precompile {precompile} + memory {memory} = {total}");
    println!(
        "Merkle depth {depth} holds {} leaves, {:.0}% headroom over {total}",
        1usize << depth,
        100.0 * ((1usize << depth) as f64 / total as f64 - 1.0)
    );
    println!(
        "depth {} holds {}, {:.0}% headroom",
        depth + 1,
        1usize << (depth + 1),
        100.0 * ((1usize << (depth + 1)) as f64 / total as f64 - 1.0)
    );
}
