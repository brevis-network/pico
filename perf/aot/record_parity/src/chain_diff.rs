//! `EMITTING_DIFF_DUMP`: why the two arms' `cpu_local_memory_chain` rows differ on a record.
//!
//! The row digests each address's chain of local-memory windows, sorted by address, so a
//! difference in it names neither the address nor the cause. With the variable set,
//! `check_at_scale` keeps every CPU chunk's windows beside its digests and, for the first record
//! whose chain row differs, prints the addresses whose chains differ: each side's chain, and
//! whether a precompile touched the address in that chunk. It also says whether the two records'
//! windows are equal as multisets, which separates a difference in order from one in content.

use std::collections::{HashMap, HashSet};

use pico_vm::{
    chips::chips::{events::MemoryLocalEvent, riscv_memory::event::MemoryRecord},
    emulator::riscv::syscalls::precompiles::PrecompileLocalMemory,
    mle::machine::riscv::EmulationOutput,
};

/// Differing addresses printed in full.
const PRINTED: usize = 16;

pub fn enabled() -> bool {
    std::env::var_os("EMITTING_DIFF_DUMP").is_some()
}

/// One arm's local-memory windows, per CPU chunk record in order, with the chunk's number.
pub struct Windows {
    chunks: Vec<(u32, Vec<MemoryLocalEvent>)>,
    /// Per chunk, the addresses its precompiles touched: only the interpreter's records carry
    /// precompile events.
    precompile_addrs: HashMap<u32, HashSet<u64>>,
}

pub fn collect(output: &EmulationOutput) -> Windows {
    let chunks = output
        .records
        .iter()
        .filter(|record| record.is_cpu_chunk)
        .map(|record| {
            let steps = record.cpu_steps();
            let chunk = if steps.is_empty() {
                0
            } else {
                steps.get(0).chunk
            };
            (chunk, record.cpu_local_memory_access.clone())
        })
        .collect();
    let mut precompile_addrs: HashMap<u32, HashSet<u64>> = HashMap::new();
    for record in &output.records {
        for (_, events) in record.precompile_events.sorted_groups() {
            for (syscall, event) in events {
                let one = vec![(*syscall, event.clone())];
                let addrs = precompile_addrs.entry(syscall.chunk).or_default();
                addrs.extend(one.get_local_mem_events().into_iter().map(|e| e.addr));
            }
        }
    }
    Windows {
        chunks,
        precompile_addrs,
    }
}

type Chain = Vec<(MemoryRecord, MemoryRecord)>;

/// Per address, its windows in the order they close, adjacent ones that meet merged into one:
/// the reduction `record_digest::field_digests` digests.
fn chains(windows: &[MemoryLocalEvent]) -> HashMap<u64, Chain> {
    let mut by_addr: HashMap<u64, Vec<&MemoryLocalEvent>> = HashMap::new();
    for window in windows {
        by_addr.entry(window.addr).or_default().push(window);
    }
    by_addr
        .into_iter()
        .map(|(addr, mut windows)| {
            windows.sort_by_key(|w| {
                (
                    w.final_mem_access.timestamp,
                    w.initial_mem_access.chunk,
                    w.initial_mem_access.timestamp,
                )
            });
            let mut chain: Chain = Vec::new();
            for window in windows {
                match chain.last_mut() {
                    Some(last) if last.1 == window.initial_mem_access => {
                        last.1 = window.final_mem_access
                    }
                    _ => chain.push((window.initial_mem_access, window.final_mem_access)),
                }
            }
            (addr, chain)
        })
        .collect()
}

fn key(window: &MemoryLocalEvent) -> (u64, [u64; 6]) {
    let (i, f) = (window.initial_mem_access, window.final_mem_access);
    (
        window.addr,
        [
            u64::from(i.chunk),
            u64::from(i.timestamp),
            i.value,
            u64::from(f.chunk),
            u64::from(f.timestamp),
            f.value,
        ],
    )
}

fn show(chain: Option<&Chain>) -> String {
    let Some(chain) = chain else {
        return "none".to_string();
    };
    let links: Vec<String> = chain
        .iter()
        .map(|(i, f)| {
            format!(
                "({},{},{:#x})->({},{},{:#x})",
                i.chunk, i.timestamp, i.value, f.chunk, f.timestamp, f.value
            )
        })
        .collect();
    format!("[{}]", links.join(" "))
}

/// Prints why CPU chunk record `cpu_index` differs between the two arms.
pub fn report(interpreter: &Windows, aot: &Windows, cpu_index: usize) {
    let (Some((chunk, left)), Some((_, right))) =
        (interpreter.chunks.get(cpu_index), aot.chunks.get(cpu_index))
    else {
        println!("[diff dump] no CPU chunk record {cpu_index} on both sides");
        return;
    };
    let (left_chains, right_chains) = (chains(left), chains(right));
    let touched = interpreter.precompile_addrs.get(chunk);
    let is_touched = |addr: &u64| touched.is_some_and(|addrs| addrs.contains(addr));

    let mut addrs: Vec<u64> = left_chains
        .keys()
        .chain(right_chains.keys())
        .copied()
        .collect::<HashSet<_>>()
        .into_iter()
        .filter(|addr| left_chains.get(addr) != right_chains.get(addr))
        .collect();
    addrs.sort_unstable();
    let by_precompile = addrs.iter().filter(|addr| is_touched(addr)).count();
    let more_links = addrs
        .iter()
        .filter(|addr| {
            left_chains.get(addr).map_or(0, Vec::len) > right_chains.get(addr).map_or(0, Vec::len)
        })
        .count();

    let mut left_keys: Vec<_> = left.iter().map(key).collect();
    let mut right_keys: Vec<_> = right.iter().map(key).collect();
    left_keys.sort_unstable();
    right_keys.sort_unstable();
    println!(
        "[diff dump] CPU chunk record {cpu_index} (chunk {chunk}): {} vs {} address(es), {} with \
         differing chains, {by_precompile} of those touched by a precompile in this chunk, {more_links} \
         with more links on the interpreter's side; {} precompile-touched address(es) in the chunk; \
         windows as multisets {} ({} vs {} window(s))",
        left_chains.len(),
        right_chains.len(),
        addrs.len(),
        touched.map_or(0, HashSet::len),
        if left_keys == right_keys {
            "equal"
        } else {
            "differ"
        },
        left.len(),
        right.len(),
    );
    for addr in addrs.iter().take(PRINTED) {
        println!(
            "[diff dump]   {addr:#x}: precompile-touched {}; interpreter {}; AOT {}",
            if is_touched(addr) { "yes" } else { "no" },
            show(left_chains.get(addr)),
            show(right_chains.get(addr)),
        );
    }
}
