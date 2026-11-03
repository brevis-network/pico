//! The memory initialize and finalize events that close a traced run.
//!
//! Both engines call [`postprocess`] once, after their last chunk, with their final state: what it
//! emits is bound in-circuit (x0 first, initialize/finalize balance on the global bus), so the two
//! must agree on it exactly.

use super::MIN_MAIN_MEMORY_ADDR;
use crate::{
    chips::chips::{
        events::{MemoryInitializeFinalizeEvent, MemoryRecord},
        riscv_memory::event::fresh_local_mem_verdict,
    },
    emulator::riscv::{
        event_types::RvAddr,
        memory::{ContiguousRiscvMemory, Memory64},
        record::EmulationRecord,
        state::RuntimeRegisterRecord,
    },
};
use tracing::debug;

/// The parts of an emulator's final state that [`postprocess`] reads.
pub struct FinalState<'a> {
    pub registers: &'a [RuntimeRegisterRecord; 32],
    pub uninitialized_memory: &'a Memory64<u64>,
    pub memory: &'a ContiguousRiscvMemory,
    pub input_stream_ptr: usize,
    pub input_stream_len: usize,
}

/// Appends the run's memory initialize and finalize events to `chunk_record`, the open record of
/// its last chunk.
pub fn postprocess(state: FinalState<'_>, chunk_record: &mut EmulationRecord) {
    // Ensure that all proofs and input bytes were read...
    if state.input_stream_ptr != state.input_stream_len {
        tracing::warn!("Not all input bytes were read.");
    }
    // helper
    // For registers, the timestamp cannot be 0
    let is_used =
        |rec: &RuntimeRegisterRecord| rec.value != 0 || rec.timestamp != 0 || rec.chunk != 0;

    let memory_finalize_events = &mut chunk_record.memory_finalize_events;
    let memory_initialize_events = &mut chunk_record.memory_initialize_events;

    // We handle x0 separately, as we constrain it to be 0 in the first row
    // of the memory finalize table so it must be first in the array of events.
    let addr_0_record = state.registers[0];
    // The payload of x0's finalize event when x0 was never accessed. It must be the exact
    // tuple the initialize event sends, because with no access in between there is nothing
    // else on the memory bus to bridge the two: MemoryInitialize sends a hardcoded
    // `(chunk = 0, timestamp = 0)` (`initialize_finalize/constraints.rs:73-74`) while
    // MemoryFinalize receives `(local.chunk, local.timestamp)` (`:93-94`). A timestamp of 1
    // here left the global bus unbalanced. Nothing constrains the Finalize chip's timestamp
    // (only the Initialize chip's, at `:247-250`), so 0 is admissible.
    let default_0_rec = RuntimeRegisterRecord {
        value: 0,
        chunk: 0,
        timestamp: 0,
    };

    let addr_0_final_record = if is_used(&addr_0_record) {
        &addr_0_record
    } else {
        &default_0_rec
    };

    let addr_0_final_record = MemoryRecord {
        value: addr_0_final_record.value,
        chunk: addr_0_final_record.chunk,
        timestamp: addr_0_final_record.timestamp,
    };
    memory_finalize_events.push(MemoryInitializeFinalizeEvent::finalize_from_record(
        0,
        &addr_0_final_record,
    ));

    // `used` must be true unconditionally. This event is pushed first, and the AIR requires
    // the first row of MemoryInitialize to be real
    // (`initialize_finalize/constraints.rs:195`, `when_first_row().assert_one(is_real)`).
    // Deriving it from `is_used(registers[0])` made an honest program that never references
    // register 0 unprovable. The value stays 0, which is what the first row is pinned to
    // anyway (`:258-262`, value zero when `is_comp == 0`), and the matching finalize event
    // above is already unconditionally `used: 1` (`riscv_memory/event.rs:185`) — so this
    // also removes an initialize/finalize asymmetry.
    let addr_0_initialize_event = MemoryInitializeFinalizeEvent::initialize(0, 0, true);
    memory_initialize_events.push(addr_0_initialize_event);

    // Handle x1..x31 registers from dedicated register storage.
    for reg in 1..32 {
        let addr = reg as u64;
        let is_in_image = chunk_record.program.memory_image.contains_key(&addr);
        debug_assert!(
            !is_in_image,
            "register address unexpectedly in memory_image: 0x{addr:08x}"
        );
        let record = state.registers[reg];
        if is_used(&record) {
            if !is_in_image {
                let initial_value = state.uninitialized_memory.get(addr).unwrap_or(&0);
                memory_initialize_events.push(MemoryInitializeFinalizeEvent::initialize(
                    addr,
                    *initial_value,
                    true,
                ));
            }
            let record = MemoryRecord {
                value: record.value,
                chunk: record.chunk,
                timestamp: record.timestamp,
            };
            memory_finalize_events.push(MemoryInitializeFinalizeEvent::finalize_from_record(
                addr, &record,
            ));
        }
    }

    // =========================================================
    // Handle main memory
    // =========================================================
    // accessed_addrs = the union set of (memory_image_addrs, global_accessed_addrs)
    let accessed_addrs: Vec<RvAddr> = state.memory.accessed_keys().collect();
    debug!("postprocess: accessed_addrs len: {}", accessed_addrs.len());

    // Preallocate: the loop below pushes at most one finalize event per accessed dword and
    // at most one initialize event per dword (far fewer than that: a zero-initial word
    // outside the image gets none, see below). These can
    // number in the hundreds of thousands, so reserve up front to avoid the repeated
    // grow-and-memmove of the event Vecs.
    memory_finalize_events.reserve(accessed_addrs.len());

    // `accessed_keys()` yields addresses in strictly ascending order and `memory_image` keys
    // are sorted, so we replace the per-dword O(log n) `contains_key` lookup with a single
    // forward cursor advanced in lock-step (ordered merge: amortized O(1) per addr instead
    // of O(log n)). `memory_image` keys are always 8-byte aligned (see Gen-1 note /
    // disassembler/elf.rs), so an exact `key == addr` test is equivalent to the previous
    // `contains_key(&addr)`.
    let mut img_iter = chunk_record
        .program
        .memory_image
        .range(MIN_MAIN_MEMORY_ADDR..)
        .peekable();
    for addr in accessed_addrs {
        if addr < MIN_MAIN_MEMORY_ADDR {
            continue;
        }

        // Advance the cursor to the first image key >= addr (monotonic: addr is ascending).
        while img_iter.peek().is_some_and(|(k, _)| **k < addr) {
            img_iter.next();
        }
        let is_in_image = img_iter.peek().is_some_and(|(k, _)| **k == addr);
        let record = state.memory.get(addr);

        // Which events a main-memory word gets, in this order:
        //
        // 1. Image word: finalize only. Its initial state is sent by the vk's image digest
        //    (`compiler/riscv/program.rs`), for every image word -- including the ones the
        //    program never touched, whose record is still `(0, 0, image value)` (bulk-load
        //    marks them accessed), so their finalize event is what balances the digest.
        // 2. Outside the image, record still at `(chunk 0, timestamp 0)`: no event at all.
        //    No constrained access ever reached the word (chunks start at 1, clks at
        //    `CHUNK_CLK_START`): only a hint wrote it (`syscalls/hint.rs` inserts
        //    `(word, 0, 0)` and marks it accessed) or an unconstrained rollback restored
        //    it. No MemoryLocal entry anywhere names it, so an init / finalize pair would
        //    only cancel against itself on the Global bus.
        // 3. Outside the image, starting at zero: finalize only. The word's first-touch
        //    MemoryLocal entry declares the zero initial state itself
        //    (`riscv_memory/event.rs`, `is_fresh_local_mem`; `has_initial = 0` on the AIR),
        //    so there is no MemoryInitialize row to receive from.
        // 4. Outside the image, nonzero initial value (a hint wrote it): initialize and
        //    finalize, as before. The entry receives the value from the MemoryInitialize
        //    row, which is where a nonzero initial state has to come from.
        //
        // Registers (above) keep their initialize events unconditionally.
        if !is_in_image {
            if record.chunk == 0 && record.timestamp == 0 {
                continue;
            }
            let initial_value = *state.uninitialized_memory.get(addr).unwrap_or(&0);
            let initial = MemoryRecord {
                chunk: 0,
                timestamp: 0,
                value: initial_value,
            };
            if !fresh_local_mem_verdict(addr, &initial, false) {
                memory_initialize_events.push(MemoryInitializeFinalizeEvent::initialize(
                    addr,
                    initial_value,
                    true,
                ));
            }
        }

        memory_finalize_events.push(MemoryInitializeFinalizeEvent::finalize_from_record(
            addr, &record,
        ));
    }

    // =========================================================
    // DEBUG: Print all memory events for comparison
    // Enable with: DEBUG_MEMORY_EVENTS=1
    // =========================================================
    if std::env::var("DEBUG_MEMORY_EVENTS").is_ok() {
        let mut sorted_program_memory: Vec<_> = chunk_record.program.memory_image.iter().collect();
        sorted_program_memory.sort_by_key(|(addr, _)| **addr);
        eprintln!(
            "\n========== PROGRAM MEMORY IMAGE ({}) ==========",
            sorted_program_memory.len()
        );
        for (i, (addr, value)) in sorted_program_memory.iter().enumerate() {
            eprintln!(
                "[PROG {:4}] addr=0x{:08x} ({:10}), value=0x{:08x}",
                i, addr, addr, value
            );
        }

        eprintln!(
            "\n========== MEMORY INITIALIZE EVENTS ({}) ==========",
            memory_initialize_events.len()
        );
        for (i, evt) in memory_initialize_events.iter().enumerate() {
            eprintln!(
                "[INIT {:4}] addr=0x{:08x} ({:10}), value=0x{:08x}, chunk={}, ts={}, used={}",
                i, evt.addr, evt.addr, evt.value, evt.chunk, evt.timestamp, evt.used
            );
        }

        eprintln!(
            "\n========== MEMORY FINALIZE EVENTS ({}) ==========",
            memory_finalize_events.len()
        );
        for (i, evt) in memory_finalize_events.iter().enumerate() {
            eprintln!(
                "[FINAL {:4}] addr=0x{:08x} ({:10}), value=0x{:08x}, chunk={}, ts={}, used={}",
                i, evt.addr, evt.addr, evt.value, evt.chunk, evt.timestamp, evt.used
            );
        }

        eprintln!("\n========== ALIGNMENT CHECK ==========");
        let prog_set: std::collections::HashSet<u64> =
            sorted_program_memory.into_iter().map(|(k, _)| *k).collect();
        let init_set: std::collections::HashSet<u64> =
            memory_initialize_events.iter().map(|e| e.addr).collect();
        let final_set: std::collections::HashSet<u64> =
            memory_finalize_events.iter().map(|e| e.addr).collect();

        let mut all_addrs: Vec<RvAddr> = final_set.iter().cloned().collect();
        all_addrs.extend(prog_set.iter());
        all_addrs.extend(init_set.iter());
        all_addrs.sort();
        all_addrs.dedup();

        for addr in all_addrs {
            let p = prog_set.contains(&addr);
            let i = init_set.contains(&addr);
            let f = final_set.contains(&addr);

            if p && i {
                eprintln!(
                    "WARN: Addr 0x{:08x} is in BOTH Program Image and Init Events",
                    addr
                );
            }
            if f && !p && !i {
                eprintln!(
                    "WARN: Addr 0x{:08x} is in Finalize but NEITHER Program nor Init",
                    addr
                );
            }
            if i && !f {
                eprintln!(
                    "WARN: Addr 0x{:08x} is in Init but NOT Finalize (might be 0 or unaccessed?)",
                    addr
                );
            }
            if p && !f {
                eprintln!("WARN: Addr 0x{:08x} is in Program Image but NOT Finalize (Should imply accessed!)", addr);
            }
        }
        eprintln!("========== END MEMORY EVENTS ==========\n");

        // DEBUG: Compare MemoryLocal initial_mem_access with MemoryInitialize
        if std::env::var("DEBUG_LOCAL_MEMORY").is_ok() {
            eprintln!("\n========== MEMORY LOCAL EVENTS (checking initial_mem_access) ==========");
            let local_events = chunk_record.cpu_local_memory_access.iter();
            for evt in local_events {
                let is_in_image = chunk_record.program.memory_image.contains_key(&evt.addr);
                let actual_init = (
                    evt.initial_mem_access.chunk,
                    evt.initial_mem_access.timestamp,
                );

                // For non-program-memory addresses, MemoryInitialize sends (0,0)
                // For program-memory addresses, MemoryProgram chip handles it (also sends 0,0)
                // So initial should ALWAYS be (0,0) for the FIRST access in a chunk
                if actual_init != (0, 0) {
                    eprintln!(
                        "NON-ZERO INIT: addr=0x{:08x}, initial=({}, {}), value={}, in_image={}",
                        evt.addr,
                        actual_init.0,
                        actual_init.1,
                        evt.initial_mem_access.value,
                        is_in_image
                    );
                }
            }
            eprintln!("========== END MEMORY LOCAL CHECK ==========\n");
        }
    }
}
