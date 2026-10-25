//! Per-record event census: how many rows each chunk's Add chip and memory chips will get, and
//! which local-memory entries are fresh. Emulation only (no GPU, no proving), streaming one
//! record at a time so the pinned event-buffer pool is never exhausted.
//!
//! Add rows are what the preparer counts (`precompute_event_size`: the record's ADD ALU events and
//! the DivRem chip's absolute-value ADD events; a JALR target is proven in the Cpu row and adds
//! nothing here). The memory columns classify the record's local-memory entries and
//! its init / finalize events: `fresh_*` are Cpu-side entries whose initial access is
//! `(chunk 0, timestamp 0)` at a main-memory address outside the program image (`fresh_zero`:
//! with a zero initial value, `fresh_low`: with `addr & 0xFFFF < 0x100`), `init_nonzero` the
//! initialize events carrying a non-zero value, `final_untouched` the finalize events whose record
//! is still `(0, 0)` at a non-image main-memory address (words written only by hints and never
//! accessed by the program), `final_image` the finalize events of program-image words.
//!
//! Usage (same chunking env as `single_node_mle.sh`):
//!   CHUNK_SIZE=8388608 cargo run --release -p pico-vm --example mle_event_stats -- \
//!       --elf reth --n 24006427 --field kb

use std::sync::Arc;

use pico_vm::{
    compiler::riscv::{
        compiler::{Compiler, SourceType},
        opcode::Opcode,
    },
    configs::stark_config::KoalaBearPoseidon2,
    emulator::{
        opts::EmulatorOpts,
        riscv::{
            emulator::{RiscvEmulator, MIN_MAIN_MEMORY_ADDR},
            public_values::RecordFinalPvsState,
        },
    },
    instances::preparer::precompute_event_size,
    machine::logger::setup_logger,
    mle::machine::riscv::Kb,
};

#[path = "common/parse_args.rs"]
mod parse_args;

fn pow2(n: usize) -> usize {
    n.max(16).next_power_of_two()
}

fn main() {
    setup_logger();
    let (elf, stdin, _args) = parse_args::parse_args::<KoalaBearPoseidon2>();
    // `compile()` already hands back an `Arc<Program>`.
    let program = Compiler::new(SourceType::RISCV, elf)
        .expect("failed to parse ELF")
        .compile();
    let opts = EmulatorOpts::default();
    let final_pvs_state = Arc::new(RecordFinalPvsState::default());
    let mut emulator = RiscvEmulator::new_single::<Kb>(program, final_pvs_state, opts, None);
    emulator.write_stdin(&stdin);

    println!(
        "chunk,cpu_rows,add_alu,jalr,add_rows,h_add,n_entries,fresh_any,fresh_zero,fresh_low,n_init,init_nonzero,n_final,final_untouched,final_image"
    );
    let mut i = 0usize;
    loop {
        let report = emulator
            .emulate_batch(&mut |r| {
                let add_alu = r
                    .add_sub_events
                    .as_slice()
                    .iter()
                    .filter(|e| matches!(e.opcode, Opcode::ADD))
                    .count();
                let jalr = r
                    .cpu_events
                    .as_slice()
                    .iter()
                    .filter(|e| matches!(e.instruction.opcode, Opcode::JALR))
                    .count();
                let add_rows = precompute_event_size::<Kb>(&r).num_add_events;
                let image = &r.program.memory_image;
                let is_fresh = |e: &pico_vm::chips::chips::events::MemoryLocalEvent| {
                    e.initial_mem_access.chunk == 0
                        && e.initial_mem_access.timestamp == 0
                        && e.addr >= MIN_MAIN_MEMORY_ADDR
                        && !image.contains_key(&e.addr)
                };
                let n_entries = r.cpu_local_memory_access.len();
                let fresh: Vec<_> = r
                    .cpu_local_memory_access
                    .iter()
                    .filter(|e| is_fresh(e))
                    .collect();
                let fresh_zero = fresh
                    .iter()
                    .filter(|e| e.initial_mem_access.value == 0)
                    .count();
                let fresh_low = fresh.iter().filter(|e| (e.addr & 0xFFFF) < 0x100).count();
                let n_init = r.memory_initialize_events.len();
                let init_nonzero = r
                    .memory_initialize_events
                    .iter()
                    .filter(|e| e.value != 0)
                    .count();
                let n_final = r.memory_finalize_events.len();
                // Untouched = never accessed by the program (record still (0, 0)) and not a
                // program-image word (image words are bulk-loaded with the accessed bit set and
                // keep their finalize event: the vk digest sends their initial state).
                let final_untouched = r
                    .memory_finalize_events
                    .iter()
                    .filter(|e| {
                        e.chunk == 0
                            && e.timestamp == 0
                            && e.addr >= MIN_MAIN_MEMORY_ADDR
                            && !image.contains_key(&e.addr)
                    })
                    .count();
                let final_image = r
                    .memory_finalize_events
                    .iter()
                    .filter(|e| image.contains_key(&e.addr))
                    .count();
                println!(
                    "{i},{},{add_alu},{jalr},{add_rows},{},{n_entries},{},{fresh_zero},{fresh_low},{n_init},{init_nonzero},{n_final},{final_untouched},{final_image}",
                    r.cpu_events.len(),
                    pow2(add_rows),
                    fresh.len()
                );
                i += 1;
            })
            .expect("emulate_batch failed");
        if report.done {
            break;
        }
    }
}
