//! Name the AIR and the bus behind a `LogupZerocheck(NonZeroRootSum)`.
//!
//! `prove` only reports that some lookup did not balance. `debug_records` walks the host matrices
//! chunk by chunk and panics at the first offending AIR, which is the difference between a two-word
//! error and a location.
//!
//! Usage: cargo run --release -p pico-vm --example mle_bus_probe -- --elf fib --n 10 --field kb

use pico_vm::{
    compiler::riscv::compiler::{Compiler, SourceType},
    configs::stark_config::KoalaBearPoseidon2,
    machine::logger::setup_logger,
    mle::machine::riscv,
};

#[path = "common/parse_args.rs"]
mod parse_args;

fn main() {
    setup_logger();
    let (elf, stdin, _args) = parse_args::parse_args::<KoalaBearPoseidon2>();
    let program = Compiler::new(SourceType::RISCV, elf)
        .expect("failed to parse ELF")
        .compile();
    // Same operating point and bucketing the e2e proves at, or the probe checks another shape.
    let records = riscv::emulate(program.clone(), stdin, Some(1 << 23));
    println!("emulated {} chunk(s)", records.len());
    riscv::debug_records(program, &records, 23, false);
    println!("ALL CHUNKS PASS (constraints + bus balance)");
}
