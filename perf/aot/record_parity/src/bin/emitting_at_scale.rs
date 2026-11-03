//! The emitting pass at a production chunk size, on the guest whose crates are in `aot-generated/`:
//!
//! ```text
//! emitting_at_scale <ELF> <INPUT> <CHUNK_SIZE>
//! ```
//!
//! `INPUT` is the guest's one stdin element, raw, as a reth block file is. Exits 1 on any problem;
//! `AOT_PARITY_WORKERS` sets the worker count, as for the tests.

use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [elf, input, chunk_size] = args.as_slice() else {
        eprintln!("usage: emitting_at_scale <ELF> <INPUT> <CHUNK_SIZE>");
        return ExitCode::from(2);
    };
    let read = |path: &str| std::fs::read(path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    let chunk_size = chunk_size
        .parse()
        .unwrap_or_else(|_| panic!("CHUNK_SIZE {chunk_size:?} is not a number"));
    let problems = aot_record_parity::check_at_scale(&read(elf), read(input), chunk_size);
    if problems == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
