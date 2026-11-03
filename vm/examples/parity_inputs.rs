//! Writes record-parity guests' stdin as files, one per element, raw, as the bench's `--input
//! file:<path>` and `perf/aot/aot_bench.sh -i <path>` pass an element.
//!
//! ```text
//! cargo run --release -p pico-vm --example parity_inputs -- <DIR> <GUEST>...
//! ```
//!
//! Each element goes to `<DIR>/<GUEST>-<i>.bin`, numbered in the order the guest reads them, and
//! its path is printed. `vm/tests/common/record_parity.rs` builds the elements, so the bench runs a
//! guest on exactly the input the parity suites do; the aggregator's are fib's committed outputs,
//! which only an emulation gives. Every run of a guest reads the same input, which is checked.

use std::{path::PathBuf, process::ExitCode};

// Only the guests and their inputs.
#[allow(dead_code)]
#[path = "../tests/common/record_parity.rs"]
mod record_parity;
use record_parity::GUESTS;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some((dir, names)) = args.split_first().filter(|(_, names)| !names.is_empty()) else {
        eprintln!("usage: parity_inputs <DIR> <GUEST>...");
        return ExitCode::from(2);
    };
    let dir = PathBuf::from(dir);
    if let Err(err) = std::fs::create_dir_all(&dir) {
        eprintln!("cannot create {}: {err}", dir.display());
        return ExitCode::FAILURE;
    }
    for name in names {
        let Some(guest) = GUESTS.iter().find(|guest| guest.name == name) else {
            eprintln!(
                "no guest {name}: expected one of {:?}",
                GUESTS.map(|guest| guest.name)
            );
            return ExitCode::from(2);
        };
        let runs = guest.runs();
        let stdin = &runs[0].stdin;
        if runs.iter().any(|run| run.stdin != *stdin) {
            eprintln!("{name}'s runs read different inputs");
            return ExitCode::FAILURE;
        }
        for (index, element) in stdin.iter().enumerate() {
            let path = dir.join(format!("{name}-{index}.bin"));
            if let Err(err) = std::fs::write(&path, element) {
                eprintln!("cannot write {}: {err}", path.display());
                return ExitCode::FAILURE;
            }
            println!("{}", path.display());
        }
    }
    ExitCode::SUCCESS
}
