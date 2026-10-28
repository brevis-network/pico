//! Params-free RISC-V constraint dump — the constraint comparator's entry point.
//!
//! Emits one line per AIR (`name<TAB>digest`) plus an overall digest, over the RISC-V machine's
//! whole constraint surface. Run it on two revisions or builds and diff the files: equal ⇒
//! constraints, interactions, column widths, public-value counts and degrees all match,
//! independent of `CHUNK_SIZE` / `log_stacked_height`.
//!
//! Why this is not `compute_vk_pre_hash`: the lean pre-hash preimage carries `SystemParams`, whose
//! `n_stack` is a function of `CHUNK_SIZE`, so two builds at different operating points get
//! different pre-hashes even with byte-identical constraints. See
//! `pico_mle_core::keygen::compute_constraint_dump`.
//!
//! The dump itself lives in `pico_vm::mle::machine::riscv::riscv_constraint_dump`, shared with the
//! `riscv_constraint_parity` gate so the pinned artifact and this tool cannot drift apart.
//!
//! Usage:
//!   cargo run --release -p pico-vm --example mle_constraint_dump [-- <out-path>]
//! Default out-path: `riscv_constraint_dump.txt` in the working directory.

use std::fs;

use pico_vm::{machine::logger::setup_logger, mle::machine::riscv::riscv_constraint_dump};
use tracing::info;

fn main() {
    setup_logger();
    let out_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "riscv_constraint_dump.txt".to_string());

    let bucketed = riscv_constraint_dump(true);
    let air_lines = bucketed
        .lines()
        .filter(|l| !l.starts_with('#') && !l.starts_with("overall"))
        .count();
    let overall = bucketed
        .lines()
        .find(|l| l.starts_with("overall"))
        .unwrap_or("overall\t<missing>");
    info!("RISC-V machine: {air_lines} AIRs; {overall}");

    // Self-check: the digest must not depend on the program table's shape. If this ever fires, the
    // dump has picked up a preprocessed-geometry dependency and is no longer a valid constraint
    // comparator (it would diverge on program size rather than on constraints).
    assert_eq!(
        bucketed,
        riscv_constraint_dump(false),
        "the constraint dump must not depend on program-table bucketing; it has picked up a \
         preprocessed-geometry dependency and is no longer workload-independent"
    );

    fs::write(&out_path, &bucketed).expect("write constraint dump");
    info!("wrote {out_path}");
    print!("{bucketed}");
}
