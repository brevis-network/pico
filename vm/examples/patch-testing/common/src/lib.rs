//! The check every patch prover runs.
//!
//! A case names the syscalls its patched crate exists to route through. A patch that silently
//! falls back to software still proves, and tests nothing, so every named syscall must have run
//! before the outcome counts. The calls are the prover's own count over the run it proves, by the
//! exact code called, and it counts precompiles only, so a case can name nothing else.
//!
//! A syscall that fires can still be handed the wrong operands, and the chip then proves the wrong
//! answer faithfully. So a case also states the bytes its guest commits, derived on the host from
//! the upstream crate rather than from the patched one, and the run must commit exactly those. A
//! guest that checks its own result instead commits nothing.
//!
//! Every syscall is in the syscall map and every chip has an AIR in the MLE air table, and
//! `vm/tests/precompile_support.rs` pins both, so a case either proves or fails. The process exits
//! 0 when it proves and 1 otherwise.

use std::{
    fmt::Write as _,
    path::{Path, PathBuf},
    process,
};

pub use pico_vm::{self, emulator::riscv::syscalls::SyscallCode};

use pico_prover::{Execution, Prover, Stdin};
use pico_vm::machine::logger::setup_logger;
use serde::Serialize;

/// `run_proof!([SYSCALL, ..], commits = bytes, input, ..)`: the syscalls the patched crate must
/// reach, the bytes the guest must commit, then one input per guest read, in order.
///
/// The ELF is the one the app beside the prover builds, or `ELF_PATH` when set.
#[macro_export]
macro_rules! run_proof {
    ( [ $( $syscall:ident ),+ $(,)? ], commits = $commits:expr $(, $input:expr )* $(,)? ) => {{
        let mut input = $crate::Input::default();
        $( input.write(&$input); )*
        $crate::run(
            concat!(env!("CARGO_MANIFEST_DIR"), "/../app/elf/riscv64im-pico-zkvm-elf"),
            &[ $( $crate::SyscallCode::$syscall ),+ ],
            ::core::convert::AsRef::<[u8]>::as_ref(&$commits),
            input,
        )
    }};
}

/// The guest's reads, each encoded once so the counted run and the proved run see the same bytes.
#[derive(Default)]
pub struct Input(Vec<Vec<u8>>);

impl Input {
    /// One element, bincode-encoded, read by the guest with `read_as::<T>()`. `read_vec()` reads
    /// the encoding itself, which is the raw bytes only for a fixed-size `[u8; N]`: a `Vec<u8>` or
    /// slice carries an 8-byte length prefix the guest would read as data.
    pub fn write<T: Serialize>(&mut self, value: &T) -> &mut Self {
        self.0
            .push(bincode::serialize(value).expect("a patch input serializes"));
        self
    }

    fn stdin(&self) -> Stdin {
        let mut stdin = Stdin::new();
        for element in &self.0 {
            stdin.write_bytes(element);
        }
        stdin
    }
}

/// Decode a hex string, for a case's expected commits. Panics on malformed input.
pub fn hex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd-length hex");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex digit"))
        .collect()
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

/// Run one case and exit. `ELF_PATH`, when set, replaces `default_elf`.
pub fn run(default_elf: &str, syscalls: &[SyscallCode], commits: &[u8], input: Input) -> ! {
    setup_logger();
    let elf_path =
        std::env::var_os("ELF_PATH").map_or_else(|| PathBuf::from(default_elf), PathBuf::from);
    match check(&elf_path, syscalls, commits, &input) {
        Ok(report) => {
            println!("patch result: ok: {report}");
            process::exit(0)
        }
        Err(failure) => {
            println!("patch result: FAILED: {failure}");
            process::exit(1)
        }
    }
}

fn check(
    elf_path: &Path,
    syscalls: &[SyscallCode],
    commits: &[u8],
    input: &Input,
) -> Result<String, String> {
    if let Some(code) = syscalls.iter().find(|code| code.should_send() == 0) {
        return Err(format!(
            "{code:?} is not a precompile, so its calls cannot be counted"
        ));
    }

    let elf =
        std::fs::read(elf_path).map_err(|e| format!("cannot read {}: {e}", elf_path.display()))?;

    // Keygen-free, so a case that fails here pays no keygen.
    let execution = Prover::builder(&elf)
        .execute(input.stdin())
        .map_err(|e| format!("emulation: {e}"))?;
    let counts = describe_counts(&execution, syscalls);
    if let Some(silent) = syscalls
        .iter()
        .copied()
        .find(|code| !execution.precompile_calls.contains_key(code))
    {
        return Err(format!(
            "{silent:?} never ran, so the patched path was not exercised ({counts})"
        ));
    }
    if execution.committed_bytes != commits {
        return Err(format!(
            "the run committed {}, the case expects {} ({counts})",
            to_hex(&execution.committed_bytes),
            to_hex(commits)
        ));
    }

    // Printed before proving, so the evidence survives a prove that runs out of memory.
    println!("patch counted: {} cycles ({counts})", execution.cycles);
    let mut prover = Prover::new(&elf).map_err(|e| format!("keygen: {e}"))?;
    let proof = prover
        .prove(input.stdin())
        .map_err(|e| format!("prove: {e} ({counts})"))?;
    if proof.committed().as_bytes() != execution.committed_bytes {
        return Err("the proof commits other bytes than the counted run".into());
    }
    let chunk_proofs = proof
        .chunk_count()
        .ok_or("the proof carries no chunk count")?;
    Ok(format!(
        "proved, {chunk_proofs} chunk proof(s), {} cycles ({counts})",
        execution.cycles
    ))
}

/// The named codes' calls, then any other precompile the run called.
fn describe_counts(execution: &Execution, named: &[SyscallCode]) -> String {
    let calls = &execution.precompile_calls;
    let mut out = String::from("named");
    for code in named {
        let _ = write!(out, " {code:?}={}", calls.get(code).copied().unwrap_or(0));
    }
    let others: Vec<_> = calls
        .iter()
        .filter(|(code, _)| !named.contains(code))
        .collect();
    if !others.is_empty() {
        out.push_str("; other precompiles");
        for (code, count) in others {
            let _ = write!(out, " {code:?}={count}");
        }
    }
    out
}
