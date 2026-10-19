//! Shared test inputs, and the host-side oracles the assertions compare against.

use std::{path::PathBuf, sync::Arc};

use pico_vm::{
    compiler::riscv::{
        compiler::{Compiler, SourceType},
        program::Program,
    },
    emulator::opts::EmulatorOpts,
    mle::machine::riscv::{self, EmulationOutput},
};

pub(super) use super::scratch::scratch_dir;
use crate::{prover::ProverBuilder, Stdin};

/// The prebuilt RV64 fibonacci guest, the same fixture `vm/src/mle/machine/riscv.rs` proves
/// against. It commits `(n, F(n), F(n+1))` as three 32-byte big-endian words via `commit_bytes`.
pub(super) const FIB_ELF: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../vm/src/compiler/test_elf/fib-elf"
));

/// A second RV64 guest, used where a test needs a program this one's keys do not describe.
pub(super) const OTHER_ELF: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../vm/src/compiler/test_elf/riscv64im-pico-fibnacci-elf"
));

/// The poseidon2 guest (`vm/examples/patch-testing/patches/poseidon2`); it reads its round count.
pub(super) const POSEIDON2_ELF: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../perf/bench_data/rv64/poseidon2-elf"
));

/// The smallest operating point that still proves a real chain: the whole run is one execution
/// chunk, beside the memory-only records the deferred split adds.
pub(super) const LOG_STACKED_HEIGHT: usize = 22;

/// The input every chain test proves.
pub(super) const N: u32 = 10;

/// Small enough that fib(10) takes several chunks.
pub(super) const SMALL_CHUNK: u32 = 1 << 12;

pub(super) fn builder() -> ProverBuilder {
    crate::Prover::builder(FIB_ELF).log_stacked_height(LOG_STACKED_HEIGHT)
}

/// For tests that never need a proof to succeed: keygen's cost grows with the stacked height, and
/// nothing they assert depends on it.
pub(super) const SMALL_LOG_STACKED_HEIGHT: usize = 20;

/// [`builder`] at [`SMALL_LOG_STACKED_HEIGHT`].
pub(super) fn small_builder() -> ProverBuilder {
    crate::Prover::builder(FIB_ELF).log_stacked_height(SMALL_LOG_STACKED_HEIGHT)
}

/// The whitelist the repo ships, and the root published beside it in `mle_vk_root.txt`.
pub(super) fn shipped_whitelist() -> (PathBuf, [u32; 8]) {
    let dir = PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../vm/src/mle/shape_vk_bins"
    ));
    let text = std::fs::read_to_string(dir.join("mle_vk_root.txt")).expect("mle_vk_root.txt");
    let root: Vec<u32> = text
        .lines()
        .find_map(|l| l.strip_prefix("MLE_VK_ROOT=\""))
        .and_then(|l| l.strip_suffix('"'))
        .expect("mle_vk_root.txt carries an MLE_VK_ROOT line")
        .split_whitespace()
        .map(|w| w.parse().expect("root limb"))
        .collect();
    let root = root.try_into().expect("eight root limbs");
    (dir.join("mle_vk_map_kb.bin"), root)
}

/// [`builder`] at the one height `verify_keys(true)` accepts.
pub(super) fn whitelist_builder() -> ProverBuilder {
    crate::Prover::builder(FIB_ELF).log_stacked_height(crate::prover::WHITELIST_LOG_STACKED_HEIGHT)
}

/// [`whitelist_builder`] in whitelist mode, under the shipped whitelist and its published root.
pub(super) fn shipped_whitelist_builder() -> ProverBuilder {
    let (map, root) = shipped_whitelist();
    whitelist_builder()
        .verify_keys(true)
        .vk_map(map)
        .trusted_vk_root(root)
}

pub(super) fn fib_program() -> Arc<Program> {
    Compiler::new(SourceType::RISCV, FIB_ELF)
        .expect("parse the fib ELF")
        .compile()
}

/// fib(N) straight through the VM's emulator, without this crate's emulation path.
pub(super) fn emulate_fib(opts: EmulatorOpts) -> EmulationOutput {
    emulate_fib_on(fib_program(), opts)
}

/// [`emulate_fib`] on a program the caller also proves against.
pub(super) fn emulate_fib_on(program: Arc<Program>, opts: EmulatorOpts) -> EmulationOutput {
    riscv::emulate_with_opts(program, &Stdin::from(&N).into_emulator_stdin(), opts)
        .expect("emulation")
}

/// `(F(n), F(n+1))` in wrapping `u32`, recomputed here so an assertion compares against a derived
/// value rather than a recorded byte string.
fn host_fib(n: u32) -> (u32, u32) {
    let (mut a, mut b) = (0u32, 1u32);
    for _ in 0..n {
        let next = a.wrapping_add(b);
        a = b;
        b = next;
    }
    (a, b)
}

/// Decode the guest's three 32-byte big-endian words.
fn decode_fib_commit(committed: &[u8]) -> (u32, u32, u32) {
    assert_eq!(
        committed.len(),
        96,
        "expected three 32-byte words from the fib guest, got {} byte(s) — if this is 0 the ELF \
         was rebuilt from a guest that does not commit",
        committed.len()
    );
    let word = |i: usize| -> u32 {
        let w = &committed[i * 32..(i + 1) * 32];
        assert!(
            w[..28].iter().all(|b| *b == 0),
            "word {i} does not fit in u32: {w:02x?}"
        );
        u32::from_be_bytes([w[28], w[29], w[30], w[31]])
    };
    (word(0), word(1), word(2))
}

/// Assert the committed bytes are what the host says fib(n) is.
pub(super) fn assert_is_fib_output(committed: &[u8], n: u32) {
    let (got_n, got_a, got_b) = decode_fib_commit(committed);
    let (want_a, want_b) = host_fib(n);
    assert_eq!(got_n, n, "the guest echoed the wrong input");
    assert_eq!((got_a, got_b), (want_a, want_b), "F(n) does not match");
}

/// Re-run this test binary for `test_name` with `envs` set, require it to print `marker`, and
/// return what it printed on stdout.
///
/// A child process, because `set_var` in a live test binary races every other thread's `getenv`,
/// because a proof loaded by the process that produced it proves nothing about what a fresh one
/// can do with it, and because the AOT registry keeps one program for the life of a process.
pub(super) fn run_child(test_name: &str, marker: &str, envs: &[(&str, String)]) -> String {
    let out = child_command(test_name, envs)
        .output()
        .expect("re-run this test binary");
    check_child(test_name, marker, out)
}

/// [`run_child`], with the child killed and the test failed if it has not exited within `timeout`,
/// so a hang is reported as one rather than stalling the run.
#[cfg(feature = "aot")]
pub(super) fn run_child_within(
    test_name: &str,
    marker: &str,
    envs: &[(&str, String)],
    timeout: std::time::Duration,
) -> String {
    use std::{io::Read, process::Stdio, thread, time::Instant};

    let mut child = child_command(test_name, envs)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("re-run this test binary");
    // Drained while the child runs: one blocked on a full pipe would look like a hang.
    let drain = |mut pipe: Box<dyn Read + Send>| {
        thread::spawn(move || {
            let mut bytes = Vec::new();
            pipe.read_to_end(&mut bytes)
                .expect("read the child's output");
            bytes
        })
    };
    let stdout = drain(Box::new(child.stdout.take().expect("piped stdout")));
    let stderr = drain(Box::new(child.stderr.take().expect("piped stderr")));

    let deadline = Instant::now() + timeout;
    let status = loop {
        if let Some(status) = child.try_wait().expect("poll the child") {
            break Some(status);
        }
        if Instant::now() >= deadline {
            child.kill().expect("kill the child");
            child.wait().expect("reap the child");
            break None;
        }
        thread::sleep(std::time::Duration::from_millis(100));
    };
    let stdout = stdout.join().expect("stdout reader");
    let stderr = stderr.join().expect("stderr reader");
    let Some(status) = status else {
        panic!(
            "child `{test_name}` did not exit within {timeout:?}, so it hung:\n{}\n{}",
            String::from_utf8_lossy(&stdout),
            String::from_utf8_lossy(&stderr)
        );
    };
    check_child(
        test_name,
        marker,
        std::process::Output {
            status,
            stdout,
            stderr,
        },
    )
}

fn child_command(test_name: &str, envs: &[(&str, String)]) -> std::process::Command {
    let exe = std::env::current_exe().expect("test binary path");
    let mut command = std::process::Command::new(exe);
    // `--include-ignored` because one of these tests is itself opt-in for its cost; without it the
    // child would skip silently and the marker check in `check_child` would be the only thing that
    // noticed.
    command.args([
        "--exact",
        test_name,
        "--nocapture",
        "--include-ignored",
        "--test-threads",
        "1",
    ]);
    for (key, value) in envs {
        command.env(key, value);
    }
    command
}

fn check_child(test_name: &str, marker: &str, out: std::process::Output) -> String {
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "child `{test_name}` failed:\n{stdout}\n{stderr}"
    );
    // A stale `--exact` name matches no test and still exits 0, so the marker is what establishes
    // that an assertion ran at all.
    assert!(
        stdout.contains(marker),
        "child `{test_name}` ran no assertion:\n{stdout}\n{stderr}"
    );
    stdout.into_owned()
}
