//! The RISC-V architectural tests that zkevm-test-monitor runs against a zkVM: ACT4 4.1.0,
//! the 72 tests of Pico's RV64IM_Zicclsm target, kept as one archive that the first test to need it
//! unpacks into the target dir. `act4/README.md` says where the ELFs come from.
//!
//! Each test compares its results with the Sail reference model's, which are compiled into it,
//! then writes `PASS` or `FAIL` to the public values and halts, with exit code 0 after `PASS` and 1
//! after `FAIL`. So a run that commits `PASS` is a test that passed.
//!
//! * The 64 tests of the I and M suites must execute, and prove to the riscv phase, which verifies
//!   the proof, committing `PASS` both times.
//! * The 8 of the Misalign suite are known failures until Pico supports misaligned loads and
//!   stores, and each must still fail. The first one that passes fails this module
//!   instead, so that the suite moves into `MUST_PASS` and all 72 are required from then on.

use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::OnceLock,
    time::Instant,
};

use sha2::{Digest, Sha256};

use super::fixture::SMALL_LOG_STACKED_HEIGHT;
use crate::{Phase, Prover, Stdin};

/// The 72 ELFs as one archive of `elfs/<suite>/<test>.elf`, one directory per ACT4 suite.
const ARCHIVE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../act4/act4-elfs-4.1.0-pico-rv64im-zicclsm.tar.xz"
);

/// The archive's SHA-256, so that a new archive is a reviewed change to this line as well.
const ARCHIVE_SHA256: &str = "abf1aae4f2fa9cac8c68ffbdb2f26a420991291af8c81f1220c574b2ade862bd";

/// The suites every test of which must pass, and how many tests each holds.
const MUST_PASS: [(&str, usize); 2] = [("I", 51), ("M", 13)];

/// Known failures until Pico supports misaligned loads and stores.
const KNOWN_FAILURES: (&str, usize) = ("Misalign", 8);

/// What a test writes to the public values when every result matched the reference model's.
const PASS: &[u8] = b"PASS";

/// The unpacked archive's `elfs/`, unpacked at most once per process.
fn elf_dir() -> &'static Path {
    static DIR: OnceLock<PathBuf> = OnceLock::new();
    DIR.get_or_init(unpack)
}

/// Checks the archive, then unpacks it into `target/<profile>/act4-elfs-<hash>/`, unless an earlier
/// run left it there complete. It unpacks into a directory of this process's own and then renames
/// that into place, so two runs at once never read each other's half-written files.
fn unpack() -> PathBuf {
    let archive = fs::read(ARCHIVE).unwrap_or_else(|e| panic!("{ARCHIVE}: {e}"));
    let sha256: String = Sha256::digest(&archive)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert_eq!(
        sha256, ARCHIVE_SHA256,
        "{ARCHIVE} is not the archive this test pins"
    );

    // `target/<profile>`, which `cargo clean` empties, is the parent of the test binary's nearest
    // ancestor named `deps` (`target/<profile>/deps/<name>`) or `build`, where newer cargo puts it
    // (`target/<profile>/build/<package>/<hash>/out/<name>`). So every test binary of a profile
    // shares one unpacked archive.
    let exe = std::env::current_exe().expect("the test binary's path");
    let base = exe
        .ancestors()
        .find(|dir| {
            matches!(
                dir.file_name().and_then(|n| n.to_str()),
                Some("deps" | "build")
            )
        })
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .unwrap_or_else(std::env::temp_dir);
    let name = format!("act4-elfs-{}", &ARCHIVE_SHA256[..16]);
    let dir = base.join(&name);
    let complete = |dir: &Path| dir.join(".unpacked").exists();
    if !complete(&dir) {
        let own = base.join(format!("{name}.{}", std::process::id()));
        let _ = fs::remove_dir_all(&own);
        fs::create_dir_all(&own).unwrap_or_else(|e| panic!("{}: {e}", own.display()));
        let status = Command::new("tar")
            .arg("-xJf")
            .arg(ARCHIVE)
            .arg("-C")
            .arg(&own)
            .status()
            .expect("run tar, which unpacks the archive (with xz)");
        assert!(status.success(), "tar -xJf {ARCHIVE}: {status}");
        fs::write(own.join(".unpacked"), "").expect("mark the unpacked archive complete");
        if fs::rename(&own, &dir).is_err() {
            // Either another run finished first, or one that died left `dir` incomplete.
            if complete(&dir) {
                let _ = fs::remove_dir_all(&own);
            } else {
                let _ = fs::remove_dir_all(&dir);
                fs::rename(&own, &dir).expect("move the unpacked archive into place");
            }
        }
    }
    dir.join("elfs")
}

/// One suite's tests, by name, in name order.
fn suite(name: &str) -> Vec<(String, PathBuf)> {
    let dir = elf_dir().join(name);
    let mut tests: Vec<_> = fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
        .map(|entry| entry.expect("a directory entry").path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "elf"))
        .map(|path| {
            let test = path.file_stem().expect("a file name").to_string_lossy();
            (test.into_owned(), path)
        })
        .collect();
    tests.sort();
    tests
}

/// A test that disappears, or one that is added, is a reviewed change rather than a quiet one.
#[test]
fn each_suite_holds_its_tests() {
    for (name, count) in MUST_PASS.into_iter().chain([KNOWN_FAILURES]) {
        assert_eq!(suite(name).len(), count, "elfs/{name} in the archive");
    }
}

/// All 64 tests run, and every failure is reported, not only the first.
#[test]
fn the_i_and_m_tests_execute_prove_and_verify() {
    let mut failed = Vec::new();
    let mut ran = 0;
    for (name, _) in MUST_PASS {
        for (test, path) in suite(name) {
            let started = Instant::now();
            let outcome = run(&fs::read(&path).expect("read the ELF"));
            let seconds = started.elapsed().as_secs_f64();
            match outcome {
                Ok(()) => eprintln!("{test}: ok ({seconds:.1} s)"),
                Err(why) => {
                    eprintln!("{test}: FAILED ({seconds:.1} s): {why}");
                    failed.push(format!("{test}: {why}"));
                }
            }
            ran += 1;
        }
    }
    assert_eq!(ran, 64, "the I and M suites hold 64 tests");
    assert!(
        failed.is_empty(),
        "{} of {ran} ACT4 tests failed:\n{}",
        failed.len(),
        failed.join("\n")
    );
}

/// Each Misalign test still fails. One that passes fails this test: move the suite into
/// `MUST_PASS`, so that from then on it has to keep passing.
#[test]
fn the_misalign_tests_are_still_known_failures() {
    let (name, _) = KNOWN_FAILURES;
    let mut passing = Vec::new();
    for (test, path) in suite(name) {
        let started = Instant::now();
        let outcome = execute(&fs::read(&path).expect("read the ELF"));
        let seconds = started.elapsed().as_secs_f64();
        match outcome {
            Err(why) => eprintln!("{test}: known failure ({seconds:.1} s): {why}"),
            Ok(()) => {
                let why = format!("it passes now; move {name} into MUST_PASS");
                eprintln!("{test}: FAILED ({seconds:.1} s): {why}");
                passing.push(test);
            }
        }
    }
    assert!(
        passing.is_empty(),
        "{} {name} test(s) pass now ({}): move the suite into MUST_PASS, so that they have to keep \
         passing",
        passing.len(),
        passing.join(", ")
    );
}

/// Execute, then prove to the riscv phase and verify. Both must commit `PASS`.
fn run(elf: &[u8]) -> Result<(), String> {
    let mut prover = Prover::builder(elf)
        .log_stacked_height(SMALL_LOG_STACKED_HEIGHT)
        .build()
        .map_err(|e| format!("cannot build the prover: {e}"))?;
    let execution = prover
        .execute_chunked(Stdin::new())
        .map_err(|e| format!("execute: {e}"))?;
    committed_pass("execute", &execution.committed_bytes)?;
    let proof = prover
        .prove_to(Stdin::new(), Phase::Riscv)
        .map_err(|e| format!("prove: {e}"))?;
    committed_pass("the proof", proof.committed().as_bytes())
}

/// Execute only, without a prover's keys.
fn execute(elf: &[u8]) -> Result<(), String> {
    let execution = Prover::builder(elf)
        .execute_chunked(Stdin::new())
        .map_err(|e| format!("execute: {e}"))?;
    committed_pass("execute", &execution.committed_bytes)
}

/// `Ok` when the bytes `what` committed are `PASS`.
fn committed_pass(what: &str, bytes: &[u8]) -> Result<(), String> {
    if bytes == PASS {
        return Ok(());
    }
    Err(format!(
        "{what} committed {:?}",
        String::from_utf8_lossy(bytes)
    ))
}
