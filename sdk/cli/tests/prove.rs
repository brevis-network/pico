//! `cargo pico prove` and `cargo pico execute`, driven through the binary.
//!
//! An exit code alone passes on a prove that wrote an empty file, so the proving test re-reads what
//! the binary wrote and verifies it here, in a process that proved nothing.

use std::{
    collections::BTreeMap,
    path::Path,
    process::{Command, Output},
};

use pico_cli::{
    groth16::{GNARK_BIN_ENV, GNARK_IMAGE_ENV, KEYS_ENV},
    guest::encode_hex as hex,
    options::MAPPED_ENV,
};
use pico_prover::{
    Phase, ProofArtifact, ProveError, Prover, Stdin, ENV_NO_LONGER_READ, ENV_READ_BY_PROVER,
};

#[path = "../../prover/src/tests/scratch.rs"]
mod scratch;
use scratch::scratch_dir;

const FIB_ELF: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../vm/src/compiler/test_elf/fib-elf"
);

/// Calls the BN254 base-field precompiles, and needs no input.
const BN254_FP_ELF: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../perf/bench_data/rv64/bn254-fp-elf"
);

/// The smallest operating point at which the fib guest proves a whole chain, as the prover crate's
/// own chain tests use.
const LOG_STACKED_HEIGHT: &str = "22";

/// Enough for emulation, which is all `execute` needs.
const SMALL_LOG_STACKED_HEIGHT: &str = "20";

/// Above the backend's maximum, so the prover refuses it before keygen and before anything else.
const UNBUILDABLE_LOG_STACKED_HEIGHT: &str = "64";

/// What `prove` prints on stdout, each line by its start.
const PROVE_RESULTS: &[&str] = &[
    "proved and verified to ",
    "committed (",
    "committed_value_digest: ",
    "program id (",
    "wrote ",
];

fn prover_reads() -> impl Iterator<Item = &'static str> {
    ENV_READ_BY_PROVER.iter().map(|(name, _)| *name)
}

fn no_longer_read() -> impl Iterator<Item = &'static str> {
    ENV_NO_LONGER_READ.iter().map(|(name, _)| *name)
}

/// The binary with every variable it reads cleared, so the caller's environment cannot decide a
/// case.
fn cargo_pico(args: &[&str]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_cargo-pico"));
    command.arg("pico").args(args);
    for name in MAPPED_ENV
        .iter()
        .copied()
        .chain(prover_reads())
        .chain(no_longer_read())
    {
        command.env_remove(name);
    }
    command
        .env_remove(GNARK_BIN_ENV)
        .env_remove(GNARK_IMAGE_ENV)
        .env_remove(KEYS_ENV)
        .env_remove("RUST_LOG")
        .env_remove("RUST_LOGGER");
    command
}

/// Run with logging on: stdout holds every line of `results` and nothing else, while the log lines,
/// without which an empty or unchanged stdout would pass, are on stderr.
fn assert_logs_leave_stdout_to(results: &[&str], stdout: &str, stderr: &str) {
    assert!(
        stderr.lines().any(|line| line.contains("INFO")),
        "no log line on stderr:\n{stderr}"
    );
    for line in stdout.lines() {
        assert!(
            results.iter().any(|prefix| line.starts_with(prefix)),
            "not a result line on stdout: {line}"
        );
    }
    for prefix in results {
        assert!(
            stdout.lines().any(|line| line.starts_with(prefix)),
            "no `{prefix}` line on stdout:\n{stdout}"
        );
    }
}

fn run(command: &mut Command) -> (Output, String, String) {
    let out = command.output().expect("run cargo-pico");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    (out, stdout, stderr)
}

/// The fib guest commits `(n, F(n), F(n+1))` as three 32-byte big-endian words.
fn fib_commit(n: u32) -> Vec<u8> {
    let (mut a, mut b) = (0u32, 1u32);
    for _ in 0..n {
        (a, b) = (b, a.wrapping_add(b));
    }
    [n, a, b]
        .iter()
        .flat_map(|w| {
            let mut word = [0u8; 32];
            word[28..].copy_from_slice(&w.to_be_bytes());
            word
        })
        .collect()
}

/// The size `prove` reported for `path`, which must be the size of the file on disk.
fn reported_size(stdout: &str, path: &Path) -> u64 {
    let prefix = format!("wrote {} (", path.display());
    stdout
        .lines()
        .find_map(|line| line.strip_prefix(&prefix)?.strip_suffix(" bytes)"))
        .unwrap_or_else(|| panic!("no `wrote` line for {}:\n{stdout}", path.display()))
        .parse()
        .expect("reported size")
}

/// The program id `prove` printed, as `(labelled whitelist mode, hex)`.
fn printed_program_id(stdout: &str) -> (bool, &str) {
    let line = stdout
        .lines()
        .find(|line| line.starts_with("program id ("))
        .unwrap_or_else(|| panic!("no program id line:\n{stdout}"));
    let (label, id) = line
        .split_once("): 0x")
        .unwrap_or_else(|| panic!("malformed program id line: {line}"));
    (label == "program id (whitelist mode", id)
}

/// `--fast` and `--field` are refused by name, with what replaces them.
#[test]
fn removed_flags_are_refused_by_name_with_their_replacement() {
    for (args, replacement) in [
        (&["--fast"][..], "`--phase riscv`"),
        (&["--field", "kb"][..], "KoalaBear-only"),
        (&["--field"][..], "KoalaBear-only"),
    ] {
        let (out, _, stderr) = run(cargo_pico(&["prove", "--elf", FIB_ELF]).args(args));
        assert!(!out.status.success(), "{args:?} was accepted");
        assert!(
            stderr.contains("has been removed") && stderr.contains(replacement),
            "{args:?} did not name {replacement}:\n{stderr}"
        );
    }
}

/// `--evm` refuses what it can before keygen, which costs minutes: no gnark, both kinds of gnark, no
/// keys, a directory that is not a key set, a setup over an existing one, and a mode the on-chain
/// verifier is not set up for. None of the refusals makes a directory.
#[cfg(feature = "multi-field-transcript")]
#[test]
fn evm_refuses_what_it_can_before_keygen() {
    let dir = scratch_dir("evm");
    let output = dir.join("out");
    let output = output.to_str().expect("utf-8 path");
    let empty = dir.join("empty");
    let keyed = dir.join("keyed");
    for d in [&empty, &keyed] {
        std::fs::create_dir_all(d).expect("key dir");
    }
    std::fs::write(keyed.join("pk"), b"key").expect("pk");
    let (empty, keyed) = (
        empty.to_str().expect("utf-8 path"),
        keyed.to_str().expect("utf-8 path"),
    );
    let evm = |args: &[&str], env: &[(&str, &str)]| {
        let mut command = cargo_pico(&["prove", "--elf", FIB_ELF, "--output", output, "--evm"]);
        command.args(args).envs(env.iter().copied());
        command
    };
    let bin = [(GNARK_BIN_ENV, "pico-gnark")];
    for (mut command, refusal) in [
        (evm(&[], &[]), "`--evm` runs gnark for the Groth16 proof"),
        (
            evm(&[], &[bin[0], (GNARK_IMAGE_ENV, "pico-gnark")]),
            "not both",
        ),
        (evm(&[], &bin), "`--keys DIR`"),
        (evm(&["--keys", empty], &bin), "has no `pk`"),
        (
            evm(&["--setup", "--keys", keyed], &bin),
            "already holds a proving key",
        ),
        (evm(&["--setup"], &bin), "whitelist mode only"),
    ] {
        let (out, stdout, stderr) = run(&mut command);
        assert!(!out.status.success(), "`{refusal}` case was accepted");
        assert!(
            stderr.contains(refusal),
            "not refused for `{refusal}`:\n{stderr}"
        );
        assert!(
            !stderr.contains("prover: log_stacked_height"),
            "keygen ran before the `{refusal}` refusal:\n{stderr}"
        );
        assert!(stdout.is_empty(), "a refusal printed a result:\n{stdout}");
    }
    assert!(
        !Path::new(output).exists(),
        "a refused run made its output directory"
    );

    // Echoed like every other variable the CLI reads.
    let (_, _, stderr) = run(&mut evm(&[], &[bin[0], (KEYS_ENV, empty)]));
    for echoed in [
        format!("env: {GNARK_BIN_ENV}=pico-gnark -> gnark_bin(\"pico-gnark\")"),
        format!("env: {GNARK_IMAGE_ENV} not set"),
        format!("env: {KEYS_ENV}={empty} -> keys(\"{empty}\")"),
    ] {
        assert!(stderr.contains(&echoed), "missing `{echoed}`:\n{stderr}");
    }
}

/// Help lists no flag that only refuses, and every one that runs.
#[test]
fn prove_help_lists_only_what_can_run() {
    let (out, stdout, stderr) = run(&mut cargo_pico(&["prove", "--help"]));
    assert!(out.status.success(), "{stderr}");
    for flag in [
        "--elf",
        "--input",
        "--log-stacked-height",
        "--phase",
        "--output",
        "--evm",
        "--keys",
        "--setup",
    ] {
        assert!(stdout.contains(flag), "{flag} is not listed:\n{stdout}");
    }
    for flag in ["--pk", "--fast", "--field"] {
        assert!(!stdout.contains(flag), "{flag} is listed:\n{stdout}");
    }
}

/// The Groth16 flags need `--evm`, and `--evm` sets its own phase: the parser refuses each pairing
/// before anything runs. An unbuildable height keeps a parser that let one through from proving.
#[test]
fn the_groth16_flags_are_refused_without_evm() {
    let dir = scratch_dir("evm_flags");
    let output = dir.to_str().expect("utf-8 path");
    for (args, refusal) in [
        (
            &["--setup"][..],
            "the following required arguments were not provided",
        ),
        (
            &["--keys", "k"],
            "the following required arguments were not provided",
        ),
        (&["--evm", "--phase", "riscv"], "cannot be used with"),
    ] {
        let (out, _, stderr) = run(cargo_pico(&[
            "prove",
            "--elf",
            FIB_ELF,
            "--output",
            output,
            "--log-stacked-height",
            UNBUILDABLE_LOG_STACKED_HEIGHT,
        ])
        .args(args));
        assert!(!out.status.success(), "{args:?} was accepted");
        assert!(stderr.contains(refusal), "{args:?}:\n{stderr}");
    }
}

/// With logging on, in every layout, stdout still holds only the result lines a script reads; the
/// guest's own output is logged at INFO. `prove`'s are checked in the proving test.
#[test]
fn logs_go_to_stderr_and_leave_stdout_to_the_results() {
    for logger in ["flat", "forest", "forest-all", "tree"] {
        let (out, stdout, stderr) = run(cargo_pico(&[
            "execute",
            "--elf",
            BN254_FP_ELF,
            "--log-stacked-height",
            SMALL_LOG_STACKED_HEIGHT,
        ])
        .env("RUST_LOG", "info")
        .env("RUST_LOGGER", logger));
        assert!(out.status.success(), "{logger}:\n{stdout}\n{stderr}");
        assert_logs_leave_stdout_to(
            &["executed: ", "committed (", "precompiles: "],
            &stdout,
            &stderr,
        );
        assert_eq!(
            stderr.contains("warning: RUST_LOGGER=tree is none of"),
            logger == "tree",
            "{logger}: an unknown layout must be named, and only that one:\n{stderr}"
        );
    }
}

/// What a proof made outside whitelist mode cannot be used for is known from the options, so it is
/// said even when keygen is refused.
#[test]
fn what_a_phase_cannot_be_used_for_is_said_before_keygen() {
    let mut cases = vec![
        (Phase::Riscv, None),
        (
            Phase::Combine,
            Some("note: no other process can verify a combine proof"),
        ),
    ];
    if cfg!(feature = "multi-field-transcript") {
        cases.push((
            Phase::Wrap,
            Some("warning: outside whitelist mode the wrap circuit pins no whitelist root"),
        ));
    }
    for (phase, said) in cases {
        let (out, _, stderr) = run(&mut cargo_pico(&[
            "prove",
            "--elf",
            FIB_ELF,
            "--phase",
            &phase.to_string(),
            "--log-stacked-height",
            UNBUILDABLE_LOG_STACKED_HEIGHT,
        ]));
        assert!(!out.status.success(), "{phase}: keygen was not refused");
        assert!(
            stderr.contains("not a height the backend can prove"),
            "{phase}: refused for another reason:\n{stderr}"
        );
        match said {
            Some(said) => assert!(
                stderr.contains(said),
                "{phase}: `{said}` not said:\n{stderr}"
            ),
            None => assert!(
                !stderr.contains("note: ") && !stderr.contains("warning: "),
                "{phase}: said something:\n{stderr}"
            ),
        }
    }
}

#[test]
fn a_bare_integer_input_is_refused_with_its_typed_spelling() {
    let (out, _, stderr) = run(&mut cargo_pico(&[
        "execute", "--elf", FIB_ELF, "--input", "10",
    ]));
    assert!(!out.status.success());
    assert!(
        stderr.contains("`u32:10`") && stderr.contains("`u64:10`"),
        "{stderr}"
    );
}

/// A missing ELF stops the run right after the environment is read, so the echo is visible
/// without paying for keygen.
#[test]
fn every_variable_the_cli_reads_is_echoed() {
    let dir = scratch_dir("echo");
    let missing = dir.join("no-such-elf");
    let missing = missing.to_str().expect("utf-8 path");
    let output = dir.to_str().expect("utf-8 path");
    let args = ["prove", "--elf", missing, "--output", output];

    let (out, _, stderr) = run(&mut cargo_pico(&args));
    assert!(!out.status.success());
    assert!(stderr.contains("cannot read"), "{stderr}");
    for name in MAPPED_ENV {
        assert!(
            stderr.contains(&format!("env: {name} not set")),
            "{name} not echoed:\n{stderr}"
        );
    }
    // The other direction: a variable read and echoed, but missing from the list, would not be
    // cleared above, and the caller's environment could decide a case.
    for line in stderr.lines() {
        if let Some(rest) = line.strip_prefix("env: ") {
            let name = rest.split([' ', '=']).next().unwrap_or_default();
            assert!(MAPPED_ENV.contains(&name), "`{name}` is not in MAPPED_ENV");
        }
    }

    let mut command = cargo_pico(&args);
    command
        .env("CHUNK_SIZE", "4096")
        .env("PROVE_CONCURRENCY", "2")
        .env("VK_VERIFICATION", "true")
        .env("MLE_VK_MAP", "whitelist.bin")
        .env("MLE_VK_ROOT", "1 2 3 4 5 6 7 8");
    for name in prover_reads().chain(no_longer_read()) {
        command.env(name, "1");
    }
    let (out, _, stderr) = run(&mut command);
    assert!(!out.status.success());
    for expected in [
        "env: CHUNK_SIZE=4096 -> chunk_size(4096)",
        "env: PROVE_CONCURRENCY=2 -> concurrency(2)",
        "env: VK_VERIFICATION=true -> verify_keys(true)",
        "env: MLE_VK_MAP=whitelist.bin -> vk_map(\"whitelist.bin\")",
        "env: MLE_VK_ROOT=1 2 3 4 5 6 7 8 -> trusted_vk_root([1, 2, 3, 4, 5, 6, 7, 8])",
    ] {
        assert!(stderr.contains(expected), "missing `{expected}`:\n{stderr}");
    }
    for name in prover_reads() {
        assert!(
            stderr.contains(&format!("warning: {name}=1 is read by the prover itself")),
            "{name} not warned about:\n{stderr}"
        );
    }
    for name in no_longer_read() {
        assert!(
            stderr.contains(&format!("warning: {name}=1 is no longer read")),
            "{name} not warned about:\n{stderr}"
        );
    }

    // Outside whitelist mode the whitelist variables are echoed as ignored, not parsed.
    let (out, _, stderr) = run(cargo_pico(&args)
        .env("MLE_VK_MAP", "whitelist.bin")
        .env("MLE_VK_ROOT", "not a root"));
    assert!(!out.status.success());
    assert!(stderr.contains("cannot read"), "{stderr}");
    for (name, value) in [
        ("MLE_VK_MAP", "whitelist.bin"),
        ("MLE_VK_ROOT", "not a root"),
    ] {
        assert!(
            stderr.contains(&format!(
                "env: {name}={value} ignored: only whitelist mode reads it"
            )),
            "{name} not echoed as ignored:\n{stderr}"
        );
    }

    let (out, _, stderr) = run(cargo_pico(&args).env("VK_VERIFICATION", "yes"));
    assert!(!out.status.success());
    assert!(
        stderr.contains("VK_VERIFICATION=yes: expected `true` or `false`"),
        "{stderr}"
    );
}

#[test]
fn typed_and_raw_input_reach_the_guest_alike() {
    let committed = |input: &str| {
        let (out, stdout, stderr) = run(&mut cargo_pico(&[
            "execute",
            "--elf",
            FIB_ELF,
            "--input",
            input,
            "--log-stacked-height",
            SMALL_LOG_STACKED_HEIGHT,
        ]));
        assert!(out.status.success(), "{input}:\n{stdout}\n{stderr}");
        stdout
            .lines()
            .find(|line| line.starts_with("committed ("))
            .unwrap_or_else(|| panic!("no committed line:\n{stdout}"))
            .to_string()
    };
    let typed = committed("u32:10");
    assert_eq!(typed, committed("0x0a000000"));
    assert!(typed.ends_with(&hex(&fib_commit(10))), "{typed}");
}

/// Whitelist mode without its artifact is refused by `prove` and does not stop `execute`, which
/// keygens nothing and reads no option but the chunk size and the stacked height.
#[test]
fn execute_is_not_stopped_by_an_option_only_proving_checks() {
    let dir = scratch_dir("whitelist");
    let output = dir.to_str().expect("utf-8 path");
    let (out, _, stderr) = run(cargo_pico(&[
        "prove", "--elf", FIB_ELF, "--input", "u32:10", "--output", output,
    ])
    .env("VK_VERIFICATION", "true"));
    assert!(!out.status.success(), "prove ran without MLE_VK_MAP");
    assert!(
        stderr.contains("verify_keys(true) needs vk_map(path)"),
        "{stderr}"
    );

    // Values `prove` would refuse, in every variable emulation does not read.
    let (out, stdout, stderr) =
        run(
            cargo_pico(&["execute", "--elf", FIB_ELF, "--input", "u32:10"])
                .env("VK_VERIFICATION", "1")
                .env("MLE_VK_MAP", "whitelist.bin")
                .env("MLE_VK_ROOT", "not a root")
                .env("PROVE_CONCURRENCY", "0"),
        );
    assert!(out.status.success(), "{stdout}\n{stderr}");
    assert!(
        !stderr.contains("prover: log_stacked_height"),
        "execute keygen'd:\n{stderr}"
    );
    assert!(stderr.contains("env: CHUNK_SIZE not set"), "{stderr}");
    for name in [
        "VK_VERIFICATION",
        "MLE_VK_MAP",
        "MLE_VK_ROOT",
        "PROVE_CONCURRENCY",
    ] {
        assert!(
            !stderr.contains(&format!("env: {name}")),
            "execute read {name}:\n{stderr}"
        );
    }
    assert!(
        stdout
            .lines()
            .any(|line| line.starts_with("committed (") && line.ends_with(&hex(&fib_commit(10)))),
        "{stdout}"
    );
}

/// One `NAME=n` per precompile the run called, by name, and the counts are the prover's own.
#[test]
fn execute_prints_the_precompile_calls_the_prover_counts() {
    let (out, stdout, stderr) = run(&mut cargo_pico(&[
        "execute",
        "--elf",
        BN254_FP_ELF,
        "--log-stacked-height",
        SMALL_LOG_STACKED_HEIGHT,
    ]));
    assert!(out.status.success(), "{stdout}\n{stderr}");
    let printed: Vec<(String, u64)> = stdout
        .lines()
        .find_map(|line| line.strip_prefix("precompiles: "))
        .unwrap_or_else(|| panic!("no precompiles line:\n{stdout}"))
        .split(' ')
        .map(|call| {
            let (name, n) = call.split_once('=').expect("NAME=n");
            (name.to_string(), n.parse().expect("a count"))
        })
        .collect();
    assert!(
        printed.windows(2).all(|pair| pair[0].0 < pair[1].0),
        "not one per precompile by name: {printed:?}"
    );

    let calls = Prover::builder(&std::fs::read(BN254_FP_ELF).expect("bn254-fp elf"))
        .log_stacked_height(SMALL_LOG_STACKED_HEIGHT.parse().unwrap())
        .execute(Stdin::new())
        .expect("execute")
        .precompile_calls;
    assert!(calls.len() > 1, "one precompile orders nothing: {calls:?}");
    let expected: BTreeMap<String, u64> = calls
        .iter()
        .map(|(code, &n)| (code.to_string(), n))
        .collect();
    assert_eq!(printed.into_iter().collect::<BTreeMap<_, _>>(), expected);
}

/// The RISC-V file verifies from the ELF at the same height and mode. A combine file made outside
/// whitelist mode is refused by name: the recursion key is not a function of the ELF, and this
/// process keygen'd none. The program id printed is the one this process derives for the same ELF,
/// height and mode.
#[test]
fn what_prove_writes_is_answered_for_in_a_fresh_process() {
    let dir = scratch_dir("prove");
    let output = dir.to_str().expect("utf-8 path");
    let verifier = Prover::builder(&std::fs::read(FIB_ELF).expect("fib elf"))
        .log_stacked_height(LOG_STACKED_HEIGHT.parse().unwrap())
        .build()
        .expect("verifier");

    for phase in [Phase::Riscv, Phase::Combine] {
        let (out, stdout, stderr) = run(cargo_pico(&[
            "prove",
            "--elf",
            FIB_ELF,
            "--input",
            "u32:10",
            "--phase",
            &phase.to_string(),
            "--log-stacked-height",
            LOG_STACKED_HEIGHT,
            "--output",
            output,
        ])
        // Left over from a whitelist run; outside whitelist mode nothing reads them.
        .env("MLE_VK_MAP", "whitelist.bin")
        .env("MLE_VK_ROOT", "1 2 3 4 5 6 7 8")
        .env("RUST_LOG", "info"));
        assert!(out.status.success(), "{phase}:\n{stdout}\n{stderr}");
        assert_logs_leave_stdout_to(PROVE_RESULTS, &stdout, &stderr);
        // Known from the options alone, so said before keygen: the `prover:` line follows keygen.
        let note = stderr.find("note: no other process can verify a combine proof");
        if phase == Phase::Combine {
            let noted_at = note.expect("no note for a combine proof outside whitelist mode");
            let keygen_done_at = stderr.find("prover: ").expect("the prover line");
            assert!(noted_at < keygen_done_at, "noted after keygen:\n{stderr}");
        } else {
            assert!(note.is_none(), "{phase}: noted about combine:\n{stderr}");
        }
        assert_eq!(
            printed_program_id(&stdout),
            (
                verifier.verify_keys(),
                hex(&verifier.program_id().vkey_hash()).as_str()
            ),
            "{phase}: not this ELF's program id at this height and mode"
        );

        let path = dir.join(format!("proof-{phase}.pico"));
        let size = std::fs::metadata(&path).expect("proof file").len();
        assert!(size > 0, "{phase}: empty proof file");
        assert_eq!(reported_size(&stdout, &path), size);

        let artifact = ProofArtifact::read(&path).expect("read the proof file");
        assert_eq!(artifact.phase(), phase);
        match (phase, verifier.verify_artifact(artifact)) {
            (Phase::Riscv, Ok(proof)) => {
                assert_eq!(proof.committed().as_bytes(), fib_commit(10));
            }
            (Phase::Combine, Err(ProveError::WhitelistRequired { phase })) => {
                assert_eq!(phase, Phase::Combine);
            }
            (phase, result) => panic!("{phase}: unexpected {:?}", result.map(|_| ())),
        }
    }

    // The file that just verified, with one bit flipped: once in the middle of its body, then,
    // starting again from the honest bytes, once near its end. Whichever check refuses each,
    // neither may verify, or the acceptance above says nothing about what was written.
    let path = dir.join("proof-riscv.pico");
    let honest = std::fs::read(&path).expect("proof file");
    for at in [honest.len() / 2, honest.len() - 64] {
        let mut bytes = honest.clone();
        bytes[at] ^= 1;
        std::fs::write(&path, bytes).expect("rewrite the proof file");
        let verified = ProofArtifact::read(&path).and_then(|a| verifier.verify_artifact(a));
        assert!(
            verified.is_err(),
            "a proof file corrupted at byte {at} verified"
        );
    }
}

/// The whitelist the repository ships, with the root its `mle_vk_root.txt` pins.
#[cfg(feature = "multi-field-transcript")]
fn shipped_whitelist() -> (String, String) {
    let dir = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../vm/src/mle/shape_vk_bins"
    );
    let root = std::fs::read_to_string(format!("{dir}/mle_vk_root.txt"))
        .expect("mle_vk_root.txt")
        .lines()
        .find_map(|line| line.strip_prefix("MLE_VK_ROOT=\"")?.strip_suffix('"'))
        .expect("an MLE_VK_ROOT line")
        .to_string();
    (format!("{dir}/mle_vk_map_kb.bin"), root)
}

/// `--evm` end to end, with a setup and then with its keys: each run proves in whitelist mode, gnark
/// proves and verifies the Groth16 proof, and `inputs.json` holds what the verifier contract is
/// called with. A gnark that did not write the proof, or wrote another one, is caught by reading
/// the files back and verifying the proof in a separate gnark process.
///
/// Run with `PICO_GNARK_BIN` naming a `pico-gnark` binary: `cargo test --release -p pico-cli --test
/// prove -- --ignored evm_proves`.
#[cfg(feature = "multi-field-transcript")]
#[test]
#[ignore = "a whitelist-mode wrap proof and a Groth16 setup: tens of GB and several minutes"]
fn evm_proves_to_groth16_and_writes_what_the_verifier_is_called_with() {
    let gnark = std::env::var(GNARK_BIN_ENV)
        .unwrap_or_else(|_| panic!("set {GNARK_BIN_ENV} to a pico-gnark binary"));
    let (map, root) = shipped_whitelist();
    let dir = scratch_dir("evm_chain");
    let keys = dir.join("groth16");
    let whitelist = |command: &mut Command| {
        command
            .env("VK_VERIFICATION", "true")
            .env("MLE_VK_MAP", &map)
            .env("MLE_VK_ROOT", &root)
            .env(GNARK_BIN_ENV, &gnark)
            .env("RUST_LOG", "info");
    };

    for (label, extra) in [
        ("setup", vec!["--setup"]),
        ("keys", vec!["--keys", keys.to_str().expect("utf-8 path")]),
    ] {
        let output = dir.join(label);
        let mut args = vec![
            "prove",
            "--elf",
            FIB_ELF,
            "--input",
            "u32:10",
            "--evm",
            "--output",
            output.to_str().expect("utf-8 path"),
        ];
        if label == "setup" {
            // Into the directory the second run reads.
            args.extend(["--keys", keys.to_str().expect("utf-8 path")]);
        }
        args.extend(extra);
        let mut command = cargo_pico(&args);
        whitelist(&mut command);
        let (out, stdout, stderr) = run(&mut command);
        assert!(out.status.success(), "{label}:\n{stdout}\n{stderr}");
        assert_logs_leave_stdout_to(PROVE_RESULTS, &stdout, &stderr);
        let (whitelisted, id) = printed_program_id(&stdout);
        assert!(
            whitelisted,
            "{label}: not a whitelist-mode proof:\n{stdout}"
        );

        let proof = output.join("proof.data");
        let verified = Command::new(&gnark)
            .args(["-cmd", "verify", "-vk"])
            .arg(keys.join("vk"))
            .arg("-proof")
            .arg(&proof)
            .output()
            .expect("run gnark verify");
        assert!(
            verified.status.success(),
            "{label}: gnark does not verify the proof `prove` wrote:\n{}",
            String::from_utf8_lossy(&verified.stdout)
        );

        let words: Vec<String> = std::fs::read_to_string(&proof)
            .expect("proof.data")
            .trim()
            .split(',')
            .map(str::to_string)
            .collect();
        let inputs: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(output.join("inputs.json")).expect("inputs.json"),
        )
        .expect("inputs.json is json");
        assert_eq!(inputs["riscvVKey"], format!("0x{id}"), "{label}");
        assert_eq!(
            words[12],
            format!("0x{id}"),
            "{label}: the proof's vkey_hash"
        );
        assert_eq!(
            inputs["publicValues"],
            format!("0x{}", hex(&fib_commit(10))),
            "{label}"
        );
        // The digest the circuit exposes: the committed_value_digest `prove` printed, with its top
        // three bits cleared to fit one BN254 element.
        let digest = stdout
            .lines()
            .find_map(|line| line.strip_prefix("committed_value_digest: "))
            .expect("a committed_value_digest line");
        let mut masked = ::hex::decode(digest).expect("hex digest");
        masked[0] &= 0x1f;
        assert_eq!(
            inputs["committedValuesDigest"],
            format!("0x{}", hex(&masked)),
            "{label}"
        );
        assert_eq!(
            words[13],
            format!("0x{}", hex(&masked)),
            "{label}: the proof's digest"
        );
        let calldata: Vec<&str> = inputs["proof"]
            .as_array()
            .expect("a proof array")
            .iter()
            .map(|w| w.as_str().expect("a word"))
            .collect();
        assert_eq!(
            calldata,
            words[..12],
            "{label}: the calldata is not the proof's"
        );
    }
    for file in ["pk", "vk", "ccs", "manifest.json", "Groth16Verifier.sol"] {
        assert!(keys.join(file).is_file(), "the setup wrote no `{file}`");
    }
}
