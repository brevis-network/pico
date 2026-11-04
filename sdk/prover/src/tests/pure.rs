//! Pure `execute` against `execute_chunked`: the same committed bytes and cycles when the chunked
//! emulation completes, and a failure of the same kind when it does not.
//!
//! Without AOT code `execute` runs the stepping interpreter, which also runs the system calls and
//! unconstrained regions in AOT mode; the guests here between them call every precompile family,
//! the hooks and unconstrained regions. The AOT path is checked by `pure_aot_library_*`, which
//! builds each guest's library with cargo and so is ignored by default.

use std::mem::discriminant;

use super::fixture::{COMMIT_OUT_OF_RANGE_ELF, FIB_ELF, POSEIDON2_ELF};
use crate::{ExecuteEngine, ProveError, Prover, ProverBuilder, Stdin};

macro_rules! bench_elf {
    ($name:literal) => {
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../perf/bench_data/rv64/",
            $name
        ))
        .as_slice()
    };
}

fn ed25519_stdin() -> Stdin {
    let mut basepoint = [0x66u8; 32];
    basepoint[0] = 0x58;
    let mut negated = basepoint;
    negated[31] |= 0x80;
    let mut scalar = [0u8; 32];
    scalar[..4].copy_from_slice(&10u32.to_le_bytes());
    let mut second = scalar;
    second[4] = 1;
    let mut stdin = Stdin::new();
    stdin
        .write(&basepoint)
        .write(&negated)
        .write(&scalar)
        .write(&second);
    stdin
}

fn bytes(data: &[u8]) -> Stdin {
    let mut stdin = Stdin::new();
    stdin.write_bytes(data);
    stdin
}

/// The guests, each with the input it reads, or none.
fn guests() -> Vec<(&'static str, &'static [u8], Stdin)> {
    let keccak_input: String = (0..300).map(|_| 'x').collect();
    vec![
        ("fib", FIB_ELF, Stdin::from(&20u32)),
        ("poseidon2", POSEIDON2_ELF, Stdin::from(&8u32)),
        ("ed25519", bench_elf!("ed25519-elf"), ed25519_stdin()),
        (
            "tiny-keccak",
            bench_elf!("tiny-keccak-elf"),
            Stdin::from(&keccak_input),
        ),
        (
            "commit-out-of-range",
            COMMIT_OUT_OF_RANGE_ELF,
            Stdin::from(&None::<u32>),
        ),
        (
            "commit-out-of-range, fails",
            COMMIT_OUT_OF_RANGE_ELF,
            Stdin::from(&Some(8u32)),
        ),
        (
            "chip-coverage",
            bench_elf!("chip-coverage-elf"),
            Stdin::new(),
        ),
        ("coprocessor", bench_elf!("coprocessor-elf"), Stdin::new()),
        (
            "standard-io",
            bench_elf!("standard-io-elf"),
            Stdin::from_input(b"pure execute"),
        ),
        ("k256", bench_elf!("k256-elf"), Stdin::new()),
        ("sha2", bench_elf!("sha2-elf"), bytes(b"abc")),
        ("sha3", bench_elf!("sha3-elf"), bytes(b"abc")),
        ("bn254", bench_elf!("bn254-elf-ws-add-double"), Stdin::new()),
        ("bn254-fp", bench_elf!("bn254-fp-elf"), Stdin::new()),
        (
            "bls12381",
            bench_elf!("bls12381-elf-ws-add-double-decompress"),
            Stdin::new(),
        ),
        ("bls12381-fp", bench_elf!("bls12381-fp-elf"), Stdin::new()),
    ]
}

/// `pure`'s `execute` agrees with `execute_chunked` on `stdin`.
fn assert_agrees(name: &str, elf: &[u8], pure: &ProverBuilder, stdin: Stdin) {
    let chunked = Prover::builder(elf).execute_chunked(stdin.clone());
    let executed = pure.execute(stdin);
    match (chunked, executed) {
        (Ok(chunked), Ok(executed)) => {
            assert_eq!(
                executed.committed_bytes, chunked.committed_bytes,
                "{name}: the committed bytes differ"
            );
            assert_eq!(executed.cycles, chunked.cycles, "{name}: the cycles differ");
        }
        (Err(chunked), Err(executed)) => assert_eq!(
            discriminant(&executed),
            discriminant(&chunked),
            "{name}: the failures differ: execute {executed}, execute_chunked {chunked}"
        ),
        (chunked, executed) => panic!(
            "{name}: only one completes: execute_chunked {:?}, execute {:?}",
            chunked.map(|e| e.cycles),
            executed.map(|e| e.cycles)
        ),
    }
}

#[test]
fn interpreter_agrees_with_chunked() {
    for (name, elf, stdin) in guests() {
        let builder = Prover::builder(elf);
        assert_eq!(builder.execute_engine(), ExecuteEngine::Interpreter);
        assert_agrees(name, elf, &builder, stdin);
    }
}

/// The guests above call a precompile of every family, so the comparison covers each.
#[test]
fn the_guests_call_every_precompile_family() {
    use pico_vm::emulator::riscv::syscalls::SyscallCode::*;
    let mut called = std::collections::BTreeSet::new();
    for (_, elf, stdin) in guests() {
        if let Ok(execution) = Prover::builder(elf).execute_chunked(stdin) {
            called.extend(execution.precompile_calls.into_keys());
        }
    }
    for code in [
        SHA_EXTEND,
        SHA_COMPRESS,
        KECCAK_PERMUTE,
        POSEIDON2_PERMUTE,
        ED_ADD,
        ED_DECOMPRESS,
        SECP256K1_ADD,
        SECP256K1_DOUBLE,
        BN254_ADD,
        BN254_DOUBLE,
        BN254_FP_ADD,
        BN254_FP2_MUL,
        BLS12381_ADD,
        BLS12381_DOUBLE,
        BLS12381_DECOMPRESS,
        BLS12381_FP_ADD,
        BLS12381_FP2_MUL,
        UINT256_MUL,
    ] {
        assert!(called.contains(&code), "no guest here calls {code:?}");
    }
}

/// Every ACT4 test, the known failures included: the stepping interpreter decodes and runs each
/// instruction as the chunked emulation does.
#[test]
fn interpreter_agrees_with_chunked_on_act4() {
    use super::act4::{suite, KNOWN_FAILURES, MUST_PASS};
    let suites = MUST_PASS
        .iter()
        .chain([&KNOWN_FAILURES])
        .map(|(name, _)| *name);
    for name in suites {
        for (test, path) in suite(name) {
            let elf = std::fs::read(&path).expect("ACT4 ELF");
            assert_agrees(
                &format!("{name}/{test}"),
                &elf,
                &Prover::builder(&elf),
                Stdin::new(),
            );
        }
    }
}

#[test]
fn require_pure_aot_refuses_the_interpreter() {
    let refused = Prover::builder(FIB_ELF)
        .require_pure_aot(true)
        .execute(Stdin::from(&20u32));
    assert!(
        matches!(refused, Err(ProveError::PureAotRequired)),
        "{refused:?}"
    );
}

#[test]
fn a_built_prover_executes_as_its_builder() {
    let prover = Prover::builder(FIB_ELF)
        .log_stacked_height(super::fixture::SMALL_LOG_STACKED_HEIGHT)
        .build()
        .expect("prover");
    let from_prover = prover.execute(Stdin::from(&20u32)).expect("execute");
    let from_builder = Prover::builder(FIB_ELF)
        .execute(Stdin::from(&20u32))
        .expect("execute");
    assert_eq!(from_prover, from_builder);
}

/// Builds each guest's pure-mode library and checks the AOT path against `execute_chunked`, and a
/// library against an ELF it was not generated from.
#[cfg(feature = "pure-build")]
#[test]
#[ignore = "builds a library per guest with cargo; run with --ignored --features pure-build"]
fn pure_aot_library_agrees_with_chunked() {
    use std::sync::Arc;

    use crate::{build_pure_library, PureBuildOptions, PureLibrary};

    let cache = super::fixture::scratch_dir("pure-aot");
    for (name, elf, stdin) in guests() {
        let path = build_pure_library(elf, &cache, &PureBuildOptions::default())
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        // SAFETY: built just now by the generator.
        let library = Arc::new(unsafe { PureLibrary::load(&path) }.expect("load"));
        let builder = Prover::builder(elf)
            .pure_aot_library(library.clone())
            .require_pure_aot(true);
        assert_eq!(builder.execute_engine(), ExecuteEngine::Aot);
        assert_agrees(name, elf, &builder, stdin);

        let other = Prover::builder(FIB_ELF).pure_aot_library(library);
        if elf != FIB_ELF {
            assert!(
                matches!(
                    other.execute(Stdin::from(&20u32)),
                    Err(ProveError::PureAotElfMismatch { .. })
                ),
                "{name}: a library ran against another ELF"
            );
        }
    }
}
