//! A precompile the AOT core runs while it writes records writes the interpreter's events.
//!
//! Each guest runs to its halt as one chunk: on the AOT core through the bootstrap stub's code,
//! which interprets every block, so every `ECALL` goes through `execute_syscall` as generated code
//! takes it; and on the interpreter. The interpreter moves a chunk's precompile events out of its
//! record and splits them into deferred records, joining the windows that chain from one event to
//! the next within a block; the AOT record's go through the same `defer` and `split`, and the two
//! are compared per syscall code in order. Between them the guests call every precompile family a
//! guest in the tree reaches but SHA-256, whose guest is too long for a test. The chunk's
//! local-memory chain is compared too: a precompile closes the CPU's window on every cell it
//! touches, and a chunk where that does not happen still matches in every other field.

use std::{collections::BTreeSet, sync::Arc};

use pico_aot_runtime::{AotEmulatorCore, AotProgram};
use pico_vm::{
    compiler::riscv::{
        compiler::{Compiler, SourceType},
        program::Program,
    },
    configs::stark_config::KoalaBearPoseidon2,
    emulator::{
        opts::{EmulatorOpts, ReplayWorkers, SnapshotMainMode},
        record::RecordBehavior,
        riscv::{record::EmulationRecord, record_digest::field_digests, syscalls::SyscallCode},
        stdin::EmulatorStdin,
    },
    mle::machine::riscv::emulate_with_opts,
};

/// The rows of `field_digests` the emulator writes into a CPU chunk's record while it runs: not the
/// public values the pipeline stamps afterwards, nor the events the chips derive later.
const WRITTEN: [&str; 3] = ["history", "add_events", "cpu_local_memory_chain"];

/// The largest chunk the AIRs admit, so that every guest below is one chunk on the interpreter as
/// it is on an AOT core with no chunk limit.
const ONE_CHUNK: u32 = 1 << 23;

struct Guest {
    name: &'static str,
    elf: &'static [u8],
    stdin: fn(&mut StdinBuilder),
    /// The codes the guest's precompile events are filed under.
    files_under: &'static [SyscallCode],
    /// The guest claims deferred proofs, so its deferred digest is nonzero.
    defers: bool,
}

type StdinBuilder = pico_vm::emulator::stdin::EmulatorStdinBuilder<Vec<u8>, KoalaBearPoseidon2>;

macro_rules! elf {
    ($file:literal) => {
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../perf/bench_data/rv64/",
            $file
        ))
    };
}

/// The inputs `vm/tests/common/record_parity.rs` gives these guests.
const GUESTS: [Guest; 8] = [
    Guest {
        name: "ed25519",
        elf: elf!("ed25519-elf"),
        stdin: |stdin| {
            let mut basepoint = [0x66u8; 32];
            basepoint[0] = 0x58;
            stdin.write(&basepoint);
            let mut negated = basepoint;
            negated[31] |= 0x80;
            stdin.write(&negated);
            let mut scalar = [0u8; 32];
            scalar[..4].copy_from_slice(&10u32.to_le_bytes());
            stdin.write(&scalar);
            scalar[4] = 1;
            stdin.write(&scalar);
        },
        files_under: &[SyscallCode::ED_ADD, SyscallCode::ED_DECOMPRESS],
        defers: false,
    },
    Guest {
        name: "poseidon2",
        elf: elf!("poseidon2-elf"),
        stdin: |stdin| stdin.write(&1u32),
        files_under: &[SyscallCode::POSEIDON2_PERMUTE],
        defers: false,
    },
    Guest {
        name: "tiny-keccak",
        elf: elf!("tiny-keccak-elf"),
        stdin: |stdin| stdin.write(&"x".repeat(10)),
        files_under: &[SyscallCode::KECCAK_PERMUTE],
        defers: false,
    },
    Guest {
        name: "k256",
        elf: elf!("k256-elf"),
        stdin: |_| {},
        files_under: &[
            SyscallCode::KECCAK_PERMUTE,
            SyscallCode::SECP256K1_ADD,
            SyscallCode::SECP256K1_DOUBLE,
        ],
        defers: false,
    },
    Guest {
        name: "bn254-fp",
        elf: elf!("bn254-fp-elf"),
        stdin: |_| {},
        files_under: &[
            SyscallCode::BN254_DOUBLE,
            SyscallCode::UINT256_MUL,
            SyscallCode::BN254_FP_ADD,
            SyscallCode::BN254_FP2_MUL,
        ],
        defers: false,
    },
    Guest {
        name: "bls12381-ws",
        elf: elf!("bls12381-elf-ws-add-double-decompress"),
        stdin: |_| {},
        files_under: &[
            SyscallCode::BLS12381_DECOMPRESS,
            SyscallCode::BLS12381_ADD,
            SyscallCode::BLS12381_DOUBLE,
            SyscallCode::BLS12381_FP_ADD,
        ],
        defers: false,
    },
    Guest {
        name: "bn254-ws",
        elf: elf!("bn254-elf-ws-add-double"),
        stdin: |_| {},
        files_under: &[
            SyscallCode::BN254_ADD,
            SyscallCode::BN254_DOUBLE,
            SyscallCode::BN254_FP_ADD,
        ],
        defers: false,
    },
    Guest {
        name: "aggregator",
        elf: elf!("aggregator-elf"),
        stdin: aggregator_stdin,
        files_under: &[],
        defers: true,
    },
];

/// Two claims over fib's real outputs, under made-up program ids, as the record-parity harness
/// writes them.
fn aggregator_stdin(stdin: &mut StdinBuilder) {
    let fib = Compiler::new(SourceType::RISCV, elf!("fib-elf"))
        .expect("the ELF parses")
        .compile();
    let outputs: Vec<Vec<u8>> = [10u32, 20]
        .iter()
        .map(|n| {
            let mut builder =
                EmulatorStdin::<Program, Vec<u8>>::new_builder::<KoalaBearPoseidon2>();
            builder.write(n);
            emulate_with_opts(fib.clone(), &builder.finalize(), opts())
                .expect("fib")
                .committed_bytes
        })
        .collect();
    let program_ids: Vec<[u32; 8]> = vec![
        std::array::from_fn(|i| i as u32 + 1),
        std::array::from_fn(|i| i as u32 + 101),
    ];
    stdin.write(&program_ids);
    stdin.write(&outputs);
}

/// Every field set, since `EmulatorOpts::default` reads the environment.
fn opts() -> EmulatorOpts {
    EmulatorOpts {
        chunk_size: ONE_CHUNK,
        chunk_batch_size: 1,
        max_cycles: Some(1 << 32),
        cycle_tracker: false,
        cost_estimator: false,
        snapshot_main: SnapshotMainMode::Interpreter,
        replay_workers: ReplayWorkers::Interpreter,
    }
}

/// The interpreter's record of the guest's one chunk, and every record it deferred, merged.
fn interpreted(
    program: Arc<Program>,
    stdin: &EmulatorStdin<Program, Vec<u8>>,
) -> (EmulationRecord, EmulationRecord) {
    let records = emulate_with_opts(program.clone(), stdin, opts())
        .expect("the guest runs under the interpreter")
        .records;
    let (mut cpu, deferred): (Vec<_>, Vec<_>) =
        records.into_iter().partition(|record| record.is_cpu_chunk);
    assert_eq!(cpu.len(), 1, "the guest is one chunk");
    let mut merged = EmulationRecord::new(program);
    for mut record in deferred {
        merged.append(&mut record);
    }
    (cpu.pop().unwrap(), merged)
}

/// The deferred records `split` makes of `deferred`, merged.
fn split(mut deferred: EmulationRecord) -> EmulationRecord {
    let mut merged = EmulationRecord::new(deferred.program.clone());
    for mut record in deferred.split(true, u32::MAX) {
        merged.append(&mut record);
    }
    merged
}

/// The AOT core's record of the guest's one chunk, written while the stub's code ran it.
fn emitted(program: Arc<Program>, stdin: &EmulatorStdin<Program, Vec<u8>>) -> EmulationRecord {
    let mut emu = AotEmulatorCore::new(program, stdin.inputs.to_vec());
    emu.emit_records();
    AotProgram::STUB
        .run(&mut emu)
        .expect("the guest runs under the AOT core");
    assert_eq!(emu.pc, 0, "the guest ran to its halt");
    emu.finish_emitted_chunk();
    let mut chunks = emu.take_emitted_chunks();
    assert_eq!(chunks.len(), 1, "the guest is one chunk");
    chunks.pop().unwrap().record
}

fn rows(record: &EmulationRecord, fields: &[&str]) -> Vec<(&'static str, usize, u64)> {
    field_digests(record)
        .into_iter()
        .filter(|(field, ..)| fields.contains(field))
        .collect()
}

#[test]
fn a_precompile_on_the_aot_core_writes_the_interpreters_events() {
    for guest in &GUESTS {
        let program = Compiler::new(SourceType::RISCV, guest.elf)
            .expect("the ELF parses")
            .compile();
        let mut builder = EmulatorStdin::<Program, Vec<u8>>::new_builder::<KoalaBearPoseidon2>();
        (guest.stdin)(&mut builder);
        let stdin = builder.finalize();

        let (interpreter, deferred) = interpreted(program.clone(), &stdin);
        let files: BTreeSet<SyscallCode> = deferred
            .precompile_events
            .sorted_groups()
            .into_iter()
            .map(|(code, _)| *code)
            .collect();
        assert_eq!(
            files,
            guest.files_under.iter().copied().collect(),
            "{}: the precompile events this test is there to compare",
            guest.name
        );
        assert!(
            interpreter
                .public_values
                .committed_value_digest
                .iter()
                .any(|&word| word != 0),
            "{}: nothing committed, so the digests compare nothing",
            guest.name
        );
        assert_eq!(
            interpreter
                .public_values
                .deferred_proofs_digest
                .iter()
                .any(|&word| word != 0),
            guest.defers,
            "{}: the deferred digest against whether the guest claims deferred proofs",
            guest.name
        );

        let mut aot = emitted(program, &stdin);
        let aot_deferred = split(aot.defer());
        assert_eq!(
            rows(&interpreter, &WRITTEN),
            rows(&aot, &WRITTEN),
            "{}: (field, len, digest), the interpreter's first",
            guest.name
        );
        assert_eq!(
            rows(&deferred, &["precompile_events"]),
            rows(&aot_deferred, &["precompile_events"]),
            "{}: the precompile events, per code in order, the interpreter's first",
            guest.name
        );
        assert_eq!(
            interpreter.public_values.committed_value_digest,
            aot.public_values.committed_value_digest,
            "{}: the committed digest the COMMIT ecalls wrote into the record",
            guest.name
        );
        assert_eq!(
            interpreter.public_values.deferred_proofs_digest,
            aot.public_values.deferred_proofs_digest,
            "{}: the deferred digest the COMMIT_DEFERRED_PROOFS ecalls wrote into the record",
            guest.name
        );
    }
}
