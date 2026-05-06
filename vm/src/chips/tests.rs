//! Common test functions for RISC-V chips.

use crate::{
    chips::chips::riscv_memory::initialize_finalize::{
        MemoryChipType, MemoryInitializeFinalizeChip,
    },
    compiler::riscv::program::Program,
    configs::{config::StarkGenericConfig, stark_config::KoalaBearPoseidon2},
    emulator::{
        opts::EmulatorOpts,
        record::RecordBehavior,
        riscv::{emulator::RiscvEmulator, record::EmulationRecord},
        stdin::EmulatorStdin,
    },
    instances::{chiptype::riscv_chiptype::RiscvChipType, machine::simple::SimpleMachine},
    machine::{
        chip::{ChipBehavior, MetaChip},
        machine::MachineBehavior,
        prover::BaseProver,
    },
    primitives::consts::RISCV_NUM_PVS,
};
use p3_koala_bear::KoalaBear;
use p3_matrix::Matrix;
use std::sync::Arc;

pub fn run_test(program: Program, test_name: &str) {
    println!("Creating {test_name} program");
    let program = Arc::new(program);

    println!("Setting up stdin");
    let stdin_builder = EmulatorStdin::<Program, Vec<u8>>::new_builder::<KoalaBearPoseidon2>();
    let (stdin, _proofs) = stdin_builder.finalize();

    println!("Setting up chips");
    let chips = vec![
        MetaChip::test_no_lookup(RiscvChipType::<KoalaBear>::Program(Default::default())),
        MetaChip::test_no_lookup(RiscvChipType::<KoalaBear>::Mul(Default::default())),
        MetaChip::test_no_lookup(RiscvChipType::<KoalaBear>::DivRem(Default::default())),
        MetaChip::test_no_lookup(RiscvChipType::<KoalaBear>::Add(Default::default())),
        MetaChip::test_no_lookup(RiscvChipType::<KoalaBear>::Sub(Default::default())),
        MetaChip::test_no_lookup(RiscvChipType::<KoalaBear>::Addw(Default::default())),
        MetaChip::test_no_lookup(RiscvChipType::<KoalaBear>::Subw(Default::default())),
        MetaChip::test_no_lookup(RiscvChipType::<KoalaBear>::SR(Default::default())),
        MetaChip::test_no_lookup(RiscvChipType::<KoalaBear>::MemoryReadWrite(
            Default::default(),
        )),
        MetaChip::test_no_lookup(RiscvChipType::<KoalaBear>::MemoryLocal(Default::default())),
        MetaChip::test_no_lookup(RiscvChipType::<KoalaBear>::MemoryInitialize(
            MemoryInitializeFinalizeChip::new(MemoryChipType::Initialize),
        )),
        MetaChip::test_no_lookup(RiscvChipType::<KoalaBear>::MemoryFinalize(
            MemoryInitializeFinalizeChip::new(MemoryChipType::Finalize),
        )),
    ];

    test_rv64_prove_and_verify(program, stdin, chips);
}

/// Run emulation and return all records.
pub(crate) fn test_rv64_emulate(
    program: Arc<Program>,
    stdin: EmulatorStdin<Program, Vec<u8>>,
) -> Vec<crate::emulator::riscv::record::EmulationRecord> {
    test_rv64_emulate_with_opts(program, stdin, EmulatorOpts::default())
}

/// Run emulation with custom opts and return all records.
pub(crate) fn test_rv64_emulate_with_opts(
    program: Arc<Program>,
    stdin: EmulatorStdin<Program, Vec<u8>>,
    opts: EmulatorOpts,
) -> Vec<crate::emulator::riscv::record::EmulationRecord> {
    println!("Setting up emulator (chunk_size={})", opts.chunk_size);
    let mut emulator = RiscvEmulator::new_single::<KoalaBear>(program.clone(), opts, None);

    emulator.write_stdin(&stdin);

    println!("Emulating");
    let mut all_records = vec![];
    loop {
        let report = emulator
            .emulate_batch(&mut |record| {
                all_records.push(record);
            })
            .unwrap();
        if report.done {
            break;
        }
    }

    all_records
}

/// Prove and verify using a specific record.
pub(crate) fn test_rv64_prove_and_verify_chunk(
    program: Arc<Program>,
    chips: Vec<MetaChip<KoalaBear, RiscvChipType<KoalaBear>>>,
    record: crate::emulator::riscv::record::EmulationRecord,
) {
    println!("Setting up machine");
    let config = KoalaBearPoseidon2::test();
    let machine = SimpleMachine::new(config.clone(), chips, RISCV_NUM_PVS);

    println!("Setting up prover keys");
    let prover = BaseProver::new();
    let (pk, vk) = prover.setup_keys(&config, &machine.base_machine().chips(), &program);

    println!("Generate main");
    let chips_and_main = prover.generate_main(&machine.base_machine().chips(), &record);
    println!("Chips and main count: {}", chips_and_main.len());
    for (i, (_, trace)) in chips_and_main.iter().enumerate() {
        println!("Chip {} trace height: {}", i, trace.height());
    }

    assert!(
        !chips_and_main.is_empty(),
        "should have at least one chip trace"
    );

    println!("Commit main");
    let main_commitment = prover.commit_main(&config, &record, chips_and_main.clone());

    let main_commitment = main_commitment.expect("should have main commitment");

    println!("Creating challenger");
    let mut challenger = config.challenger();
    pk.observed_by(&mut challenger);

    println!("Proving");
    let proof = prover.prove(
        &config,
        &machine.base_machine().chips(),
        &pk,
        main_commitment,
        &mut challenger,
        0,
        RISCV_NUM_PVS,
    );

    println!("Verifying");
    let meta_proof =
        crate::machine::proof::MetaProof::new(vec![proof].into(), vec![vk.clone()].into(), None);

    machine
        .verify(&meta_proof, &vk)
        .expect("proof should verify");

    println!("Done");
}

/// Run extra_record for all active chips to populate derived events
/// (e.g. global_lookup_events from MemoryInitFinalize, byte_lookups from GlobalChip).
pub(crate) fn run_extra_records(
    chips: &[MetaChip<KoalaBear, RiscvChipType<KoalaBear>>],
    record: &mut EmulationRecord,
) {
    let mut extra = EmulationRecord::default();
    for chip in chips {
        if chip.is_active(record) {
            chip.extra_record(record, &mut extra);
        }
    }
    record.append(&mut extra);
}

/// Find the first record containing events for the given syscall code.
pub(crate) fn find_record_with_events(
    records: Vec<EmulationRecord>,
    syscall_code: crate::emulator::riscv::syscalls::SyscallCode,
) -> EmulationRecord {
    records
        .into_iter()
        .find(|r| {
            r.precompile_events
                .get_events(syscall_code)
                .is_some_and(|evts| !evts.is_empty())
        })
        .unwrap_or_else(|| panic!("No record contains {:?} events", syscall_code))
}

/// Count precompile events of a given syscall code in a record.
pub(crate) fn count_events(
    record: &EmulationRecord,
    syscall_code: crate::emulator::riscv::syscalls::SyscallCode,
) -> usize {
    record.get_precompile_events(syscall_code).len()
}

/// Count total precompile events across all records.
pub(crate) fn count_total_events(
    records: &[EmulationRecord],
    syscall_code: crate::emulator::riscv::syscalls::SyscallCode,
) -> usize {
    records.iter().map(|r| count_events(r, syscall_code)).sum()
}

/// Common function for proving and verifying RISC-V programs.
/// Uses only the first emulation record (CPU/ALU/Memory events).
pub fn test_rv64_prove_and_verify(
    program: Arc<Program>,
    stdin: EmulatorStdin<Program, Vec<u8>>,
    chips: Vec<MetaChip<KoalaBear, RiscvChipType<KoalaBear>>>,
) {
    let all_records = test_rv64_emulate(program.clone(), stdin);

    let mut record = all_records.first().cloned().unwrap();
    println!("CPU events count: {}", record.cpu_events.len());
    println!("ADD events count: {}", record.add_events.len());
    println!("SUB events count: {}", record.sub_events.len());
    println!("MUL events count: {}", record.mul_events.len());
    println!("DIVREM events count: {}", record.divrem_events.len());
    println!("LT events count: {}", record.lt_events.len());
    println!("Bitwise events count: {}", record.bitwise_events.len());

    // Chain extra_record to populate derived events (e.g. global_lookup_events).
    run_extra_records(&chips, &mut record);
    println!(
        "Memory init events: {}, finalize events: {}, global events: {}",
        record.memory_initialize_events.len(),
        record.memory_finalize_events.len(),
        record.global_lookup_events.len(),
    );

    test_rv64_prove_and_verify_chunk(program, chips, record);
}
