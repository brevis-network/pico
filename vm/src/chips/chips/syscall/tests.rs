use crate::{
    chips::{chips::syscall::SyscallChunkKind, tests::test_rv64_prove_and_verify},
    compiler::riscv::{instruction::Instruction, opcode::Opcode, program::Program},
    configs::stark_config::KoalaBearPoseidon2,
    emulator::{
        riscv::{record::EmulationRecord, syscalls::SyscallEvent},
        stdin::EmulatorStdin,
    },
    instances::chiptype::riscv_chiptype::RiscvChipType,
    machine::chip::{ChipBehavior, MetaChip},
};
use p3_koala_bear::KoalaBear;
use std::sync::Arc;

/// Construct a Program that invokes SHA_COMPRESS syscall.
fn create_sha_compress_program() -> Program {
    // SHA_COMPRESS syscall code = 0x00010106
    let syscall_code: u64 = 0x00010106;
    // Input and output addresses must be 8-byte aligned
    let input_addr: u64 = 0x1000;
    let output_addr: u64 = 0x2000;

    let instructions = vec![
        // Set x5 = syscall code (SHA_COMPRESS)
        Instruction::new(Opcode::ADD, 5, 0, syscall_code, false, true),
        // Set x10 = input address
        Instruction::new(Opcode::ADD, 10, 0, input_addr, false, true),
        // Set x11 = output address
        Instruction::new(Opcode::ADD, 11, 0, output_addr, false, true),
        // ECALL to invoke SHA_COMPRESS
        Instruction::new(Opcode::ECALL, 0, 0, 0, false, false),
    ];
    Program::new(instructions, 0x10000, 0x10000)
}

#[test]
fn test_rv64_syscall_chip() {
    println!("Creating SHA_COMPRESS syscall program");
    let program = Arc::new(create_sha_compress_program());

    println!("Setting up stdin");
    let stdin_builder = EmulatorStdin::<Program, Vec<u8>>::new_builder::<KoalaBearPoseidon2>();
    let (stdin, _proofs) = stdin_builder.finalize();

    println!("Setting up chips");
    let chips = vec![
        MetaChip::test_no_lookup(RiscvChipType::<KoalaBear>::Program(Default::default())),
        MetaChip::test_no_lookup(RiscvChipType::<KoalaBear>::SyscallRiscv(
            crate::chips::chips::syscall::SyscallChip::riscv(),
        )),
    ];

    test_rv64_prove_and_verify(program, stdin, chips);
}

#[test]
#[should_panic(expected = "frozen 48-bit proof address contract")]
fn syscall_extra_record_rejects_arg1_above_48_bits() {
    let chip = crate::chips::chips::syscall::SyscallChip::<KoalaBear>::new(SyscallChunkKind::Riscv);
    let mut record = EmulationRecord::default();
    let mut complete_record = EmulationRecord::default();
    record.syscall_events.push(SyscallEvent {
        chunk: 0,
        clk: 1,
        syscall_id: 7,
        arg1: 1u64 << 48,
        arg2: 0,
    });

    chip.extra_record(&record, &mut complete_record);
}

#[test]
#[should_panic(expected = "frozen 48-bit proof address contract")]
fn syscall_extra_record_rejects_arg2_above_48_bits() {
    let chip = crate::chips::chips::syscall::SyscallChip::<KoalaBear>::new(SyscallChunkKind::Riscv);
    let mut record = EmulationRecord::default();
    let mut complete_record = EmulationRecord::default();
    record.syscall_events.push(SyscallEvent {
        chunk: 0,
        clk: 1,
        syscall_id: 7,
        arg1: 0,
        arg2: 1u64 << 48,
    });

    chip.extra_record(&record, &mut complete_record);
}
