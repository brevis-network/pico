use crate::{
    chips::chips::syscall::SyscallChunkKind,
    emulator::riscv::{history::ExecutionHistory, record::EmulationRecord, syscalls::SyscallEvent},
    machine::chip::ChipBehavior,
};
use p3_koala_bear::KoalaBear;

#[test]
#[should_panic(expected = "frozen 48-bit proof address contract")]
fn syscall_extra_record_rejects_arg1_above_48_bits() {
    let chip = crate::chips::chips::syscall::SyscallChip::<KoalaBear>::new(SyscallChunkKind::Riscv);
    let mut record = EmulationRecord {
        is_cpu_chunk: true,
        history: Some(ExecutionHistory::default()),
        ..Default::default()
    };
    let mut complete_record = EmulationRecord::default();
    record
        .history
        .as_mut()
        .unwrap()
        .syscalls
        .push(SyscallEvent {
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
    let mut record = EmulationRecord {
        is_cpu_chunk: true,
        history: Some(ExecutionHistory::default()),
        ..Default::default()
    };
    let mut complete_record = EmulationRecord::default();
    record
        .history
        .as_mut()
        .unwrap()
        .syscalls
        .push(SyscallEvent {
            chunk: 0,
            clk: 1,
            syscall_id: 7,
            arg1: 0,
            arg2: 1u64 << 48,
        });

    chip.extra_record(&record, &mut complete_record);
}
