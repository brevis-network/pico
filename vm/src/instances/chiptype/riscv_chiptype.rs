use crate::{
    chips::{
        chips::{
            alu::{
                add_sub::AddSubChip, bitwise::BitwiseChip, divrem::DivRemChip, lt::LtChip,
                mul::MulChip, sll::SLLChip, sr::traces::ShiftRightChip,
            },
            byte::ByteChip,
            memory_program::MemoryProgramChip,
            rangecheck::RangeCheckChip,
            riscv_cpu::CpuChip,
            riscv_memory::{
                initialize_finalize::{MemoryChipType, MemoryInitializeFinalizeChip},
                read_write::MemoryReadWriteChip,
            },
            riscv_program::ProgramChip,
        },
        precompiles::keccak256::KeccakPermuteChip,
    },
    compiler::riscv::program::Program,
    define_chip_type,
    emulator::riscv::record::EmulationRecord,
    machine::{
        builder::ChipBuilder,
        chip::{ChipBehavior, MetaChip},
    },
};
use p3_air::{Air, BaseAir};
use p3_field::{Field, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;

define_chip_type!(
    RiscvChipType<F>,
    [
        (Program, ProgramChip),
        (MemoryProgram, MemoryProgramChip),
        (Cpu, CpuChip),
        (MemoryInitialize, MemoryInitializeFinalizeChip),
        (MemoryFinalize, MemoryInitializeFinalizeChip),
        (MemoryReadWrite, MemoryReadWriteChip),
        (DivRem, DivRemChip),
        (Mul, MulChip),
        (Lt, LtChip),
        (SR, ShiftRightChip),
        (SLL, SLLChip),
        (AddSub, AddSubChip),
        (Bitwise, BitwiseChip),
        (Byte, ByteChip),
        (Range, RangeCheckChip),
        (KeecakP, KeccakPermuteChip)
    ]
);
