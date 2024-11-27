use p3_air::{Air, BaseAir};
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;

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
        gadgets::curves::edwards::ed25519::{Ed25519, Ed25519Parameters},
        precompiles::{
            edwards::{EdAddAssignChip, EdDecompressChip},
            keccak256::KeccakPermuteChip,
            sha256::{compress::ShaCompressChip, extend::ShaExtendChip},
            uint256::Uint256MulChip,
        },
    },
    compiler::riscv::program::Program,
    define_chip_type,
    emulator::riscv::record::EmulationRecord,
    machine::{
        builder::ChipBuilder,
        chip::{ChipBehavior, MetaChip},
    },
};

define_chip_type!(
    RiscvChipType<F>,
    [
        (Program, ProgramChip),
        (MemoryProgram, MemoryProgramChip),
        (Cpu, CpuChip),
        (ShaCompress, ShaCompressChip),
        (Ed25519Add, EdAddAssignChip),
        (Ed25519Decompress, EdDecompressChip),
        (ShaExtend, ShaExtendChip),
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
        (KeecakP, KeccakPermuteChip),
        (U256Mul, Uint256MulChip)
    ]
);
