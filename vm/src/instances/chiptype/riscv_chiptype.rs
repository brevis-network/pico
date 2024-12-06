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
        gadgets::{
            curves::edwards::ed25519::{Ed25519, Ed25519Parameters},
            field::{bls381::Bls381BaseField, bn254::Bn254BaseField},
        },
        precompiles::{
            edwards::{EdAddAssignChip, EdDecompressChip},
            fptower::{fp::FpOpChip, fp2_addsub::Fp2AddSubChip, fp2_mul::Fp2MulChip},
            keccak256::KeccakPermuteChip,
            poseidon2::Poseidon2PermuteChip,
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

type FpOpBn254<F> = FpOpChip<F, Bn254BaseField>;
type Fp2AddSubBn254<F> = Fp2AddSubChip<F, Bn254BaseField>;
type Fp2MulBn254<F> = Fp2MulChip<F, Bn254BaseField>;
type FpOpBls381<F> = FpOpChip<F, Bls381BaseField>;
type Fp2AddSubBls381<F> = Fp2AddSubChip<F, Bls381BaseField>;
type Fp2MulBls381<F> = Fp2MulChip<F, Bls381BaseField>;

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
        (FpBn254, FpOpBn254),
        (Fp2AddSubBn254, Fp2AddSubBn254),
        (Fp2MulBn254, Fp2MulBn254),
        (FpBls381, FpOpBls381),
        (Fp2AddSubBls381, Fp2AddSubBls381),
        (Fp2MulBls381, Fp2MulBls381),
        (U256Mul, Uint256MulChip),
        (Poseidon2P, Poseidon2PermuteChip)
    ]
);
