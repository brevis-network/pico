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
                local::MemoryLocalChip,
                read_write::MemoryReadWriteChip,
            },
            riscv_program::ProgramChip,
        },
        gadgets::curves::{
            edwards::ed25519::{Ed25519, Ed25519Parameters},
            weierstrass::{
                bls381::{Bls12381, Bls381BaseField},
                bn254::{Bn254, Bn254BaseField},
                secp256k1::Secp256k1,
            },
        },
        precompiles::{
            edwards::{EdAddAssignChip, EdDecompressChip},
            fptower::{fp::FpOpChip, fp2_addsub::Fp2AddSubChip, fp2_mul::Fp2MulChip},
            keccak256::KeccakPermuteChip,
            poseidon2::Poseidon2PermuteChip,
            sha256::{compress::ShaCompressChip, extend::ShaExtendChip},
            uint256::Uint256MulChip,
            weierstrass::{
                weierstrass_add::WeierstrassAddAssignChip,
                weierstrass_decompress::WeierstrassDecompressChip,
                weierstrass_double::WeierstrassDoubleAssignChip,
            },
        },
    },
    compiler::riscv::program::Program,
    define_chip_type,
    emulator::riscv::record::EmulationRecord,
    machine::{
        builder::ChipBuilder,
        chip::{ChipBehavior, MetaChip},
        lookup::LookupScope,
    },
};

type FpOpBn254<F> = FpOpChip<F, Bn254BaseField>;
type Fp2AddSubBn254<F> = Fp2AddSubChip<F, Bn254BaseField>;
type Fp2MulBn254<F> = Fp2MulChip<F, Bn254BaseField>;
type FpOpBls381<F> = FpOpChip<F, Bls381BaseField>;
type Fp2AddSubBls381<F> = Fp2AddSubChip<F, Bls381BaseField>;
type Fp2MulBls381<F> = Fp2MulChip<F, Bls381BaseField>;

type WsBn254Add<F> = WeierstrassAddAssignChip<F, Bn254>;
type WsBls381Add<F> = WeierstrassAddAssignChip<F, Bls12381>;

type WsSecp256k1Add<F> = WeierstrassAddAssignChip<F, Secp256k1>;

type WsDecompressBls381<F> = WeierstrassDecompressChip<F, Bls12381>;

type WsDecompressSecp256k1<F> = WeierstrassDecompressChip<F, Secp256k1>;

type WsDoubleBn254<F> = WeierstrassDoubleAssignChip<F, Bn254>;
type WsDoubleBls381<F> = WeierstrassDoubleAssignChip<F, Bls12381>;
type WsDoubleSecp256k1<F> = WeierstrassDoubleAssignChip<F, Secp256k1>;

define_chip_type!(
    RiscvChipType<F>,
    [
        (Program, ProgramChip),
        (MemoryProgram, MemoryProgramChip),
        (Cpu, CpuChip),
        (ShaCompress, ShaCompressChip),
        (Ed25519Add, EdAddAssignChip),
        (Ed25519Decompress, EdDecompressChip),
        (WsBn254Add, WsBn254Add),
        (WsBls381Add, WsBls381Add),
        (WsSecp256k1Add, WsSecp256k1Add),
        (WsDecompressBls381, WsDecompressBls381),
        (WsDecompressSecp256k1, WsDecompressSecp256k1),
        (WsDoubleBn254, WsDoubleBn254),
        (WsDoubleBls381, WsDoubleBls381),
        (WsDoubleSecp256k1, WsDoubleSecp256k1),
        (ShaExtend, ShaExtendChip),
        (MemoryInitialize, MemoryInitializeFinalizeChip),
        (MemoryFinalize, MemoryInitializeFinalizeChip),
        (MemoryLocal, MemoryLocalChip),
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
