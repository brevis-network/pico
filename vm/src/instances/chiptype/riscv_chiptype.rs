use hashbrown::HashSet;
use itertools::Itertools;
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
            riscv_cpu::CpuChip,
            riscv_memory::{
                initialize_finalize::{
                    MemoryChipType,
                    MemoryChipType::{Finalize, Initialize},
                    MemoryInitializeFinalizeChip,
                },
                local::{columns::NUM_LOCAL_MEMORY_ENTRIES_PER_ROW, MemoryLocalChip},
                read_write::MemoryReadWriteChip,
            },
            riscv_program::ProgramChip,
            syscall::SyscallChip,
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
    emulator::riscv::{record::EmulationRecord, syscalls::precompiles::PrecompileLocalMemory},
    instances::compiler_v2::shapes::riscv_shape::{
        precompile_rows_per_event, precompile_syscall_code,
    },
    machine::{
        builder::ChipBuilder,
        chip::{ChipBehavior, MetaChip},
        lookup::{LookupScope, LookupType},
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
        (KeecakP, KeccakPermuteChip),
        (FpBn254, FpOpBn254),
        (Fp2AddSubBn254, Fp2AddSubBn254),
        (Fp2MulBn254, Fp2MulBn254),
        (FpBls381, FpOpBls381),
        (Fp2AddSubBls381, Fp2AddSubBls381),
        (Fp2MulBls381, Fp2MulBls381),
        (U256Mul, Uint256MulChip),
        (Poseidon2P, Poseidon2PermuteChip),
        (SyscallRiscv, SyscallChip),
        (SyscallPrecompile, SyscallChip)
    ]
);

impl<F: PrimeField32, const HALF_EXTERNAL_ROUNDS: usize, const NUM_INTERNAL_ROUNDS: usize>
    RiscvChipType<F, HALF_EXTERNAL_ROUNDS, NUM_INTERNAL_ROUNDS>
where
    Poseidon2PermuteChip<F, HALF_EXTERNAL_ROUNDS, NUM_INTERNAL_ROUNDS>:
        ChipBehavior<F, Record = EmulationRecord, Program = Program>,
{
    /// Get the heights of the preprocessed chips for a given program.
    pub(crate) fn preprocessed_heights(program: &Program) -> Vec<(String, usize)> {
        vec![
            (
                RiscvChipType::<F, HALF_EXTERNAL_ROUNDS, NUM_INTERNAL_ROUNDS>::Program(
                    ProgramChip::default(),
                )
                .name(),
                program.instructions.len(),
            ),
            (
                RiscvChipType::<F, HALF_EXTERNAL_ROUNDS, NUM_INTERNAL_ROUNDS>::Byte(
                    ByteChip::default(),
                )
                .name(),
                1 << 16,
            ),
        ]
    }

    /// Get the heights of the chips for a given execution record.
    pub(crate) fn riscv_heights(record: &EmulationRecord) -> Vec<(String, usize)> {
        vec![
            (
                RiscvChipType::<F, HALF_EXTERNAL_ROUNDS, NUM_INTERNAL_ROUNDS>::Cpu(CpuChip::default()).name(),
                record.cpu_events.len(),
            ),
            (
                RiscvChipType::<F, HALF_EXTERNAL_ROUNDS, NUM_INTERNAL_ROUNDS>::DivRem(DivRemChip::default()).name(),
                record.divrem_events.len(),
            ),
            (
                RiscvChipType::<F, HALF_EXTERNAL_ROUNDS, NUM_INTERNAL_ROUNDS>::AddSub(AddSubChip::default()).name(),
                record.add_events.len() + record.sub_events.len(),
            ),
            (
                RiscvChipType::<F, HALF_EXTERNAL_ROUNDS, NUM_INTERNAL_ROUNDS>::Bitwise(BitwiseChip::default()).name(),
                record.bitwise_events.len(),
            ),
            (
                RiscvChipType::<F, HALF_EXTERNAL_ROUNDS, NUM_INTERNAL_ROUNDS>::Mul(MulChip::default()).name(),
                record.mul_events.len(),
            ),
            (
                RiscvChipType::<F, HALF_EXTERNAL_ROUNDS, NUM_INTERNAL_ROUNDS>::SR(ShiftRightChip::default()).name(),
                record.shift_right_events.len(),
            ),
            (
                RiscvChipType::<F, HALF_EXTERNAL_ROUNDS, NUM_INTERNAL_ROUNDS>::SLL(SLLChip::default()).name(),
                record.shift_left_events.len(),
            ),
            (
                RiscvChipType::<F, HALF_EXTERNAL_ROUNDS, NUM_INTERNAL_ROUNDS>::Lt(LtChip::default()).name(),
                record.lt_events.len(),
            ),
            (
                RiscvChipType::<F, HALF_EXTERNAL_ROUNDS, NUM_INTERNAL_ROUNDS>::MemoryLocal(MemoryLocalChip::default()).name(),
                record
                    .get_local_mem_events()
                    .chunks(NUM_LOCAL_MEMORY_ENTRIES_PER_ROW)
                    .into_iter()
                    .count(),
            ),
            (
                RiscvChipType::<F, HALF_EXTERNAL_ROUNDS, NUM_INTERNAL_ROUNDS>::MemoryReadWrite(MemoryReadWriteChip::default()).name(),
                record
                    .cpu_events
                    .iter()
                    .filter(|e| e.instruction.is_memory_instruction())
                    .count(),
            ),
            (
                RiscvChipType::<F, HALF_EXTERNAL_ROUNDS, NUM_INTERNAL_ROUNDS>::SyscallRiscv(SyscallChip::riscv()).name(),
                record.syscall_events.len(),
            ),
        ]
    }

    pub(crate) fn get_memory_init_final_heights(record: &EmulationRecord) -> Vec<(String, usize)> {
        vec![
            (
                RiscvChipType::<F, HALF_EXTERNAL_ROUNDS, NUM_INTERNAL_ROUNDS>::MemoryInitialize(
                    MemoryInitializeFinalizeChip::new(Initialize),
                )
                .name(),
                record.memory_initialize_events.len(),
            ),
            (
                RiscvChipType::<F, HALF_EXTERNAL_ROUNDS, NUM_INTERNAL_ROUNDS>::MemoryFinalize(
                    MemoryInitializeFinalizeChip::new(Finalize),
                )
                .name(),
                record.memory_finalize_events.len(),
            ),
        ]
    }

    /// Get the height of the corresponding precompile chip.
    ///
    /// If the precompile is not included in the record, returns `None`. Otherwise, returns
    /// `Some(num_rows, num_local_mem_events)`, where `num_rows` is the number of rows of the
    /// corresponding chip and `num_local_mem_events` is the number of local memory events.
    pub(crate) fn get_precompile_heights(
        chip_name: &str,
        record: &EmulationRecord,
    ) -> Option<(usize, usize)> {
        record
            .precompile_events
            .get_events(precompile_syscall_code(chip_name))
            .filter(|events| !events.is_empty())
            .map(|events| {
                (
                    events.len() * precompile_rows_per_event(chip_name),
                    events.get_local_mem_events().into_iter().count(),
                )
            })
    }

    pub(crate) fn get_all_riscv_chips() -> Vec<MetaChip<F, Self>> {
        vec![
            MetaChip::new(Self::Cpu(CpuChip::default())),
            MetaChip::new(Self::AddSub(AddSubChip::default())),
            MetaChip::new(Self::Bitwise(BitwiseChip::default())),
            MetaChip::new(Self::Mul(MulChip::default())),
            MetaChip::new(Self::DivRem(DivRemChip::default())),
            MetaChip::new(Self::SLL(SLLChip::default())),
            MetaChip::new(Self::SR(ShiftRightChip::default())),
            MetaChip::new(Self::Lt(LtChip::default())),
            MetaChip::new(Self::MemoryLocal(MemoryLocalChip::default())),
            MetaChip::new(Self::MemoryReadWrite(MemoryReadWriteChip::default())),
            MetaChip::new(Self::SyscallRiscv(SyscallChip::riscv())),
        ]
    }

    pub(crate) fn memory_init_final_chips() -> Vec<MetaChip<F, Self>> {
        vec![
            MetaChip::new(Self::MemoryInitialize(MemoryInitializeFinalizeChip::new(
                MemoryChipType::Initialize,
            ))),
            MetaChip::new(Self::MemoryInitialize(MemoryInitializeFinalizeChip::new(
                MemoryChipType::Finalize,
            ))),
        ]
    }

    /// return (precompile_chip_name, memory_local_per_event)
    pub(crate) fn get_all_precompile_chips() -> Vec<(String, usize)> {
        let all_chips = Self::all_chips();

        let mut excluded_chip_names: HashSet<String> = HashSet::new();

        for riscv_air in Self::get_all_riscv_chips() {
            excluded_chip_names.insert(riscv_air.name());
        }
        for memory_chip in Self::memory_init_final_chips() {
            excluded_chip_names.insert(memory_chip.name());
        }

        excluded_chip_names.insert(Self::SyscallPrecompile(SyscallChip::precompile()).name());
        // Remove the preprocessed chips.
        excluded_chip_names.insert(Self::Program(ProgramChip::default()).name());
        excluded_chip_names.insert(Self::Byte(ByteChip::default()).name());

        all_chips
            .into_iter()
            .filter(|chip| !excluded_chip_names.contains(&chip.name()))
            .map(|chip| {
                let local_mem_events: usize = chip
                    .get_looking()
                    .iter()
                    .chain(chip.get_looked())
                    .filter(|lookup| {
                        lookup.kind == LookupType::Memory && lookup.scope == LookupScope::Regional
                    })
                    .count();

                (chip.name(), local_mem_events)
            })
            .collect()
    }
}
