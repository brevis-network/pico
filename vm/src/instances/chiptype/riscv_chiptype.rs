use hashbrown::HashSet;
use itertools::Itertools;
use p3_air::{Air, BaseAir};
use p3_baby_bear::BabyBear;
use p3_field::PrimeField32;
use p3_koala_bear::KoalaBear;
use p3_matrix::dense::RowMajorMatrix;
use p3_mersenne_31::Mersenne31;

use crate::{
    chips::{
        chips::{
            alu::{
                add_sub::AddSubChip, bitwise::BitwiseChip, divrem::DivRemChip, lt::LtChip,
                mul::MulChip, sll::SLLChip, sr::traces::ShiftRightChip,
            },
            byte::ByteChip,
            riscv_cpu::CpuChip,
            riscv_global::GlobalChip,
            riscv_memory::{
                initialize_finalize::{
                    MemoryChipType::{self, Finalize, Initialize},
                    MemoryInitializeFinalizeChip,
                },
                local::MemoryLocalChip,
                read_write::MemoryReadWriteChip,
            },
            riscv_poseidon2::{
                BabyBearPoseidon2Chip, KoalaBearPoseidon2Chip, Mersenne31Poseidon2Chip,
            },
            riscv_program::ProgramChip,
            syscall::SyscallChip,
        },
        gadgets::{
            curves::{
                edwards::ed25519::{Ed25519, Ed25519Parameters},
                weierstrass::{
                    bls381::{Bls12381, Bls381BaseField},
                    bn254::{Bn254, Bn254BaseField},
                    secp256k1::Secp256k1,
                },
            },
            field::secp256k1::Secp256k1BaseField,
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
    instances::compiler::shapes::riscv_shape::{
        precompile_rows_per_event, precompile_syscall_code,
    },
    machine::{
        builder::ChipBuilder,
        chip::{ChipBehavior, MetaChip},
        field::{same_field, FieldSpecificPoseidon2Config},
        folder::SymbolicConstraintFolder,
        lookup::{LookupScope, LookupType},
    },
    primitives::consts::{
        ADD_SUB_DATAPAR, BITWISE_DATAPAR, DIVREM_DATAPAR, LOCAL_MEMORY_DATAPAR, LT_DATAPAR,
        MEMORY_RW_DATAPAR, MUL_DATAPAR, RISCV_POSEIDON2_DATAPAR, SLL_DATAPAR, SR_DATAPAR,
    },
};

type FpOpBn254<F> = FpOpChip<F, Bn254BaseField>;
type Fp2AddSubBn254<F> = Fp2AddSubChip<F, Bn254BaseField>;
type Fp2MulBn254<F> = Fp2MulChip<F, Bn254BaseField>;
type FpOpBls381<F> = FpOpChip<F, Bls381BaseField>;
type Fp2AddSubBls381<F> = Fp2AddSubChip<F, Bls381BaseField>;
type Fp2MulBls381<F> = Fp2MulChip<F, Bls381BaseField>;
type FpOpSecp256k1<F> = FpOpChip<F, Secp256k1BaseField>;

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
        (KeecakP, KeccakPermuteChip),
        (FpBn254, FpOpBn254),
        (Fp2AddSubBn254, Fp2AddSubBn254),
        (Fp2MulBn254, Fp2MulBn254),
        (FpBls381, FpOpBls381),
        (Fp2AddSubBls381, Fp2AddSubBls381),
        (Fp2MulBls381, Fp2MulBls381),
        (FpSecp256k1, FpOpSecp256k1),
        (U256Mul, Uint256MulChip),
        (Poseidon2P, Poseidon2PermuteChip),
        (SyscallRiscv, SyscallChip),
        (SyscallPrecompile, SyscallChip),
        (Global, GlobalChip),
        (BabyBearPoseidon2, BabyBearPoseidon2Chip),
        (KoalaBearPoseidon2, KoalaBearPoseidon2Chip),
        (Mersenne31Poseidon2, Mersenne31Poseidon2Chip),
        (Byte, ByteChip)
    ]
);

impl<F: PrimeField32 + FieldSpecificPoseidon2Config> RiscvChipType<F>
where
    Poseidon2PermuteChip<F, F::Poseidon2Config>:
        ChipBehavior<F, Record = EmulationRecord, Program = Program>,
    BabyBearPoseidon2Chip<F>: Air<SymbolicConstraintFolder<F>>,
    KoalaBearPoseidon2Chip<F>: Air<SymbolicConstraintFolder<F>>,
    Mersenne31Poseidon2Chip<F>: Air<SymbolicConstraintFolder<F>>,
{
    pub fn all_chips() -> Vec<MetaChip<F, Self>> {
        let mut chips = [
            Self::Program(Default::default()),
            Self::Cpu(Default::default()),
            Self::ShaCompress(Default::default()),
            Self::Ed25519Add(Default::default()),
            Self::Ed25519Decompress(Default::default()),
            Self::WsBn254Add(Default::default()),
            Self::WsBls381Add(Default::default()),
            Self::WsSecp256k1Add(Default::default()),
            Self::WsDecompressBls381(Default::default()),
            Self::WsDecompressSecp256k1(Default::default()),
            Self::WsDoubleBn254(Default::default()),
            Self::WsDoubleBls381(Default::default()),
            Self::WsDoubleSecp256k1(Default::default()),
            Self::ShaExtend(Default::default()),
            Self::MemoryInitialize(MemoryInitializeFinalizeChip::new(
                MemoryChipType::Initialize,
            )),
            Self::MemoryFinalize(MemoryInitializeFinalizeChip::new(MemoryChipType::Finalize)),
            Self::MemoryLocal(Default::default()),
            Self::MemoryReadWrite(Default::default()),
            Self::DivRem(Default::default()),
            Self::Mul(Default::default()),
            Self::Lt(Default::default()),
            Self::SR(Default::default()),
            Self::SLL(Default::default()),
            Self::AddSub(Default::default()),
            Self::Bitwise(Default::default()),
            Self::KeecakP(Default::default()),
            Self::FpBn254(Default::default()),
            Self::Fp2AddSubBn254(Default::default()),
            Self::Fp2MulBn254(Default::default()),
            Self::FpBls381(Default::default()),
            Self::Fp2AddSubBls381(Default::default()),
            Self::Fp2MulBls381(Default::default()),
            Self::FpSecp256k1(Default::default()),
            Self::U256Mul(Default::default()),
            Self::Poseidon2P(Default::default()),
            Self::SyscallRiscv(SyscallChip::riscv()),
            Self::SyscallPrecompile(SyscallChip::precompile()),
            Self::Global(Default::default()),
            Self::Byte(Default::default()),
        ]
        .into_iter()
        .map(MetaChip::new)
        .collect_vec();

        if same_field::<F, BabyBear, 4>() {
            chips.push(MetaChip::new(Self::BabyBearPoseidon2(Default::default())));
        } else if same_field::<F, KoalaBear, 4>() {
            chips.push(MetaChip::new(Self::KoalaBearPoseidon2(Default::default())));
        } else if same_field::<F, Mersenne31, 3>() {
            let a = MetaChip::new(Self::Mersenne31Poseidon2(Default::default()));

            chips.push(a);
        } else {
            panic!("Unsupported field type");
        }

        chips
    }

    /// Get the heights of the preprocessed chips for a given program.
    pub(crate) fn preprocessed_heights(program: &Program) -> Vec<(String, usize)> {
        vec![
            (
                Self::Program(Default::default()).name(),
                program.instructions.len(),
            ),
            (Self::Byte(Default::default()).name(), 1 << 16),
        ]
    }

    /// Get the heights of the chips for a given execution record.
    pub(crate) fn riscv_heights(record: &EmulationRecord) -> Vec<(String, usize)> {
        let num_global_events =
            2 * record.get_local_mem_events().count() + record.syscall_events.len();
        vec![
            (
                Self::Cpu(Default::default()).name(),
                record.cpu_events.len(),
            ),
            (
                Self::DivRem(Default::default()).name(),
                record.divrem_events.len().div_ceil(DIVREM_DATAPAR),
            ),
            (
                Self::AddSub(Default::default()).name(),
                (record.add_events.len() + record.sub_events.len()).div_ceil(ADD_SUB_DATAPAR),
            ),
            (
                Self::Bitwise(Default::default()).name(),
                record.bitwise_events.len().div_ceil(BITWISE_DATAPAR),
            ),
            (
                Self::Mul(Default::default()).name(),
                record.mul_events.len().div_ceil(MUL_DATAPAR),
            ),
            (
                Self::SR(Default::default()).name(),
                record.shift_right_events.len().div_ceil(SR_DATAPAR),
            ),
            (
                Self::SLL(Default::default()).name(),
                record.shift_left_events.len().div_ceil(SLL_DATAPAR),
            ),
            (
                Self::Lt(Default::default()).name(),
                record.lt_events.len().div_ceil(LT_DATAPAR),
            ),
            (
                Self::MemoryLocal(Default::default()).name(),
                record
                    .get_local_mem_events()
                    .count()
                    .div_ceil(LOCAL_MEMORY_DATAPAR),
            ),
            (
                Self::MemoryReadWrite(Default::default()).name(),
                record
                    .cpu_events
                    .iter()
                    .filter(|e| e.instruction.is_memory_instruction())
                    .count()
                    .div_ceil(MEMORY_RW_DATAPAR),
            ),
            (Self::Global(Default::default()).name(), num_global_events),
            (
                <F as FieldSpecificPoseidon2Config>::riscv_poseidon2_name().to_string(),
                num_global_events.div_ceil(RISCV_POSEIDON2_DATAPAR),
            ),
            (
                Self::SyscallRiscv(SyscallChip::riscv()).name(),
                record.syscall_events.len(),
            ),
        ]
    }

    pub(crate) fn get_memory_init_final_heights(record: &EmulationRecord) -> Vec<(String, usize)> {
        let num_global_events =
            record.memory_finalize_events.len() + record.memory_initialize_events.len();
        vec![
            (
                Self::MemoryInitialize(MemoryInitializeFinalizeChip::new(Initialize)).name(),
                record.memory_initialize_events.len(),
            ),
            (
                Self::MemoryFinalize(MemoryInitializeFinalizeChip::new(Finalize)).name(),
                record.memory_finalize_events.len(),
            ),
            (
                Self::Global(GlobalChip::default()).name(),
                num_global_events,
            ),
            (
                <F as FieldSpecificPoseidon2Config>::riscv_poseidon2_name().to_string(),
                num_global_events / RISCV_POSEIDON2_DATAPAR,
            ),
        ]
    }

    /// Get the height of the corresponding precompile chip.
    ///
    /// If the precompile is not included in the record, returns `None`. Otherwise, returns
    /// `Some(num_rows, num_local_mem_events, num_global_events)`, where `num_rows` is the number of rows of the
    /// corresponding chip, `num_local_mem_events` is the number of local memory events, and `num_global_events`
    /// is the number of global lookup events
    pub(crate) fn get_precompile_heights(
        chip_name: &str,
        record: &EmulationRecord,
    ) -> Option<(usize, usize, usize)> {
        record
            .precompile_events
            .get_events(precompile_syscall_code(chip_name))
            .filter(|events| !events.is_empty())
            .map(|events| {
                (
                    events.len() * precompile_rows_per_event(chip_name),
                    events.get_local_mem_events().into_iter().count(),
                    record.global_lookup_events.len(),
                )
            })
    }

    pub(crate) fn get_all_riscv_chips() -> Vec<MetaChip<F, Self>> {
        let mut chips = [
            Self::Cpu(Default::default()),
            Self::AddSub(Default::default()),
            Self::Bitwise(Default::default()),
            Self::Mul(Default::default()),
            Self::DivRem(Default::default()),
            Self::SLL(Default::default()),
            Self::SR(Default::default()),
            Self::Lt(Default::default()),
            Self::MemoryLocal(Default::default()),
            Self::MemoryReadWrite(Default::default()),
            Self::Global(Default::default()),
            Self::SyscallRiscv(SyscallChip::riscv()),
        ]
        .into_iter()
        .map(MetaChip::new)
        .collect_vec();

        if same_field::<F, BabyBear, 4>() {
            chips.push(MetaChip::new(Self::BabyBearPoseidon2(Default::default())));
        } else if same_field::<F, KoalaBear, 4>() {
            chips.push(MetaChip::new(Self::KoalaBearPoseidon2(Default::default())));
        } else if same_field::<F, Mersenne31, 3>() {
            chips.push(MetaChip::new(Self::Mersenne31Poseidon2(Default::default())));
        } else {
            panic!("Unsupported field type");
        }

        chips
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
