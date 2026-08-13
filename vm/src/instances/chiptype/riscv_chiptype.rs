use crate::chips::precompiles::poseidon2::FieldSpecificPrecompilePoseidon2Chip;
use hashbrown::HashSet;
use p3_air::{Air, BaseAir};
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;

use crate::{
    chips::{
        chips::{
            alu::{
                add::AddChip, addw::AddwChip, bitwise::BitwiseChip, divrem::DivRemChip, lt::LtChip,
                mul::MulChip, sll::SLLChip, sr::traces::ShiftRightChip, sub::SubChip,
                subw::SubwChip,
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
            riscv_poseidon2::FieldSpecificPoseidon2Chip,
            riscv_program::ProgramChip,
            syscall::SyscallChip,
        },
        gadgets::{
            curves::{
                edwards::ed25519::{Ed25519, Ed25519Parameters},
                weierstrass::{
                    bls381::Bls381BaseField, bn254::Bn254BaseField, Bls12381, Bn254, Secp256k1,
                    Secp256r1,
                },
            },
            field::secp256k1::Secp256k1BaseField,
        },
        precompiles::{
            edwards::{EdAddAssignChip, EdDecompressChip},
            fptower::{fp::FpOpChip, fp2_addsub::Fp2AddSubChip, fp2_mul::Fp2MulChip},
            keccak256::KeccakPermuteChip,
            sha256::{
                compress::{ShaCompressChip, ShaCompressControlChip},
                extend::{ShaExtendChip, ShaExtendControlChip},
            },
            uint256::Uint256MulChip,
            weierstrass::{
                weierstrass_add::WeierstrassAddAssignChip,
                weierstrass_decompress::WeierstrassDecompressChip,
                weierstrass_double::WeierstrassDoubleAssignChip,
            },
        },
    },
    compiler::riscv::{opcode::Opcode, program::Program},
    define_chip_type,
    emulator::riscv::{record::EmulationRecord, syscalls::precompiles::PrecompileLocalMemory},
    instances::compiler::shapes::riscv_shape::{
        precompile_rows_per_event, precompile_syscall_code,
    },
    machine::{
        builder::ChipBuilder,
        chip::{ChipBehavior, MetaChip},
        field::FieldSpecificPoseidon2Config,
        lookup::{LookupScope, LookupType},
    },
    primitives::consts::{
        ADD_DATAPAR, BITWISE_DATAPAR, DIVREM_DATAPAR, LOCAL_MEMORY_DATAPAR, LT_DATAPAR,
        MEMORY_RW_DATAPAR, MUL_DATAPAR, RISCV_POSEIDON2_DATAPAR, SLL_DATAPAR, SR_DATAPAR,
        SUB_DATAPAR,
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
type WsSecp256r1Add<F> = WeierstrassAddAssignChip<F, Secp256r1>;
type WsDecompressBls381<F> = WeierstrassDecompressChip<F, Bls12381>;
type WsDecompressSecp256k1<F> = WeierstrassDecompressChip<F, Secp256k1>;
type WsDecompressSecp256r1<F> = WeierstrassDecompressChip<F, Secp256r1>;
type WsDoubleBn254<F> = WeierstrassDoubleAssignChip<F, Bn254>;
type WsDoubleBls381<F> = WeierstrassDoubleAssignChip<F, Bls12381>;
type WsDoubleSecp256k1<F> = WeierstrassDoubleAssignChip<F, Secp256k1>;
type WsDoubleSecp256r1<F> = WeierstrassDoubleAssignChip<F, Secp256r1>;

define_chip_type!(
    RiscvChipType<F>,
    [
        (Program, ProgramChip),
        (Cpu, CpuChip),
        (ShaCompress, ShaCompressChip),
        (ShaCompressControl, ShaCompressControlChip),
        (Ed25519Add, EdAddAssignChip),
        (Ed25519Decompress, EdDecompressChip),
        (WsBn254Add, WsBn254Add),
        (WsBls381Add, WsBls381Add),
        (WsSecp256k1Add, WsSecp256k1Add),
        (WsSecp256r1Add, WsSecp256r1Add),
        (WsDecompressBls381, WsDecompressBls381),
        (WsDecompressSecp256k1, WsDecompressSecp256k1),
        (WsDecompressSecp256r1, WsDecompressSecp256r1),
        (WsDoubleBn254, WsDoubleBn254),
        (WsDoubleBls381, WsDoubleBls381),
        (WsDoubleSecp256k1, WsDoubleSecp256k1),
        (WsDoubleSecp256r1, WsDoubleSecp256r1),
        (ShaExtend, ShaExtendChip),
        (ShaExtendControl, ShaExtendControlChip),
        (MemoryInitialize, MemoryInitializeFinalizeChip),
        (MemoryFinalize, MemoryInitializeFinalizeChip),
        (MemoryLocal, MemoryLocalChip),
        (MemoryReadWrite, MemoryReadWriteChip),
        (DivRem, DivRemChip),
        (Mul, MulChip),
        (Lt, LtChip),
        (SR, ShiftRightChip),
        (SLL, SLLChip),
        (Add, AddChip),
        (Sub, SubChip),
        (Addw, AddwChip),
        (Subw, SubwChip),
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
        (Poseidon2P, FieldSpecificPrecompilePoseidon2Chip),
        (SyscallRiscv, SyscallChip),
        (SyscallPrecompile, SyscallChip),
        (Global, GlobalChip),
        (Poseidon2, FieldSpecificPoseidon2Chip),
        (Byte, ByteChip)
    ]
);

impl<F: PrimeField32 + FieldSpecificPoseidon2Config> RiscvChipType<F> {
    pub fn all_chips() -> Vec<MetaChip<F, Self>> {
        Self::all_chip_variants()
            .into_iter()
            .map(MetaChip::new)
            .collect()
    }

    /// The same chip list as [`Self::all_chips`], before wrapping.
    ///
    /// Tests that need a non-default `MetaChip` constructor build from this, so the list stays
    /// in one place.
    pub fn all_chip_variants() -> Vec<Self> {
        vec![
            Self::Program(Default::default()),
            Self::Cpu(Default::default()),
            Self::ShaCompress(Default::default()),
            Self::ShaCompressControl(Default::default()),
            // The two Ed25519 chips are deliberately out of the machine, and both need work
            // before either goes back in. Do not simply uncomment.
            //
            // - `EdAddAssignChip`'s `eval` is `todo!()`, so it constrains nothing.
            // - `EdDecompressChip` was never ported to the u16-limb memory model this VM uses.
            // - `EdDecompressChip` writes `neg_x.result` back to guest memory while only bounding
            //   its limbs to u8. `2p - x` satisfies the same subtraction identity as `p - x`, so a
            //   prover can store a non-canonical value; the canonicality check that would stop it
            //   is missing (compare `neg_y_range_check` in `weierstrass_decompress.rs`, which does
            //   have one). **This one is a soundness gap, not just an unfinished port** -- it
            //   becomes exploitable the moment the chip is in the machine.
            // - `EdDecompressChip` also rejects any `y >= p` that the emulator happily accepts, so
            //   re-enabling it turns a class of guest input into a prover-side abort.
            //
            // The matching syscalls are unregistered in `emulator/riscv/syscalls/mod.rs`; putting a
            // chip back requires restoring that registration too.
            //Self::Ed25519Add(Default::default()),
            //Self::Ed25519Decompress(Default::default()),
            Self::WsBn254Add(Default::default()),
            Self::WsBls381Add(Default::default()),
            Self::WsSecp256k1Add(Default::default()),
            Self::WsSecp256r1Add(Default::default()),
            Self::WsDecompressBls381(Default::default()),
            Self::WsDecompressSecp256k1(Default::default()),
            Self::WsDecompressSecp256r1(Default::default()),
            Self::WsDoubleBn254(Default::default()),
            Self::WsDoubleBls381(Default::default()),
            Self::WsDoubleSecp256k1(Default::default()),
            Self::WsDoubleSecp256r1(Default::default()),
            Self::ShaExtend(Default::default()),
            Self::ShaExtendControl(Default::default()),
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
            Self::Add(Default::default()),
            Self::Sub(Default::default()),
            Self::Addw(Default::default()),
            Self::Subw(Default::default()),
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
            // The poseidon2 precompile is deliberately out of the machine. Unlike the Ed25519
            // chips below, this one works -- what is missing is a usable way to call it and a
            // reason to keep paying for it:
            //
            // - The syscall ABI hands over `*const [u32; 16]` / `*mut [u32; 16]`, which Rust
            //   aligns to 4 bytes, but this VM's memory is 8-byte granular and the address gadget
            //   range checks `addr[0] / 8`. A buffer that happens to land 4 mod 8 -- roughly half
            //   of them, and every stack-local `[u32; 16]` in the SDK's own hasher -- cannot be
            //   proved. That is a leftover of the 32-bit origin of this ABI.
            // - Each written-back half word is pinned only modulo the field order, so
            //   `state[j] + p` (and sometimes `+ 2p`) satisfies the same equation. Making the
            //   written value unique needs a `value < p` check on all 16 inputs and 16 outputs,
            //   which `gadgets/field_range_check/word_range.rs` can now supply. Until that lands,
            //   the written value is not unique -- a soundness gap, not an unfinished port.
            //
            // Re-enabling means: fix the alignment on the caller side (or relax the gadget),
            // add the canonicality checks, restore the syscall registration in
            // `emulator/riscv/syscalls/mod.rs` and the AOT dispatch arm in
            // `aot-runtime/src/syscall.rs`, and un-deprecate the SDK entry points. The chip's own
            // AIR, columns and trace generation are untouched and still compiled -- and still
            // tested, see the poseidon2 tests in `chips/tests.rs`, which register the syscall
            // themselves so this code cannot rot while it is shelved.
            //
            // Self::Poseidon2P(Default::default()),
            Self::SyscallRiscv(SyscallChip::riscv()),
            Self::SyscallPrecompile(SyscallChip::precompile()),
            Self::Global(Default::default()),
            Self::Byte(Default::default()),
            Self::Poseidon2(Default::default()),
        ]
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
                Self::Add(Default::default()).name(),
                record
                    .add_events
                    .iter()
                    .filter(|e| e.opcode == Opcode::ADD)
                    .count()
                    .div_ceil(ADD_DATAPAR),
            ),
            (
                Self::Sub(Default::default()).name(),
                record
                    .sub_events
                    .iter()
                    .filter(|e| e.opcode == Opcode::SUB)
                    .count()
                    .div_ceil(SUB_DATAPAR),
            ),
            (
                Self::Addw(Default::default()).name(),
                record
                    .add_events
                    .iter()
                    .filter(|e| e.opcode == Opcode::ADDW)
                    .count()
                    .div_ceil(ADD_DATAPAR),
            ),
            (
                Self::Subw(Default::default()).name(),
                record
                    .sub_events
                    .iter()
                    .filter(|e| e.opcode == Opcode::SUBW)
                    .count()
                    .div_ceil(SUB_DATAPAR),
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
                // Must be div_ceil, matching the trace side.
                //
                // `RiscvPoseidon2Chip::generate_main` computes its height as
                // `events.len().div_ceil(RISCV_POSEIDON2_DATAPAR)`
                // (`chips/chips/riscv_poseidon2/traces.rs:49`). Plain division truncates, so
                // whenever `num_global_events` is not a multiple of the datapar width this
                // under-reported the height by one row and the generated trace did not fit the
                // shape. Every sibling entry in this list already uses `div_ceil`; this was the
                // only one left.
                num_global_events.div_ceil(RISCV_POSEIDON2_DATAPAR),
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
        [
            Self::Cpu(Default::default()),
            Self::Add(Default::default()),
            Self::Sub(Default::default()),
            Self::Addw(Default::default()),
            Self::Subw(Default::default()),
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
            Self::Poseidon2(Default::default()),
        ]
        .map(MetaChip::new)
        .into()
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
        // SHA control chips are siblings of the compute chips: they share the same
        // syscall events and emit no Memory+Regional lookups of their own. Exclude
        // them from the precompile pool — their shape entry is appended directly to
        // the parent ShaCompress/ShaExtend shape in `get_precompile_shapes`.
        excluded_chip_names.insert(Self::ShaCompressControl(Default::default()).name());
        excluded_chip_names.insert(Self::ShaExtendControl(Default::default()).name());

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
