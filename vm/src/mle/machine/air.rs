//! Trait wiring so brevis RISCV chips satisfy the MLE backend's `AnyAir<SC>`.
//!
//! `AnyAir<SC>` requires, on top of `Air<SymbolicRapBuilder>` + `Air<DebugConstraintBuilder>`
//! (provided by `constraints.rs` + the builders' native `ChipBuilder` impls in
//! `pico_mle_core::air::{symbolic, debug}`):
//!   - `PartitionedBaseAir<F>`  — opted-in per chip below (default: no cached main, a single
//!      un-partitioned common main trace — correct for brevis chips).
//!   - `BaseAirWithPublicValues<F>` — p3 trait with no blanket; opted-in per chip below
//!      (default 0 PVs; `CpuChip` and `EcallChip` expose `RISCV_NUM_PVS`).
//!
//! `PrepAir` wraps a preprocessed chip (Byte/Program) so the MLE keygen picks up its table via
//! p3 `BaseAir::preprocessed_trace` (which brevis chips leave as `None`) — without modifying the
//! chip. The wrapped chip's `constraints.rs` reads the table through `builder.preprocessed()`,
//! which the builders' `ChipBuilder` impls map to the MLE preprocessed matrix.

use std::{borrow::Borrow, marker::PhantomData, sync::Arc};

use p3_air::{Air, BaseAir, WindowAccess};
use p3_field::Field;
use p3_matrix::dense::RowMajorMatrix;

use crate::{
    chips::chips::{
        alu::{
            add::AddChip, addw::AddwChip, bitwise::BitwiseChip, divrem::DivRemChip, lt::LtChip,
            mul::MulChip, sll::SLLChip, sr::traces::ShiftRightChip, sub::SubChip, subw::SubwChip,
        },
        byte::ByteChip,
        riscv_cpu::CpuChip,
        riscv_ecall::EcallChip,
        riscv_global::{
            columns::{GlobalCols, NUM_GLOBAL_AUX_COLS, NUM_GLOBAL_COLS, NUM_GLOBAL_TABLE_COLS},
            constraints::eval_global_row,
            GlobalChip,
        },
        riscv_memory::{
            initialize_finalize::MemoryInitializeFinalizeChip, local::MemoryLocalChip,
            read_write::MemoryReadWriteChip, unaligned::MemoryUnalignedChip,
        },
        riscv_program::ProgramChip,
        syscall::SyscallChip,
    },
    compiler::riscv::program::Program,
    configs::config::Poseidon2Config,
    machine::{builder::ChipBuilder, chip::ChipBehavior},
    primitives::consts::{MAX_NUM_PVS, RISCV_NUM_PVS},
};
use pico_mle_core::{air::PartitionedAirBuilder, BaseAirWithPublicValues, PartitionedBaseAir};

// ──────────── PartitionedBaseAir + BaseAirWithPublicValues (per chip) ────────────
//
// Both traits are opted-in per chip. The empty `PartitionedBaseAir` impl uses the default
// (no cached main, common_main = full width) — correct for every brevis chip, which uses a single
// un-partitioned main trace. `BaseAirWithPublicValues` defaults to 0 public values;
// `CpuChip`/`EcallChip`/`MemInit`/`MemFinal` override below, and `GlobalAir` has its own impls.

macro_rules! no_pvs {
    ($($ty:ty),* $(,)?) => {
        $(
            impl<F: Field> PartitionedBaseAir<F> for $ty {}
            impl<F: Field> BaseAirWithPublicValues<F> for $ty {}
        )*
    };
}

/// Same, but for chips whose `BaseAir` requires `PrimeField32` (e.g. the SHA chips).
macro_rules! no_pvs_pf32 {
    ($($ty:ty),* $(,)?) => {
        $(
            impl<F: p3_field::PrimeField32> PartitionedBaseAir<F> for $ty {}
            impl<F: p3_field::PrimeField32> BaseAirWithPublicValues<F> for $ty {}
        )*
    };
}

no_pvs!(
    AddChip<F>,
    SubChip<F>,
    MulChip<F>,
    BitwiseChip<F>,
    LtChip<F>,
    SLLChip<F>,
    ShiftRightChip<F>,
    DivRemChip<F>,
    AddwChip<F>,
    SubwChip<F>,
    GlobalChip<F>,
    MemoryLocalChip<F>,
    MemoryReadWriteChip<F>,
    MemoryUnalignedChip<F>,
    SyscallChip<F>,
    ByteChip<F>,
    ProgramChip<F>,
);

impl<F: Field> PartitionedBaseAir<F> for CpuChip<F> {}
impl<F: Field> BaseAirWithPublicValues<F> for CpuChip<F> {
    fn num_public_values(&self) -> usize {
        RISCV_NUM_PVS
    }
}

// The Ecall chip owns the ecall-driven PV constraints (exit_code, commit digests) — it reads
// the same RISCV public values as the Cpu chip.
impl<F: Field> PartitionedBaseAir<F> for EcallChip<F> {}
impl<F: Field> BaseAirWithPublicValues<F> for EcallChip<F> {
    fn num_public_values(&self) -> usize {
        RISCV_NUM_PVS
    }
}

// MemInit/MemFinal read the RISCV public values as a `[_; MAX_NUM_PVS]` array.
impl<F: Field> PartitionedBaseAir<F> for MemoryInitializeFinalizeChip<F> {}
impl<F: Field> BaseAirWithPublicValues<F> for MemoryInitializeFinalizeChip<F> {
    fn num_public_values(&self) -> usize {
        MAX_NUM_PVS
    }
}

// The poseidon2 *precompile* chip (covers the `FieldSpecificPrecompilePoseidon2Chip` alias).
// Same shape as the bus receiver above, and for the same reason it is written out rather than
// listed in `no_pvs_pf32!` below: the macro takes a concrete type, and this one carries two
// further generics that are projections of `F`.
impl<F: Field, LL, Config: Poseidon2Config> PartitionedBaseAir<F>
    for Poseidon2PermuteChip<F, LL, Config>
{
}
impl<F: Field, LL, Config: Poseidon2Config> BaseAirWithPublicValues<F>
    for Poseidon2PermuteChip<F, LL, Config>
{
}

// ── Compute precompile chips ─────────────────────────────────────────────────────────
//
// All are generic `impl<F, CB: ChipBuilder<F>> Air<CB>` so they adapt; here we just opt them in
// to `BaseAirWithPublicValues` (0 PVs). Memory boundary chips (MemInit/MemFinal) and GlobalChip
// are added with the cross-chunk / global-lookup handling.
use crate::chips::{
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
        bls12381_g2::{add::Bls12381G2AddChip, double::Bls12381G2DoubleChip},
        edwards::{EdAddAssignChip, EdDecompressChip},
        fptower::{fp::FpOpChip, fp2_addsub::Fp2AddSubChip, fp2_mul::Fp2MulChip},
        keccak256::KeccakControlChip,
        poseidon2::Poseidon2PermuteChip,
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
};

no_pvs_pf32!(
    KeccakControlChip<F>,
    ShaExtendChip<F>,
    ShaExtendControlChip<F>,
    ShaCompressChip<F>,
    ShaCompressControlChip<F>,
    Uint256MulChip<F>,
    WeierstrassAddAssignChip<F, Secp256k1>,
    WeierstrassDoubleAssignChip<F, Secp256k1>,
    WeierstrassDecompressChip<F, Secp256k1>,
    WeierstrassAddAssignChip<F, Secp256r1>,
    WeierstrassDoubleAssignChip<F, Secp256r1>,
    WeierstrassDecompressChip<F, Secp256r1>,
    WeierstrassAddAssignChip<F, Bn254>,
    WeierstrassDoubleAssignChip<F, Bn254>,
    WeierstrassAddAssignChip<F, Bls12381>,
    WeierstrassDoubleAssignChip<F, Bls12381>,
    WeierstrassDecompressChip<F, Bls12381>,
    FpOpChip<F, Bn254BaseField>,
    Fp2AddSubChip<F, Bn254BaseField>,
    Fp2MulChip<F, Bn254BaseField>,
    FpOpChip<F, Bls381BaseField>,
    Fp2AddSubChip<F, Bls381BaseField>,
    Fp2MulChip<F, Bls381BaseField>,
    FpOpChip<F, Secp256k1BaseField>,
    EdAddAssignChip<F, Ed25519>,
    EdDecompressChip<F, Ed25519Parameters>,
    Bls12381G2AddChip<F>,
    Bls12381G2DoubleChip<F>,
);

// ───────────────────────── PrepAir: preprocessed-table wrapper ─────────────────────────

/// Wraps a preprocessed chip so the MLE keygen sees its table via p3 `preprocessed_trace`.
///
/// `program` is the ELF program (ignored by `ByteChip`, used by `ProgramChip`). For an ELF-fixed
/// test, keygen is built per-ELF, so the program is known at wrapper-construction time.
pub struct PrepAir<F, C> {
    pub inner: C,
    pub program: Arc<Program>,
    _phantom: PhantomData<F>,
}

impl<F, C> PrepAir<F, C> {
    pub fn new(inner: C, program: Arc<Program>) -> Self {
        Self {
            inner,
            program,
            _phantom: PhantomData,
        }
    }
}

impl<F, C> BaseAir<F> for PrepAir<F, C>
where
    F: Field,
    C: ChipBehavior<F, Program = Program>,
{
    fn width(&self) -> usize {
        BaseAir::<F>::width(&self.inner)
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        self.inner.generate_preprocessed(&self.program)
    }
}

impl<F, C> PartitionedBaseAir<F> for PrepAir<F, C>
where
    F: Field,
    C: ChipBehavior<F, Program = Program>,
{
}

impl<F, C> BaseAirWithPublicValues<F> for PrepAir<F, C>
where
    F: Field,
    C: ChipBehavior<F, Program = Program>,
{
}

impl<F, C, CB> Air<CB> for PrepAir<F, C>
where
    F: Field,
    C: ChipBehavior<F, Program = Program> + Air<CB>,
    CB: p3_air::AirBuilder<F = F>,
{
    fn eval(&self, builder: &mut CB) {
        self.inner.eval(builder);
    }
}

// ───────────────────────── GlobalAir: the Global chip, partitioned ─────────────────────────

/// The Global chip as the MLE machine proves it.
///
/// A Global row's leading columns are the chunk's cross-chunk event table. Here they are the
/// AIR's cached main trace, committed on its own, so that a global-LogUp group proof can open
/// the same commitment later; the row's remaining columns are the common main trace. The
/// constraints are the chip's, applied to the row assembled from the two partitions.
///
/// The AIR is present in every chunk (the machine registers it as required), which also makes
/// it the carrier of the riscv public values the Convert layer reads: its public values are a
/// copy of them, committed and unconstrained here, like MemInit's copy.
#[derive(Default)]
pub struct GlobalAir<F>(PhantomData<F>);

impl<F: Field> PartitionedBaseAir<F> for GlobalAir<F> {
    fn cached_main_widths(&self) -> Vec<usize> {
        vec![NUM_GLOBAL_TABLE_COLS]
    }
    fn common_main_width(&self) -> usize {
        NUM_GLOBAL_AUX_COLS
    }
}

impl<F: Field> BaseAir<F> for GlobalAir<F> {
    fn width(&self) -> usize {
        NUM_GLOBAL_COLS
    }
}

impl<F: Field> BaseAirWithPublicValues<F> for GlobalAir<F> {
    fn num_public_values(&self) -> usize {
        MAX_NUM_PVS
    }
}

impl<F, CB> Air<CB> for GlobalAir<F>
where
    F: Field,
    CB: ChipBuilder<F> + PartitionedAirBuilder,
{
    fn eval(&self, builder: &mut CB) {
        let row: Vec<CB::Var> = builder.cached_mains()[0]
            .current_slice()
            .iter()
            .chain(builder.common_main().current_slice())
            .copied()
            .collect();
        let local: &GlobalCols<CB::Var> = row.as_slice().borrow();
        eval_global_row(builder, local);
    }
}
