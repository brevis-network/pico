use super::super::{columns::CpuCols, CpuChip};
use crate::{
    chips::chips::riscv_ecall::NUM_EXTRA_CLK_BITS, machine::builder::ChipBuilder,
    primitives::consts::CHUNK_CLK_START,
};
use p3_air::AirBuilder;
use p3_field::{Field, PrimeCharacteristicRing, PrimeField32};
use p3_koala_bear::KoalaBear;
use pico_mle_core::config::MAX_RISCV_LOG_STACKED_HEIGHT;

/// The largest step the row chain can take per row: `4 + num_extra_clk` with `num_extra_clk`
/// capped at `NUM_EXTRA_CLK_BITS` bits by the Ecall chip (`riscv_ecall/constraints.rs`).
pub const MAX_ROW_CHAIN_STEP: u64 = 4 + ((1u64 << NUM_EXTRA_CLK_BITS) - 1);

/// The row-chain clk bound must leave the 25-bit timestamp-difference window below the modulus:
/// `clk <= 4 + (2^MAX_RISCV_LOG_STACKED_HEIGHT - 1) * MAX_ROW_CHAIN_STEP`, plus the largest
/// `MemoryAccessPosition` (3), plus `2^25`, all below `p`. Raising the height limit or the
/// extra-cycle cap past this makes `eval_memory_access_timestamp` unsound.
const CLK_BOUND_FITS: () = assert!(
    (1u64 << MAX_RISCV_LOG_STACKED_HEIGHT) * MAX_ROW_CHAIN_STEP + 3 + (1u64 << 25)
        < KoalaBear::ORDER_U32 as u64
);

impl<F: Field> CpuChip<F> {
    /// Constraints related to the chunk and clk.
    ///
    /// This method ensures that the clk starts at `CHUNK_CLK_START` (there is no chunk column:
    /// every message that names the chunk carries the `execution_chunk` public value, which is
    /// what keeps all rows on the same chunk). The clk *step* is the rotation constraint N2 in
    /// `eval_row_chain`; with the start value here it makes `clk` an integer below `B` (see the
    /// body), which is what the memory access timestamp check needs.
    /// See `RiscVMemoryBuilder::eval_memory_access_timestamp`.
    pub(crate) fn eval_chunk_clk<CB: ChipBuilder<F>>(
        &self,
        builder: &mut CB,
        local: &CpuCols<CB::Var>,
    ) {
        // No `chunk == next.chunk` transition constraint and no chunk column: every message that
        // names the chunk carries the `execution_chunk` public value, so all rows agree through it.

        // No chunk range check here: it moved to the convert circuit, which range-checks every
        // proof's `chunk` public value to MAX_LOG_NUMBER_OF_CHUNKS bits
        // (riscv_circuit/convert/builder.rs). Both counters start at 1 (`assert_complete`) and
        // `execution_chunk` only increments where `chunk` does, so `execution_chunk <= chunk`
        // < 2^16 across an accepted chain -- the same bound the deleted lookup gave.

        // The compile-time bound check below is what licenses the missing range check; name it
        // here so the lint keeps it alive and a reader finds it from the constraint it serves.
        let () = CLK_BOUND_FITS;

        // `clk` is one committed column, not range-checked (see below): one free witness, read
        // through `clk_expr`.
        let local_clk = Self::clk_expr::<CB>(local);

        // Verify that the first row starts at `CHUNK_CLK_START`, not at zero. The memory bus
        // needs one timestamp below every real access so `MemoryLocalChip` can label the state a
        // chunk inherits from an earlier one; a memory access is stamped
        // `clk + MemoryAccessPosition` and all four positions are taken, so the room comes from
        // the start of the counter. `chunk_split` charges it to the split threshold, so the
        // admissible CHUNK_SIZE is unchanged.
        builder
            .when_first_row()
            .assert_eq(local_clk, CB::Expr::from_u32(CHUNK_CLK_START));

        // No clk range check. The row chain (`eval_row_chain`) makes every real row's clk a
        // bounded integer by induction: the first row holds 4 (above), the real rows are a
        // prefix (N3), and on every edge inside it `next.clk = clk + 4 + num_extra_clk` (N2) with
        // `num_extra_clk < 64` certified by the Ecall chip's BitRange(6) lookup. Over at most
        // 2^MAX_RISCV_LOG_STACKED_HEIGHT rows (the verifier's height bound, from the proof shape
        // and the VK, not from this AIR) that gives
        // `clk <= 4 + (2^MAX_RISCV_LOG_STACKED_HEIGHT - 1) * 67 =: B` as an integer, with no
        // wrap-around. The memory-access timestamp check
        // (`RiscVMemoryBuilder::eval_memory_access_timestamp`) needs both compared clks below
        // `p - 2^25`; `B + 3` is (`CLK_BOUND_FITS` above). The Global bus does not depend on
        // this: it range-checks its own slot 0 (`gadgets/global_interaction.rs`).
    }
}
