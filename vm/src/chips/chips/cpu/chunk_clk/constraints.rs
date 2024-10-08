use crate::{
    chips::{
        chips::cpu::{columns::CpuCols, CpuChip},
        utils::memory::MemoryAirBuilder,
    },
    compiler::opcode::ByteOpcode,
    machine::builder::{ChipBuilder, ChipLookupBuilder, ChipRangeBuilder},
};
use p3_air::AirBuilder;
use p3_field::{AbstractField, Field};

impl<F: Field> CpuChip<F> {
    /// Constraints related to the chunk and clk.
    ///
    /// This method ensures that all of the chunk values are the same and that the clk starts at 0
    /// and is transitioned apporpriately.  It will also check that chunk values are within 16 bits
    /// and clk values are within 24 bits.  Those range checks are needed for the memory access
    /// timestamp check, which assumes those values are within 2^24.  See
    /// [`MemoryAirBuilder::verify_mem_access_ts`].
    pub(crate) fn eval_chunk_clk<CB: ChipBuilder<F>>(
        &self,
        builder: &mut CB,
        local: &CpuCols<CB::Var>,
        next: &CpuCols<CB::Var>,
    ) {
        // Verify that all chunk values are the same.
        builder
            .when_transition()
            .when(next.is_real)
            .assert_eq(local.chunk, next.chunk);

        // Verify that the chunk value is within 16 bits.
        builder.looking_byte(
            CB::Expr::from_canonical_u8(ByteOpcode::U16Range as u8),
            local.chunk,
            CB::Expr::zero(),
            CB::Expr::zero(),
            local.chunk,
            local.channel,
            local.is_real,
        );

        // Verify that the first row has a clk value of 0.
        builder.when_first_row().assert_zero(local.clk);

        // Verify that the clk increments are correct.  Most clk increment should be 4, but for some
        // precompiles, there are additional cycles.
        let num_extra_cycles = self.get_num_extra_ecall_cycles::<CB>(local);

        // We already assert that `local.clk < 2^24`. `num_extra_cycles` is an entry of a word and
        // therefore less than `2^8`, this means that the sum cannot overflow in a 31 bit field.
        let expected_next_clk =
            local.clk + CB::Expr::from_canonical_u32(4) + num_extra_cycles.clone();

        builder
            .when_transition()
            .when(next.is_real)
            .assert_eq(expected_next_clk.clone(), next.clk);

        // Range check that the clk is within 24 bits using it's limb values.
        builder.range_check_u24(
            local.clk,
            local.clk_16bit_limb,
            local.clk_8bit_limb,
            local.chunk,
            local.channel,
            local.is_real,
        );
    }
}
