use crate::chips::cpu::{columns::CpuCols, CpuChip};
use p3_air::AirBuilder;
use p3_field::Field;
use pico_machine::chip::ChipBuilder;

impl<F: Field> CpuChip<F> {
    /// Constraints related to the shard and clk.
    ///
    /// This method ensures that all of the shard values are the same and that the clk starts at 0
    /// and is transitioned apporpriately.  It will also check that shard values are within 16 bits
    /// and clk values are within 24 bits.  Those range checks are needed for the memory access
    /// timestamp check, which assumes those values are within 2^24.  See
    /// [`MemoryAirBuilder::verify_mem_access_ts`].
    pub(crate) fn eval_shard_clk<CB: ChipBuilder<F>>(
        &self,
        builder: &mut CB,
        local: &CpuCols<CB::Var>,
        next: &CpuCols<CB::Var>,
    ) {
        // Verify that all shard values are the same.
        builder
            .when_transition()
            .when(next.is_real)
            .assert_eq(local.shard, next.shard);

        /* TODO: Enable after lookup integration.
                // Verify that the shard value is within 16 bits.
                builder.send_byte(
                    CB::Expr::from_canonical_u8(ByteOpcode::U16Range as u8),
                    local.shard,
                    CB::Expr::zero(),
                    CB::Expr::zero(),
                    local.shard,
                    local.channel,
                    local.is_real,
                );
        */

        // Verify that the first row has a clk value of 0.
        builder.when_first_row().assert_zero(local.clk);

        /* TODO: Enable after adding memory read write chip.
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
                builder.eval_range_check_24bits(
                    local.clk,
                    local.clk_16bit_limb,
                    local.clk_8bit_limb,
                    local.shard,
                    local.channel,
                    local.is_real,
                );
        */
    }
}
