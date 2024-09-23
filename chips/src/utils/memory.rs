use crate::chips::memory::read_write::columns::{MemoryAccessCols, MemoryCols};
use itertools::Itertools;
use p3_air::AirBuilder;
use p3_field::{AbstractField, Field};
use pico_machine::builder::ChipBuilder;
use std::iter::once;

pub trait MemoryAirBuilder<F: Field>: AirBuilder {
    /// Constrain a memory read or write.
    ///
    /// This method verifies that a memory access timestamp (chunk, clk) is greater than the
    /// previous access's timestamp.  It will also add to the memory argument.
    fn eval_memory_access<E: Into<Self::Expr> + Clone>(
        &mut self,
        chunk: impl Into<Self::Expr>,
        channel: impl Into<Self::Expr>,
        clk: impl Into<Self::Expr>,
        addr: impl Into<Self::Expr>,
        memory_access: &impl MemoryCols<E>,
        do_check: impl Into<Self::Expr>,
    );

    /// Constraints a memory read or write to a slice of `MemoryAccessCols`.
    fn eval_memory_access_slice<E: Into<Self::Expr> + Copy>(
        &mut self,
        chunk: impl Into<Self::Expr> + Copy,
        channel: impl Into<Self::Expr> + Clone,
        clk: impl Into<Self::Expr> + Clone,
        initial_addr: impl Into<Self::Expr> + Clone,
        memory_access_slice: &[impl MemoryCols<E>],
        verify_memory_access: impl Into<Self::Expr> + Copy,
    );

    /// Verifies the memory access timestamp.
    ///
    /// This method verifies that the current memory access happened after the previous one's.
    /// Specifically it will ensure that if the current and previous access are in the same chunk,
    /// then the current's clk val is greater than the previous's.  If they are not in the same
    /// chunk, then it will ensure that the current's chunk val is greater than the previous's.
    fn eval_memory_access_timestamp(
        &mut self,
        mem_access: &MemoryAccessCols<impl Into<Self::Expr> + Clone>,
        do_check: impl Into<Self::Expr>,
        chunk: impl Into<Self::Expr> + Clone,
        channel: impl Into<Self::Expr> + Clone,
        clk: impl Into<Self::Expr>,
    );

    /// Verifies the inputted value is within 24 bits.
    ///
    /// This method verifies that the inputted is less than 2^24 by doing a 16 bit and 8 bit range
    /// check on it's limbs.  It will also verify that the limbs are correct.  This method is needed
    /// since the memory access timestamp check (see [Self::verify_mem_access_ts]) needs to assume
    /// the clk is within 24 bits.
    fn eval_range_check_24bits(
        &mut self,
        value: impl Into<Self::Expr>,
        limb_16: impl Into<Self::Expr> + Clone,
        limb_8: impl Into<Self::Expr> + Clone,
        chunk: impl Into<Self::Expr> + Clone,
        channel: impl Into<Self::Expr> + Clone,
        do_check: impl Into<Self::Expr> + Clone,
    );
}
impl<F: Field, CB: ChipBuilder<F>> MemoryAirBuilder<F> for CB {
    /// Constrain a memory read or write.
    ///
    /// This method verifies that a memory access timestamp (chunk, clk) is greater than the
    /// previous access's timestamp.  It will also add to the memory argument.
    fn eval_memory_access<E: Into<CB::Expr> + Clone>(
        &mut self,
        chunk: impl Into<CB::Expr>,
        channel: impl Into<CB::Expr>,
        clk: impl Into<CB::Expr>,
        addr: impl Into<CB::Expr>,
        memory_access: &impl MemoryCols<E>,
        do_check: impl Into<Self::Expr>,
    ) {
        let do_check: Self::Expr = do_check.into();
        let chunk: Self::Expr = chunk.into();
        let channel: Self::Expr = channel.into();
        let clk: Self::Expr = clk.into();
        let mem_access = memory_access.access();

        self.assert_bool(do_check.clone());

        // Verify that the current memory access time is greater than the previous's.
        self.eval_memory_access_timestamp(
            mem_access,
            do_check.clone(),
            chunk.clone(),
            channel,
            clk.clone(),
        );

        // Add to the memory argument.
        let addr = addr.into();
        let prev_chunk = mem_access.prev_chunk.clone().into();
        let prev_clk = mem_access.prev_clk.clone().into();
        let prev_values = once(prev_chunk)
            .chain(once(prev_clk))
            .chain(once(addr.clone()))
            .chain(memory_access.prev_value().clone().map(Into::into))
            .collect_vec();
        let current_values = once(chunk)
            .chain(once(clk))
            .chain(once(addr.clone()))
            .chain(memory_access.value().clone().map(Into::into))
            .collect_vec();

        /* TODO: Enable after generating dependencies for memory.
                // The previous values get sent with multiplicity = 1, for "read".
                self.send(AirInteraction::new(
                    prev_values,
                    do_check.clone(),
                    InteractionKind::Memory,
                ));

                // The current values get "received", i.e. multiplicity = -1
                self.receive(AirInteraction::new(
                    current_values,
                    do_check.clone(),
                    InteractionKind::Memory,
                ));
        */
    }

    /// Constraints a memory read or write to a slice of `MemoryAccessCols`.
    fn eval_memory_access_slice<E: Into<Self::Expr> + Copy>(
        &mut self,
        chunk: impl Into<Self::Expr> + Copy,
        channel: impl Into<Self::Expr> + Clone,
        clk: impl Into<Self::Expr> + Clone,
        initial_addr: impl Into<Self::Expr> + Clone,
        memory_access_slice: &[impl MemoryCols<E>],
        verify_memory_access: impl Into<Self::Expr> + Copy,
    ) {
        for (i, access_slice) in memory_access_slice.iter().enumerate() {
            self.eval_memory_access(
                chunk,
                channel.clone(),
                clk.clone(),
                initial_addr.clone().into() + Self::Expr::from_canonical_usize(i * 4),
                access_slice,
                verify_memory_access,
            );
        }
    }

    /// Verifies the memory access timestamp.
    ///
    /// This method verifies that the current memory access happened after the previous one's.
    /// Specifically it will ensure that if the current and previous access are in the same chunk,
    /// then the current's clk val is greater than the previous's.  If they are not in the same
    /// chunk, then it will ensure that the current's chunk val is greater than the previous's.
    fn eval_memory_access_timestamp(
        &mut self,
        mem_access: &MemoryAccessCols<impl Into<Self::Expr> + Clone>,
        do_check: impl Into<Self::Expr>,
        chunk: impl Into<Self::Expr> + Clone,
        channel: impl Into<Self::Expr> + Clone,
        clk: impl Into<Self::Expr>,
    ) {
        let do_check: Self::Expr = do_check.into();
        let compare_clk: Self::Expr = mem_access.compare_clk.clone().into();
        let chunk: Self::Expr = chunk.clone().into();
        let prev_chunk: Self::Expr = mem_access.prev_chunk.clone().into();

        // First verify that compare_clk's value is correct.
        self.when(do_check.clone()).assert_bool(compare_clk.clone());
        self.when(do_check.clone())
            .when(compare_clk.clone())
            .assert_eq(chunk.clone(), prev_chunk);

        // Get the comparison timestamp values for the current and previous memory access.
        let prev_comp_value = self.if_else(
            mem_access.compare_clk.clone(),
            mem_access.prev_clk.clone(),
            mem_access.prev_chunk.clone(),
        );

        let current_comp_val = self.if_else(compare_clk.clone(), clk.into(), chunk.clone());

        // Assert `current_comp_val > prev_comp_val`. We check this by asserting that
        // `0 <= current_comp_val-prev_comp_val-1 < 2^24`.
        //
        // The equivalence of these statements comes from the fact that if
        // `current_comp_val <= prev_comp_val`, then `current_comp_val-prev_comp_val-1 < 0` and will
        // underflow in the prime field, resulting in a value that is `>= 2^24` as long as both
        // `current_comp_val, prev_comp_val` are range-checked to be `<2^24` and as long as we're
        // working in a field larger than `2 * 2^24` (which is true of the BabyBear and Mersenne31
        // prime).
        let diff_minus_one = current_comp_val - prev_comp_value - Self::Expr::one();

        // Verify that mem_access.ts_diff = mem_access.ts_diff_16bit_limb
        // + mem_access.ts_diff_8bit_limb * 2^16.
        self.eval_range_check_24bits(
            diff_minus_one,
            mem_access.diff_16bit_limb.clone(),
            mem_access.diff_8bit_limb.clone(),
            chunk.clone(),
            channel.clone(),
            do_check,
        );
    }

    /// Verifies the inputted value is within 24 bits.
    ///
    /// This method verifies that the inputted is less than 2^24 by doing a 16 bit and 8 bit range
    /// check on it's limbs.  It will also verify that the limbs are correct.  This method is needed
    /// since the memory access timestamp check (see [Self::verify_mem_access_ts]) needs to assume
    /// the clk is within 24 bits.
    fn eval_range_check_24bits(
        &mut self,
        value: impl Into<Self::Expr>,
        limb_16: impl Into<Self::Expr> + Clone,
        limb_8: impl Into<Self::Expr> + Clone,
        chunk: impl Into<Self::Expr> + Clone,
        channel: impl Into<Self::Expr> + Clone,
        do_check: impl Into<Self::Expr> + Clone,
    ) {
        // Verify that value = limb_16 + limb_8 * 2^16.
        self.when(do_check.clone()).assert_eq(
            value,
            limb_16.clone().into()
                + limb_8.clone().into() * Self::Expr::from_canonical_u32(1 << 16),
        );

        /* TODO: Enable after generating dependencies for memory.
                // Send the range checks for the limbs.
                self.send_byte(
                    Self::Expr::from_canonical_u8(ByteOpcode::U16Range as u8),
                    limb_16,
                    Self::Expr::zero(),
                    Self::Expr::zero(),
                    chunk.clone(),
                    channel.clone(),
                    do_check.clone(),
                );

                self.send_byte(
                    Self::Expr::from_canonical_u8(ByteOpcode::U8Range as u8),
                    Self::Expr::zero(),
                    Self::Expr::zero(),
                    limb_8,
                    chunk.clone(),
                    channel.clone(),
                    do_check,
                )
        */
    }
}
