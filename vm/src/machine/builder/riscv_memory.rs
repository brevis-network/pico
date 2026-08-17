use crate::{
    chips::chips::riscv_memory::read_write::columns::{MemoryAccessCols, MemoryCols},
    compiler::word::Word,
    machine::{
        builder::{ChipBuilder, ChipRangeBuilder},
        lookup::{LookupScope, LookupType, SymbolicLookup},
    },
};
use itertools::Itertools;
use p3_air::AirBuilder;
use p3_field::{Field, FieldAlgebra};
use std::iter::once;

pub trait RiscVMemoryBuilder<F: Field>: ChipBuilder<F> {
    /// Constrain a memory read or write.
    ///
    /// This method verifies that a memory access timestamp (chunk, clk) is greater than the
    /// previous access's timestamp.  It will also add to the memory argument.
    ///
    /// `addr` is a 3-element array of u16 limbs representing the full 48-bit address.
    ///
    /// # Contract for writes: this does NOT constrain the written value
    ///
    /// `memory_access.value()` is placed on the memory bus verbatim. Nothing here ties it to
    /// whatever the caller computed, so **for a write it is a free column unless the caller adds
    /// the equality itself**:
    ///
    /// ```ignore
    /// builder.eval_memory_access(chunk, clk, addr, &access, is_real);
    /// for (v, w) in access.value().0.iter().zip(computed.0.iter()) {
    ///     builder.when(is_real).assert_eq((*v).into(), w.clone());
    /// }
    /// ```
    ///
    /// Omitting that second step is a soundness hole: the prover may write any value it likes.
    /// It has happened twice, in both cases with correct arithmetic that was simply never wired
    /// to memory:
    ///
    /// - `sha_extend` computed `w[i]` into `local.s2` and never bound it to the written word.
    ///   The `s2_value_word` named in a comment there did not exist.
    /// - Every constraint in `sha_compress` acted on `mem.prev_value`, the value *read*;
    ///   `mem.access.value` was referenced nowhere.
    ///
    /// [`Self::eval_memory_access_slice_write`] bundles both steps, but only for callers whose
    /// addresses follow `initial_addr + i * addr_offset`.
    fn eval_memory_access<E: Into<Self::Expr> + Clone>(
        &mut self,
        chunk: impl Into<Self::Expr>,
        clk: impl Into<Self::Expr>,
        addr: [impl Into<Self::Expr> + Clone; 3],
        memory_access: &impl MemoryCols<E>,
        do_check: impl Into<Self::Expr>,
    ) {
        let do_check: Self::Expr = do_check.into();
        let chunk: Self::Expr = chunk.into();
        let clk: Self::Expr = clk.into();
        let mem_access = memory_access.access();

        self.assert_bool(do_check.clone());

        // Verify that the current memory access time is greater than the previous's.
        self.eval_memory_access_timestamp(mem_access, do_check.clone(), chunk.clone(), clk.clone());

        // Regional lookup: 9 elements [chunk, clk, addr[0], addr[1], addr[2], v0, v1, v2, v3]
        let addr0: Self::Expr = addr[0].clone().into();
        let addr1: Self::Expr = addr[1].clone().into();
        let addr2: Self::Expr = addr[2].clone().into();
        let prev_chunk = mem_access.prev_chunk.clone().into();
        let prev_clk = mem_access.prev_clk.clone().into();
        let prev_values = once(prev_chunk)
            .chain(once(prev_clk))
            .chain(once(addr0.clone()))
            .chain(once(addr1.clone()))
            .chain(once(addr2.clone()))
            .chain(memory_access.prev_value().clone().map(Into::into))
            .collect_vec();
        let current_values = once(chunk)
            .chain(once(clk))
            .chain(once(addr0))
            .chain(once(addr1))
            .chain(once(addr2))
            .chain(memory_access.value().clone().map(Into::into))
            .collect_vec();

        // The previous values get sent with multiplicity = 1, for "read".
        self.looking(SymbolicLookup::new(
            prev_values.clone(),
            do_check.clone(),
            LookupType::Memory,
            LookupScope::Regional,
        ));

        // The current values get "received", i.e. multiplicity = -1
        self.looked(SymbolicLookup::new(
            current_values,
            do_check.clone(),
            LookupType::Memory,
            LookupScope::Regional,
        ));
    }

    /// Constraints a memory read or write to a slice of `MemoryAccessCols`.
    ///
    /// `initial_addr` is a 3-element array of u16 limbs. The offset `i * addr_offset` is added
    /// to limb[0] for each element. Use `addr_offset=4` for u32 words, `addr_offset=8` for u64.
    fn eval_memory_access_slice<E: Into<Self::Expr> + Copy>(
        &mut self,
        chunk: impl Into<Self::Expr> + Copy,
        clk: impl Into<Self::Expr> + Clone,
        initial_addr: [impl Into<Self::Expr> + Clone; 3],
        memory_access_slice: &[impl MemoryCols<E>],
        addr_offset: usize,
        verify_memory_access: impl Into<Self::Expr> + Copy,
    ) {
        for (i, access_slice) in memory_access_slice.iter().enumerate() {
            self.eval_memory_access(
                chunk,
                clk.clone(),
                [
                    initial_addr[0].clone().into()
                        + Self::Expr::from_canonical_usize(i * addr_offset),
                    initial_addr[1].clone().into(),
                    initial_addr[2].clone().into(),
                ],
                access_slice,
                verify_memory_access,
            );
        }
    }

    /// Constraints a memory write to a slice of `MemoryAccessCols`, additionally constraining
    /// that the write values match `write_values`.
    ///
    /// This is needed for precompile chips that compute new values (e.g. via FieldOpCols) and
    /// write them back to memory. The constraint ensures `access.value() == write_value`.
    #[allow(clippy::too_many_arguments)]
    fn eval_memory_access_slice_write<E: Into<Self::Expr> + Copy>(
        &mut self,
        chunk: impl Into<Self::Expr> + Copy,
        clk: impl Into<Self::Expr> + Clone,
        initial_addr: [impl Into<Self::Expr> + Clone; 3],
        memory_access_slice: &[impl MemoryCols<E>],
        write_values: &[Word<Self::Expr>],
        addr_offset: usize,
        verify_memory_access: impl Into<Self::Expr> + Copy,
    ) {
        for (i, (access_slice, write_value)) in memory_access_slice
            .iter()
            .zip(write_values.iter())
            .enumerate()
        {
            self.eval_memory_access(
                chunk,
                clk.clone(),
                [
                    initial_addr[0].clone().into()
                        + Self::Expr::from_canonical_usize(i * addr_offset),
                    initial_addr[1].clone().into(),
                    initial_addr[2].clone().into(),
                ],
                access_slice,
                verify_memory_access,
            );

            // Constrain that the current value matches the computed write value.
            let do_check: Self::Expr = verify_memory_access.into();
            for (j, (v, w)) in access_slice
                .value()
                .0
                .iter()
                .zip(write_value.0.iter())
                .enumerate()
            {
                let _ = j;
                self.when(do_check.clone())
                    .assert_eq((*v).into(), w.clone());
            }
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
        // working in a field larger than `2 * 2^24` (which is true of the BabyBear, KoalaBear and
        // Mersenne31 prime).
        let diff_minus_one = current_comp_val - prev_comp_value - Self::Expr::ONE;

        // Verify that mem_access.ts_diff = mem_access.ts_diff_16bit_limb
        // + mem_access.ts_diff_8bit_limb * 2^16.
        self.range_check_u24(
            diff_minus_one,
            mem_access.diff_16bit_limb.clone(),
            mem_access.diff_8bit_limb.clone(),
            do_check,
        );
    }
}
