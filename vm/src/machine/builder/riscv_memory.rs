use crate::{
    chips::chips::riscv_memory::read_write::columns::{
        MemoryAccessCols, MemoryCols, MemoryLiteCols,
    },
    machine::{
        builder::{ChipBuilder, ChipRangeBuilder},
        lookup::{LookupScope, LookupType, SymbolicLookup},
    },
};
use itertools::Itertools;
use p3_field::{Field, PrimeCharacteristicRing};
use std::iter::once;

pub trait RiscVMemoryBuilder<F: Field>: ChipBuilder<F> {
    /// Constrain a memory read or write.
    ///
    /// This method verifies that a memory access timestamp (chunk, clk) is greater than the
    /// previous access's timestamp.  It will also add to the memory argument.
    ///
    /// `addr` is a 3-element array of u16 limbs: the memory bus carries a 48-bit address shape.
    /// The RISC-V chips put a constant 0 in the third limb, as guest addresses lie below 2^32.
    /// The caller is responsible for the limb bounds: nothing here range-checks `addr`, and the
    /// MemoryLocal chip, which is bound to these tuples over the bus, does not either.
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
    /// There is no slice helper: each caller forms its own per-word address with a carry
    /// (`AddrAddGadget`) and calls this method once per word.
    fn eval_memory_access<E: Into<Self::Expr> + Clone>(
        &mut self,
        chunk: impl Into<Self::Expr>,
        clk: impl Into<Self::Expr>,
        addr: [impl Into<Self::Expr> + Clone; 3],
        memory_access: &impl MemoryCols<E>,
        do_check: impl Into<Self::Expr>,
    ) {
        let do_check: Self::Expr = do_check.into();
        self.assert_bool(do_check.clone());
        self.eval_memory_access_unchecked(chunk, clk, addr, memory_access, do_check);
    }

    /// [`Self::eval_memory_access`] without the `assert_bool(do_check)`. Only for callers whose
    /// gate is already boolean by other constraints -- the Cpu chip's `1 - imm_b` / `1 - imm_c`
    /// (`imm_*` is a Program-table selector on real rows and forced to 1 on padding rows) -- where
    /// the extra constraint would be pure round-0 zerocheck cost. Everyone else uses
    /// [`Self::eval_memory_access`].
    fn eval_memory_access_unchecked<E: Into<Self::Expr> + Clone>(
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

        // Verify that the current memory access time is greater than the previous's.
        self.eval_memory_access_timestamp(mem_access, do_check.clone(), clk.clone());

        // Regional lookup: 9 elements [chunk, clk, addr[0], addr[1], addr[2], v0, v1, v2, v3]
        let addr0: Self::Expr = addr[0].clone().into();
        let addr1: Self::Expr = addr[1].clone().into();
        let addr2: Self::Expr = addr[2].clone().into();
        // The predecessor is always in this chunk, so the tuple carries *this* row's chunk
        // rather than a committed `prev_chunk`. An address whose previous touch was in an
        // earlier chunk names the sentinel `prev_clk = 0` instead, and `MemoryLocalChip` puts
        // the matching label on the state the chunk inherits.
        let prev_clk = mem_access.prev_clk.clone().into();
        let prev_values = once(chunk.clone())
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

    /// [`Self::eval_memory_access`] over the `MemoryLiteCols` layout, which commits no
    /// `prev_clk` column (the Cpu chip's register accesses and the MemoryReadWrite chip's data
    /// access). Same bus messages, same timestamp argument, one column fewer per access; the
    /// write contract of `eval_memory_access` applies unchanged.
    fn eval_memory_access_lite<E: Into<Self::Expr> + Clone>(
        &mut self,
        chunk: impl Into<Self::Expr>,
        clk: impl Into<Self::Expr>,
        addr: [impl Into<Self::Expr> + Clone; 3],
        memory_access: &impl MemoryLiteCols<E>,
        do_check: impl Into<Self::Expr>,
    ) {
        let do_check: Self::Expr = do_check.into();
        self.assert_bool(do_check.clone());
        self.eval_memory_access_lite_unchecked(chunk, clk, addr, memory_access, do_check);
    }

    /// [`Self::eval_memory_access_lite`] without the `assert_bool(do_check)`; same caveat as
    /// [`Self::eval_memory_access_unchecked`].
    fn eval_memory_access_lite_unchecked<E: Into<Self::Expr> + Clone>(
        &mut self,
        chunk: impl Into<Self::Expr>,
        clk: impl Into<Self::Expr>,
        addr: [impl Into<Self::Expr> + Clone; 3],
        memory_access: &impl MemoryLiteCols<E>,
        do_check: impl Into<Self::Expr>,
    ) {
        let do_check: Self::Expr = do_check.into();
        let chunk: Self::Expr = chunk.into();
        let clk: Self::Expr = clk.into();
        let mem_access = memory_access.access();

        // The previous access's clk is not committed. It is *defined* from the committed
        // difference limbs,
        //
        //     prev_clk = clk - (diff_16bit_limb + diff_hi9 * 2^16) - 1,
        //
        // so the decomposition equation of `eval_memory_access_timestamp` is an identity here
        // and only its two limb lookups remain: they pin `clk - prev_clk - 1` to `[0, 2^25)`,
        // which is the whole of the timestamp argument (see that method for why this is
        // `clk > prev_clk` in the field). Where the gate is off the expression names an
        // arbitrary value, but the row then sends nothing on the bus, so the value is
        // irrelevant.
        let limb_16: Self::Expr = mem_access.diff_16bit_limb.clone().into();
        let hi9: Self::Expr = mem_access.diff_hi9.clone().into();
        let prev_clk: Self::Expr = clk.clone()
            - (limb_16.clone() + hi9.clone() * Self::Expr::from_u32(1 << 16))
            - Self::Expr::ONE;
        self.range_check_u25_16_9_limbs(limb_16, hi9, do_check.clone());

        // Regional lookup: 9 elements [chunk, clk, addr[0], addr[1], addr[2], v0, v1, v2, v3].
        // The predecessor is always in this chunk (see `eval_memory_access_unchecked`).
        let addr0: Self::Expr = addr[0].clone().into();
        let addr1: Self::Expr = addr[1].clone().into();
        let addr2: Self::Expr = addr[2].clone().into();
        let prev_values = once(chunk.clone())
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
            prev_values,
            do_check.clone(),
            LookupType::Memory,
            LookupScope::Regional,
        ));

        // The current values get "received", i.e. multiplicity = -1
        self.looked(SymbolicLookup::new(
            current_values,
            do_check,
            LookupType::Memory,
            LookupScope::Regional,
        ));
    }

    /// Verifies the memory access timestamp.
    ///
    /// This method verifies that the current memory access happened after the previous one's.
    /// The predecessor is always in this chunk — an address whose previous touch was in an
    /// earlier chunk names the sentinel `prev_clk = 0` instead — so the comparison is
    /// unconditionally on `clk`, with no `prev_chunk` witness and no selector choosing between
    /// the two arms.
    fn eval_memory_access_timestamp(
        &mut self,
        mem_access: &MemoryAccessCols<impl Into<Self::Expr> + Clone>,
        do_check: impl Into<Self::Expr>,
        clk: impl Into<Self::Expr>,
    ) {
        let do_check: Self::Expr = do_check.into();
        let prev_comp_value: Self::Expr = mem_access.prev_clk.clone().into();
        let current_comp_val: Self::Expr = clk.into();

        // Assert `current_comp_val > prev_comp_val`. We check this by asserting that
        // `0 <= current_comp_val-prev_comp_val-1 < 2^25`.
        //
        // The equivalence of these statements comes from the fact that if
        // `current_comp_val <= prev_comp_val`, then `current_comp_val-prev_comp_val-1 < 0` and will
        // underflow in the prime field, resulting in a value that is `>= 2^25` as long as both
        // `current_comp_val, prev_comp_val` are integers below `p - 2^25`.
        //
        // Both sides are clks. Neither is range-checked here: callers pass a `clk` their own chip
        // constrains, and `prev_clk` is pinned only by the regional bus, against a predecessor
        // access or `MemoryLocal`'s `initial_clk_regional`. The Cpu chip supplies its clk as an
        // integer below `4 + (2^24 - 1) * 67` through the row chain
        // (`riscv_cpu/chunk_clk/constraints.rs`, `CLK_BOUND_FITS`), and every other clk on the
        // memory bus is that value plus a `MemoryAccessPosition` (at most 3), a dispatch of it,
        // or a syscall-bus copy of it plus a precompile's own offset (at most 2) -- all below
        // `p - 2^25` with room to spare.
        let diff_minus_one = current_comp_val - prev_comp_value - Self::Expr::ONE;

        // Verify that diff = diff_16bit_limb + diff_hi9 * 2^16 with the limbs range-checked
        // to 16 and 9 bits respectively (a repack of the former 16+8+1 decomposition —
        // same [0, 2^25) coverage, one column and one lookup fewer per access).
        self.range_check_u25_16_9(
            diff_minus_one,
            mem_access.diff_16bit_limb.clone(),
            mem_access.diff_hi9.clone(),
            do_check,
        );
    }
}
