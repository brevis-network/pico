//! Recursion memory associating builder functions

use super::{ChipBuilder, ChipLookupBuilder};
use crate::{
    chips::chips::recursion_memory::{MemoryAccessTimestampCols, MemoryCols},
    compiler::riscv::opcode::RangeCheckOpcode,
    machine::lookup::{LookupType, SymbolicLookup},
    recursion::air::Block,
};
use p3_air::AirBuilder;
use p3_field::{AbstractField, Field};
use std::iter::{once, repeat};

pub trait RecursionMemoryBuilder<F: Field>: ChipBuilder<F> {
    fn recursion_eval_memory_access<E: Into<Self::Expr> + Clone>(
        &mut self,
        timestamp: impl Into<Self::Expr>,
        addr: impl Into<Self::Expr>,
        memory_access: &impl MemoryCols<E, Block<E>>,
        is_real: impl Into<Self::Expr>,
    ) {
        let is_real: Self::Expr = is_real.into();
        self.assert_bool(is_real.clone());

        let timestamp: Self::Expr = timestamp.into();
        let mem_access = memory_access.access();

        self.recursion_eval_memory_access_timestamp(timestamp.clone(), mem_access, is_real.clone());

        let addr = addr.into();
        let prev_timestamp = mem_access.prev_timestamp.clone().into();
        let prev_values = once(prev_timestamp)
            .chain(once(addr.clone()))
            .chain(memory_access.prev_value().clone().map(Into::into))
            .collect();
        let current_values = once(timestamp)
            .chain(once(addr.clone()))
            .chain(memory_access.value().clone().map(Into::into))
            .collect();

        self.looked(SymbolicLookup::new(
            prev_values,
            is_real.clone(),
            LookupType::Memory,
        ));
        self.looking(SymbolicLookup::new(
            current_values,
            is_real,
            LookupType::Memory,
        ));
    }

    fn recursion_eval_memory_access_single<E: Into<Self::Expr> + Clone>(
        &mut self,
        timestamp: impl Into<Self::Expr>,
        addr: impl Into<Self::Expr>,
        memory_access: &impl MemoryCols<E, E>,
        is_real: impl Into<Self::Expr>,
    ) {
        let is_real: Self::Expr = is_real.into();
        self.assert_bool(is_real.clone());

        let timestamp: Self::Expr = timestamp.into();
        let mem_access = memory_access.access();

        self.recursion_eval_memory_access_timestamp(timestamp.clone(), mem_access, is_real.clone());

        let addr = addr.into();
        let prev_timestamp = mem_access.prev_timestamp.clone().into();
        let prev_values = once(prev_timestamp)
            .chain(once(addr.clone()))
            .chain(once(memory_access.prev_value().clone().into()))
            .chain(repeat(Self::Expr::zero()).take(3))
            .collect();
        let current_values = once(timestamp)
            .chain(once(addr.clone()))
            .chain(once(memory_access.value().clone().into()))
            .chain(repeat(Self::Expr::zero()).take(3))
            .collect();

        self.looked(SymbolicLookup::new(
            prev_values,
            is_real.clone(),
            LookupType::Memory,
        ));
        self.looking(SymbolicLookup::new(
            current_values,
            is_real,
            LookupType::Memory,
        ));
    }

    /// Verifies that the memory access happens after the previous memory access.
    fn recursion_eval_memory_access_timestamp<E: Into<Self::Expr> + Clone>(
        &mut self,
        timestamp: impl Into<Self::Expr>,
        mem_access: &impl MemoryAccessTimestampCols<E>,
        is_real: impl Into<Self::Expr> + Clone,
    ) {
        // We subtract one since a diff of zero is not valid.
        let diff_minus_one: Self::Expr =
            timestamp.into() - mem_access.prev_timestamp().clone().into() - Self::Expr::one();

        // Verify that mem_access.ts_diff = mem_access.ts_diff_16bit_limb
        // + mem_access.ts_diff_12bit_limb * 2^16.
        self.recursion_eval_range_check_28bits(
            diff_minus_one,
            mem_access.diff_16bit_limb().clone(),
            mem_access.diff_12bit_limb().clone(),
            is_real.clone(),
        );
    }

    /// Verifies the inputted value is within 28 bits.
    ///
    /// This method verifies that the inputted is less than 2^24 by doing a 16 bit and 12 bit range
    /// check on it's limbs.  It will also verify that the limbs are correct.  This method is needed
    /// since the memory access timestamp check (see [Self::eval_memory_access_timestamp]) needs to
    /// assume the clk is within 28 bits.
    fn recursion_eval_range_check_28bits(
        &mut self,
        value: impl Into<Self::Expr>,
        limb_16: impl Into<Self::Expr> + Clone,
        limb_12: impl Into<Self::Expr> + Clone,
        is_real: impl Into<Self::Expr> + Clone,
    ) {
        // Verify that value = limb_16 + limb_12 * 2^16.
        self.when(is_real.clone()).assert_eq(
            value,
            limb_16.clone().into()
                + limb_12.clone().into() * Self::Expr::from_canonical_u32(1 << 16),
        );

        // Send the range checks for the limbs.
        self.looking_rangecheck(
            RangeCheckOpcode::U16,
            limb_16,
            Self::Expr::zero(),
            is_real.clone(),
        );
        self.looking_rangecheck(RangeCheckOpcode::U12, limb_12, Self::Expr::zero(), is_real);
    }
}
