use super::is_zero::IsZeroGadget;
use crate::{
    chips::chips::byte::event::ByteRecordBehavior,
    compiler::riscv::opcode::ByteOpcode,
    machine::builder::{ChipBuilder, ChipLookupBuilder, ChipRangeBuilder},
    primitives::consts::u64_to_u16_limbs,
};
use p3_air::AirBuilder;
use p3_field::{Field, FieldAlgebra};
use pico_derive::AlignedBorrow;

/// A set of columns needed to validate the address and return the aligned address.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct SyscallAddrGadget<T> {
    /// The address itself.
    pub addr: [T; 3],

    /// This is used to check if the top two limbs of the address is not both zero.
    pub top_two_limb_min: T,

    /// This is used to check if the top two limbs of the address is u16::MAX.
    pub top_two_limb_max: IsZeroGadget<T>,
}

impl<F: Field> SyscallAddrGadget<F> {
    pub fn populate(&mut self, record: &mut impl ByteRecordBehavior, addr: u64, len: u64) {
        let addr_limbs = u64_to_u16_limbs(addr);
        let sum_top_two_limb =
            F::from_canonical_u16(addr_limbs[1]) + F::from_canonical_u16(addr_limbs[2]);
        self.addr[0] = F::from_canonical_u16(addr_limbs[0]);
        self.addr[1] = F::from_canonical_u16(addr_limbs[1]);
        self.addr[2] = F::from_canonical_u16(addr_limbs[2]);
        // A zero sum has no inverse, and `inverse()` panics on it. That happens for every
        // pointer below 2^16 -- precisely the range this gadget's 64KB stack guard exists to
        // reject. Panicking here would crash the prover on attacker-controlled input, since the
        // emulator only floors addresses at 0x100 and accepts the whole window [0x100, 2^16).
        //
        // Witness zero instead. `eval`'s guard is
        //     when(is_real): top_two_limb_min * (addr[1] + addr[2]) == is_real
        // which with a zero sum and a zero witness reads `0 == 1` on a real row, so the row is
        // unsatisfiable and verification rejects it cleanly at `verifier.rs:384` -- the intended
        // outcome, reached without a crash. Padding rows have `is_real = 0` and are unaffected.
        self.top_two_limb_min = sum_top_two_limb.try_inverse().unwrap_or(F::ZERO);
        let is_max = self.top_two_limb_max.populate_from_field_element(
            sum_top_two_limb - F::from_canonical_u16(u16::MAX) * F::TWO,
        );
        if is_max == 1 {
            record.add_bit_range_check((addr_limbs[0] + (len as u16)) / 8, 13);
        } else {
            record.add_bit_range_check(addr_limbs[0] / 8, 13);
        }
        // Matches the `slice_range_check_u16` in `eval`.
        record.add_u16_range_checks(&addr_limbs[..3]);
    }
}

impl<F: Field> SyscallAddrGadget<F> {
    /// The memory address is constrained to be aligned, `>= 2^16` and less than `2^48 - len`.
    /// The `cols.addr` is assumed to be composed of valid 3 u16 limbs.
    pub fn eval<CB: ChipBuilder<F> + ChipLookupBuilder<F> + ChipRangeBuilder<F>>(
        builder: &mut CB,
        len: u32,
        cols: SyscallAddrGadget<CB::Var>,
        is_real: CB::Expr,
    ) -> [CB::Var; 3] {
        // This is not a constraint, but a sanity check
        assert!(len.is_multiple_of(8));

        // Check that `is_real` and offset bits are boolean.
        builder.assert_bool(is_real.clone());

        // Range check the limbs before anything reads them.
        //
        // Everything below treats the upper two limbs only as a *sum*: the stack guard asserts
        // `addr[1] + addr[2] != 0` and the IsZeroGadget compares that same sum against
        // `2 * u16::MAX`. Neither pins the limbs individually, and `addr[0]` is only bounded
        // indirectly, by the BitRange(13) check on `addr[0] / 8`. So without this the doc comment's
        // "assumed to be composed of valid 3 u16 limbs" is an assumption the caller has to supply,
        // and a non-canonical pair with the right weighted value passes.
        //
        // Same order as `read_write/constraints.rs:146-153`, which range checks immediately before
        // a byte-for-byte identical stack guard.
        builder.slice_range_check_u16(&cols.addr, is_real.clone());

        let sum_top_two_limb = cols.addr[1] + cols.addr[2];

        // Check that `addr >= 2^16`, so it doesn't touch registers.
        // This implements a stack guard of size 2^16 bytes = 64KB.
        // If `is_real = 1`, then `addr.0[1] + addr.0[2] != 0`, so `addr >= 2^16`.
        builder.when(is_real.clone()).assert_eq(
            cols.top_two_limb_min * sum_top_two_limb.clone(),
            is_real.clone(),
        );

        IsZeroGadget::<CB::F>::eval(
            builder,
            sum_top_two_limb - CB::F::from_canonical_u16(u16::MAX) * CB::F::from_canonical_u8(2),
            cols.top_two_limb_max,
            is_real.clone(),
        );

        // Check `0 <= (addr[0] + len * top_two_limb_max.result) / 8 < 2^13`.
        // If `addr[1] == addr[2] == u16::MAX`, this shows `addr + len < 2^48`.
        // This also shows that `addr[0]` is a multiple of 8 in all cases.
        builder.looking_byte(
            CB::Expr::from_canonical_u32(ByteOpcode::BitRange as u32),
            (cols.addr[0] + cols.top_two_limb_max.result * CB::Expr::from_canonical_u32(len))
                * CB::F::from_canonical_u32(8).inverse(),
            CB::Expr::from_canonical_u32(13),
            CB::Expr::ZERO,
            is_real.clone(),
        );

        [cols.addr[0], cols.addr[1], cols.addr[2]]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::machine::{builder::PublicValuesBuilder, folder::SymbolicConstraintFolder};
    use p3_koala_bear::KoalaBear;
    use p3_matrix::Matrix;
    use pico_derive::AlignedBorrow;
    use std::{borrow::Borrow, mem::size_of};

    #[derive(AlignedBorrow, Clone, Copy)]
    #[repr(C)]
    struct TestCols<T> {
        syscall_addr: SyscallAddrGadget<T>,
        is_real: T,
    }

    #[test]
    fn test_syscall_addr_gadget_simple_eval() {
        let width = size_of::<TestCols<u8>>();
        let mut builder = SymbolicConstraintFolder::new(0, width);
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &TestCols<_> = (*local).borrow();

        SyscallAddrGadget::<KoalaBear>::eval(
            &mut builder,
            8u32,
            local.syscall_addr,
            local.is_real.into(),
        );

        assert_eq!(builder.num_constraints(), 5);
        assert_eq!(builder.public_values().len(), 119);
        assert_eq!(builder.num_lookups(), 4);
    }
}
