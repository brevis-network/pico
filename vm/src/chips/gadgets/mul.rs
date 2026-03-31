//! Multiplication gadget

use super::{msb::U16MSBGadget, u16_to_u8::U16ToU8Gadget};
use crate::{
    chips::chips::byte::event::{ByteLookupEvent, ByteRecordBehavior},
    compiler::{riscv::opcode::ByteOpcode, word::Word},
    machine::builder::{ChipBuilder, ChipLookupBuilder, ChipRangeBuilder},
    primitives::consts::{
        u64_to_u16_limbs, BYTE_SIZE, LONG_WORD_BYTE_SIZE, WORD_BYTE_SIZE, WORD_SIZE,
    },
};
use p3_air::AirBuilder;
use p3_field::Field;
use pico_derive::AlignedBorrow;
use std::num::Wrapping;

/// The mask for a byte.
const BYTE_MASK: u8 = 0xff;

pub const fn get_msb(a: [u8; 8]) -> u8 {
    (a[7] >> (BYTE_SIZE - 1)) & 1
}

/// A set of columns needed for the MUL operations.
#[derive(Debug, Clone, Copy, AlignedBorrow)]
#[repr(C)]
pub struct MulGadget<T> {
    /// Trace.
    pub carry: [T; LONG_WORD_BYTE_SIZE],

    /// An array storing the product of `b * c` after the carry propagation.
    pub product: [T; LONG_WORD_BYTE_SIZE],

    /// The lower byte of two limbs of `b`.
    pub b_lower_byte: U16ToU8Gadget<T>,

    /// The lower byte of two limbs of `c`.
    pub c_lower_byte: U16ToU8Gadget<T>,

    /// The most significant bit of `b`.
    pub b_msb: T,

    /// The most significant bit of `c`.
    pub c_msb: T,

    /// The most significant bit of the product.
    pub product_msb: U16MSBGadget<T>,

    /// The sign extension of `b`.
    pub b_sign_extend: T,

    /// The sign extension of `c`.
    pub c_sign_extend: T,
}

impl<T: Default + Copy> Default for MulGadget<T> {
    fn default() -> Self {
        let default_t = T::default();
        Self {
            carry: [default_t; LONG_WORD_BYTE_SIZE],
            product: [default_t; LONG_WORD_BYTE_SIZE],
            b_lower_byte: U16ToU8Gadget::default(),
            c_lower_byte: U16ToU8Gadget::default(),
            b_msb: default_t,
            c_msb: default_t,
            product_msb: U16MSBGadget::default(),
            b_sign_extend: default_t,
            c_sign_extend: default_t,
        }
    }
}

impl<F: Field> MulGadget<F> {
    /// Populate the MUL operation from an event.
    pub fn populate(
        &mut self,
        record: &mut impl ByteRecordBehavior,
        b_u64: u64,
        c_u64: u64,
        is_mulh: bool,
        is_mulhsu: bool,
        is_mulw: bool,
    ) {
        let b_word = b_u64.to_le_bytes();
        let c_word = c_u64.to_le_bytes();

        let mulw_value = (Wrapping(b_u64 as i32) * Wrapping(c_u64 as i32)).0 as i64 as u64;
        let limbs = u64_to_u16_limbs(mulw_value);

        if is_mulw {
            self.product_msb.populate(record, limbs[1]);
        } else {
            self.product_msb.msb = F::ZERO;
        }

        let mut b = b_word.to_vec();
        let mut c = c_word.to_vec();

        // Extract lower bytes using U16ToU8Gadget
        // This converts the full u64 to 4 u16 limbs and extracts the lower byte from each
        self.b_lower_byte.populate_u16_to_u8_safe(record, b_u64);
        self.c_lower_byte.populate_u16_to_u8_safe(record, c_u64);

        // Handle b and c's signs.
        {
            let b_msb = get_msb(b_word);
            self.b_msb = F::from_canonical_u8(b_msb);
            let c_msb = get_msb(c_word);
            self.c_msb = F::from_canonical_u8(c_msb);

            // If b is signed and it is negative, sign extend b.
            if (is_mulh || is_mulhsu) && b_msb == 1 {
                self.b_sign_extend = F::ONE;
                b.resize(LONG_WORD_BYTE_SIZE, BYTE_MASK);
            } else {
                self.b_sign_extend = F::ZERO;
            }

            // If c is signed and it is negative, sign extend c.
            if is_mulh && c_msb == 1 {
                self.c_sign_extend = F::ONE;
                c.resize(LONG_WORD_BYTE_SIZE, BYTE_MASK);
            } else {
                self.c_sign_extend = F::ZERO;
            }

            // Insert the MSB lookup events.
            {
                let words = [b_word, c_word];
                let mut blu_events: Vec<ByteLookupEvent> = vec![];
                for word in words.iter() {
                    let most_significant_byte = word[WORD_BYTE_SIZE - 1];
                    blu_events.push(ByteLookupEvent {
                        opcode: ByteOpcode::MSB,
                        a1: get_msb(*word) as u16,
                        a2: 0,
                        b: most_significant_byte,
                        c: 0,
                    });
                }
                record.add_byte_lookup_events(blu_events);
            }
        }

        let mut product = [0u32; LONG_WORD_BYTE_SIZE];
        for i in 0..b.len() {
            for j in 0..c.len() {
                if i + j < LONG_WORD_BYTE_SIZE {
                    product[i + j] += (b[i] as u32) * (c[j] as u32);
                }
            }
        }

        // Calculate the correct product using the `product` array. We store the
        // correct carry value for verification.
        let base = (1 << BYTE_SIZE) as u32;
        let mut carry = [0u32; LONG_WORD_BYTE_SIZE];
        for i in 0..LONG_WORD_BYTE_SIZE {
            carry[i] = product[i] / base;
            product[i] %= base;
            if i + 1 < LONG_WORD_BYTE_SIZE {
                product[i + 1] += carry[i];
            }
            self.carry[i] = F::from_canonical_u32(carry[i]);
        }

        self.product = product.map(F::from_canonical_u32);

        // Range check.
        {
            record.add_u16_range_checks(&carry.map(|x| x as u16));
            record.add_u8_range_checks(product.map(|x| x as u8));
        }
    }

    /// Evaluate the MUL operation.
    /// Assumes that `b_word`, `c_word` are valid `Word`s of u16 limbs.
    /// Constrains that all flags are boolean.
    /// Constrains that at most one of `is_mul`, `is_mulh`, `is_mulhu`, `is_mulhsu` is true.
    /// If `is_real` is true, constrains that the product is correctly placed at `a_word`.
    #[allow(clippy::too_many_arguments)]
    pub fn eval<AB: ChipBuilder<F>>(
        builder: &mut AB,
        a: Word<AB::Var>,
        b: Word<AB::Var>,
        c: Word<AB::Var>,
        cols: MulGadget<AB::Var>,
        is_real: AB::Expr,
        is_mul: AB::Expr,
        is_mulh: AB::Expr,
        is_mulw: AB::Expr,
        is_mulhu: AB::Expr,
        is_mulhsu: AB::Expr,
    ) {
        let zero: AB::Expr = AB::F::ZERO.into();
        let base = AB::F::from_canonical_u32(1 << 8);
        let one: AB::Expr = AB::F::ONE.into();
        let byte_mask = AB::F::from_canonical_u8(BYTE_MASK);

        // Use U16ToU8Gadget for lower byte extraction constraints
        // Convert all 4 u16 limbs to get 8 bytes
        let b = U16ToU8Gadget::eval_u16_to_u8_safe(
            builder,
            [b[0].into(), b[1].into(), b[2].into(), b[3].into()],
            cols.b_lower_byte,
            is_real.clone(),
        );
        let c = U16ToU8Gadget::eval_u16_to_u8_safe(
            builder,
            [c[0].into(), c[1].into(), c[2].into(), c[3].into()],
            cols.c_lower_byte,
            is_real.clone(),
        );

        // Calculate the MSBs.
        let msb_opcode = AB::F::from_canonical_u32(ByteOpcode::MSB as u32);
        let (b_msb, c_msb) = {
            let msb_pairs = [
                (cols.b_msb, b[WORD_BYTE_SIZE - 1].clone()),
                (cols.c_msb, c[WORD_BYTE_SIZE - 1].clone()),
            ];

            for msb_pair in msb_pairs.iter() {
                let msb = msb_pair.0;
                let byte = msb_pair.1.clone();
                builder.looking_byte(msb_opcode, msb, byte, zero.clone(), is_real.clone());
            }
            (cols.b_msb, cols.c_msb)
        };

        // Use U16MSBGadget for product MSB constraints
        U16MSBGadget::eval(builder, a.0[1].into(), cols.product_msb, is_mulw.clone());

        // Calculate whether to extend b and c's sign.
        let (b_sign_extend, c_sign_extend) = {
            let is_b_i64 = is_mulh.clone() + is_mulhsu.clone();
            let is_c_i64 = is_mulh.clone();

            builder.assert_eq(cols.b_sign_extend, is_b_i64 * b_msb);
            builder.assert_eq(cols.c_sign_extend, is_c_i64 * c_msb);
            (cols.b_sign_extend, cols.c_sign_extend)
        };

        // Sign extend `b` and `c` whenever appropriate.
        let (b, c) = {
            let mut b_extended: Vec<AB::Expr> = vec![AB::F::ZERO.into(); LONG_WORD_BYTE_SIZE];
            let mut c_extended: Vec<AB::Expr> = vec![AB::F::ZERO.into(); LONG_WORD_BYTE_SIZE];
            for i in 0..LONG_WORD_BYTE_SIZE {
                if i < WORD_BYTE_SIZE {
                    b_extended[i] = b[i].clone();
                    c_extended[i] = c[i].clone();
                } else {
                    b_extended[i] = b_sign_extend * byte_mask;
                    c_extended[i] = c_sign_extend * byte_mask;
                }
            }
            (b_extended, c_extended)
        };

        // Compute the uncarried product b(x) * c(x) = m(x).
        let mut m: Vec<AB::Expr> = vec![AB::F::ZERO.into(); LONG_WORD_BYTE_SIZE];
        for i in 0..LONG_WORD_BYTE_SIZE {
            for j in 0..LONG_WORD_BYTE_SIZE {
                if i + j < LONG_WORD_BYTE_SIZE {
                    m[i + j] = m[i + j].clone() + b[i].clone() * c[j].clone();
                }
            }
        }

        // Propagate carry.
        let product = {
            for i in 0..LONG_WORD_BYTE_SIZE {
                if i == 0 {
                    builder
                        .when(is_real.clone())
                        .assert_eq(cols.product[i], m[i].clone() - cols.carry[i] * base);
                } else {
                    builder.when(is_real.clone()).assert_eq(
                        cols.product[i],
                        m[i].clone() + cols.carry[i - 1] - cols.carry[i] * base,
                    );
                }
            }
            cols.product
        };

        // Compare the product's appropriate bytes with that of the result.
        {
            let is_lower = is_mul.clone();
            let is_upper = is_mulh.clone() + is_mulhu.clone() + is_mulhsu.clone();
            let is_word = is_mulw.clone();
            let u16_max = AB::F::from_canonical_u32((1 << 16) - 1);
            for i in 0..WORD_SIZE {
                if i < WORD_SIZE / 2 {
                    builder.when(is_word.clone()).assert_eq(
                        product[2 * i] + product[2 * i + 1] * AB::F::from_canonical_u16(1 << 8),
                        a[i],
                    );
                } else {
                    builder
                        .when(is_word.clone())
                        .assert_eq(cols.product_msb.msb * u16_max, a[i]);
                }
                builder.when(is_lower.clone()).assert_eq(
                    product[2 * i] + product[2 * i + 1] * AB::F::from_canonical_u16(1 << 8),
                    a[i],
                );
                builder.when(is_upper.clone()).assert_eq(
                    product[2 * i + WORD_BYTE_SIZE]
                        + product[2 * i + 1 + WORD_BYTE_SIZE] * AB::F::from_canonical_u16(1 << 8),
                    a[i],
                );
            }
        }

        // Check that the boolean values are indeed boolean values.
        {
            let booleans = [
                cols.b_msb.into(),
                cols.c_msb.into(),
                cols.b_sign_extend.into(),
                cols.c_sign_extend.into(),
                is_mul.clone(),
                is_mulh.clone(),
                is_mulhu.clone(),
                is_mulhsu.clone(),
                is_mulw.clone(),
                is_mul.clone()
                    + is_mulh.clone()
                    + is_mulhu.clone()
                    + is_mulhsu.clone()
                    + is_mulw.clone(),
                is_real.clone(),
            ];
            for boolean in booleans.iter() {
                builder.assert_bool(boolean.clone());
            }
        }

        // If signed extended, the MSB better be 1.
        builder
            .when(cols.b_sign_extend)
            .assert_eq(cols.b_msb, one.clone());
        builder
            .when(cols.c_sign_extend)
            .assert_eq(cols.c_msb, one.clone());

        // Range check.
        {
            // Ensure that the carry is at most 2^16. This ensures that
            // product_before_carry_propagation - carry * base + last_carry never overflows or
            // underflows enough to "wrap" around to create a second solution.
            builder.slice_range_check_u16(&cols.carry, is_real.clone());
            builder.slice_range_check_u8(&cols.product, is_real.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::machine::folder::SymbolicConstraintFolder;
    use p3_koala_bear::KoalaBear;
    use p3_matrix::Matrix;
    use pico_derive::AlignedBorrow;
    use std::borrow::Borrow;
    use std::mem::size_of;

    #[derive(AlignedBorrow, Clone, Copy)]
    #[repr(C)]
    struct TestCols<T> {
        a: Word<T>,
        b: Word<T>,
        c: Word<T>,
        mul: MulGadget<T>,
        is_real: T,
        is_mul: T,
        is_mulh: T,
        is_mulw: T,
        is_mulhu: T,
        is_mulhsu: T,
    }

    #[test]
    fn test_mul_gadget_simple_eval() {
        let width = size_of::<TestCols<u8>>();
        let mut builder = SymbolicConstraintFolder::new(0, width);
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &TestCols<_> = (*local).borrow();

        MulGadget::<KoalaBear>::eval(
            &mut builder,
            local.a,
            local.b,
            local.c,
            local.mul,
            local.is_real.into(),
            local.is_mul.into(),
            local.is_mulh.into(),
            local.is_mulw.into(),
            local.is_mulhu.into(),
            local.is_mulhsu.into(),
        );
    }
}
