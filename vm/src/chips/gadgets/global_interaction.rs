use crate::{
    chips::chips::riscv_poseidon2::Poseidon2Event,
    compiler::riscv::opcode::ByteOpcode,
    machine::{
        builder::{ChipBuilder, ChipLookupBuilder, SepticExtensionBuilder},
        field::FieldBehavior,
        lookup::{LookupScope, LookupType, SymbolicLookup},
        septic::{FieldSepticCurve, SepticBlock, SepticCurve, SepticExtension},
    },
};
use p3_air::AirBuilder;
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing, PrimeField32};
use pico_derive::AlignedBorrow;
use std::any::Any;

/// A set of columns needed to compute the global interaction elliptic curve digest.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct GlobalInteractionOperation<T> {
    /// The hash-to-curve offset, a single byte (range-checked via a `U8Range` byte lookup rather
    /// than an 8-bit decomposition).
    pub offset: T,
    pub x_coordinate: SepticBlock<T>,
    pub y_coordinate: SepticBlock<T>,
    /// Compact limb decomposition of the `y_6` range-check value `y6_value`, proving
    /// `0 <= y6_value < (p - 1) / 2 = 2^30 - 2^(30 - TOP_BITS)` via byte lookups (replaces the
    /// 30-bit decomposition + inverse witness). Layout: `[lo16, mid, top]` with
    /// `y6_value = lo16 + mid * 2^16 + top * 2^(30 - TOP_BITS)`, where `lo16` is u16,
    /// `mid < 2^(14 - TOP_BITS)`, and `top < 2^TOP_BITS - 1` (so the top field bits are never
    /// all-ones — the exact original bound).
    pub y6_limbs: [T; 3],
}

impl<F: PrimeField32 + FieldBehavior> GlobalInteractionOperation<F> {
    pub fn get_digest(
        values: [u32; 8],
        is_receive: bool,
        kind: u8,
    ) -> (SepticCurve<F>, u8, [F; 16], [F; 16]) {
        let mut new_values = values.map(|x| F::from_u32(x));
        // kind is packed above the 25-bit values[0] budget (clk widening).
        // Capacity: (2^25-1) + 31*2^25 = 2^30-1 < KoalaBear p.
        new_values[0] += F::from_u32((kind as u32) << 25);
        let (point, offset, m_trial, m_hash) = SepticCurve::<F>::lift_x(new_values);
        if !is_receive {
            return (point.neg(), offset, m_trial, m_hash);
        }
        (point, offset, m_trial, m_hash)
    }

    pub fn populate(
        &mut self,
        values: [u32; 8],
        is_receive: bool,
        is_real: bool,
        kind: u8,
    ) -> Option<Poseidon2Event> {
        if is_real {
            let (point, offset, m_trial, m_hash) = Self::get_digest(values, is_receive, kind);
            self.offset = F::from_u8(offset);
            self.x_coordinate = SepticBlock::<F>::from(point.x.0);
            self.y_coordinate = SepticBlock::<F>::from(point.y.0);
            let range_check_value = if is_receive {
                point.y.0[6].as_canonical_u32() - 1
            } else {
                point.y.0[6].as_canonical_u32() - F::ORDER_U32.div_ceil(2)
            };
            // Compact limb decomposition of `range_check_value` (see struct docs).
            let split = 30 - F::TOP_BITS; // bit position where the `top` limb begins (23).
            let mid_mask = (1u32 << (split - 16)) - 1; // 14 - TOP_BITS bits (0x7f).
            let top_mask = (1u32 << F::TOP_BITS) - 1; // TOP_BITS bits (0x7f).
            self.y6_limbs[0] = F::from_u32(range_check_value & 0xFFFF);
            self.y6_limbs[1] = F::from_u32((range_check_value >> 16) & mid_mask);
            self.y6_limbs[2] = F::from_u32((range_check_value >> split) & top_mask);

            assert_eq!(self.x_coordinate.0[0], m_hash[0]);

            let input = m_trial.map(|v| v.as_canonical_u32());
            let output = m_hash.map(|v| v.as_canonical_u32());
            Some(Poseidon2Event { input, output })
        } else {
            self.populate_dummy();
            None
        }
    }

    pub fn populate_dummy(&mut self) {
        self.offset = F::ZERO;
        self.x_coordinate = SepticBlock::<F>::from_basis_coefficients_fn(|i| {
            F::from_u32(F::CURVE_WITNESS_DUMMY_POINT_X[i])
        });
        self.y_coordinate = SepticBlock::<F>::from_basis_coefficients_fn(|i| {
            F::from_u32(F::CURVE_WITNESS_DUMMY_POINT_Y[i])
        });
        self.y6_limbs = [F::ZERO; 3];
    }
}

impl<F: Field> GlobalInteractionOperation<F> {
    /// Constrain that the elliptic curve point for the global interaction is correctly derived.
    #[allow(clippy::too_many_arguments)]
    pub fn eval_single_digest<CB: ChipBuilder<F>>(
        builder: &mut CB,
        values: [CB::Expr; 8],
        cols: GlobalInteractionOperation<CB::Var>,
        is_receive: CB::Expr,
        is_send: CB::Expr,
        is_real: CB::Var,
        kind: CB::Var,
        message_0_limbs: [CB::Var; 3],
    ) where
        CB::Expr: Any,
    {
        // Constrain that the `is_real` is boolean.
        builder.assert_bool(is_real);

        let offset: CB::Expr = cols.offset.into();

        // Range check the first element in the message to be 25 bits (the chunk-clk budget)
        // so that we can encode the interaction kind in the upper bits. Decompose
        // values[0] = message_0_16bit_limb + message_0_8bit_limb * 2^16
        // + message_0_high_bit * 2^24, with a boolean high bit.
        builder.when(is_real).assert_bool(message_0_limbs[2].into());
        builder.when(is_real).assert_eq(
            values[0].clone(),
            message_0_limbs[0]
                + message_0_limbs[1] * CB::F::from_u32(1 << 16)
                + message_0_limbs[2] * CB::F::from_u32(1 << 24),
        );
        // Range check: message_0_16bit_limb is u16, values[7] is u16.
        builder.looking_byte(
            CB::Expr::from_u8(ByteOpcode::U16Range as u8),
            message_0_limbs[0].into(),
            CB::Expr::ZERO,
            CB::Expr::ZERO,
            is_real,
        );
        builder.looking_byte(
            CB::Expr::from_u8(ByteOpcode::U16Range as u8),
            values[7].clone(),
            CB::Expr::ZERO,
            CB::Expr::ZERO,
            is_real,
        );
        // Byte-range the offset and the 8-bit limb in ONE dual-slot U8Range instance: the byte
        // table's looked side constrains the b and c slots independently, so the pair costs what
        // a single check used to. Slot order is load-bearing — the trace-gen mirrors emit
        // (b = offset, c = message_0_8bit_limb) and a swap would balance only by accident.
        builder.looking_byte(
            CB::Expr::from_u8(ByteOpcode::U8Range as u8),
            CB::Expr::ZERO,
            offset.clone(),
            message_0_limbs[1].into(),
            is_real,
        );
        // No `kind < 32` range check: every Global-bus SENDER passes a compile-time constant
        // kind < 32, so a receiver row carrying anything else cannot balance the multiset. Both
        // keygen paths assert that statically (`assert_global_kind_is_bounded_constant`) so the
        // invariant cannot rot. The bound is what keeps the bit-25 packing inside the field.

        // Turn the message into a hash input. The Poseidon2 input `m_trial` is
        // `(message-derived prefix ++ [0; 8])`; only the non-zero prefix `input[0..8]` is carried
        // in the lookup tuple (see below), so only those 8 elements are materialized here.
        // Combining `values[0]` with `kind` is safe, as `values[0]` is range checked to be 25 bits,
        // and `kind` is known to be 5 bits (max packed value 2^30 - 1 < p).
        // Combining `values[7]` with `offset` is also safe, since `values[7]` is range checked
        // to be 16 bits, while `offset` is known to be 8 bits.
        let m_trial_prefix = [
            values[0].clone() + CB::Expr::from_u32(1 << 25) * kind,
            values[1].clone(),
            values[2].clone(),
            values[3].clone(),
            values[4].clone(),
            values[5].clone(),
            values[6].clone(),
            values[7].clone() + CB::Expr::from_u32(1 << 16) * offset.clone(),
        ];

        // Truncated Poseidon2 lookup tuple `(input[0..8], output[0..7])` (15-wide, was 32).
        //   * `input[0..8]` is the non-zero prefix of `m_trial` (`input[8..16]` are constant zero and
        //     are dropped from the tuple; the riscv Poseidon2 chip has no columns for lanes 8..16 and
        //     feeds them as the constant 0, so binding only the prefix still uniquely determines the
        //     full permutation input).
        //   * `output[0..7]` is exactly `x_coordinate` (the constraint that the x-coordinate is the
        //     hash of the message). The trailing `output[7..16]` are unused by the curve digest and
        //     are dropped from the tuple (no longer committed as `poseidon2_output`).
        let lookup_values = m_trial_prefix
            .iter()
            .cloned()
            .chain((0..7).map(|i| cols.x_coordinate[i].into()))
            .collect();
        builder.looking(SymbolicLookup::new(
            lookup_values,
            is_real.into(),
            LookupType::Poseidon2,
            LookupScope::Regional,
        ));

        let x = SepticExtension::<CB::Expr>::from_basis_coefficients_fn(|i| {
            cols.x_coordinate[i].into()
        });
        let y = SepticExtension::<CB::Expr>::from_basis_coefficients_fn(|i| {
            cols.y_coordinate[i].into()
        });

        // Constrain that `(x, y)` is a valid point on the curve.
        let y2 = y.square();
        let x3_2x_26z5 = SepticCurve::<CB::Expr>::curve_formula(x);
        builder.assert_septic_ext_eq(y2, x3_2x_26z5);

        // Constrain that `0 <= y6_value < (p - 1) / 2 = 2^30 - 2^(30 - TOP_BITS)` via a compact
        // limb decomposition validated by byte lookups (replaces the 30-bit decomposition + inverse
        // witness). `y6_value = lo16 + mid * 2^16 + top * 2^(30 - TOP_BITS)` where `lo16` is u16,
        // `mid < 2^(14 - TOP_BITS)`, and `top < 2^TOP_BITS - 1`. Because `top` is strictly less than
        // `2^TOP_BITS - 1` the top `TOP_BITS` field bits can never be all-ones, so the reconstructed
        // value is exactly bounded by `2^30 - 2^(30 - TOP_BITS)` — the identical bound.
        let split = 30 - F::TOP_BITS; // 23
        let mid_bound = 1u32 << (split - 16); // 2^(14 - TOP_BITS) = 128
        let top_bound = (1u32 << F::TOP_BITS) - 1; // 2^TOP_BITS - 1 = 127
        let y6_value: CB::Expr = cols.y6_limbs[0].into()
            + cols.y6_limbs[1] * CB::F::from_u32(1 << 16)
            + cols.y6_limbs[2] * CB::F::from_u32(1 << split);
        // `lo16` is a u16.
        builder.looking_byte(
            CB::Expr::from_u8(ByteOpcode::U16Range as u8),
            cols.y6_limbs[0].into(),
            CB::Expr::ZERO,
            CB::Expr::ZERO,
            is_real,
        );
        // `mid < mid_bound` (u8 LTU).
        builder.looking_byte(
            CB::Expr::from_u8(ByteOpcode::LTU as u8),
            CB::Expr::ONE,
            cols.y6_limbs[1].into(),
            CB::Expr::from_u32(mid_bound),
            is_real,
        );
        // `top < top_bound` (u8 LTU) — the load-bearing "top bits not all-ones" constraint.
        builder.looking_byte(
            CB::Expr::from_u8(ByteOpcode::LTU as u8),
            CB::Expr::ONE,
            cols.y6_limbs[2].into(),
            CB::Expr::from_u32(top_bound),
            is_real,
        );

        // Constrain that y has correct sign.
        // If it's a receive: `1 <= y_6 <= (p - 1) / 2`, so `0 <= y_6 - 1 = y6_value < (p - 1) / 2`.
        // If it's a send: `(p + 1) / 2 <= y_6 <= p - 1`, so `0 <= y_6 - (p + 1) / 2 = y6_value < (p - 1) / 2`.
        builder
            .when(is_receive)
            .assert_eq(y.0[6].clone(), CB::Expr::ONE + y6_value.clone());
        builder.when(is_send).assert_eq(
            y.0[6].clone(),
            CB::Expr::from_u32((1 << 30) - (1 << (30 - F::TOP_BITS)) + 1) + y6_value,
        );
    }
}
