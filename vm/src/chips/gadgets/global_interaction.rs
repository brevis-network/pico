use crate::{
    chips::chips::riscv_poseidon2::Poseidon2Event,
    compiler::riscv::opcode::ByteOpcode,
    machine::{
        builder::{ChipBuilder, ChipLookupBuilder, SepticExtensionBuilder},
        field::FieldBehavior,
        lookup::{LookupScope, LookupType, SymbolicLookup},
        septic::{
            SepticBlock, SepticCurve, SepticExtension, CURVE_WITNESS_DUMMY_POINT_X,
            CURVE_WITNESS_DUMMY_POINT_Y, TOP_BITS,
        },
    },
    primitives::consts::PERMUTATION_WIDTH,
};
use p3_air::AirBuilder;
use p3_field::{Field, FieldAlgebra, FieldExtensionAlgebra, PrimeField32};
use pico_derive::AlignedBorrow;

/// A set of columns needed to compute the global interaction elliptic curve digest.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct GlobalInteractionOperation<T> {
    pub offset_bits: [T; 8],
    pub x_coordinate: SepticBlock<T>,
    pub y_coordinate: SepticBlock<T>,
    pub y6_bit_decomp: [T; 30],
    pub range_check_witness: T,
    pub poseidon2_input: [T; PERMUTATION_WIDTH],
    pub poseidon2_output: [T; PERMUTATION_WIDTH],
}

impl<F: PrimeField32 + FieldBehavior> GlobalInteractionOperation<F> {
    pub fn get_digest(
        values: SepticBlock<u32>,
        is_receive: bool,
        kind: u8,
    ) -> (SepticCurve<F>, u8, [F; 16], [F; 16]) {
        let x_start = SepticExtension::<F>::from_base_fn(|i| F::from_canonical_u32(values.0[i]))
            + SepticExtension::from_base(F::from_canonical_u32((kind as u32) << 16));
        let (point, offset, m_trial, m_hash) = SepticCurve::<F>::lift_x(x_start);
        if !is_receive {
            return (point.neg(), offset, m_trial, m_hash);
        }
        (point, offset, m_trial, m_hash)
    }

    pub fn populate(
        &mut self,
        values: SepticBlock<u32>,
        is_receive: bool,
        is_real: bool,
        kind: u8,
    ) -> Option<Poseidon2Event> {
        if is_real {
            let (point, offset, m_trial, m_hash) = Self::get_digest(values, is_receive, kind);
            for i in 0..8 {
                self.offset_bits[i] = F::from_canonical_u8((offset >> i) & 1);
            }
            self.x_coordinate = SepticBlock::<F>::from(point.x.0);
            self.y_coordinate = SepticBlock::<F>::from(point.y.0);
            let range_check_value = if is_receive {
                point.y.0[6].as_canonical_u32() - 1
            } else {
                point.y.0[6].as_canonical_u32() - (F::ORDER_U32 + 1) / 2
            };
            let mut top_field_bits = F::ZERO;
            for i in 0..30 {
                self.y6_bit_decomp[i] = F::from_canonical_u32((range_check_value >> i) & 1);
                if i >= 30 - TOP_BITS {
                    top_field_bits += self.y6_bit_decomp[i];
                }
            }
            top_field_bits -= F::from_canonical_usize(TOP_BITS);
            self.range_check_witness = top_field_bits.inverse();

            assert_eq!(self.x_coordinate.0[0], m_hash[0]);

            self.poseidon2_input = m_trial;
            self.poseidon2_output = m_hash;

            let [input, output] = [self.poseidon2_input, self.poseidon2_output]
                .map(|values| values.map(|v| v.as_canonical_u32()));
            Some(Poseidon2Event { input, output })
        } else {
            self.populate_dummy();
            None
        }
    }

    pub fn populate_dummy(&mut self) {
        for i in 0..8 {
            self.offset_bits[i] = F::ZERO;
        }
        self.x_coordinate = SepticBlock::<F>::from_base_fn(|i| {
            F::from_canonical_u32(CURVE_WITNESS_DUMMY_POINT_X[i])
        });
        self.y_coordinate = SepticBlock::<F>::from_base_fn(|i| {
            F::from_canonical_u32(CURVE_WITNESS_DUMMY_POINT_Y[i])
        });
        for i in 0..30 {
            self.y6_bit_decomp[i] = F::ZERO;
        }
        self.range_check_witness = F::ZERO;

        self.poseidon2_input = [F::ZERO; PERMUTATION_WIDTH];
        self.poseidon2_output = [F::ZERO; PERMUTATION_WIDTH];
    }
}

impl<F: Field> GlobalInteractionOperation<F> {
    /// Constrain that the elliptic curve point for the global interaction is correctly derived.
    pub fn eval_single_digest<CB: ChipBuilder<F>>(
        builder: &mut CB,
        values: [CB::Expr; 7],
        cols: GlobalInteractionOperation<CB::Var>,
        is_receive: CB::Expr,
        is_send: CB::Expr,
        is_real: CB::Var,
        kind: CB::Var,
    ) {
        // Constrain that the `is_real` is boolean.
        builder.assert_bool(is_real);

        // Compute the offset and range check each bits, ensuring that the offset is a byte.
        let mut offset = CB::Expr::ZERO;
        for i in 0..8 {
            builder.assert_bool(cols.offset_bits[i]);
            offset = offset.clone() + cols.offset_bits[i] * CB::F::from_canonical_u32(1 << i);
        }

        // Range check the first element in the message to be a u16 so that we can encode the interaction kind in the upper 8 bits.
        builder.looking_byte(
            CB::Expr::from_canonical_u8(ByteOpcode::U16Range as u8),
            values[0].clone(),
            CB::Expr::ZERO,
            CB::Expr::ZERO,
            is_real,
        );

        // Turn the message into a hash input. Only the first 8 elements are non-zero, as the rate of the Poseidon2 hash is 8.
        // Combining `values[0]` with `kind` is safe, as `values[0]` is range checked to be u16, and `kind` is known to be u8.
        let m_trial = [
            values[0].clone() + CB::Expr::from_canonical_u32(1 << 16) * kind,
            values[1].clone(),
            values[2].clone(),
            values[3].clone(),
            values[4].clone(),
            values[5].clone(),
            values[6].clone(),
            offset.clone(),
            CB::Expr::ZERO,
            CB::Expr::ZERO,
            CB::Expr::ZERO,
            CB::Expr::ZERO,
            CB::Expr::ZERO,
            CB::Expr::ZERO,
            CB::Expr::ZERO,
            CB::Expr::ZERO,
        ];

        // Constrain the input of the permutation to be the message.
        for i in 0..16 {
            builder
                .when(is_real)
                .assert_eq(cols.poseidon2_input[i], m_trial[i].clone());
        }

        // Constrain that when `is_real` is true, the x-coordinate is the hash of the message.
        for i in 0..7 {
            builder
                .when(is_real)
                .assert_eq(cols.x_coordinate[i].into(), cols.poseidon2_output[i]);
        }

        let lookup_values = cols
            .poseidon2_input
            .iter()
            .chain(cols.poseidon2_output.iter())
            .cloned()
            .map(Into::into)
            .collect();
        builder.looking(SymbolicLookup::new(
            lookup_values,
            is_real.into(),
            LookupType::Poseidon2,
            LookupScope::Regional,
        ));

        let x = SepticExtension::<CB::Expr>::from_base_fn(|i| cols.x_coordinate[i].into());
        let y = SepticExtension::<CB::Expr>::from_base_fn(|i| cols.y_coordinate[i].into());

        // Constrain that `(x, y)` is a valid point on the curve.
        let y2 = y.square();
        let x3_2x_26z5 = SepticCurve::<CB::Expr>::curve_formula(x);
        builder.assert_septic_ext_eq(y2, x3_2x_26z5);

        // Constrain that `0 <= y6_value < (p - 1) / 2 = 2^30 - 2^(30 - TOP_BITS)`.
        // Decompose `y6_value` into 30 bits, and then constrain that the top field bits cannot be all 1.
        // To do this, check that the sum of the top field bits is not equal to TOP_BITS, which can be done by providing an inverse.
        let mut y6_value = CB::Expr::ZERO;
        let mut top_field_bits = CB::Expr::ZERO;
        for i in 0..30 {
            builder.assert_bool(cols.y6_bit_decomp[i]);
            y6_value = y6_value.clone() + cols.y6_bit_decomp[i] * CB::F::from_canonical_u32(1 << i);
            if i >= 30 - TOP_BITS {
                top_field_bits = top_field_bits.clone() + cols.y6_bit_decomp[i];
            }
        }
        // If `is_real` is true, check that `top_field_bits - TOP_BITS` is non-zero, by checking `range_check_witness` is an inverse of it.
        builder.when(is_real).assert_eq(
            cols.range_check_witness * (top_field_bits - CB::Expr::from_canonical_usize(TOP_BITS)),
            CB::Expr::ONE,
        );

        // Constrain that y has correct sign.
        // If it's a receive: `1 <= y_6 <= (p - 1) / 2`, so `0 <= y_6 - 1 = y6_value < (p - 1) / 2`.
        // If it's a send: `(p + 1) / 2 <= y_6 <= p - 1`, so `0 <= y_6 - (p + 1) / 2 = y6_value < (p - 1) / 2`.
        builder
            .when(is_receive)
            .assert_eq(y.0[6].clone(), CB::Expr::ONE + y6_value.clone());
        builder.when(is_send).assert_eq(
            y.0[6].clone(),
            CB::Expr::from_canonical_u32((1 << 30) - (1 << (30 - TOP_BITS)) + 1) + y6_value,
        );
    }
}
