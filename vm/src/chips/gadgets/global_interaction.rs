use crate::{
    chips::chips::rangecheck::event::RangeRecordBehavior,
    compiler::riscv::opcode::RangeCheckOpcode,
    machine::{
        builder::{ChipBuilder, ChipLookupBuilder, ChipRangeBuilder, SepticExtensionBuilder},
        lookup::LookupType,
        septic::{
            SepticBlock, SepticCurve, SepticExtension, CURVE_WITNESS_DUMMY_POINT_X,
            CURVE_WITNESS_DUMMY_POINT_Y, TOP_BITS,
        },
    },
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
}

impl<F: PrimeField32> GlobalInteractionOperation<F> {
    pub fn get_digest(
        values: SepticBlock<u32>,
        is_receive: bool,
        kind: LookupType,
    ) -> (SepticCurve<F>, u8) {
        let x_start = SepticExtension::<F>::from_base_fn(|i| F::from_canonical_u32(values.0[i]))
            + SepticExtension::from_base(F::from_canonical_u32((kind as u32) << 24));
        let (point, offset) = SepticCurve::<F>::lift_x(x_start);
        if !is_receive {
            return (point.neg(), offset);
        }
        (point, offset)
    }

    pub fn populate(
        &mut self,
        values: SepticBlock<u32>,
        is_receive: bool,
        is_real: bool,
        kind: LookupType,
    ) {
        if is_real {
            let (point, offset) = Self::get_digest(values, is_receive, kind);
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
        } else {
            self.populate_dummy();
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn populate_memory_range_check_witness(
        &self,
        shard: u32,
        value: u32,
        is_real: bool,
        blu: &mut impl RangeRecordBehavior,
    ) {
        if is_real {
            blu.add_u8_range_checks(value.to_le_bytes(), Some(shard));
            blu.add_u16_range_check(shard as u16, Some(shard));
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn populate_memory(
        &mut self,
        shard: u32,
        clk: u32,
        addr: u32,
        value: u32,
        is_receive: bool,
        is_real: bool,
    ) {
        self.populate(
            SepticBlock([
                shard,
                clk,
                addr,
                value & 255,
                (value >> 8) & 255,
                (value >> 16) & 255,
                (value >> 24) & 255,
            ]),
            is_receive,
            is_real,
            LookupType::Memory,
        );
    }

    #[allow(clippy::too_many_arguments)]
    pub fn populate_syscall_range_check_witness(
        &self,
        shard: u32,
        clk_16: u16,
        clk_8: u8,
        syscall_id: u32,
        is_real: bool,
        blu: &mut impl RangeRecordBehavior,
    ) {
        if is_real {
            blu.add_u16_range_checks(&[shard as u16, clk_16], Some(shard));
            blu.add_u8_range_checks([clk_8, syscall_id as u8], Some(shard));
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn populate_syscall(
        &mut self,
        shard: u32,
        clk_16: u16,
        clk_8: u8,
        syscall_id: u32,
        arg1: u32,
        arg2: u32,
        is_receive: bool,
        is_real: bool,
    ) {
        self.populate(
            SepticBlock([
                shard,
                clk_16.into(),
                clk_8.into(),
                syscall_id,
                arg1,
                arg2,
                0,
            ]),
            is_receive,
            is_real,
            LookupType::Syscall,
        );
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
    }
}

impl<F: Field> GlobalInteractionOperation<F> {
    /// Constrain that the y coordinate is correct decompression, and send the resulting digest coordinate to the permutation trace.
    /// The first value in `values` must be a value range checked to u16.
    fn eval_single_digest<AB: ChipBuilder<F>>(
        builder: &mut AB,
        values: [AB::Expr; 7],
        cols: GlobalInteractionOperation<AB::Var>,
        is_receive: bool,
        is_real: AB::Var,
        kind: LookupType,
    ) {
        // Constrain that the `is_real` is boolean.
        builder.assert_bool(is_real);

        // Compute the offset and range check each bits, ensuring that the offset is a byte.
        let mut offset = AB::Expr::ZERO;
        for i in 0..8 {
            builder.assert_bool(cols.offset_bits[i]);
            offset = offset.clone() + cols.offset_bits[i] * AB::F::from_canonical_u32(1 << i);
        }

        // Compute the message.
        let message = SepticExtension(values)
            + SepticExtension::<AB::Expr>::from_base(
                offset * AB::F::from_canonical_u32(1 << 16)
                    + AB::F::from_canonical_u32(kind as u32) * AB::F::from_canonical_u32(1 << 24),
            );

        // Compute a * m + b.
        let am_plus_b = SepticCurve::<AB::Expr>::universal_hash(message);

        let x = SepticExtension::<AB::Expr>::from_base_fn(|i| cols.x_coordinate[i].into());

        // Constrain that when `is_real` is true, then `x == a * m + b`.
        builder
            .when(is_real)
            .assert_septic_ext_eq(x.clone(), am_plus_b);

        // Constrain that y is a valid y-coordinate.
        let y = SepticExtension::<AB::Expr>::from_base_fn(|i| cols.y_coordinate[i].into());

        // Constrain that `(x, y)` is a valid point on the curve.
        let y2 = y.square();
        let x3_2x_26z5 = SepticCurve::<AB::Expr>::curve_formula(x);

        builder.assert_septic_ext_eq(y2, x3_2x_26z5);

        let mut y6_value = AB::Expr::ZERO;
        let mut top_field_bits = AB::Expr::ZERO;
        for i in 0..30 {
            builder.assert_bool(cols.y6_bit_decomp[i]);
            y6_value = y6_value.clone() + cols.y6_bit_decomp[i] * AB::F::from_canonical_u32(1 << i);
            if i >= 30 - TOP_BITS {
                top_field_bits = top_field_bits.clone() + cols.y6_bit_decomp[i];
            }
        }
        top_field_bits = top_field_bits.clone() - AB::Expr::from_canonical_usize(TOP_BITS);
        builder
            .when(is_real)
            .assert_eq(cols.range_check_witness * top_field_bits, AB::Expr::ONE);

        // Constrain that y has correct sign.
        // If it's a receive: 0 <= y_6 - 1 < (p - 1) / 2 = 2^30 - 2^26
        // If it's a send: 0 <= y_6 - (p + 1) / 2 < (p - 1) / 2 = 2^30 - 2^26
        if is_receive {
            builder
                .when(is_real)
                .assert_eq(y.0[6].clone(), AB::Expr::ONE + y6_value);
        } else {
            builder.when(is_real).assert_eq(
                y.0[6].clone(),
                AB::Expr::from_canonical_u32((1 << 30) - (1 << (30 - TOP_BITS)) + 1) + y6_value,
            );
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn eval_single_digest_memory<AB: ChipBuilder<F>>(
        builder: &mut AB,
        shard: AB::Expr,
        clk: AB::Expr,
        addr: AB::Expr,
        value: [AB::Expr; 4],
        cols: GlobalInteractionOperation<AB::Var>,
        is_receive: bool,
        is_real: AB::Var,
    ) {
        let values = [
            shard.clone(),
            clk.clone(),
            addr.clone(),
            value[0].clone(),
            value[1].clone(),
            value[2].clone(),
            value[3].clone(),
        ];

        Self::eval_single_digest(
            builder,
            values,
            cols,
            is_receive,
            is_real,
            LookupType::Memory,
        );

        // Range check for message space.
        // Range check shard to be a valid u16.
        builder.looking_rangecheck(RangeCheckOpcode::U16, shard.clone(), shard.clone(), is_real);
        // Range check the word value to be valid u8 word.
        builder.slice_range_check_u8(&value, shard, is_real);
    }

    #[allow(clippy::too_many_arguments)]
    pub fn eval_single_digest_syscall<AB: ChipBuilder<F>>(
        builder: &mut AB,
        shard: AB::Expr,
        clk_16: AB::Expr,
        clk_8: AB::Expr,
        syscall_id: AB::Expr,
        arg1: AB::Expr,
        arg2: AB::Expr,
        cols: GlobalInteractionOperation<AB::Var>,
        is_receive: bool,
        is_real: AB::Var,
    ) {
        let values = [
            shard.clone(),
            clk_16.clone(),
            clk_8.clone(),
            syscall_id.clone(),
            arg1.clone(),
            arg2.clone(),
            AB::Expr::ZERO,
        ];

        Self::eval_single_digest(
            builder,
            values,
            cols,
            is_receive,
            is_real,
            LookupType::Syscall,
        );

        // Range check for message space.
        // Range check shard to be a valid u16.
        builder.looking_rangecheck(
            RangeCheckOpcode::U16,
            shard.clone(),
            AB::Expr::ZERO,
            is_real,
        );

        // Range check clk_8 and syscall_id to be u8.
        builder.slice_range_check_u8(&[clk_8, syscall_id], shard, is_real);

        // Range check clk_16 to be u16.
        builder.looking_rangecheck(RangeCheckOpcode::U16, clk_16, AB::Expr::ZERO, is_real);
    }
}
