use core::{
    borrow::{Borrow, BorrowMut},
    mem::size_of,
};
use std::fmt::Debug;

use crate::{
    chips::{
        chips::{
            byte::event::ByteRecordBehavior,
            riscv_memory::read_write::columns::{MemoryReadColsU8, MemoryWriteColsU8},
        },
        gadgets::{
            addr_add::AddrAddGadget,
            curves::{
                weierstrass::{
                    bls381::{bls12381_sqrt, Bls12381},
                    secp256k1::{secp256k1_sqrt, Secp256k1},
                    secp256r1::{secp256r1_sqrt, Secp256r1},
                    WeierstrassParameters,
                },
                CurveType, EllipticCurve,
            },
            field::{
                field_inner_product::FieldInnerProductCols,
                field_lt::FieldLtCols,
                field_op::{FieldOpCols, FieldOperation},
                field_sqrt::FieldSqrtCols,
            },
            syscall_addr::SyscallAddrGadget,
            utils::{
                conversions::{
                    generate_limbs_from_read_cols_u8, generate_limbs_from_write_cols_u8,
                    limbs_to_words,
                },
                field_params::{limbs_from_slice, FieldParameters, NumLimbs, NumWords},
                limbs::Limbs,
                polynomial::Polynomial,
            },
        },
        precompiles::checked_u64_to_u32,
        utils::pad_rows_fixed,
    },
    compiler::{riscv::program::Program, word::Word},
    emulator::riscv::{
        record::EmulationRecord,
        syscalls::{precompiles::PrecompileEvent, SyscallCode},
    },
    machine::{
        builder::{ChipBaseBuilder, ChipBuilder, ChipLookupBuilder, RiscVMemoryBuilder},
        chip::ChipBehavior,
    },
    primitives::consts::u64_to_u16_limbs,
};
use hybrid_array::Array;
use num::{BigUint, One, Zero};
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{Field, FieldAlgebra, PrimeField32};
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use pico_derive::AlignedBorrow;
use std::marker::PhantomData;
use typenum::Unsigned;

pub const fn num_weierstrass_decompress_cols<P: FieldParameters + NumWords>() -> usize {
    size_of::<WeierstrassDecompressCols<u8, P>>()
}

/// A set of columns to compute `WeierstrassDecompress` that decompresses a point on a Weierstrass
/// curve.
#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct WeierstrassDecompressCols<T, P: FieldParameters + NumWords> {
    pub is_real: T,
    pub chunk: T,
    pub clk: T,
    pub ptr: SyscallAddrGadget<T>,
    pub x_addrs: Array<AddrAddGadget<T>, P::WordsFieldElement>,
    pub y_addrs: Array<AddrAddGadget<T>, P::WordsFieldElement>,
    pub sign_bit: T,
    pub x_access: Array<MemoryReadColsU8<T>, P::WordsFieldElement>,
    pub y_access: Array<MemoryWriteColsU8<T>, P::WordsFieldElement>,
    pub(crate) range_x: FieldLtCols<T, P>,
    pub(crate) x_2: FieldOpCols<T, P>,
    pub(crate) x_3: FieldOpCols<T, P>,
    pub(crate) ax_plus_b: FieldInnerProductCols<T, P>,
    pub(crate) x_3_plus_b_plus_ax: FieldOpCols<T, P>,
    pub(crate) y: FieldSqrtCols<T, P>,
    pub(crate) neg_y: FieldOpCols<T, P>,
    pub(crate) neg_y_range_check: FieldLtCols<T, P>,
}

/// A set of columns to compute `WeierstrassDecompress` that decompresses a point on a Weierstrass
/// curve.
#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct LexicographicChoiceCols<T, P: FieldParameters + NumWords> {
    pub comparison_lt_cols: FieldLtCols<T, P>,
    pub is_y_eq_sqrt_y_result: T,
    pub when_sqrt_y_res_is_lt: T,
    pub when_neg_y_res_is_lt: T,
}

/// The convention for choosing the decompressed `y` value given a sign bit.
pub enum SignChoiceRule {
    /// Lease significant bit convention.
    ///
    /// In this convention, the `sign_bit` matches the pairty of the `y` value. This is the
    /// convention used in the ECDSA signature scheme, for example, in the secp256k1 curve.
    LeastSignificantBit,
    /// Lexicographic convention.
    ///
    /// In this convention, the `sign_bit` corresponds to whether the `y` value is larger than its
    /// negative counterpart with respect to the embedding of ptime field elements as integers.
    /// This onvention used in the BLS signature scheme, for example, in the BLS12-381 curve.
    Lexicographic,
}

#[allow(clippy::type_complexity)]
pub struct WeierstrassDecompressChip<F, E> {
    sign_rule: SignChoiceRule,
    _marker: PhantomData<fn(F, E) -> (F, E)>,
}

impl<F> Default for WeierstrassDecompressChip<F, Bls12381> {
    fn default() -> Self {
        Self::with_lexicographic_rule()
    }
}

impl<F> Default for WeierstrassDecompressChip<F, Secp256k1> {
    fn default() -> Self {
        Self::with_lsb_rule()
    }
}

impl<F> Default for WeierstrassDecompressChip<F, Secp256r1> {
    fn default() -> Self {
        Self::with_lsb_rule()
    }
}

impl<F, E> WeierstrassDecompressChip<F, E> {
    pub const fn new(sign_rule: SignChoiceRule) -> Self {
        Self {
            sign_rule,
            _marker: PhantomData,
        }
    }

    pub const fn with_lsb_rule() -> Self {
        Self {
            sign_rule: SignChoiceRule::LeastSignificantBit,
            _marker: PhantomData,
        }
    }

    pub const fn with_lexicographic_rule() -> Self {
        Self {
            sign_rule: SignChoiceRule::Lexicographic,
            _marker: PhantomData,
        }
    }
}

impl<F: PrimeField32, E: EllipticCurve + WeierstrassParameters> WeierstrassDecompressChip<F, E> {
    fn populate_field_ops(
        blu_events: &mut impl ByteRecordBehavior,
        cols: &mut WeierstrassDecompressCols<F, E::BaseField>,
        x: BigUint,
    ) {
        // Y = sqrt(x^3 + ax + b)
        cols.range_x
            .populate(blu_events, &x, &E::BaseField::modulus());
        let x_2 = cols
            .x_2
            .populate(blu_events, &x.clone(), &x.clone(), FieldOperation::Mul);
        let x_3 = cols.x_3.populate(blu_events, &x_2, &x, FieldOperation::Mul);
        let b = E::b_int();
        let a = E::a_int();
        let ax_plus_b = cols
            .ax_plus_b
            .populate(blu_events, &[a, b], &[x, BigUint::one()]);
        let x_3_plus_b_plus_ax =
            cols.x_3_plus_b_plus_ax
                .populate(blu_events, &x_3, &ax_plus_b, FieldOperation::Add);

        let sqrt_fn = match E::CURVE_TYPE {
            CurveType::Bls12381 => bls12381_sqrt,
            CurveType::Secp256k1 => secp256k1_sqrt,
            CurveType::Secp256r1 => secp256r1_sqrt,
            _ => panic!("Unsupported curve: {}", E::CURVE_TYPE),
        };
        let y = cols.y.populate(blu_events, &x_3_plus_b_plus_ax, sqrt_fn);

        let zero = BigUint::zero();
        let neg_y = cols
            .neg_y
            .populate(blu_events, &zero, &y, FieldOperation::Sub);
        cols.neg_y_range_check
            .populate(blu_events, &neg_y, &E::BaseField::modulus());
    }
}

impl<F: PrimeField32, E: EllipticCurve + WeierstrassParameters> ChipBehavior<F>
    for WeierstrassDecompressChip<F, E>
{
    type Record = EmulationRecord;
    type Program = Program;

    fn name(&self) -> String {
        match E::CURVE_TYPE {
            CurveType::Secp256k1 => "Secp256k1Decompress".to_string(),
            CurveType::Secp256r1 => "Secp256r1Decompress".to_string(),
            CurveType::Bls12381 => "Bls12381Decompress".to_string(),
            _ => panic!("Unsupported curve: {}", E::CURVE_TYPE),
        }
    }

    fn extra_record(&self, input: &Self::Record, extra: &mut Self::Record) {
        self.generate_main(input, extra);
    }

    fn generate_main(
        &self,
        input: &EmulationRecord,
        output: &mut EmulationRecord,
    ) -> RowMajorMatrix<F> {
        let events = match E::CURVE_TYPE {
            CurveType::Secp256k1 => input.get_precompile_events(SyscallCode::SECP256K1_DECOMPRESS),
            CurveType::Secp256r1 => input.get_precompile_events(SyscallCode::SECP256R1_DECOMPRESS),
            CurveType::Bls12381 => input.get_precompile_events(SyscallCode::BLS12381_DECOMPRESS),
            _ => panic!("Unsupported curve"),
        };

        let mut rows = Vec::new();
        let weierstrass_width = num_weierstrass_decompress_cols::<E::BaseField>();
        let width = BaseAir::<F>::width(self);

        let mut new_byte_lookup_events = Vec::new();

        let modulus = E::BaseField::modulus();

        for i in 0..events.len() {
            let (_syscall_event, precompile_event) = &events[i];

            let event = match precompile_event {
                PrecompileEvent::Secp256k1Decompress(event)
                | PrecompileEvent::Secp256r1Decompress(event)
                | PrecompileEvent::Bls12381Decompress(event) => event,
                _ => unreachable!(),
            };

            let mut row = vec![F::ZERO; width];
            let cols: &mut WeierstrassDecompressCols<F, E::BaseField> =
                row[0..weierstrass_width].borrow_mut();

            cols.is_real = F::from_bool(true);
            cols.chunk = F::from_canonical_u32(event.chunk);
            cols.clk =
                F::from_canonical_u32(checked_u64_to_u32(event.clk, "weierstrass decompress clk"));
            let num_limbs = <E::BaseField as NumLimbs>::Limbs::USIZE;
            let len = num_limbs as u64 * 2;
            cols.ptr
                .populate(&mut new_byte_lookup_events, event.ptr, len);
            cols.sign_bit = F::from_bool(event.sign_bit);

            let x = BigUint::from_bytes_le(
                &event
                    .x_words
                    .iter()
                    .flat_map(|word| word.to_le_bytes())
                    .collect::<Vec<u8>>(),
            );
            Self::populate_field_ops(&mut new_byte_lookup_events, cols, x);

            for i in 0..cols.x_access.len() {
                cols.x_access[i]
                    .inner
                    .populate(event.x_memory_records[i], &mut new_byte_lookup_events);
                cols.x_access[i].prev_value_u8.populate_u16_to_u8_safe(
                    &mut new_byte_lookup_events,
                    event.x_memory_records[i].value,
                );
                cols.x_addrs[i].populate(
                    &mut new_byte_lookup_events,
                    event.ptr + num_limbs as u64,
                    8 * i as u64,
                );
            }
            for i in 0..cols.y_access.len() {
                cols.y_access[i]
                    .inner
                    .populate(event.y_memory_records[i], &mut new_byte_lookup_events);
                cols.y_access[i].prev_value_u8.populate_u16_to_u8_safe(
                    &mut new_byte_lookup_events,
                    event.y_memory_records[i].prev_value,
                );
                cols.y_addrs[i].populate(&mut new_byte_lookup_events, event.ptr, 8 * i as u64);
            }

            if matches!(self.sign_rule, SignChoiceRule::Lexicographic) {
                let lsb = cols.y.lsb;
                let choice_cols: &mut LexicographicChoiceCols<F, E::BaseField> =
                    row[weierstrass_width..width].borrow_mut();

                let decompressed_y = BigUint::from_bytes_le(
                    &event
                        .decompressed_y_words
                        .iter()
                        .flat_map(|word| word.to_le_bytes())
                        .collect::<Vec<u8>>(),
                );
                let neg_y = &modulus - &decompressed_y;

                let is_y_eq_sqrt_y_result =
                    F::from_canonical_u8((event.decompressed_y_words[0] & 1) as u8) == lsb;
                choice_cols.is_y_eq_sqrt_y_result = F::from_bool(is_y_eq_sqrt_y_result);

                if event.sign_bit {
                    assert!(neg_y < decompressed_y);
                    choice_cols.when_sqrt_y_res_is_lt = F::from_bool(!is_y_eq_sqrt_y_result);
                    choice_cols.when_neg_y_res_is_lt = F::from_bool(is_y_eq_sqrt_y_result);
                    choice_cols.comparison_lt_cols.populate(
                        &mut new_byte_lookup_events,
                        &neg_y,
                        &decompressed_y,
                    );
                } else {
                    assert!(neg_y > decompressed_y);
                    choice_cols.when_sqrt_y_res_is_lt = F::from_bool(is_y_eq_sqrt_y_result);
                    choice_cols.when_neg_y_res_is_lt = F::from_bool(!is_y_eq_sqrt_y_result);
                    choice_cols.comparison_lt_cols.populate(
                        &mut new_byte_lookup_events,
                        &decompressed_y,
                        &neg_y,
                    );
                }
            }

            rows.push(row);
        }
        output.add_byte_lookup_events(new_byte_lookup_events);

        let log_rows = input.shape_chip_size(&self.name());
        pad_rows_fixed(
            &mut rows,
            || {
                let mut row = vec![F::ZERO; width];
                let cols: &mut WeierstrassDecompressCols<F, E::BaseField> =
                    row.as_mut_slice()[0..weierstrass_width].borrow_mut();

                // take X of the generator as a dummy value to make sure Y^2 = X^3 + aX + b holds
                let dummy_value = E::generator().0;
                let dummy_bytes = dummy_value.to_bytes_le();
                // Convert bytes to u64 words for the dummy x_access values
                let u64_words: Vec<u64> = dummy_bytes
                    .chunks(8)
                    .map(|chunk| {
                        let mut arr = [0u8; 8];
                        arr[..chunk.len()].copy_from_slice(chunk);
                        u64::from_le_bytes(arr)
                    })
                    .collect();
                for i in 0..cols.x_access.len() {
                    let limbs = u64_to_u16_limbs(u64_words[i]);
                    cols.x_access[i].inner.access.value = crate::compiler::word::Word([
                        F::from_canonical_u16(limbs[0]),
                        F::from_canonical_u16(limbs[1]),
                        F::from_canonical_u16(limbs[2]),
                        F::from_canonical_u16(limbs[3]),
                    ]);
                    // Must also set prev_value_u8.low_bytes so that the U16→U8
                    // decomposition in eval (generate_limbs_from_read_cols_u8)
                    // produces correct byte limbs.  Without this, padding rows
                    // have low_bytes=0 while value≠0, causing the polynomial
                    // constraint (which is NOT gated by is_real) to fail.
                    for j in 0..4 {
                        cols.x_access[i].prev_value_u8.low_bytes[j] =
                            F::from_canonical_u8((limbs[j] & 0xFF) as u8);
                    }
                }

                Self::populate_field_ops(&mut vec![], cols, dummy_value);
                row
            },
            log_rows,
        );

        RowMajorMatrix::new(rows.into_iter().flatten().collect::<Vec<_>>(), width)
    }

    fn is_active(&self, chunk: &Self::Record) -> bool {
        if let Some(shape) = chunk.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            match E::CURVE_TYPE {
                CurveType::Secp256k1 => !chunk
                    .get_precompile_events(SyscallCode::SECP256K1_DECOMPRESS)
                    .is_empty(),
                CurveType::Secp256r1 => !chunk
                    .get_precompile_events(SyscallCode::SECP256R1_DECOMPRESS)
                    .is_empty(),
                CurveType::Bls12381 => !chunk
                    .get_precompile_events(SyscallCode::BLS12381_DECOMPRESS)
                    .is_empty(),
                _ => panic!("Unsupported curve"),
            }
        }
    }

    fn local_only(&self) -> bool {
        true
    }
}

impl<F, E: EllipticCurve> BaseAir<F> for WeierstrassDecompressChip<F, E> {
    fn width(&self) -> usize {
        num_weierstrass_decompress_cols::<E::BaseField>()
            + match self.sign_rule {
                SignChoiceRule::LeastSignificantBit => 0,
                SignChoiceRule::Lexicographic => {
                    size_of::<LexicographicChoiceCols<u8, E::BaseField>>()
                }
            }
    }
}

impl<F: PrimeField32, CB, E: EllipticCurve + WeierstrassParameters> Air<CB>
    for WeierstrassDecompressChip<F, E>
where
    F: Field,
    CB: ChipBuilder<F>,
    Limbs<CB::Var, <E::BaseField as NumLimbs>::Limbs>: Copy,
{
    fn eval(&self, builder: &mut CB) {
        let main = builder.main();

        let weierstrass_cols = num_weierstrass_decompress_cols::<E::BaseField>();
        let local_slice = main.row_slice(0);
        let local: &WeierstrassDecompressCols<CB::Var, E::BaseField> =
            (*local_slice)[0..weierstrass_cols].borrow();

        let num_limbs = <E::BaseField as NumLimbs>::Limbs::USIZE;

        builder.assert_bool(local.sign_bit);

        // Extract byte limbs from u16 word limbs via U16→U8 conversion.
        let x_limbs =
            generate_limbs_from_read_cols_u8(builder, &local.x_access[..], local.is_real.into());

        // `y_access.prev_value_u8` is populated by the trace, which emits u8 range checks;
        // they need a matching evaluation here or the byte table is over-received. The
        // returned limbs are unused — `y_access`'s value is constrained below against
        // `sqrt_y`/`neg_y` — so this call exists to balance those lookups and to pin the
        // byte decomposition. It is a write access, hence the `write` helper, which reads
        // `inner.prev_value` just as the trace did.
        let _ =
            generate_limbs_from_write_cols_u8(builder, &local.y_access[..], local.is_real.into());
        let x: Limbs<CB::Expr, <E::BaseField as NumLimbs>::Limbs> =
            Limbs(Array::try_from_iter(x_limbs).expect("failed to convert x limbs"));
        let max_num_limbs = E::BaseField::to_limbs_field_slice(&E::BaseField::modulus());
        local.range_x.eval(
            builder,
            &x,
            &limbs_from_slice::<CB::Expr, <E::BaseField as NumLimbs>::Limbs, CB::F>(max_num_limbs),
            local.is_real,
        );
        local
            .x_2
            .eval(builder, &x, &x, FieldOperation::Mul, local.is_real);
        local.x_3.eval(
            builder,
            &local.x_2.result,
            &x,
            FieldOperation::Mul,
            local.is_real,
        );
        let b_const = E::BaseField::to_limbs_field::<CB::F, _>(&E::b_int());
        let a_const = E::BaseField::to_limbs_field::<CB::F, _>(&E::a_int());
        let params = [a_const, b_const];
        let p_x: Polynomial<CB::Expr> = x.into();
        let p_one: Polynomial<CB::Expr> =
            E::BaseField::to_limbs_field::<CB::F, _>(&BigUint::one()).into();
        local
            .ax_plus_b
            .eval(builder, &params, &[p_x, p_one], local.is_real);
        local.x_3_plus_b_plus_ax.eval(
            builder,
            &local.x_3.result,
            &local.ax_plus_b.result,
            FieldOperation::Add,
            local.is_real,
        );

        local.neg_y.eval(
            builder,
            &[CB::Expr::ZERO].iter(),
            &local.y.multiplication.result,
            FieldOperation::Sub,
            local.is_real,
        );

        // Range check neg_y against the field modulus.
        let modulus = E::BaseField::to_limbs_field::<CB::Expr, CB::F>(&E::BaseField::modulus());
        local
            .neg_y_range_check
            .eval(builder, &local.neg_y.result, &modulus, local.is_real);

        local.y.eval(
            builder,
            &local.x_3_plus_b_plus_ax.result,
            local.y.lsb,
            local.is_real,
        );

        // Convert computed sqrt(y) and neg_y results from u8 limbs to u16 Words for value constraints.
        let sqrt_y_words = limbs_to_words(
            &local
                .y
                .multiplication
                .result
                .0
                .iter()
                .map(|v| (*v).into())
                .collect::<Vec<CB::Expr>>(),
            CB::F::from_canonical_u32(256).into(),
        );
        let neg_y_words = limbs_to_words(
            &local
                .neg_y
                .result
                .0
                .iter()
                .map(|v| (*v).into())
                .collect::<Vec<CB::Expr>>(),
            CB::F::from_canonical_u32(256).into(),
        );

        // Constrain the y value according the sign rule convention.
        match self.sign_rule {
            SignChoiceRule::LeastSignificantBit => {
                // When the sign rule is LeastSignificantBit, the sign_bit should match the parity
                // of the result. The parity of the square root result is given by the local.y.lsb
                // value. Thus, if the sign_bit matches the local.y.lsb value, then the result
                // should be the square root of the y value. Otherwise, the result should be the
                // negative square root of the y value.
                // The actual y write value constraint is applied in the memory write loop below.
            }
            SignChoiceRule::Lexicographic => {
                // When the sign rule is Lexicographic, the sign_bit corresponds to whether
                // the result is greater than or less its negative with respect to the lexicographic
                // ordering, embedding prime field values as integers.
                //
                // In order to endorce these constraints, we will use the auxillary choice columns.

                // Get the choice columns from the row slice
                let choice_cols: &LexicographicChoiceCols<CB::Var, E::BaseField> = (*local_slice)
                    [weierstrass_cols
                        ..weierstrass_cols
                            + size_of::<LexicographicChoiceCols<u8, E::BaseField>>()]
                    .borrow();

                // Assert that the flags are booleans.
                builder.assert_bool(choice_cols.is_y_eq_sqrt_y_result);
                builder.assert_bool(choice_cols.when_sqrt_y_res_is_lt);
                builder.assert_bool(choice_cols.when_neg_y_res_is_lt);

                // Assert that the `when` flags are disjoint:
                builder.when(local.is_real).assert_one(
                    choice_cols.when_sqrt_y_res_is_lt + choice_cols.when_neg_y_res_is_lt,
                );

                // NOTE: The actual y write value constraint is applied in the memory write loop below
                // using sqrt_y_words / neg_y_words, conditioned on is_y_eq_sqrt_y_result.

                // Assert that the comparison only turns on when `is_real` is true.
                builder
                    .when_not(local.is_real)
                    .assert_zero(choice_cols.when_sqrt_y_res_is_lt);
                builder
                    .when_not(local.is_real)
                    .assert_zero(choice_cols.when_neg_y_res_is_lt);

                // Assert that the flags are set correctly. When the sign_bit is true, we want that
                // `neg_y < y`, and vice versa when the sign_bit is false. Hence, when should have:
                // - When `sign_bit` is true , then when_sqrt_y_res_is_lt = (y != sqrt(y)).
                // - When `sign_bit` is false, then when_neg_y_res_is_lt = (y == sqrt(y)).
                // - When `sign_bit` is true , then when_sqrt_y_res_is_lt = (y != sqrt(y)).
                // - When `sign_bit` is false, then when_neg_y_res_is_lt = (y == sqrt(y)).
                //
                // Since the when less-than flags are disjoint, we can assert that:
                // - When `sign_bit` is true , then is_y_eq_sqrt_y_result == when_neg_y_res_is_lt.
                // - When `sign_bit` is false, then is_y_eq_sqrt_y_result == when_sqrt_y_res_is_lt.
                builder.when(local.is_real).when(local.sign_bit).assert_eq(
                    choice_cols.is_y_eq_sqrt_y_result,
                    choice_cols.when_neg_y_res_is_lt,
                );
                builder
                    .when(local.is_real)
                    .when_not(local.sign_bit)
                    .assert_eq(
                        choice_cols.is_y_eq_sqrt_y_result,
                        choice_cols.when_sqrt_y_res_is_lt,
                    );

                // Assert the less-than comparisons according to the flags.

                choice_cols.comparison_lt_cols.eval(
                    builder,
                    &local.y.multiplication.result,
                    &local.neg_y.result,
                    choice_cols.when_sqrt_y_res_is_lt,
                );

                choice_cols.comparison_lt_cols.eval(
                    builder,
                    &local.neg_y.result,
                    &local.y.multiplication.result,
                    choice_cols.when_neg_y_res_is_lt,
                );
            }
        }

        // Address alignment constraints.
        let ptr = SyscallAddrGadget::<CB::F>::eval(
            builder,
            <E::BaseField as NumLimbs>::Limbs::USIZE as u32 * 2,
            local.ptr,
            local.is_real.into(),
        );

        // x_addrs[i] = ptr + num_limbs + 8*i
        for i in 0..local.x_addrs.len() {
            AddrAddGadget::<CB::F>::eval(
                builder,
                Word([ptr[0].into(), ptr[1].into(), ptr[2].into(), CB::Expr::ZERO]),
                Word::from(num_limbs as u64 + 8 * i as u64),
                local.x_addrs[i],
                local.is_real.into(),
            );
        }

        // y_addrs[i] = ptr + 8*i
        for i in 0..local.y_addrs.len() {
            AddrAddGadget::<CB::F>::eval(
                builder,
                Word([ptr[0].into(), ptr[1].into(), ptr[2].into(), CB::Expr::ZERO]),
                Word::from(8 * i as u64),
                local.y_addrs[i],
                local.is_real.into(),
            );
        }

        // Memory access constraints.
        // Read x — x is at offset num_limbs from ptr.
        for (i, x_col) in local.x_access.iter().enumerate() {
            builder.eval_memory_access(
                local.chunk,
                local.clk.into(),
                local.x_addrs[i].value.map(Into::into),
                &x_col.inner,
                local.is_real,
            );
        }
        // Write y — y is at offset 0 from ptr, with value constraints.
        // We constrain y_access.value == sqrt_y_words or neg_y_words conditionally.

        for (i, y_col) in local.y_access.iter().enumerate() {
            builder.eval_memory_access(
                local.chunk,
                local.clk.into(),
                local.y_addrs[i].value.map(Into::into),
                &y_col.inner,
                local.is_real,
            );

            // Constrain the write value to the correct computed y result.
            let do_check: CB::Expr = local.is_real.into();
            match self.sign_rule {
                SignChoiceRule::LeastSignificantBit => {
                    // When lsb != 1 - sign_bit (i.e., lsb == sign_bit),
                    // write value = sqrt(y).
                    for (v, w) in y_col
                        .inner
                        .access
                        .value
                        .0
                        .iter()
                        .zip(sqrt_y_words[i].0.iter())
                    {
                        builder
                            .when(do_check.clone())
                            .when_ne(local.y.lsb, CB::Expr::ONE - local.sign_bit)
                            .assert_eq((*v).into(), w.clone());
                    }
                    // When lsb != sign_bit (i.e., lsb == 1 - sign_bit),
                    // write value = neg_y.
                    for (v, w) in y_col
                        .inner
                        .access
                        .value
                        .0
                        .iter()
                        .zip(neg_y_words[i].0.iter())
                    {
                        builder
                            .when(do_check.clone())
                            .when_ne(local.y.lsb, local.sign_bit)
                            .assert_eq((*v).into(), w.clone());
                    }
                }
                SignChoiceRule::Lexicographic => {
                    let choice_cols: &LexicographicChoiceCols<CB::Var, E::BaseField> =
                        (*local_slice)[weierstrass_cols
                            ..weierstrass_cols
                                + size_of::<LexicographicChoiceCols<u8, E::BaseField>>()]
                            .borrow();
                    // When is_y_eq_sqrt_y_result, write value = sqrt(y).
                    for (v, w) in y_col
                        .inner
                        .access
                        .value
                        .0
                        .iter()
                        .zip(sqrt_y_words[i].0.iter())
                    {
                        builder
                            .when(do_check.clone())
                            .when(choice_cols.is_y_eq_sqrt_y_result)
                            .assert_eq((*v).into(), w.clone());
                    }
                    // When not is_y_eq_sqrt_y_result, write value = neg_y.
                    for (v, w) in y_col
                        .inner
                        .access
                        .value
                        .0
                        .iter()
                        .zip(neg_y_words[i].0.iter())
                    {
                        builder
                            .when(do_check.clone())
                            .when_not(choice_cols.is_y_eq_sqrt_y_result)
                            .assert_eq((*v).into(), w.clone());
                    }
                }
            }
        }

        let syscall_id = match E::CURVE_TYPE {
            CurveType::Bls12381 => {
                CB::F::from_canonical_u32(SyscallCode::BLS12381_DECOMPRESS.syscall_id())
            }
            CurveType::Secp256k1 => {
                CB::F::from_canonical_u32(SyscallCode::SECP256K1_DECOMPRESS.syscall_id())
            }
            CurveType::Secp256r1 => {
                CB::F::from_canonical_u32(SyscallCode::SECP256R1_DECOMPRESS.syscall_id())
            }
            _ => panic!("Unsupported curve: {}", E::CURVE_TYPE),
        };

        let sign_bit_expr: CB::Expr = local.sign_bit.into();
        builder.looked_syscall(
            local.chunk,
            local.clk,
            syscall_id,
            ptr.map(Into::into),
            [sign_bit_expr, CB::Expr::ZERO, CB::Expr::ZERO],
            local.is_real,
        );
    }
}
