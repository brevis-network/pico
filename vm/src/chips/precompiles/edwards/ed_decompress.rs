use crate::{
    chips::{
        chips::{
            byte::event::ByteRecordBehavior,
            riscv_memory::read_write::columns::{MemoryReadCols, MemoryWriteCols},
        },
        gadgets::{
            curves::edwards::{
                ed25519::{ed25519_sqrt, Ed25519BaseField},
                EdwardsParameters, WordsFieldElement,
            },
            field::{
                field_lt::FieldLtCols,
                field_op::{FieldOpCols, FieldOperation},
                field_sqrt::FieldSqrtCols,
            },
            utils::{
                field_params::{limbs_from_slice, FieldParameters},
                limbs::Limbs,
            },
        },
    },
    compiler::riscv::program::Program,
    emulator::{
        record::RecordBehavior,
        riscv::{
            record::EmulationRecord,
            syscalls::{
                precompiles::{edwards::event::EdDecompressEvent, PrecompileEvent},
                SyscallCode,
            },
        },
    },
    machine::{
        builder::{ChipBaseBuilder, ChipBuilder, ChipLookupBuilder, RiscVMemoryBuilder},
        chip::ChipBehavior,
        utils::{limbs_from_access, limbs_from_prev_access},
    },
    recursion_v2::stark::utils::pad_rows_fixed,
};
use core::{
    borrow::{Borrow, BorrowMut},
    mem::size_of,
};
use hybrid_array::Array;
use num::{BigUint, One, Zero};
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{Field, FieldAlgebra, PrimeField32};
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use pico_derive::AlignedBorrow;
use std::marker::PhantomData;
use tracing::debug;
use typenum::U32;

pub const NUM_ED_DECOMPRESS_COLS: usize = size_of::<EdDecompressCols<u8>>();

/// A set of columns to compute `EdDecompress` given a pointer to a 16 word slice formatted as such:
/// The 31st byte of the slice is the sign bit. The second half of the slice is the 255-bit
/// compressed Y (without sign bit).
///
/// After `EdDecompress`, the first 32 bytes of the slice are overwritten with the decompressed X.
#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct EdDecompressCols<T> {
    pub is_real: T,
    pub chunk: T,
    pub clk: T,
    pub ptr: T,
    pub sign: T,
    pub x_access: Array<MemoryWriteCols<T>, WordsFieldElement>,
    pub y_access: Array<MemoryReadCols<T>, WordsFieldElement>,
    pub(crate) y_range: FieldLtCols<T, Ed25519BaseField>,
    pub(crate) yy: FieldOpCols<T, Ed25519BaseField>,
    pub(crate) u: FieldOpCols<T, Ed25519BaseField>,
    pub(crate) dyy: FieldOpCols<T, Ed25519BaseField>,
    pub(crate) v: FieldOpCols<T, Ed25519BaseField>,
    pub(crate) u_div_v: FieldOpCols<T, Ed25519BaseField>,
    pub(crate) x: FieldSqrtCols<T, Ed25519BaseField>,
    pub(crate) neg_x: FieldOpCols<T, Ed25519BaseField>,
}

impl<F: PrimeField32> EdDecompressCols<F> {
    pub fn populate<P: FieldParameters, E: EdwardsParameters>(
        &mut self,
        event: EdDecompressEvent,
        record: &mut EmulationRecord,
    ) {
        let mut new_byte_lookup_events = Vec::new();
        self.is_real = F::from_bool(true);
        self.chunk = F::from_canonical_u32(event.chunk);
        self.clk = F::from_canonical_u32(event.clk);
        self.ptr = F::from_canonical_u32(event.ptr);
        self.sign = F::from_bool(event.sign);
        for i in 0..8 {
            self.x_access[i].populate(event.x_memory_records[i], &mut new_byte_lookup_events);
            self.y_access[i].populate(event.y_memory_records[i], &mut new_byte_lookup_events);
        }

        let y = &BigUint::from_bytes_le(&event.y_bytes);
        self.populate_field_ops::<E>(&mut new_byte_lookup_events, y);

        record.add_byte_lookup_events(new_byte_lookup_events);
    }

    fn populate_field_ops<E: EdwardsParameters>(
        &mut self,
        blu_events: &mut impl ByteRecordBehavior,
        y: &BigUint,
    ) {
        let one = BigUint::one();
        self.y_range
            .populate(blu_events, y, &Ed25519BaseField::modulus());
        let yy = self.yy.populate(blu_events, y, y, FieldOperation::Mul);
        let u = self.u.populate(blu_events, &yy, &one, FieldOperation::Sub);
        let dyy = self
            .dyy
            .populate(blu_events, &E::d_biguint(), &yy, FieldOperation::Mul);
        let v = self.v.populate(blu_events, &one, &dyy, FieldOperation::Add);
        let u_div_v = self
            .u_div_v
            .populate(blu_events, &u, &v, FieldOperation::Div);
        let x = self.x.populate(blu_events, &u_div_v, |p| {
            ed25519_sqrt(p).expect("ed25519_sqrt failed, syscall invariant violated")
        });
        self.neg_x
            .populate(blu_events, &BigUint::zero(), &x, FieldOperation::Sub);
    }
}

impl<V: Copy> EdDecompressCols<V> {
    pub fn eval<F: Field, CB: ChipBuilder<F, Var = V>, P: FieldParameters, E: EdwardsParameters>(
        &self,
        builder: &mut CB,
    ) where
        V: Into<CB::Expr>,
    {
        builder.assert_bool(self.sign);

        let y: Limbs<V, U32> = limbs_from_prev_access(&self.y_access);
        let max_num_limbs = P::to_limbs_field_slice(&Ed25519BaseField::modulus());
        self.y_range.eval(
            builder,
            &y,
            &limbs_from_slice::<CB::Expr, P::Limbs, CB::F>(max_num_limbs),
            self.is_real,
        );
        self.yy
            .eval(builder, &y, &y, FieldOperation::Mul, self.is_real);
        self.u.eval(
            builder,
            &self.yy.result,
            &[CB::Expr::ONE].iter(),
            FieldOperation::Sub,
            self.is_real,
        );
        let d_biguint = E::d_biguint();
        let d_const = E::BaseField::to_limbs_field::<CB::F, _>(&d_biguint);
        self.dyy.eval(
            builder,
            &d_const,
            &self.yy.result,
            FieldOperation::Mul,
            self.is_real,
        );
        self.v.eval(
            builder,
            &[CB::Expr::ONE].iter(),
            &self.dyy.result,
            FieldOperation::Add,
            self.is_real,
        );
        self.u_div_v.eval(
            builder,
            &self.u.result,
            &self.v.result,
            FieldOperation::Div,
            self.is_real,
        );
        self.x
            .eval(builder, &self.u_div_v.result, CB::F::ZERO, self.is_real);
        self.neg_x.eval(
            builder,
            &[CB::Expr::ZERO].iter(),
            &self.x.multiplication.result,
            FieldOperation::Sub,
            self.is_real,
        );

        builder.eval_memory_access_slice(
            self.chunk,
            self.clk,
            self.ptr,
            &self.x_access,
            self.is_real,
        );
        builder.eval_memory_access_slice(
            self.chunk,
            self.clk,
            self.ptr.into() + CB::F::from_canonical_u32(32),
            &self.y_access,
            self.is_real,
        );

        // Constrain that the correct result is written into x.
        let x_limbs: Limbs<V, U32> = limbs_from_access(&self.x_access);
        builder
            .when(self.is_real)
            .when(self.sign)
            .assert_all_eq(self.neg_x.result, x_limbs);
        builder
            .when(self.is_real)
            .when_not(self.sign)
            .assert_all_eq(self.x.multiplication.result, x_limbs);

        builder.looked_syscall(
            self.clk,
            CB::F::from_canonical_u32(SyscallCode::ED_DECOMPRESS.syscall_id()),
            self.ptr,
            self.sign,
            self.is_real,
        );
    }
}

#[derive(Default)]
pub struct EdDecompressChip<F, E> {
    _phantom: PhantomData<(F, E)>,
}

impl<F: Field, E: EdwardsParameters> EdDecompressChip<F, E> {
    pub const fn new() -> Self {
        Self {
            _phantom: PhantomData,
        }
    }
}

impl<F: PrimeField32, E: EdwardsParameters> ChipBehavior<F> for EdDecompressChip<F, E> {
    type Record = EmulationRecord;

    type Program = Program;

    fn name(&self) -> String {
        "EdDecompress".to_string()
    }

    fn extra_record(&self, input: &Self::Record, extra: &mut Self::Record) {
        self.generate_main(input, extra);
    }

    fn generate_main(
        &self,
        input: &EmulationRecord,
        output: &mut EmulationRecord,
    ) -> RowMajorMatrix<F> {
        let mut rows = Vec::new();
        let events: Vec<_> = input
            .get_precompile_events(SyscallCode::ED_DECOMPRESS)
            .iter()
            .filter_map(|(_, event)| {
                if let PrecompileEvent::EdDecompress(event) = event {
                    Some(event)
                } else {
                    unreachable!()
                }
            })
            .collect();

        debug!(
            "record {} ed decompress precompile events {:?}",
            input.chunk_index(),
            events.len()
        );

        for event in events {
            let mut row = [F::ZERO; NUM_ED_DECOMPRESS_COLS];
            let cols: &mut EdDecompressCols<F> = row.as_mut_slice().borrow_mut();
            cols.populate::<E::BaseField, E>(event.clone(), output);

            rows.push(row);
        }

        let log_rows = input.shape_chip_size(&self.name());
        pad_rows_fixed(
            &mut rows,
            || {
                let mut row = [F::ZERO; NUM_ED_DECOMPRESS_COLS];
                let cols: &mut EdDecompressCols<F> = row.as_mut_slice().borrow_mut();
                let zero = BigUint::zero();
                cols.populate_field_ops::<E>(&mut vec![], &zero);
                row
            },
            log_rows,
        );

        RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_ED_DECOMPRESS_COLS,
        )
    }

    fn is_active(&self, record: &Self::Record) -> bool {
        if let Some(shape) = record.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            !record
                .get_precompile_events(SyscallCode::ED_DECOMPRESS)
                .is_empty()
        }
    }

    fn local_only(&self) -> bool {
        true
    }
}

impl<F: Sync, E: EdwardsParameters> BaseAir<F> for EdDecompressChip<F, E> {
    fn width(&self) -> usize {
        NUM_ED_DECOMPRESS_COLS
    }
}

impl<F, CB, E> Air<CB> for EdDecompressChip<F, E>
where
    F: Field,
    CB: ChipBuilder<F>,
    E: EdwardsParameters,
{
    fn eval(&self, builder: &mut CB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &EdDecompressCols<CB::Var> = (*local).borrow();

        local.eval::<F, CB, E::BaseField, E>(builder);
    }
}
