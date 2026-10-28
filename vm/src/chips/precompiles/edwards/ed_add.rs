#[cfg(feature = "cuda")]
use crate::{
    chips::trace::TraceData,
    instances::preparer::{gpu_add_host_byte_lookups, PreallocatedGpuMemory, PreparedGpuEvents},
    machine::chip::GpuChipBehavior,
};
use crate::{
    chips::{
        chips::{
            byte::event::ByteRecordBehavior,
            riscv_memory::read_write::columns::{MemoryCols, MemoryReadColsU8, MemoryWriteColsU8},
        },
        gadgets::{
            addr_add::AddrAddGadget,
            curves::{
                edwards::{
                    ed25519::Ed25519BaseField, EdwardsParameters, WordsCurvePoint, NUM_LIMBS,
                    WORDS_CURVE_POINT, WORDS_FIELD_ELEMENT,
                },
                AffinePoint, EllipticCurve,
            },
            field::{
                field_den::FieldDenCols,
                field_inner_product::FieldInnerProductCols,
                field_lt::FieldLtCols,
                field_op::{FieldOpCols, FieldOperation},
            },
            syscall_addr::SyscallAddrGadget,
            utils::{
                conversions::{
                    generate_limbs_from_read_cols_u8, generate_limbs_from_write_cols_u8,
                    limbs_to_words,
                },
                field_params::{FieldParameters, NumLimbs},
                limbs::Limbs,
            },
        },
        precompiles::checked_u64_to_u32,
        utils::pad_rows_fixed,
    },
    compiler::{riscv::program::Program, word::Word},
    emulator::{
        record::RecordBehavior,
        riscv::{
            record::EmulationRecord,
            syscalls::{
                precompiles::{edwards::event::EllipticCurveAddEvent, PrecompileEvent},
                SyscallCode,
            },
        },
    },
    machine::{
        builder::{ChipBuilder, ChipLookupBuilder, RiscVMemoryBuilder},
        chip::ChipBehavior,
    },
};
use core::{
    borrow::{Borrow, BorrowMut},
    mem::size_of,
};
use hybrid_array::Array;
use num::{BigUint, Zero};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;
use pico_derive::AlignedBorrow;
use std::{fmt::Debug, marker::PhantomData};
use tracing::debug;

pub const NUM_ED_ADD_COLS: usize = size_of::<EdAddAssignCols<u8>>();

/// The 32 u8 limbs an Ed25519 base-field element decomposes into.
type EdLimbs<T> = Limbs<T, <Ed25519BaseField as NumLimbs>::Limbs>;

/// A set of columns to compute `EdAdd` where a, b are field elements.
///
/// The two points live in guest memory as `WORDS_CURVE_POINT` dwords each, x first then y, and
/// the field arithmetic runs on the u8 limbs those dwords decompose into. `p_access` is a
/// read-then-write: the addition's inputs are its `prev_value`, and its `value` is the result.
#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct EdAddAssignCols<T> {
    pub is_real: T,
    pub chunk: T,
    pub clk: T,
    pub p_ptr: SyscallAddrGadget<T>,
    pub q_ptr: SyscallAddrGadget<T>,
    pub p_addrs: Array<AddrAddGadget<T>, WordsCurvePoint>,
    pub q_addrs: Array<AddrAddGadget<T>, WordsCurvePoint>,
    pub p_access: Array<MemoryWriteColsU8<T>, WordsCurvePoint>,
    pub q_access: Array<MemoryReadColsU8<T>, WordsCurvePoint>,
    pub(crate) x3_numerator: FieldInnerProductCols<T, Ed25519BaseField>,
    pub(crate) y3_numerator: FieldInnerProductCols<T, Ed25519BaseField>,
    pub(crate) x1_mul_y1: FieldOpCols<T, Ed25519BaseField>,
    pub(crate) x2_mul_y2: FieldOpCols<T, Ed25519BaseField>,
    pub(crate) f: FieldOpCols<T, Ed25519BaseField>,
    pub(crate) d_mul_f: FieldOpCols<T, Ed25519BaseField>,
    pub(crate) x3_ins: FieldDenCols<T, Ed25519BaseField>,
    pub(crate) y3_ins: FieldDenCols<T, Ed25519BaseField>,
    /// `x3 < p`. The division gadget pins `x3` only up to the field identity it satisfies, which
    /// `x3 + p` satisfies just as well; without this the prover picks which representative is
    /// written back to guest memory. Matches `x3_range`/`y3_range` in `weierstrass_add.rs`.
    pub(crate) x3_range: FieldLtCols<T, Ed25519BaseField>,
    pub(crate) y3_range: FieldLtCols<T, Ed25519BaseField>,
}

#[derive(Default)]
pub struct EdAddAssignChip<F, E> {
    _marker: PhantomData<(F, E)>,
}

impl<F: PrimeField32, E: EllipticCurve + EdwardsParameters> EdAddAssignChip<F, E> {
    pub const fn new() -> Self {
        Self {
            _marker: PhantomData,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn populate_field_ops(
        record: &mut impl ByteRecordBehavior,
        cols: &mut EdAddAssignCols<F>,
        p_x: BigUint,
        p_y: BigUint,
        q_x: BigUint,
        q_y: BigUint,
    ) {
        let x3_numerator = cols.x3_numerator.populate(
            record,
            &[p_x.clone(), q_x.clone()],
            &[q_y.clone(), p_y.clone()],
        );
        let y3_numerator = cols.y3_numerator.populate(
            record,
            &[p_y.clone(), p_x.clone()],
            &[q_y.clone(), q_x.clone()],
        );
        let x1_mul_y1 = cols
            .x1_mul_y1
            .populate(record, &p_x, &p_y, FieldOperation::Mul);
        let x2_mul_y2 = cols
            .x2_mul_y2
            .populate(record, &q_x, &q_y, FieldOperation::Mul);
        let f = cols
            .f
            .populate(record, &x1_mul_y1, &x2_mul_y2, FieldOperation::Mul);

        let d = E::d_biguint();
        let d_mul_f = cols.d_mul_f.populate(record, &f, &d, FieldOperation::Mul);

        let x3 = cols.x3_ins.populate(record, &x3_numerator, &d_mul_f, true);
        let y3 = cols.y3_ins.populate(record, &y3_numerator, &d_mul_f, false);

        cols.x3_range
            .populate(record, &x3, &Ed25519BaseField::modulus());
        cols.y3_range
            .populate(record, &y3, &Ed25519BaseField::modulus());
    }
}

impl<F: PrimeField32, E: EllipticCurve + EdwardsParameters> ChipBehavior<F>
    for EdAddAssignChip<F, E>
{
    type Record = EmulationRecord;
    type Program = Program;

    fn name(&self) -> String {
        "EdAddAssign".to_string()
    }

    fn generate_main(
        &self,
        input: &EmulationRecord,
        output: &mut EmulationRecord,
    ) -> RowMajorMatrix<F> {
        let events: Vec<_> = input
            .get_precompile_events(SyscallCode::ED_ADD)
            .iter()
            .filter_map(|(_, event)| {
                if let PrecompileEvent::EdAdd(event) = event {
                    Some(event)
                } else {
                    unreachable!()
                }
            })
            .collect();
        debug!(
            "record {} ed add precompile events {:?}",
            input.chunk_index(),
            events.len()
        );

        let mut blu_events = Vec::new();
        let mut rows: Vec<[F; NUM_ED_ADD_COLS]> = events
            .iter()
            .map(|event| {
                let mut row = [F::ZERO; NUM_ED_ADD_COLS];
                let cols: &mut EdAddAssignCols<F> = row.as_mut_slice().borrow_mut();
                Self::event_to_row(event, cols, &mut blu_events);
                row
            })
            .collect();
        output.add_byte_lookup_events(blu_events);

        let log_rows = input.shape_chip_size(&self.name());
        pad_rows_fixed(
            &mut rows,
            || {
                let mut row = [F::ZERO; NUM_ED_ADD_COLS];
                let cols: &mut EdAddAssignCols<F> = row.as_mut_slice().borrow_mut();
                // All four coordinates are zero, because the memory columns of a padding row
                // are, and `eval` reads the operands out of those columns. The polynomial
                // identity each field gadget asserts is **not** gated by `is_real`
                // (`eval_field_operation` calls `assert_zero` directly), so a witness written
                // for operands the memory columns do not hold fails on every padding row. Same
                // rule, and the same fix, as the note in `weierstrass_add.rs` -- there the
                // operands have to be distinct to keep a slope denominator non-zero, so that
                // chip writes them into the memory columns; here `(0, 0) + (0, 0)` divides by
                // `1 + d*0`, so leaving everything zero is both consistent and valid.
                let zero = BigUint::zero();
                Self::populate_field_ops(
                    &mut vec![],
                    cols,
                    zero.clone(),
                    zero.clone(),
                    zero.clone(),
                    zero,
                );
                row
            },
            log_rows,
        );

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_ED_ADD_COLS,
        )
    }

    fn extra_record(&self, input: &Self::Record, output: &mut Self::Record) {
        let events: Vec<_> = input
            .get_precompile_events(SyscallCode::ED_ADD)
            .iter()
            .filter_map(|(_, event)| {
                if let PrecompileEvent::EdAdd(event) = event {
                    Some(event)
                } else {
                    unreachable!()
                }
            })
            .collect();

        let mut blu_events = Vec::new();
        for event in events {
            let mut row = [F::ZERO; NUM_ED_ADD_COLS];
            let cols: &mut EdAddAssignCols<F> = row.as_mut_slice().borrow_mut();
            Self::event_to_row(event, cols, &mut blu_events);
        }

        output.add_byte_lookup_events(blu_events);
    }

    fn is_active(&self, record: &Self::Record) -> bool {
        if let Some(shape) = record.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            !record.get_precompile_events(SyscallCode::ED_ADD).is_empty()
        }
    }

    fn local_only(&self) -> bool {
        true
    }
}

#[cfg(feature = "cuda")]
impl<F: PrimeField32, E: EllipticCurve + EdwardsParameters> GpuChipBehavior<F>
    for EdAddAssignChip<F, E>
{
    /// The GPU prover generates this trace on the host.
    ///
    /// `cuda_edwards_add_ed25519_generate_extra_record_and_main` is stale: its kernel writes the
    /// columns this chip had before its RV64 port (32-bit memory words, no address gadgets, no
    /// `x3_range`/`y3_range`), so it cannot fill these and is not called. `generate_main` pushes
    /// exactly the byte lookups `extra_record` would, so its output record is the one source of
    /// them; they are added to the device byte table here because no kernel puts them there.
    fn gpu_generate_extra_record_and_main(
        &self,
        _device_id: usize,
        input: &Self::Record,
        _prepared_gpu_events: &PreparedGpuEvents,
        preallocated_gpu_memory: &mut PreallocatedGpuMemory,
    ) -> TraceData<'_, F> {
        let mut output = EmulationRecord::default();
        let trace = self.generate_main(input, &mut output);
        gpu_add_host_byte_lookups(
            std::mem::take(&mut output.byte_lookups),
            preallocated_gpu_memory,
        )
        .expect("edwards add: adding the byte lookups to the device table failed");
        TraceData::Cpu(trace)
    }

    fn is_active_for_extra_record(&self, record: &PreparedGpuEvents) -> bool {
        if let Some(shape) = record.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            record
                .event_counter
                .get_precompile_event_num(SyscallCode::ED_ADD)
                > 0
        }
    }
}

impl<F: PrimeField32, E: EllipticCurve + EdwardsParameters> EdAddAssignChip<F, E> {
    /// Create a row from an event.
    fn event_to_row(
        event: &EllipticCurveAddEvent,
        cols: &mut EdAddAssignCols<F>,
        blu: &mut impl ByteRecordBehavior,
    ) {
        // Decode affine points straight from the dwords the guest wrote.
        let p = AffinePoint::<E>::from_dwords_le(&event.p);
        let (p_x, p_y) = (p.x, p.y);
        let q = AffinePoint::<E>::from_dwords_le(&event.q);
        let (q_x, q_y) = (q.x, q.y);

        // Populate basic columns.
        cols.is_real = F::ONE;
        cols.chunk = F::from_u32(event.chunk);
        cols.clk = F::from_u32(checked_u64_to_u32(event.clk, "edwards add clk"));
        let len = NUM_LIMBS as u64 * 2;
        cols.p_ptr.populate(blu, event.p_ptr, len);
        cols.q_ptr.populate(blu, event.q_ptr, len);

        Self::populate_field_ops(blu, cols, p_x, p_y, q_x, q_y);

        // Populate the memory access columns.
        for i in 0..WORDS_CURVE_POINT {
            cols.q_access[i]
                .inner
                .populate(event.q_memory_records[i], blu);
            cols.q_access[i]
                .prev_value_u8
                .populate_u16_to_u8_safe(blu, event.q_memory_records[i].value);
            cols.q_addrs[i].populate(blu, event.q_ptr, 8 * i as u64);
        }
        for i in 0..WORDS_CURVE_POINT {
            cols.p_access[i]
                .inner
                .populate(event.p_memory_records[i], blu);
            cols.p_access[i]
                .prev_value_u8
                .populate_u16_to_u8_safe(blu, event.p_memory_records[i].prev_value);
            cols.p_addrs[i].populate(blu, event.p_ptr, 8 * i as u64);
        }
    }
}

impl<F: Sync, E: EllipticCurve + EdwardsParameters> BaseAir<F> for EdAddAssignChip<F, E> {
    fn width(&self) -> usize {
        NUM_ED_ADD_COLS
    }
}

impl<F, CB, E> Air<CB> for EdAddAssignChip<F, E>
where
    F: Field,
    CB: ChipBuilder<F>,
    E: EllipticCurve + EdwardsParameters,
{
    fn eval(&self, builder: &mut CB) {
        let main = builder.main();
        let local = main.current_slice();
        let local: &EdAddAssignCols<CB::Var> = (*local).borrow();

        // Extract byte limbs from the u16 word limbs. `p` is the accumulator, so its *previous*
        // value is the addition's input; `q` is read-only, so its current value is.
        let to_limbs = |v: Vec<CB::Expr>, what: &str| -> EdLimbs<CB::Expr> {
            Limbs(
                Array::try_from_iter(v)
                    .unwrap_or_else(|_| panic!("failed to convert {what} limbs")),
            )
        };
        let x1 = to_limbs(
            generate_limbs_from_write_cols_u8(
                builder,
                &local.p_access[..WORDS_FIELD_ELEMENT],
                local.is_real.into(),
            ),
            "p_x",
        );
        let y1 = to_limbs(
            generate_limbs_from_write_cols_u8(
                builder,
                &local.p_access[WORDS_FIELD_ELEMENT..],
                local.is_real.into(),
            ),
            "p_y",
        );
        let x2 = to_limbs(
            generate_limbs_from_read_cols_u8(
                builder,
                &local.q_access[..WORDS_FIELD_ELEMENT],
                local.is_real.into(),
            ),
            "q_x",
        );
        let y2 = to_limbs(
            generate_limbs_from_read_cols_u8(
                builder,
                &local.q_access[WORDS_FIELD_ELEMENT..],
                local.is_real.into(),
            ),
            "q_y",
        );

        // x3_numerator = x1 * y2 + x2 * y1.
        local.x3_numerator.eval(
            builder,
            &[x1.clone(), x2.clone()],
            &[y2.clone(), y1.clone()],
            local.is_real,
        );

        // y3_numerator = y1 * y2 + x1 * x2.
        local.y3_numerator.eval(
            builder,
            &[y1.clone(), x1.clone()],
            &[y2.clone(), x2.clone()],
            local.is_real,
        );

        // f = x1 * x2 * y1 * y2.
        local
            .x1_mul_y1
            .eval(builder, &x1, &y1, FieldOperation::Mul, local.is_real);
        local
            .x2_mul_y2
            .eval(builder, &x2, &y2, FieldOperation::Mul, local.is_real);

        let x1_mul_y1 = local.x1_mul_y1.result;
        let x2_mul_y2 = local.x2_mul_y2.result;
        local.f.eval(
            builder,
            &x1_mul_y1,
            &x2_mul_y2,
            FieldOperation::Mul,
            local.is_real,
        );

        // d * f.
        let f = local.f.result;
        let d_biguint = E::d_biguint();
        let d_const = Ed25519BaseField::to_limbs_field::<CB::Expr, CB::F>(&d_biguint);
        local
            .d_mul_f
            .eval(builder, &f, &d_const, FieldOperation::Mul, local.is_real);

        let d_mul_f = local.d_mul_f.result;

        // x3 = x3_numerator / (1 + d * f).
        local.x3_ins.eval(
            builder,
            &local.x3_numerator.result,
            &d_mul_f,
            true,
            local.is_real,
        );

        // y3 = y3_numerator / (1 - d * f).
        local.y3_ins.eval(
            builder,
            &local.y3_numerator.result,
            &d_mul_f,
            false,
            local.is_real,
        );

        // Both results go back into guest memory, so both have to be the canonical representative
        // of their field element: `x3` and `x3 + p` satisfy the same division identity.
        let modulus =
            Ed25519BaseField::to_limbs_field::<CB::Expr, CB::F>(&Ed25519BaseField::modulus());
        local
            .x3_range
            .eval(builder, &local.x3_ins.result, &modulus, local.is_real);
        local
            .y3_range
            .eval(builder, &local.y3_ins.result, &modulus, local.is_real);

        // Reconstruct byte-level results into Words for the memory write constraints.
        let as_words = |limbs: &Limbs<CB::Var, _>| {
            limbs_to_words(
                &limbs
                    .0
                    .iter()
                    .map(|v| (*v).into())
                    .collect::<Vec<CB::Expr>>(),
                CB::F::from_u32(256).into(),
            )
        };
        let result_words: Vec<_> = as_words(&local.x3_ins.result)
            .into_iter()
            .chain(as_words(&local.y3_ins.result))
            .collect();

        // Address alignment constraints.
        let p_ptr = SyscallAddrGadget::<CB::F>::eval(
            builder,
            NUM_LIMBS as u32 * 2,
            local.p_ptr,
            local.is_real.into(),
        );
        let q_ptr = SyscallAddrGadget::<CB::F>::eval(
            builder,
            NUM_LIMBS as u32 * 2,
            local.q_ptr,
            local.is_real.into(),
        );

        for i in 0..local.p_addrs.len() {
            AddrAddGadget::<CB::F>::eval(
                builder,
                Word([
                    p_ptr[0].into(),
                    p_ptr[1].into(),
                    p_ptr[2].into(),
                    CB::Expr::ZERO,
                ]),
                Word::from(8 * i as u64),
                local.p_addrs[i],
                local.is_real.into(),
            );
        }
        for i in 0..local.q_addrs.len() {
            AddrAddGadget::<CB::F>::eval(
                builder,
                Word([
                    q_ptr[0].into(),
                    q_ptr[1].into(),
                    q_ptr[2].into(),
                    CB::Expr::ZERO,
                ]),
                Word::from(8 * i as u64),
                local.q_addrs[i],
                local.is_real.into(),
            );
        }

        // Memory access constraints. Read q first, then write p at clk + 1: p and q may be the
        // same pointer (doubling is `add(p, p)`), so the write has to be ordered after the read.
        for (i, q_col) in local.q_access.iter().enumerate() {
            builder.eval_memory_access(
                local.chunk,
                local.clk.into(),
                local.q_addrs[i].value.map(Into::into),
                &q_col.inner,
                local.is_real,
            );
        }
        for (i, (p_col, write_value)) in local.p_access.iter().zip(result_words.iter()).enumerate()
        {
            builder.eval_memory_access(
                local.chunk,
                local.clk + CB::F::from_u32(1),
                local.p_addrs[i].value.map(Into::into),
                &p_col.inner,
                local.is_real,
            );
            let do_check: CB::Expr = local.is_real.into();
            for (v, w) in p_col.inner.value().0.iter().zip(write_value.0.iter()) {
                builder
                    .when(do_check.clone())
                    .assert_eq((*v).into(), w.clone());
            }
        }

        builder.looked_syscall(
            local.chunk,
            local.clk,
            CB::F::from_u32(SyscallCode::ED_ADD.syscall_id()),
            p_ptr.map(Into::into),
            q_ptr.map(Into::into),
            local.is_real,
        );
    }
}
