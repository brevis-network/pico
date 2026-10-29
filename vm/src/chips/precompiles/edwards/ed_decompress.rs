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
            curves::edwards::{
                ed25519::{ed25519_sqrt, Ed25519BaseField},
                EdwardsParameters, WordsFieldElement, NUM_LIMBS, WORDS_FIELD_ELEMENT,
            },
            field::{
                field_lt::FieldLtCols,
                field_op::{FieldOpCols, FieldOperation},
                field_sqrt::FieldSqrtCols,
            },
            is_zero::IsZeroGadget,
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
                precompiles::{edwards::event::EdDecompressEvent, PrecompileEvent},
                SyscallCode,
            },
        },
    },
    machine::{
        builder::{ChipBaseBuilder, ChipBuilder, ChipLookupBuilder, RiscVMemoryBuilder},
        chip::ChipBehavior,
    },
};
use core::{
    borrow::{Borrow, BorrowMut},
    mem::size_of,
};
use hybrid_array::Array;
use num::{BigUint, One, Zero};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;
use pico_derive::AlignedBorrow;
use std::marker::PhantomData;
use tracing::debug;

pub const NUM_ED_DECOMPRESS_COLS: usize = size_of::<EdDecompressCols<u8>>();

/// The 32 u8 limbs an Ed25519 base-field element decomposes into.
type EdLimbs<T> = Limbs<T, <Ed25519BaseField as NumLimbs>::Limbs>;

/// A set of columns to compute `EdDecompress`, given a pointer to a 64-byte slice: the second
/// half holds the 255-bit compressed Y (the sign bit having been stripped by the caller and
/// passed in `arg2`), and the first half is overwritten with the decompressed X.
#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct EdDecompressCols<T> {
    pub is_real: T,
    pub chunk: T,
    pub clk: T,
    pub ptr: SyscallAddrGadget<T>,
    pub x_addrs: Array<AddrAddGadget<T>, WordsFieldElement>,
    pub y_addrs: Array<AddrAddGadget<T>, WordsFieldElement>,
    pub sign: T,
    pub x_access: Array<MemoryWriteColsU8<T>, WordsFieldElement>,
    pub y_access: Array<MemoryReadColsU8<T>, WordsFieldElement>,
    /// `y < p`. The guest contract is that a non-canonical `y` is *not* decompressable: the
    /// `FD_EDDECOMPRESS` hook rejects `y >= p` so the guest never reaches the syscall with one.
    pub(crate) y_range: FieldLtCols<T, Ed25519BaseField>,
    pub(crate) yy: FieldOpCols<T, Ed25519BaseField>,
    pub(crate) u: FieldOpCols<T, Ed25519BaseField>,
    pub(crate) dyy: FieldOpCols<T, Ed25519BaseField>,
    pub(crate) v: FieldOpCols<T, Ed25519BaseField>,
    pub(crate) u_div_v: FieldOpCols<T, Ed25519BaseField>,
    pub(crate) x: FieldSqrtCols<T, Ed25519BaseField>,
    pub(crate) neg_x: FieldOpCols<T, Ed25519BaseField>,
    /// `neg_x < p`. `neg_x` is pinned only by `neg_x + x == 0 (mod p)`, which `p - x` and
    /// `2p - x` satisfy alike, and one of the two is written back to guest memory. Without this
    /// the prover chooses which. Matches `neg_y_range_check` in `weierstrass_decompress.rs`.
    pub(crate) neg_x_range: FieldLtCols<T, Ed25519BaseField>,
    /// Gadget to check if x is zero. This is used to ensure that when x is zero, sign must be 0.
    pub(crate) x_is_zero: IsZeroGadget<T>,
}

impl<F: PrimeField32> EdDecompressCols<F> {
    pub fn populate<E: EdwardsParameters>(
        &mut self,
        event: &EdDecompressEvent,
        blu: &mut impl ByteRecordBehavior,
    ) {
        self.is_real = F::from_bool(true);
        self.chunk = F::from_u32(event.chunk);
        self.clk = F::from_u32(checked_u64_to_u32(event.clk, "edwards decompress clk"));
        self.sign = F::from_bool(event.sign);
        self.ptr.populate(blu, event.ptr, NUM_LIMBS as u64 * 2);

        for i in 0..WORDS_FIELD_ELEMENT {
            self.x_access[i]
                .inner
                .populate(event.x_memory_records[i], blu);
            self.x_access[i]
                .prev_value_u8
                .populate_u16_to_u8_safe(blu, event.x_memory_records[i].prev_value);
            self.x_addrs[i].populate(blu, event.ptr, 8 * i as u64);

            self.y_access[i]
                .inner
                .populate(event.y_memory_records[i], blu);
            self.y_access[i]
                .prev_value_u8
                .populate_u16_to_u8_safe(blu, event.y_memory_records[i].value);
            self.y_addrs[i].populate(blu, event.ptr + NUM_LIMBS as u64, 8 * i as u64);
        }

        let y = BigUint::from_bytes_le(
            &event
                .y_words
                .iter()
                .flat_map(|word| word.to_le_bytes())
                .collect::<Vec<u8>>(),
        );
        self.populate_field_ops::<E>(blu, &y);
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
        let neg_x = self
            .neg_x
            .populate(blu_events, &BigUint::zero(), &x, FieldOperation::Sub);
        self.neg_x_range
            .populate(blu_events, &neg_x, &Ed25519BaseField::modulus());

        // Check if x is zero by checking if all limbs sum to zero.
        // Since all limbs are non-negative (range checked), if their sum is zero, all limbs are zero.
        // self.x.multiplication.result already contains the sqrt as field elements after populate.
        let x_limbs_sum = self
            .x
            .multiplication
            .result
            .0
            .iter()
            .fold(F::ZERO, |acc, limb| acc + *limb);
        self.x_is_zero.populate_from_field_element(x_limbs_sum);
    }
}

impl<V: Copy> EdDecompressCols<V> {
    pub fn eval<F: Field, CB: ChipBuilder<F, Var = V>, E: EdwardsParameters>(
        &self,
        builder: &mut CB,
    ) where
        V: Into<CB::Expr>,
    {
        builder.assert_bool(self.sign);

        // Extract byte limbs from the u16 word limbs.
        let y_limbs =
            generate_limbs_from_read_cols_u8(builder, &self.y_access[..], self.is_real.into());
        let y: EdLimbs<CB::Expr> =
            Limbs(Array::try_from_iter(y_limbs).expect("failed to convert y limbs"));

        // `x_access.prev_value_u8` is populated by the trace, which emits u8 range checks; they
        // need a matching evaluation here or the byte table is over-received. The returned limbs
        // are unused — `x_access`'s value is constrained below against `x`/`neg_x`.
        let _ = generate_limbs_from_write_cols_u8(builder, &self.x_access[..], self.is_real.into());

        let modulus =
            Ed25519BaseField::to_limbs_field::<CB::Expr, CB::F>(&Ed25519BaseField::modulus());
        self.y_range.eval(builder, &y, &modulus, self.is_real);

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
        let d_const = Ed25519BaseField::to_limbs_field::<CB::Expr, CB::F>(&d_biguint);
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
        // Whichever of the two is written back has to be the canonical representative.
        self.neg_x_range
            .eval(builder, &self.neg_x.result, &modulus, self.is_real);

        // Address alignment constraints, over the whole 64-byte slice.
        let ptr = SyscallAddrGadget::<CB::F>::eval(
            builder,
            NUM_LIMBS as u32 * 2,
            self.ptr,
            self.is_real.into(),
        );
        let base = |ptr: &[CB::Var; 3]| {
            Word([ptr[0].into(), ptr[1].into(), ptr[2].into(), CB::Expr::ZERO])
        };
        // x_addrs[i] = ptr + 8*i
        for i in 0..self.x_addrs.len() {
            AddrAddGadget::<CB::F>::eval(
                builder,
                base(&ptr),
                Word::from(8 * i as u64),
                self.x_addrs[i],
                self.is_real.into(),
            );
        }
        // y_addrs[i] = ptr + NUM_LIMBS + 8*i
        for i in 0..self.y_addrs.len() {
            AddrAddGadget::<CB::F>::eval(
                builder,
                base(&ptr),
                Word::from(NUM_LIMBS as u64 + 8 * i as u64),
                self.y_addrs[i],
                self.is_real.into(),
            );
        }

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
        let x_words = as_words(&self.x.multiplication.result);
        let neg_x_words = as_words(&self.neg_x.result);

        // Memory access constraints.
        for (i, y_col) in self.y_access.iter().enumerate() {
            builder.eval_memory_access(
                self.chunk,
                self.clk.into(),
                self.y_addrs[i].value.map(Into::into),
                &y_col.inner,
                self.is_real,
            );
        }
        for (i, x_col) in self.x_access.iter().enumerate() {
            builder.eval_memory_access(
                self.chunk,
                self.clk.into(),
                self.x_addrs[i].value.map(Into::into),
                &x_col.inner,
                self.is_real,
            );

            // Constrain that the correct result is written into x.
            let do_check: CB::Expr = self.is_real.into();
            for (v, w) in x_col.inner.value().0.iter().zip(neg_x_words[i].0.iter()) {
                builder
                    .when(do_check.clone())
                    .when(self.sign)
                    .assert_eq((*v).into(), w.clone());
            }
            for (v, w) in x_col.inner.value().0.iter().zip(x_words[i].0.iter()) {
                builder
                    .when(do_check.clone())
                    .when_not(self.sign)
                    .assert_eq((*v).into(), w.clone());
            }
        }

        // Constraint: if x is zero, then sign must be 0.
        // This prevents the case where x = 0 and sign = 1, which would result in x = mod - 0 = mod.
        // This is equivalent to: if sign = 1, then x != 0.
        let x_sum: CB::Expr = self
            .x
            .multiplication
            .result
            .0
            .iter()
            .fold(CB::Expr::ZERO, |acc, limb| acc + (*limb).into());
        IsZeroGadget::<CB::F>::eval(builder, x_sum, self.x_is_zero, self.is_real.into());
        // If sign = 1, then x_is_zero.result must be 0 (i.e., x != 0)
        builder
            .when(self.x_is_zero.result) // x == 0
            .assert_zero(self.sign); // sign must be 0

        builder.looked_syscall(
            self.chunk,
            self.clk,
            CB::F::from_u32(SyscallCode::ED_DECOMPRESS.syscall_id()),
            ptr.map(Into::into),
            [self.sign.into(), CB::Expr::ZERO, CB::Expr::ZERO],
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

    fn events(input: &EmulationRecord) -> Vec<&EdDecompressEvent> {
        input
            .get_precompile_events(SyscallCode::ED_DECOMPRESS)
            .iter()
            .filter_map(|(_, event)| {
                if let PrecompileEvent::EdDecompress(event) = event {
                    Some(event)
                } else {
                    unreachable!()
                }
            })
            .collect()
    }
}

impl<F: PrimeField32, E: EdwardsParameters> ChipBehavior<F> for EdDecompressChip<F, E> {
    type Record = EmulationRecord;
    type Program = Program;

    fn name(&self) -> String {
        "EdDecompress".to_string()
    }

    fn extra_record(&self, input: &Self::Record, extra: &mut Self::Record) {
        let mut blu_events = Vec::new();
        for event in Self::events(input) {
            let mut row = [F::ZERO; NUM_ED_DECOMPRESS_COLS];
            let cols: &mut EdDecompressCols<F> = row.as_mut_slice().borrow_mut();
            cols.populate::<E>(event, &mut blu_events);
        }
        extra.add_byte_lookup_events(blu_events);
    }

    fn generate_main(
        &self,
        input: &EmulationRecord,
        output: &mut EmulationRecord,
    ) -> RowMajorMatrix<F> {
        let events = Self::events(input);

        debug!(
            "record {} ed decompress precompile events {:?}",
            input.chunk_index(),
            events.len()
        );

        let mut blu_events = Vec::new();
        let mut rows = Vec::new();
        for event in events {
            let mut row = [F::ZERO; NUM_ED_DECOMPRESS_COLS];
            let cols: &mut EdDecompressCols<F> = row.as_mut_slice().borrow_mut();
            cols.populate::<E>(event, &mut blu_events);
            rows.push(row);
        }
        output.add_byte_lookup_events(blu_events);

        let log_rows = input.shape_chip_size(&self.name());
        pad_rows_fixed(
            &mut rows,
            || {
                let mut row = [F::ZERO; NUM_ED_DECOMPRESS_COLS];
                let cols: &mut EdDecompressCols<F> = row.as_mut_slice().borrow_mut();
                // `y = 0`, because the memory columns of a padding row are zero and `eval`
                // reads `y` out of them. The polynomial identity each field gadget asserts is
                // **not** gated by `is_real` (`eval_field_operation` calls `assert_zero`
                // directly), so a witness written for a `y` the memory columns do not hold
                // fails on every padding row -- see the same note in `weierstrass_add.rs`.
                // `y = 0` stays inside the gadgets' domain: `u/v` is then `-1`, which is a
                // square mod `2^255 - 19`, so `ed25519_sqrt` returns rather than failing.
                cols.populate_field_ops::<E>(&mut vec![], &BigUint::zero());
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

#[cfg(feature = "cuda")]
impl<F: PrimeField32, E: EdwardsParameters> GpuChipBehavior<F> for EdDecompressChip<F, E> {
    /// The GPU prover generates this trace on the host.
    ///
    /// `cuda_edwards_decompress_generate_extra_record_and_main` is stale: its kernel writes the
    /// columns this chip had before its RV64 port (32-bit memory words, no address gadgets, no
    /// `neg_x_range`), so it cannot fill these and is not called. `generate_main` pushes exactly
    /// the byte lookups `extra_record` would, so its output record is the one source of them;
    /// they are added to the device byte table here because no kernel puts them there.
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
        .expect("edwards decompress: adding the byte lookups to the device table failed");
        TraceData::Cpu(trace)
    }

    fn is_active_for_extra_record(&self, record: &PreparedGpuEvents) -> bool {
        if let Some(shape) = record.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            record
                .event_counter
                .get_precompile_event_num(SyscallCode::ED_DECOMPRESS)
                > 0
        }
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
        let local = main.current_slice();
        let local: &EdDecompressCols<CB::Var> = (*local).borrow();

        local.eval::<F, CB, E>(builder);
    }
}
