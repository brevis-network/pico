//! `BLS12381_G2_ADD`: `p ← p + q` for affine G2 points with `p.x ≠ q.x`.

use super::{
    cols::{ResultCols, SlopeCols, P},
    coords, point_from_dwords, G2_POINT_BYTES as POINT_BYTES,
};
use crate::{
    chips::{
        chips::{
            byte::event::ByteRecordBehavior,
            riscv_memory::read_write::columns::{MemoryCols, MemoryReadColsU8, MemoryWriteColsU8},
        },
        gadgets::{
            addr_add::AddrAddGadget,
            code_range::CodeRangeCols,
            field::{
                field_lt::FieldLtCols,
                field_op::{FieldOpCols, FieldOperation},
            },
            syscall_addr::SyscallAddrGadget,
            utils::{
                conversions::{
                    generate_limbs_from_read_cols_u8, generate_limbs_from_write_cols_u8,
                    limbs_to_words,
                },
                field_params::FieldParameters,
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
        builder::{ChipBuilder, ChipLookupBuilder, RiscVMemoryBuilder},
        chip::ChipBehavior,
    },
};
use core::{
    borrow::{Borrow, BorrowMut},
    mem::size_of,
};
use hybrid_array::{typenum::U24, Array};
use num::BigUint;
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;
use pico_derive::AlignedBorrow;
use std::marker::PhantomData;

pub const NUM_G2_ADD_COLS: usize = size_of::<G2AddCols<u8>>();

#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct G2AddCols<T> {
    pub is_real: T,
    pub chunk: T,
    pub clk: T,
    pub p_ptr: SyscallAddrGadget<T>,
    pub q_ptr: SyscallAddrGadget<T>,
    pub p_addrs: Array<AddrAddGadget<T>, U24>,
    pub q_addrs: Array<AddrAddGadget<T>, U24>,
    pub p_access: Array<MemoryWriteColsU8<T>, U24>,
    pub q_access: Array<MemoryReadColsU8<T>, U24>,
    /// Each input coordinate is below the modulus, as the emulator requires.
    pub p_range: [FieldLtCols<T, P>; 4],
    pub q_range: [FieldLtCols<T, P>; 4],
    /// `q.x - p.x` and `q.y - p.y`, per component.
    pub d0: FieldOpCols<T, P>,
    pub d1: FieldOpCols<T, P>,
    pub n0: FieldOpCols<T, P>,
    pub n1: FieldOpCols<T, P>,
    pub slope: SlopeCols<T>,
    pub result: ResultCols<T>,

    /// The result is written back over `p`, which may not lie on the program's code.
    pub code_range: CodeRangeCols<T>,
}

#[derive(Default)]
pub struct Bls12381G2AddChip<F> {
    _marker: PhantomData<fn(F) -> F>,
}

impl<F: PrimeField32> Bls12381G2AddChip<F> {
    pub const fn new() -> Self {
        Self {
            _marker: PhantomData,
        }
    }

    /// Populates the field columns for `p + q`; all zeros on padding.
    pub(crate) fn populate_field_ops(
        record: &mut impl ByteRecordBehavior,
        cols: &mut G2AddCols<F>,
        p: &[BigUint; 4],
        q: &[BigUint; 4],
        is_real: bool,
    ) -> [BigUint; 4] {
        use FieldOperation::Sub;
        let modulus = P::modulus();
        for i in 0..4 {
            cols.p_range[i].populate(record, &p[i], &modulus);
            cols.q_range[i].populate(record, &q[i], &modulus);
        }
        let d = [
            cols.d0.populate(record, &q[0], &p[0], Sub),
            cols.d1.populate(record, &q[1], &p[1], Sub),
        ];
        let n = [
            cols.n0.populate(record, &q[2], &p[2], Sub),
            cols.n1.populate(record, &q[3], &p[3], Sub),
        ];
        let lambda = cols.slope.populate(record, &n, &d, is_real);
        cols.result.populate(
            record,
            &lambda,
            &[p[0].clone(), p[1].clone()],
            &[p[2].clone(), p[3].clone()],
            &[q[0].clone(), q[1].clone()],
        )
    }
}

impl<F: PrimeField32> ChipBehavior<F> for Bls12381G2AddChip<F> {
    type Record = EmulationRecord;
    type Program = Program;

    fn name(&self) -> String {
        "Bls12381G2AddAssign".to_string()
    }

    fn generate_main(
        &self,
        input: &EmulationRecord,
        output: &mut EmulationRecord,
    ) -> RowMajorMatrix<F> {
        let events = input.get_precompile_events(SyscallCode::BLS12381_G2_ADD);
        let code = input.program.code();
        let mut rows = Vec::with_capacity(events.len());
        let mut blu = Vec::new();

        for (_, precompile_event) in events.iter() {
            let PrecompileEvent::Bls12381G2Add(event) = precompile_event else {
                unreachable!()
            };
            let mut row = vec![F::ZERO; NUM_G2_ADD_COLS];
            let cols: &mut G2AddCols<F> = row.as_mut_slice().borrow_mut();

            cols.is_real = F::ONE;
            cols.chunk = F::from_u32(event.chunk);
            cols.clk = F::from_u32(checked_u64_to_u32(event.clk, "G2 add clk"));
            let len = u64::from(POINT_BYTES);
            cols.p_ptr.populate(&mut blu, event.p_ptr, len);
            cols.code_range.populate(event.p_ptr, len, &code, &mut blu);
            cols.q_ptr.populate(&mut blu, event.q_ptr, len);

            let p = point_from_dwords(&event.p);
            let q = point_from_dwords(&event.q);
            Self::populate_field_ops(&mut blu, cols, &p, &q, true);

            for i in 0..cols.q_access.len() {
                cols.q_access[i]
                    .inner
                    .populate(event.q_memory_records[i], &mut blu);
                cols.q_access[i]
                    .prev_value_u8
                    .populate_u16_to_u8_safe(&mut blu, event.q_memory_records[i].value);
                cols.q_addrs[i].populate(&mut blu, event.q_ptr, 8 * i as u64);
            }
            for i in 0..cols.p_access.len() {
                cols.p_access[i]
                    .inner
                    .populate(event.p_memory_records[i], &mut blu);
                cols.p_access[i]
                    .prev_value_u8
                    .populate_u16_to_u8_safe(&mut blu, event.p_memory_records[i].prev_value);
                cols.p_addrs[i].populate(&mut blu, event.p_ptr, 8 * i as u64);
            }
            rows.push(row);
        }
        blu.iter().for_each(|x| output.add_byte_lookup_event(*x));

        let log_rows = input.shape_chip_size(&self.name());
        pad_rows_fixed(
            &mut rows,
            || {
                let mut row = vec![F::ZERO; NUM_G2_ADD_COLS];
                let cols: &mut G2AddCols<F> = row.as_mut_slice().borrow_mut();
                let zero: [BigUint; 4] = Default::default();
                Self::populate_field_ops(&mut vec![], cols, &zero, &zero, false);
                row
            },
            log_rows,
        );

        RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_G2_ADD_COLS,
        )
    }

    fn extra_record(&self, input: &Self::Record, extra: &mut Self::Record) {
        self.generate_main(input, extra);
    }

    fn is_active(&self, chunk: &Self::Record) -> bool {
        if let Some(shape) = chunk.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            !chunk
                .get_precompile_events(SyscallCode::BLS12381_G2_ADD)
                .is_empty()
        }
    }

    fn local_only(&self) -> bool {
        true
    }
}

impl<F> BaseAir<F> for Bls12381G2AddChip<F> {
    fn width(&self) -> usize {
        NUM_G2_ADD_COLS
    }
}

impl<F, CB> Air<CB> for Bls12381G2AddChip<F>
where
    F: Field,
    CB: ChipBuilder<F>,
{
    fn eval(&self, builder: &mut CB) {
        let main = builder.main();
        let local = main.current_slice();
        let local: &G2AddCols<CB::Var> = (*local).borrow();
        let is_real: CB::Expr = local.is_real.into();
        builder.assert_bool(local.is_real);

        let p = coords(generate_limbs_from_write_cols_u8(
            builder,
            &local.p_access,
            is_real.clone(),
        ));
        let q = coords(generate_limbs_from_read_cols_u8(
            builder,
            &local.q_access,
            is_real.clone(),
        ));

        let modulus = P::to_limbs_field::<CB::Expr, CB::F>(&P::modulus());
        for i in 0..4 {
            local.p_range[i].eval(builder, &p[i], &modulus, is_real.clone());
            local.q_range[i].eval(builder, &q[i], &modulus, is_real.clone());
        }

        use FieldOperation::Sub;
        local.d0.eval(builder, &q[0], &p[0], Sub, is_real.clone());
        local.d1.eval(builder, &q[1], &p[1], Sub, is_real.clone());
        local.n0.eval(builder, &q[2], &p[2], Sub, is_real.clone());
        local.n1.eval(builder, &q[3], &p[3], Sub, is_real.clone());
        let d = [local.d0.result.into(), local.d1.result.into()];
        let n = [local.n0.result.into(), local.n1.result.into()];
        let lambda = local.slope.eval(builder, &n, &d, is_real.clone());
        let result = local.result.eval(
            builder,
            &lambda,
            &[p[0].clone(), p[1].clone()],
            &[p[2].clone(), p[3].clone()],
            &[q[0].clone(), q[1].clone()],
            is_real.clone(),
        );

        let result_limbs: Vec<CB::Expr> = result
            .iter()
            .flat_map(|c| c.0.iter().map(|v| (*v).into()))
            .collect();
        let result_words = limbs_to_words(&result_limbs, CB::F::from_u32(256).into());

        let p_ptr =
            SyscallAddrGadget::<CB::F>::eval(builder, POINT_BYTES, local.p_ptr, is_real.clone());
        CodeRangeCols::<CB::F>::eval(
            builder,
            &local.code_range,
            [p_ptr[0].into(), p_ptr[1].into()],
            CB::Expr::from_u32(POINT_BYTES),
            is_real.clone(),
        );
        let q_ptr =
            SyscallAddrGadget::<CB::F>::eval(builder, POINT_BYTES, local.q_ptr, is_real.clone());

        for (i, addr) in local.p_addrs.iter().enumerate() {
            AddrAddGadget::<CB::F>::eval(
                builder,
                Word([
                    p_ptr[0].into(),
                    p_ptr[1].into(),
                    p_ptr[2].into(),
                    CB::Expr::ZERO,
                ]),
                Word::from(8 * i as u64),
                *addr,
                is_real.clone(),
            );
        }
        for (i, addr) in local.q_addrs.iter().enumerate() {
            AddrAddGadget::<CB::F>::eval(
                builder,
                Word([
                    q_ptr[0].into(),
                    q_ptr[1].into(),
                    q_ptr[2].into(),
                    CB::Expr::ZERO,
                ]),
                Word::from(8 * i as u64),
                *addr,
                is_real.clone(),
            );
        }

        for (i, q_col) in local.q_access.iter().enumerate() {
            builder.eval_memory_access(
                local.chunk,
                local.clk.into(),
                local.q_addrs[i].value.map(Into::into),
                &q_col.inner,
                local.is_real,
            );
        }
        // `p` is written at clk + 1, as `p` and `q` may be the same.
        for (i, (p_col, write_value)) in local.p_access.iter().zip(result_words.iter()).enumerate()
        {
            builder.eval_memory_access(
                local.chunk,
                local.clk + CB::F::from_u32(1),
                local.p_addrs[i].value.map(Into::into),
                &p_col.inner,
                local.is_real,
            );
            for (v, w) in p_col.inner.value().0.iter().zip(write_value.0.iter()) {
                builder
                    .when(local.is_real)
                    .assert_eq((*v).into(), w.clone());
            }
        }

        builder.looked_syscall(
            local.chunk,
            local.clk,
            CB::F::from_u32(SyscallCode::BLS12381_G2_ADD.syscall_id()),
            p_ptr.map(Into::into),
            q_ptr.map(Into::into),
            local.is_real,
        );
    }
}

#[cfg(feature = "cuda")]
impl<F: PrimeField32> crate::machine::chip::GpuChipBehavior<F> for Bls12381G2AddChip<F> {
    /// The GPU prover generates this trace on the host, and adds its byte lookups to the device
    /// table, as for the Ed25519 chips.
    fn gpu_generate_extra_record_and_main(
        &self,
        _device_id: usize,
        input: &Self::Record,
        _prepared_gpu_events: &crate::instances::preparer::PreparedGpuEvents,
        preallocated_gpu_memory: &mut crate::instances::preparer::PreallocatedGpuMemory,
    ) -> crate::chips::trace::TraceData<'_, F> {
        let mut output = EmulationRecord::default();
        let trace = self.generate_main(input, &mut output);
        crate::instances::preparer::gpu_add_host_byte_lookups(
            std::mem::take(&mut output.byte_lookups),
            preallocated_gpu_memory,
        )
        .expect("G2 add: adding the byte lookups to the device table failed");
        crate::chips::trace::TraceData::Cpu(trace)
    }

    fn is_active_for_extra_record(
        &self,
        record: &crate::instances::preparer::PreparedGpuEvents,
    ) -> bool {
        if let Some(shape) = record.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            record
                .event_counter
                .get_precompile_event_num(SyscallCode::BLS12381_G2_ADD)
                > 0
        }
    }
}
