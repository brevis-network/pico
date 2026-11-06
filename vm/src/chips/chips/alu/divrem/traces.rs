use super::{columns::NUM_DIVREM_COLS, DivRemChip};
#[cfg(feature = "cuda")]
use crate::{
    chips::{
        chips::alu::add::traces::{chunk_history, chunk_history_reader},
        trace::TraceData,
    },
    cuda_adaptor::resource_pool::{
        mem_pool::get_global_mem_pool, stream_pool::get_global_stream_pool,
    },
    emulator::riscv::{history_fill::HISTORY_LAYOUT, history_view::HistoryView},
    instances::preparer::{PreallocatedGpuMemory, PreparedGpuEvents},
    machine::chip::GpuChipBehavior,
    mle::{machine::trace_oracle::history_launch, spans::device},
};
use crate::{
    chips::{
        chips::{
            alu::{
                divrem::{
                    columns::{DivRemValueCols, NUM_DIVREM_VALUE_COLS},
                    utils::{
                        derived_add_rows, get_msb, get_quotient_and_remainder,
                        is_signed_64bit_operation, is_signed_word_operation,
                        is_unsigned_64bit_operation, is_unsigned_word_operation, is_word_operation,
                        DivremExtraEventIndices,
                    },
                },
                event::AluEvent,
            },
            byte::event::{ByteLookupEvent, ByteRecordBehavior},
        },
        utils::next_power_of_two,
    },
    compiler::{
        riscv::{opcode::Opcode, program::Program},
        word::Word,
    },
    emulator::riscv::record::{AluStream, EmulationRecord},
    iter::{PicoIterator, PicoSlice},
    machine::{
        chip::ChipBehavior,
        estimator::{EventCapture, EventSizeCapture},
    },
    primitives::consts::{DIVREM_DATAPAR, LONG_WORD_SIZE},
};
use core::borrow::BorrowMut;
#[cfg(feature = "cuda")]
use cudart::{
    event::{CudaEvent, CudaEventCreateFlags},
    memory_pools::DevicePoolAllocation,
    slice::{CudaSlice, CudaSliceMut},
    stream::{CudaStream, CudaStreamCreateFlags, CudaStreamWaitEventFlags},
};
#[cfg(feature = "cuda")]
use cudart_sys::*;
use hashbrown::HashMap;
use p3_air::BaseAir;
use p3_field::{Field, PrimeField32};
#[cfg(feature = "cuda")]
use p3_koala_bear::KoalaBear;
use p3_matrix::dense::RowMajorMatrix;
#[cfg(feature = "cuda")]
use pico_gpu_api::history_add_sub_divrem::cuda_divrem_generate_extra_record_and_main_history;
#[cfg(feature = "cuda")]
use std::ffi::c_void;
use std::num::Wrapping;
#[cfg(feature = "cuda")]
use tracing::info;

impl<F: Field> BaseAir<F> for DivRemChip<F> {
    fn width(&self) -> usize {
        NUM_DIVREM_COLS
    }
}

impl<F: PrimeField32> ChipBehavior<F> for DivRemChip<F> {
    type Record = EmulationRecord;
    type Program = Program;

    fn name(&self) -> String {
        "DivRem".to_string()
    }

    fn generate_main(
        &self,
        input: &EmulationRecord,
        output: &mut EmulationRecord,
    ) -> RowMajorMatrix<F> {
        let ops = input.alu_ops(AluStream::DivRem);
        let nrows = ops.len().div_ceil(DIVREM_DATAPAR);
        let log2_nrows = input.shape_chip_size(&self.name());
        let padded_nrows = match log2_nrows {
            Some(log2_nrows) => 1 << log2_nrows,
            None => next_power_of_two(nrows, None),
        };

        let mut values = vec![F::ZERO; padded_nrows * NUM_DIVREM_COLS];

        let populate_len = ops.len() * NUM_DIVREM_VALUE_COLS;
        values[..populate_len]
            .chunks_mut(NUM_DIVREM_VALUE_COLS)
            .enumerate()
            .for_each(|(index, row)| {
                let event = ops.get(index);
                let cols: &mut DivRemValueCols<_> = row.borrow_mut();

                // Get the correct computational values of `b`.
                let b = if is_signed_word_operation(event.opcode) {
                    event.b as i32 as i64 as u64
                } else if is_unsigned_word_operation(event.opcode) {
                    event.b as u32 as u64
                } else {
                    event.b
                };

                // Get the correct computational values of `c`.
                let c = if is_signed_word_operation(event.opcode) {
                    event.c as i32 as i64 as u64
                } else if is_unsigned_word_operation(event.opcode) {
                    event.c as u32 as u64
                } else {
                    event.c
                };

                // Initialize cols with basic operands and flags derived from the current event.
                {
                    cols.a = Word::from(event.a);
                    cols.b = Word::from(b);
                    cols.c = Word::from(c);
                    // Raw register values, as sent by the CPU on the ALU bus.
                    cols.b_raw = Word::from(event.b);
                    cols.c_raw = Word::from(event.c);

                    cols.is_real = F::ONE;

                    cols.is_divu = F::from_bool(event.opcode == Opcode::DIVU);
                    cols.is_remu = F::from_bool(event.opcode == Opcode::REMU);
                    cols.is_div = F::from_bool(event.opcode == Opcode::DIV);
                    cols.is_rem = F::from_bool(event.opcode == Opcode::REM);
                    cols.is_divw = F::from_bool(event.opcode == Opcode::DIVW);
                    cols.is_remw = F::from_bool(event.opcode == Opcode::REMW);
                    cols.is_divuw = F::from_bool(event.opcode == Opcode::DIVUW);
                    cols.is_remuw = F::from_bool(event.opcode == Opcode::REMUW);

                    let not_word_operation =
                        F::ONE - cols.is_divw - cols.is_remw - cols.is_divuw - cols.is_remuw;
                    cols.is_real_not_word = cols.is_real * not_word_operation;
                    cols.is_c_0.populate(c);
                }

                let (quotient, remainder) =
                    get_quotient_and_remainder(event.b, event.c, event.opcode);
                cols.quotient = Word::from(quotient);
                cols.remainder = Word::from(remainder);

                // Get the computational form of `quotient`.
                let quotient_comp = if is_unsigned_word_operation(event.opcode) {
                    quotient as u32 as u64
                } else {
                    quotient
                };
                cols.quotient_comp = Word::from(quotient_comp);

                let remainder_comp = if is_unsigned_word_operation(event.opcode) {
                    remainder as u32 as u64
                } else {
                    remainder
                };
                cols.remainder_comp = Word::from(remainder_comp);

                // Calculate flags for sign detection.
                {
                    if is_signed_64bit_operation(event.opcode) {
                        cols.rem_neg = F::from_u8(get_msb(remainder));
                        cols.b_neg = F::from_u8(get_msb(event.b));
                        cols.c_neg = F::from_u8(get_msb(event.c));
                        cols.is_overflow =
                            F::from_bool(event.b as i64 == i64::MIN && event.c as i64 == -1);
                        cols.abs_remainder = Word::from((remainder as i64).unsigned_abs());
                        cols.abs_c = Word::from((event.c as i64).unsigned_abs());
                        cols.max_abs_c_or_1 =
                            Word::from(u64::max(1, (event.c as i64).unsigned_abs()));
                    } else if is_signed_word_operation(event.opcode) {
                        cols.rem_neg = F::from_u8(get_msb((remainder as i32) as i64 as u64));
                        cols.b_neg = F::from_u8(get_msb((event.b as i32) as i64 as u64));
                        cols.c_neg = F::from_u8(get_msb((event.c as i32) as i64 as u64));
                        cols.is_overflow =
                            F::from_bool(event.b as i32 == i32::MIN && event.c as i32 == -1);
                        cols.abs_remainder = Word::from((remainder as i64).unsigned_abs());
                        cols.abs_c = Word::from((c as i64).unsigned_abs());
                        cols.max_abs_c_or_1 = Word::from(u64::max(1, (c as i64).unsigned_abs()));
                    } else if is_unsigned_word_operation(event.opcode) {
                        cols.abs_remainder = cols.remainder_comp;
                        cols.abs_c = Word::from(event.c as u32);
                        cols.max_abs_c_or_1 = Word::from(u32::max(1, event.c as u32));
                    } else {
                        cols.abs_remainder = cols.remainder_comp;
                        cols.abs_c = Word::from(event.c);
                        cols.max_abs_c_or_1 = Word::from(u64::max(1, event.c));
                    }

                    if is_word_operation(event.opcode) {
                        cols.is_overflow_b
                            .populate((event.b as u32) as u64, i32::MIN as u32 as u64);
                        cols.is_overflow_c
                            .populate((event.c as u32) as u64, (-1i32 as u32) as u64);
                    } else {
                        cols.is_overflow_b.populate(event.b, i64::MIN as u64);
                        cols.is_overflow_c.populate(event.c, (-1i64) as u64);
                    }

                    cols.b_neg_not_overflow = cols.b_neg * (F::ONE - cols.is_overflow);
                    cols.b_not_neg_not_overflow =
                        (F::ONE - cols.b_neg) * (F::ONE - cols.is_overflow);

                    // Set the `alu_event` flags.
                    cols.abs_c_alu_event = cols.c_neg * cols.is_real;
                    cols.abs_rem_alu_event = cols.rem_neg * cols.is_real;

                    output.add_u16_range_checks_field(&cols.abs_c.0);
                    output.add_u16_range_checks_field(&cols.abs_remainder.0);

                    // Populate the c_neg_operation and rem_neg_operation.
                    {
                        let mut blu_events = vec![];
                        if cols.abs_c_alu_event == F::ONE {
                            cols.c_neg_gadget.populate(
                                &mut blu_events,
                                cols.c.to_u64(),
                                cols.abs_c.to_u64(),
                            );
                        }
                        if cols.abs_rem_alu_event == F::ONE {
                            cols.rem_neg_gadget.populate(
                                &mut blu_events,
                                cols.remainder.to_u64(),
                                cols.abs_remainder.to_u64(),
                            );
                        }
                        output.add_byte_lookup_events(blu_events);
                    }

                    // Insert the MSB lookup events.
                    {
                        let mut blu_events: Vec<ByteLookupEvent> = vec![];

                        if is_word_operation(event.opcode) {
                            cols.b_msb.populate(&mut blu_events, (event.b >> 16) as u16);
                            cols.c_msb.populate(&mut blu_events, (event.c >> 16) as u16);
                            cols.rem_msb
                                .populate(&mut blu_events, (remainder >> 16) as u16);
                            cols.quot_msb
                                .populate(&mut blu_events, (quotient >> 16) as u16);
                        } else {
                            cols.b_msb.populate(&mut blu_events, (b >> 48) as u16);
                            cols.c_msb.populate(&mut blu_events, (c >> 48) as u16);
                            cols.rem_msb
                                .populate(&mut blu_events, (remainder >> 48) as u16);
                        }

                        output.add_byte_lookup_events(blu_events);
                    }
                }

                // Calculate the modified multiplicity
                {
                    let mut blu_events = vec![];
                    cols.remainder_check_multiplicity =
                        cols.is_real * (F::ONE - cols.is_c_0.result);
                    if cols.remainder_check_multiplicity == F::ONE {
                        cols.remainder_lt_gadget.populate(
                            &mut blu_events,
                            1,
                            cols.abs_remainder.to_u64(),
                            cols.max_abs_c_or_1.to_u64(),
                        );
                    }

                    output.add_byte_lookup_events(blu_events);
                }

                // Calculate c * quotient + remainder.
                {
                    let mut blu_events = vec![];
                    let mut c_times_quotient_byte = [0u8; 16];

                    let c_times_quotient_byte_lower =
                        (Wrapping(quotient_comp) * Wrapping(c)).0.to_le_bytes();

                    let c_times_quotient_byte_upper = if is_signed_64bit_operation(event.opcode)
                        || is_signed_word_operation(event.opcode)
                    {
                        ((((quotient_comp as i64) as i128).wrapping_mul((c as i64) as i128) >> 64)
                            as u64)
                            .to_le_bytes()
                    } else {
                        (((quotient_comp as u128 * c as u128) >> 64) as u64).to_le_bytes()
                    };

                    c_times_quotient_byte[..8].copy_from_slice(&c_times_quotient_byte_lower);
                    c_times_quotient_byte[8..].copy_from_slice(&c_times_quotient_byte_upper);

                    let c_times_quotient_u16: [u16; LONG_WORD_SIZE] = core::array::from_fn(|i| {
                        u16::from_le_bytes([
                            c_times_quotient_byte[2 * i],
                            c_times_quotient_byte[2 * i + 1],
                        ])
                    });

                    cols.c_times_quotient = c_times_quotient_u16.map(F::from_u16);

                    cols.c_times_quotient_lower.populate(
                        &mut blu_events,
                        quotient_comp,
                        c,
                        false,
                        false,
                        false,
                    );

                    if is_signed_64bit_operation(event.opcode) {
                        cols.c_times_quotient_upper.populate(
                            &mut blu_events,
                            quotient_comp,
                            c,
                            true,  // is_mulh - true for DIV/REM (signed)
                            false, // is_mulhsu
                            false, // is_mulw
                        );
                    }
                    if is_unsigned_64bit_operation(event.opcode) {
                        cols.c_times_quotient_upper.populate(
                            &mut blu_events,
                            quotient_comp,
                            c,
                            false, // is_mulh
                            false, // is_mulhsu
                            false, // is_mulw
                        );
                    }

                    output.add_byte_lookup_events(blu_events);

                    // Create remainder_u16 with sign extension based on rem_neg
                    let mut remainder_u16 = [0u32; 8];
                    for i in 0..4 {
                        remainder_u16[i] = cols.remainder_comp[i].as_canonical_u32();
                        remainder_u16[i + 4] = cols.rem_neg.as_canonical_u32() * ((1 << 16) - 1);
                    }

                    // Add remainder to product.
                    let mut carry = [0u32; 8];
                    let base = 1 << 16;
                    for i in 0..LONG_WORD_SIZE {
                        let mut x = c_times_quotient_u16[i] as u32 + remainder_u16[i];
                        if i > 0 {
                            x += carry[i - 1];
                        }
                        carry[i] = x / base;
                        cols.carry[i] = F::from_u32(carry[i]);
                        output.add_u16_range_check((x & 0xFFFF) as u16);
                    }

                    // Insert the necessary multiplication & LT events.
                    //
                    // This generate_trace for div must be executed _before_ calling generate_trace for
                    // mul and LT upon which div depends. This ordering is critical as mul and LT
                    // require all the mul and LT events be added before we can call generate_trace.
                    {
                        // Insert the absolute value computation events.
                        {
                            let mut add_events: Vec<AluEvent> = vec![];
                            if cols.abs_c_alu_event == F::ONE {
                                add_events.push(AluEvent {
                                    clk: event.clk,
                                    opcode: Opcode::ADD,
                                    a: 0,
                                    b: c,
                                    c: cols.abs_c.to_u64(),
                                    ..Default::default()
                                })
                            }
                            if cols.abs_rem_alu_event == F::ONE {
                                add_events.push(AluEvent {
                                    clk: event.clk,
                                    opcode: Opcode::ADD,
                                    a: 0,
                                    b: remainder,
                                    c: cols.abs_remainder.to_u64(),
                                    ..Default::default()
                                })
                            }
                            let mut alu_events = HashMap::new();
                            alu_events.insert(Opcode::ADD, add_events);
                            output.add_alu_events(alu_events);
                        }
                    }

                    // Range check.
                    {
                        output.add_u16_range_checks(&[
                            (quotient & 0xFFFF) as u16,
                            (quotient >> 16) as u16,
                            (quotient >> 32) as u16,
                            (quotient >> 48) as u16,
                        ]);
                        output.add_u16_range_checks(&[
                            (remainder & 0xFFFF) as u16,
                            (remainder >> 16) as u16,
                            (remainder >> 32) as u16,
                            (remainder >> 48) as u16,
                        ]);
                        output.add_u16_range_checks(&c_times_quotient_u16);
                    }
                }
            });

        // Create the template for the padded rows. These are fake rows that don't fail on some
        // sanity checks.
        let padded_row_template = {
            let mut row = [F::ZERO; NUM_DIVREM_VALUE_COLS];
            let cols: &mut DivRemValueCols<F> = row.as_mut_slice().borrow_mut();
            // 0 divided by 1. quotient = remainder = 0.
            cols.is_divu = F::ONE;
            cols.c[0] = F::ONE;
            // Padding is a non-word op, so the b/c alignment constraints require
            // `*_raw == *` on every limb.
            cols.c_raw[0] = F::ONE;
            cols.abs_c[0] = F::ONE;
            cols.max_abs_c_or_1[0] = F::ONE;
            cols.b_not_neg_not_overflow = F::ONE;

            cols.is_c_0.populate(1);

            row
        };

        for i in populate_len..values.len() {
            values[i] = padded_row_template[i % NUM_DIVREM_VALUE_COLS];
        }

        RowMajorMatrix::new(values, NUM_DIVREM_COLS)
    }

    fn extra_record(&self, input: &Self::Record, extra: &mut Self::Record) {
        self.generate_main(input, extra);
    }

    fn is_active(&self, record: &Self::Record) -> bool {
        // Under a pad shape the shape decides presence, so a bucketed chunk's proof shape
        // depends on the chunk kind rather than on its opcode mix. Without a shape the
        // chip is event-driven, which is what the natural-height path wants.
        if let Some(shape) = record.shape.as_ref() {
            return shape.included::<F, _>(self);
        }
        !record.alu_ops(AluStream::DivRem).is_empty()
    }

    fn local_only(&self) -> bool {
        true
    }
}

#[cfg(feature = "cuda")]
impl<F: PrimeField32> GpuChipBehavior<F> for DivRemChip<F> {
    fn is_active_for_extra_record(&self, record: &PreparedGpuEvents) -> bool {
        record.event_counter.num_divrem_events > 0
    }

    fn gpu_generate_extra_record_and_main(
        &self,
        device_id: usize,
        input: &Self::Record,
        prepared_gpu_events: &PreparedGpuEvents,
        preallocated_gpu_memory: &mut PreallocatedGpuMemory,
    ) -> TraceData<'_, F> {
        let history = input
            .history_view()
            .expect("a CPU chunk's record carries its execution history");
        self.gpu_generate_from_history(
            device_id,
            input,
            history,
            prepared_gpu_events,
            preallocated_gpu_memory,
        )
    }
}

#[cfg(feature = "cuda")]
impl<F: PrimeField32> DivRemChip<F> {
    /// The trace from the chunk's history on the device, the div/rem list's rows, and the ADD rows
    /// they derive appended there in row order for the add chip, which takes them from
    /// `d_divrem_add_rows`. The fill's descriptor counts the appended rows; the device sets the
    /// error word if it appends another count, and the count is read back and held to it here too.
    fn gpu_generate_from_history(
        &self,
        device_id: usize,
        input: &EmulationRecord,
        history: HistoryView<'_>,
        prepared_gpu_events: &PreparedGpuEvents,
        preallocated_gpu_memory: &mut PreallocatedGpuMemory,
    ) -> TraceData<'_, F> {
        let event_size = history.history.chip_steps.alu(AluStream::DivRem).len();
        assert_eq!(
            prepared_gpu_events.event_counter.num_divrem_events, event_size,
            "the counter's div/rem height is not the history's div/rem list"
        );
        let derived_rows = chunk_history(preallocated_gpu_memory)
            .descriptor()
            .divrem_add_rows as usize;

        let nrows = event_size.div_ceil(DIVREM_DATAPAR);
        let log2_nrows = input.shape_chip_size(&self.name());
        let padded_nrows = match log2_nrows {
            Some(log2_nrows) => 1 << log2_nrows,
            None => next_power_of_two(nrows, None),
        };

        let stream = &CudaStream::create_with_flags(CudaStreamCreateFlags::NON_BLOCKING).unwrap();

        let sync_mem_pool = get_global_mem_pool(device_id);
        let mem_pool = &sync_mem_pool.0;

        let trace_size = padded_nrows * NUM_DIVREM_COLS;
        let mut d_trace =
            DevicePoolAllocation::<KoalaBear>::alloc_from_pool_async(trace_size, mem_pool, stream)
                .unwrap();
        let mut d_derived = (derived_rows > 0).then(|| {
            DevicePoolAllocation::<AluEvent>::alloc_from_pool_async(derived_rows, mem_pool, stream)
                .unwrap()
        });
        let mut d_appended =
            DevicePoolAllocation::<u32>::alloc_from_pool_async(1, mem_pool, stream).unwrap();
        let d_byte_trace = preallocated_gpu_memory
            .d_byte_trace
            .as_mut()
            .unwrap()
            .as_mut_ptr();

        let reader = chunk_history_reader(preallocated_gpu_memory, stream);
        let args = reader.args();
        let kernels = device::start(stream);
        let err = unsafe {
            cuda_divrem_generate_extra_record_and_main_history(
                std::ptr::from_ref(&args).cast(),
                HISTORY_LAYOUT,
                NUM_DIVREM_COLS,
                trace_size,
                d_trace.as_mut_ptr() as *mut _,
                d_byte_trace as *mut _,
                d_derived
                    .as_mut()
                    .map_or(std::ptr::null_mut(), |rows| rows.as_mut_ptr() as *mut _),
                derived_rows,
                d_appended.as_mut_ptr() as *mut _,
                stream.into(),
            )
        };
        assert_eq!(
            err.code, 0,
            "cuda_divrem_generate_extra_record_and_main_history failed: {err}"
        );
        history_launch::note(&self.name());
        drop(reader);
        let appended = CudaEvent::create_with_flags(CudaEventCreateFlags::DISABLE_TIMING).unwrap();
        appended.record(stream).unwrap();

        let sync_stream = get_global_stream_pool(device_id);
        let main_stream = &sync_stream.0;
        device::launched(kernels, stream);
        device::wait(stream).unwrap();

        let mut appended_rows = 0u32;
        let copied = unsafe {
            cudaMemcpyAsync(
                std::ptr::from_mut(&mut appended_rows).cast(),
                d_appended.as_c_void_ptr(),
                size_of::<u32>(),
                CudaMemoryCopyKind::DeviceToHost,
                stream.into(),
            )
        };
        assert_eq!(
            copied,
            CudaError::Success,
            "reading back div/rem's appended count"
        );
        stream.synchronize().unwrap();
        assert_eq!(
            appended_rows as usize, derived_rows,
            "div/rem appended {appended_rows} derived ADD row(s) on the device, and the fill's \
             descriptor counts {derived_rows}"
        );

        let d_trace = d_trace.swap_stream(main_stream);
        preallocated_gpu_memory.d_divrem_add_rows = Some(DivRemAddRows {
            rows: d_derived.map(|rows| rows.swap_stream(main_stream)),
            len: derived_rows,
            owner: main_stream,
            appended,
        });
        device::wait(stream).unwrap();
        device::wait(main_stream).unwrap();

        info!("[divrem-chip] generate_extra_record_and_main from the history on GPU");

        TraceData::Gpu(NUM_DIVREM_COLS, d_trace)
    }
}

#[cfg(feature = "cuda")]
/// The ADD rows div/rem derives, appended on the device in its rows' order when it reads the
/// chunk's history, for the add chip to read after its own. They live on the device's main stream,
/// as a finished trace does; `appended` is recorded on the div/rem stream once they are written.
pub struct DivRemAddRows<'a> {
    rows: Option<DevicePoolAllocation<'a, AluEvent>>,
    len: usize,
    owner: &'a CudaStream,
    appended: CudaEvent,
}

#[cfg(feature = "cuda")]
impl DivRemAddRows<'_> {
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The rows on the device, or null when there are none.
    #[must_use]
    pub fn as_ptr(&self) -> *const c_void {
        self.rows
            .as_ref()
            .map_or(std::ptr::null(), |rows| rows.as_c_void_ptr())
    }

    /// Makes `stream` wait for the rows to have been appended.
    pub fn wait_appended(&self, stream: &CudaStream) {
        stream
            .wait_event(&self.appended, CudaStreamWaitEventFlags::DEFAULT)
            .unwrap_or_else(|e| panic!("waiting for div/rem's derived ADD rows: {e}"));
    }

    /// Frees the rows once the kernels enqueued on `reader` so far have run. If that point cannot
    /// be marked, `reader` is waited for on the host, so the free never overtakes a read.
    pub fn release_after(self, reader: &CudaStream) {
        let ordered =
            CudaEvent::create_with_flags(CudaEventCreateFlags::DISABLE_TIMING).and_then(|read| {
                read.record(reader)?;
                self.owner
                    .wait_event(&read, CudaStreamWaitEventFlags::DEFAULT)
            });
        if let Err(e) = ordered {
            reader.synchronize().unwrap_or_else(|sync| {
                panic!(
                    "div/rem's derived ADD rows could neither be ordered after their reader ({e}) \
                     nor waited for: {sync}"
                )
            });
        }
    }
}

impl<F> EventCapture for DivRemChip<F> {
    fn count_extra_records(record: &EmulationRecord, event_counter: &mut EventSizeCapture) {
        let ops = record.alu_ops(AluStream::DivRem);
        event_counter.num_divrem_events += ops.len();
        if event_counter.num_divrem_events == 0 {
            return;
        }

        let chunk_size = std::cmp::max(ops.len() / num_cpus::get(), 1);
        let divrem_counts: Vec<usize> = ops.par_flat_map(|event, counts| {
            counts.push(Self::count_event(event).add);
        });
        let divrem_add = divrem_counts
            .as_slice()
            .pico_chunks(chunk_size)
            .map(|chunk| chunk.iter().sum::<usize>())
            .pico_reduce(|| 0, |a, b| a + b);
        event_counter.num_add_sub_events += divrem_add;
    }
}

impl<F> DivRemChip<F> {
    #[inline(always)]
    fn count_event(event: &AluEvent) -> DivremExtraEventIndices {
        DivremExtraEventIndices {
            add: derived_add_rows(event.opcode, event.b, event.c),
        }
    }
}
