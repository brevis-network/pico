use super::{
    columns::{GlobalCols, NUM_GLOBAL_COLS},
    event::GlobalInteractionEvent,
    GlobalChip,
};
use crate::{
    chips::{
        chips::{
            byte::event::{ByteLookupEvent, ByteRecordBehavior},
            riscv_poseidon2::Poseidon2Event,
        },
        gadgets::global_interaction::GlobalInteractionOperation,
        trace::TraceData,
        utils::{next_power_of_two, zeroed_f_vec},
    },
    compiler::riscv::{opcode::ByteOpcode, program::Program},
    cuda_adaptor::resource_pool::{
        mem_pool::get_global_mem_pool, stream_pool::get_global_stream_pool,
    },
    emulator::riscv::{ffi::FFIEmulationRecord, record::EmulationRecord},
    instances::preparer::{EventCounter, PreallocatedGpuMemory, PreparedGpuEvents},
    iter::{
        IndexedPicoIterator, IntoPicoIterator, IntoPicoRefMutIterator, PicoBridge, PicoIterator,
        PicoScanIterator,
    },
    machine::{
        chip::ChipBehavior,
        estimator::{EventCapture, EventSizeCapture},
        field::FieldSpecificPoseidon2Config,
        lookup::LookupScope,
        septic::{
            FieldSepticCurve, SepticCurve, SepticCurveComplete, SepticDigest, SepticExtension,
        },
    },
};
use cudart::{
    memory_pools::DevicePoolAllocation,
    slice::{CudaSlice, CudaSliceMut},
    stream::{CudaStream, CudaStreamCreateFlags},
};
use cudart_sys::{cudaMemcpyAsync, CudaMemoryCopyKind};
use p3_field::PrimeField32;
use p3_koala_bear::KoalaBear;
use p3_matrix::dense::RowMajorMatrix;
use pico_gpu_api::cuda_riscv_global_generate_extra_record_and_main;
use std::borrow::BorrowMut;
use tracing::info;

impl<F: PrimeField32> ChipBehavior<F> for GlobalChip<F> {
    type Record = EmulationRecord;
    type GpuRecord = FFIEmulationRecord;
    type Program = Program;

    fn name(&self) -> String {
        "Global".to_string()
    }

    fn extra_record(&self, input: &Self::Record, output: &mut Self::Record) {
        let events = &input.global_lookup_events;

        let chunk_size = std::cmp::max(events.len() / num_cpus::get(), 1);

        let (blu_batches, poseidon2_events): (Vec<_>, Vec<_>) = events
            .chunks(chunk_size)
            .pico_bridge()
            .map(|events| {
                let mut blu: Vec<ByteLookupEvent> = vec![];
                let mut poseidon2: Vec<Poseidon2Event> = vec![];
                events.iter().for_each(|event| {
                    // 25-bit decomposition of message[0] (16 + 8 + 1; the boolean high bit
                    // needs no byte lookup).
                    let message0_16bit_limb = (event.message[0] & 0xFFFF) as u16;
                    let message0_8bit_limb = ((event.message[0] >> 16) & 0xFF) as u8;
                    blu.add_u16_range_check(message0_16bit_limb);
                    blu.add_u16_range_check(event.message[7] as u16);
                    // No `kind < 32` LTU event: every sender passes a compile-time constant,
                    // so the multiset pins the receiver's column and keygen checks the constant.
                    // `message0_8bit_limb` rides the offset U8 pair below instead.

                    // Populate the interaction columns so we can emit the byte lookups that mirror
                    // `eval_single_digest`: the offset u8 range check and the three `y6_limbs`
                    // range checks (U16Range on lo16, LTU bounds on mid/top).
                    let mut op = GlobalInteractionOperation::<F>::default();
                    let p2 = op
                        .populate(event.message, event.is_receive, true, event.kind)
                        .unwrap();
                    // Must match `eval_single_digest`'s bounds exactly. The `as u8` casts are only
                    // lossless for the fields the `y6_limbs` docs allow, which `populate` asserts.
                    let mid_bound = (1u32 << (30 - F::TOP_BITS - 16)) as u8; // 128
                    let top_bound = ((1u32 << F::TOP_BITS) - 1) as u8; // 127

                    // Merged U8 pair -- slot order must match the constraint: b = offset,
                    // c = message0_8bit_limb.
                    blu.add_u8_range_check(op.offset.as_canonical_u32() as u8, message0_8bit_limb);
                    blu.add_u16_range_check(op.y6_limbs[0].as_canonical_u32() as u16);
                    blu.push(ByteLookupEvent::new(
                        ByteOpcode::LTU,
                        1,
                        0,
                        op.y6_limbs[1].as_canonical_u32() as u8,
                        mid_bound,
                    ));
                    blu.push(ByteLookupEvent::new(
                        ByteOpcode::LTU,
                        1,
                        0,
                        op.y6_limbs[2].as_canonical_u32() as u8,
                        top_bound,
                    ));
                    poseidon2.push(p2);
                });

                (blu, poseidon2)
            })
            .unzip();

        let flat_p2: Vec<_> = poseidon2_events.into_iter().flatten().collect();

        output.add_byte_lookup_events(blu_batches.into_iter().flatten().collect());
        output.poseidon2_events.extend(flat_p2);
    }

    fn generate_main(&self, input: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {
        let events = &input.global_lookup_events;

        let nb_rows = events.len();
        let log_rows = input.shape_chip_size(&self.name());
        // `+ 1`: the accumulation constraints need the last row to be padding (A8), whose `cum`
        // is the chunk total that `GcsBindAir` binds to the public values.
        let padded_nb_rows = next_power_of_two(nb_rows + 1, log_rows);
        assert!(nb_rows < padded_nb_rows);

        let mut values = zeroed_f_vec(padded_nb_rows * NUM_GLOBAL_COLS);
        let chunk_size = std::cmp::max(nb_rows / num_cpus::get(), 0) + 1;

        let mut chunks = values[..nb_rows * NUM_GLOBAL_COLS]
            .chunks_mut(chunk_size * NUM_GLOBAL_COLS)
            .collect::<Vec<_>>();

        let point_chunks = chunks
            .pico_iter_mut()
            .enumerate()
            .map(|(i, rows)| {
                let mut point_chunks = Vec::with_capacity(chunk_size * NUM_GLOBAL_COLS + 1);
                if i == 0 {
                    point_chunks.push(SepticCurveComplete::Affine(SepticDigest::<F>::zero().0));
                }
                rows.chunks_mut(NUM_GLOBAL_COLS)
                    .enumerate()
                    .for_each(|(j, row)| {
                        let idx = i * chunk_size + j;
                        let cols: &mut GlobalCols<F> = row.borrow_mut();
                        let event: &GlobalInteractionEvent = &events[idx];
                        cols.message = event.message.map(F::from_u32);
                        cols.kind = F::from_u8(event.kind);
                        cols.message_0_16bit_limb = F::from_u32(event.message[0] & 0xFFFF);
                        cols.message_0_8bit_limb = F::from_u32((event.message[0] >> 16) & 0xFF);
                        cols.message_0_high_bit = F::from_u32((event.message[0] >> 24) & 1);
                        cols.interaction.populate(
                            event.message,
                            event.is_receive,
                            true,
                            event.kind,
                        );
                        cols.is_real = F::ONE;
                        if event.is_receive {
                            cols.is_receive = F::ONE;
                        } else {
                            cols.is_send = F::ONE;
                        }
                        point_chunks.push(SepticCurveComplete::Affine(SepticCurve {
                            x: SepticExtension(cols.interaction.x_coordinate.0),
                            y: SepticExtension(cols.interaction.y_coordinate.0),
                        }));
                    });
                point_chunks
            })
            .collect::<Vec<_>>();

        let points = point_chunks.into_iter().flatten().collect::<Vec<_>>();
        let prefix_sums = points
            .into_pico_iter()
            .with_min_len(1 << 15)
            .pico_scan(|a, b| *a + *b, SepticCurveComplete::Infinity)
            .collect::<Vec<SepticCurveComplete<F>>>();

        // `prefix_sums[k] = START + Σ_{j<k} P_j` (the row-`k` incoming sum); its last entry
        // (k = nb_rows) is the chunk total. With no events the total is the START point itself
        // (Σ∅ = zero digest), which is also what the FIRST-row constraint expects.
        let final_digest = match prefix_sums.last() {
            Some(digest) => digest.point(),
            None => SepticDigest::<F>::zero().0,
        };

        let chunk_size = std::cmp::max(padded_nb_rows / num_cpus::get(), 0) + 1;
        values
            .chunks_mut(chunk_size * NUM_GLOBAL_COLS)
            .enumerate()
            .pico_bridge()
            .for_each(|(i, rows)| {
                rows.chunks_mut(NUM_GLOBAL_COLS)
                    .enumerate()
                    .for_each(|(j, row)| {
                        let idx = i * chunk_size + j;
                        let cols: &mut GlobalCols<F> = row.borrow_mut();
                        if idx < nb_rows {
                            let point = SepticCurve {
                                x: SepticExtension(cols.interaction.x_coordinate.0),
                                y: SepticExtension(cols.interaction.y_coordinate.0),
                            };
                            cols.accumulation
                                .populate_real(prefix_sums[idx].point(), [point]);
                        } else {
                            cols.interaction.populate_dummy();
                            cols.accumulation.populate_dummy(final_digest);
                        }
                    });
            });

        RowMajorMatrix::new(values, NUM_GLOBAL_COLS)
    }

    fn is_active(&self, _: &Self::Record) -> bool {
        true
    }

    fn lookup_scope(&self) -> LookupScope {
        LookupScope::Global
    }

    fn count_extra_records(_record: &Self::Record, counter: &mut EventCounter) {
        // counter.num_global_lookup_events += record.global_lookup_events.len();
        counter.num_poseidon2_events += counter.num_global_lookup_events;
    }

    fn gpu_generate_extra_record_and_main(
        &self,
        device_id: usize,
        input: &Self::Record,
        prepared_gpu_events: &PreparedGpuEvents,
        preallocated_gpu_memory: &mut PreallocatedGpuMemory,
    ) -> TraceData<'_, F> {
        let event_size = prepared_gpu_events.event_counter.num_global_lookup_events;

        let nb_rows = event_size;
        let log_rows = input.shape_chip_size(&self.name());
        // `+ 1`: the accumulation constraints need the last row to be padding (A8), whose `cum`
        // is the chunk total that `GcsBindAir` binds to the public values.
        let padded_nb_rows = next_power_of_two(nb_rows + 1, log_rows);
        assert!(nb_rows < padded_nb_rows);

        let stream = &CudaStream::create_with_flags(CudaStreamCreateFlags::NON_BLOCKING).unwrap();

        let sync_mem_pool = get_global_mem_pool(device_id);
        let mem_pool = &sync_mem_pool.0;

        let d_global_events = preallocated_gpu_memory.d_global_events.as_mut();
        let d_poseidon2_events = preallocated_gpu_memory.d_poseidon2_events.as_mut();
        let d_byte_trace = preallocated_gpu_memory.d_byte_trace.as_mut().unwrap();

        let trace_size = padded_nb_rows * NUM_GLOBAL_COLS;
        let mut d_trace =
            DevicePoolAllocation::<KoalaBear>::alloc_from_pool_async(trace_size, mem_pool, stream)
                .unwrap();

        // The hash-to-curve inside the kernel runs the KoalaBear Poseidon2 instance; ship its
        // round constants in the layout the kernel reads.
        let rc_flat = KoalaBear::round_constants().flatten_for_gpu();
        let mut d_round_constants = DevicePoolAllocation::<KoalaBear>::alloc_from_pool_async(
            rc_flat.len(),
            mem_pool,
            stream,
        )
        .unwrap();
        unsafe {
            let _ = cudaMemcpyAsync(
                d_round_constants.as_mut_c_void_ptr(),
                rc_flat.as_c_void_ptr(),
                rc_flat.len() * size_of::<KoalaBear>(),
                CudaMemoryCopyKind::HostToDevice,
                stream.into(),
            );
        }

        // With no events the kernel still runs: it fills every row as padding with `cum = START`
        // (the CPU tracegen's `final_digest` for n = 0) and never touches the event buffers, so
        // absent buffers are passed as null.
        let d_events_ptr: Option<(*const std::ffi::c_void, *mut std::ffi::c_void)> =
            match (event_size, d_global_events, d_poseidon2_events) {
                (0, _, _) => Some((std::ptr::null(), std::ptr::null_mut())),
                (_, Some(d_global_events), Some(d_poseidon2_events)) => Some((
                    d_global_events.as_mut_ptr() as *const std::ffi::c_void,
                    d_poseidon2_events.as_mut_ptr() as *mut std::ffi::c_void,
                )),
                _ => None,
            };
        if let Some((d_global_events, d_poseidon2_events)) = d_events_ptr {
            unsafe {
                cuda_riscv_global_generate_extra_record_and_main(
                    NUM_GLOBAL_COLS,
                    event_size,
                    trace_size,
                    d_global_events,
                    d_trace.as_mut_ptr() as *mut _,
                    stream.into(),
                    d_byte_trace.as_mut_ptr() as *mut _,
                    d_poseidon2_events,
                    prepared_gpu_events
                        .event_counter
                        .start_indices
                        .global_extra_poseidon2_start_index,
                    d_round_constants.as_ptr() as *const _,
                );
            }
        }

        let sync_stream = get_global_stream_pool(device_id);
        let main_stream = &sync_stream.0;
        stream.synchronize().unwrap();
        let d_trace = d_trace.swap_stream(main_stream);
        stream.synchronize().unwrap();
        main_stream.synchronize().unwrap();

        info!("[riscv-global-chip] generate_extra_record_and_main on GPU");
        TraceData::Gpu(NUM_GLOBAL_COLS, d_trace)
    }

    fn is_active_for_extra_record(&self, _record: &PreparedGpuEvents) -> bool {
        true
    }
}

impl<F> EventCapture for GlobalChip<F> {
    fn count_extra_records(_record: &EmulationRecord, event_counter: &mut EventSizeCapture) {
        event_counter.num_poseidon2_events += event_counter.num_global_lookup_events;
    }
}
