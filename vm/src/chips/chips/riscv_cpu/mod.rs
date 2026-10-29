use std::marker::PhantomData;

pub mod branch;
pub mod chunk_clk;
pub mod columns;
pub mod constraints;
pub mod ecall;
pub mod event;
pub mod instruction;
pub mod jump;
pub mod opcode_selector;
pub mod public_values;
pub mod register;
pub mod traces;
pub mod utils;

#[derive(Default)]
pub struct CpuChip<F>(PhantomData<F>);

#[cfg(test)]
mod tests {
    #[cfg(feature = "cuda")]
    use crate::emulator::riscv::event_pool::HostAllocFlags;
    #[cfg(feature = "cuda")]
    use crate::machine::chip::GpuChipBehavior;
    #[cfg(feature = "cuda")]
    use crate::{
        chips::{
            chips::{
                byte::{columns::NUM_BYTE_MULT_COLS, ByteChip},
                riscv_cpu::CpuChip,
                riscv_memory::read_write::MemoryReadWriteChip,
            },
            tests::{generate_test_chunks, init_test_stream, TestElf, TestInput},
            trace::TraceData,
        },
        emulator::riscv::{
            alu_event_pool::{init_alu_event_buffer_pool, is_alu_pool_initialized},
            cpu_event_pool::{init_cpu_event_buffer_pool, is_pool_initialized, CpuEventBuffer},
            record::EmulationRecord,
        },
        instances::{
            compiler::shapes::riscv_shape::RiscvPadShape,
            preparer::{
                gpu_allocate_and_copy_add_sub_events, gpu_allocate_and_copy_lt_events,
                gpu_allocate_and_copy_mul_events, gpu_allocate_byte_trace, gpu_allocate_cpu_events,
                gpu_finalize_byte_trace, init_packed_event_pools, precompute_event_size,
                try_stage_forced, verify_add_sub_events, verify_lt_events, PackedEventStage,
                PreallocatedGpuMemory, PreparedGpuEvents,
            },
        },
        machine::chip::ChipBehavior,
        primitives::consts::MEMORY_RW_DATAPAR,
    };
    #[cfg(feature = "cuda")]
    use cudart::stream::CudaStream;
    #[cfg(feature = "cuda")]
    use p3_field::PrimeCharacteristicRing;
    #[cfg(feature = "cuda")]
    use p3_koala_bear::KoalaBear;
    #[cfg(feature = "cuda")]
    use p3_matrix::dense::RowMajorMatrix;
    #[cfg(feature = "cuda")]
    use std::sync::{Arc, Mutex, PoisonError};

    #[cfg(feature = "cuda")]
    type F = KoalaBear;

    #[cfg(feature = "cuda")]
    fn cpu_generate_main(chip: &CpuChip<F>, input: &EmulationRecord) -> RowMajorMatrix<F> {
        chip.generate_main(input, &mut EmulationRecord::default())
    }

    #[cfg(feature = "cuda")]
    fn gpu_generate_extra_record_and_main(
        chip: &CpuChip<F>,
        input: &EmulationRecord,
        prepared_gpu_events: &PreparedGpuEvents,
        preallocated_gpu_memory: &mut PreallocatedGpuMemory,
    ) -> RowMajorMatrix<F> {
        let stream = init_test_stream();
        let trace = chip.gpu_generate_extra_record_and_main(
            0,
            input,
            prepared_gpu_events,
            preallocated_gpu_memory,
        );
        trace.to_host(stream)
    }

    #[cfg(feature = "cuda")]
    /// The real-program fixture the parity tests share: one Fib chunk, replicated. Returns the
    /// record and its number of branch rows.
    #[allow(clippy::field_reassign_with_default)]
    fn fib_fixture() -> (EmulationRecord, usize) {
        if !is_pool_initialized() {
            init_cpu_event_buffer_pool(50, HostAllocFlags::DEFAULT);
        }
        if !is_alu_pool_initialized() {
            init_alu_event_buffer_pool(50, HostAllocFlags::DEFAULT);
        }
        // Fib's loop is driven by branches over the counter, so a < b, a > b and a = b all
        // occur with both taken and not-taken outcomes. Replicated x3 to cross the GPU slice
        // boundary (2^16 events per launch).
        let chunk = &generate_test_chunks(TestElf::Fib, TestInput::Fib(100_000))[0];
        let chunk_cpu_events = chunk.cpu_events.as_slice().to_vec();

        let mut new_buffer = CpuEventBuffer::Empty;
        for _ in 0..3 {
            new_buffer.extend_from_slice(&chunk_cpu_events).unwrap();
        }
        let n_branches = chunk_cpu_events
            .iter()
            .filter(|e| e.instruction.is_branch_instruction())
            .count()
            * 3;
        assert!(n_branches > 0, "fixture has no branch rows");
        // Same shape, for the other row kind this chip stopped treating specially: since X12 the
        // transpiler re-encodes `AUIPC rd, imm` as the two-immediate `ADD rd, imm, pc`, and a
        // two-immediate row whose `op_c` is its own address is that re-encoding (LUI is the only
        // other two-immediate ADD, and its `op_c` is a link-time constant that would have to
        // coincide with the row's address). Those rows exercise the derived ALU class and the
        // `is_alu_not_x0` multiplicity on both sides of the parity check. Without the guard the
        // fixture could stop containing them -- `_start` opens with `auipc gp, ...` today -- and
        // the traces would still match, with one instruction shape silently untested.
        let n_reencoded_auipc = chunk_cpu_events
            .iter()
            .filter(|e| e.instruction.imm_b && e.instruction.imm_c && e.instruction.op_c == e.pc)
            .count();
        assert!(
            n_reencoded_auipc > 0,
            "fixture has no re-encoded AUIPC rows"
        );
        // `EmulationRecord` implements `Drop`, so struct-update syntax cannot move the other
        // fields out of a `Default` value (E0509); assign instead.
        let mut original_record = EmulationRecord::default();
        original_record.cpu_events = new_buffer;
        (original_record, n_branches)
    }

    #[cfg(feature = "cuda")]
    /// The packed pools below hold one buffer each and the test harness runs tests concurrently,
    /// so a second stage taken while another test still holds its stage would find the pools
    /// exhausted and fall back to the fat path. Every test that stages holds this for its whole
    /// body (the stage returns its buffers on drop, at the end of the test).
    static PACKED_STAGE_SERIAL: Mutex<()> = Mutex::new(());

    #[cfg(feature = "cuda")]
    /// Stage the packed event mirror for `record` regardless of `MLE_PACKED_EVENTS`; the pools
    /// are sized for one chunk (idempotent init).
    fn force_packed_stage(
        record: &EmulationRecord,
        prepared: &PreparedGpuEvents,
    ) -> PackedEventStage {
        init_packed_event_pools(1, HostAllocFlags::DEFAULT);
        try_stage_forced(record, &prepared.event_counter)
            .expect("the Fib fixture satisfies every packing invariant")
    }

    #[cfg(feature = "cuda")]
    /// The buffers the prover hands the Cpu chip: an empty cpu-event allocation (the chip uploads
    /// the stream itself, fat or packed) and the ALU event buffers filled by the same functions
    /// the prover uses, which copy the packed prefix instead when a stage is present.
    fn allocate_like_the_prover<'a>(
        stream: &'a CudaStream,
        record: &'a EmulationRecord,
        prepared: &'a PreparedGpuEvents,
    ) -> PreallocatedGpuMemory<'a> {
        PreallocatedGpuMemory {
            d_cpu_events: gpu_allocate_cpu_events(stream, 0, prepared).unwrap(),
            d_add_sub_events: gpu_allocate_and_copy_add_sub_events(stream, 0, record, prepared)
                .unwrap(),
            d_lt_events: gpu_allocate_and_copy_lt_events(stream, 0, record, prepared).unwrap(),
            d_mul_events: gpu_allocate_and_copy_mul_events(stream, 0, record, prepared).unwrap(),
            d_byte_trace: gpu_allocate_byte_trace(stream, 0).unwrap(),
            ..Default::default()
        }
    }

    #[cfg(feature = "cuda")]
    /// CPU / GPU parity of the Cpu chip on a real program, including the extra ALU events it
    /// emits: one merged SLT/SLTU comparison per branch (`is_cmp`, both bits in `a`); the JALR
    /// target is proven in-row, so no add events. `verify_lt_events` compares the GPU-written
    /// events field by field (clk/opcode/a/b/c/is_imm/is_cmp) with the CPU `extra_record`, so a
    /// missing flag, a
    /// wrong `a` packing, or a slot-count drift between `count_cpu_event` and the emitters
    /// fails here rather than at MLE_VERIFY.
    #[test]
    fn test_riscv_cpu_gpu_generate_extra_record_and_main() {
        cpu_parity(false);
    }

    #[cfg(feature = "cuda")]
    /// The same check through the packed event mirror (`MLE_PACKED_EVENTS=1`, the production
    /// default): the packed Cpu kernel runs on the staged 80 B stream and must produce the same
    /// main and byte traces. Production only ever runs this path, so without it a packed kernel
    /// could drift from the fat one unnoticed until MLE_VERIFY.
    #[test]
    fn test_riscv_cpu_gpu_generate_extra_record_and_main_packed() {
        cpu_parity(true);
    }

    #[cfg(feature = "cuda")]
    fn cpu_parity(packed: bool) {
        let _serial = packed.then(|| {
            PACKED_STAGE_SERIAL
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
        });
        let (original_record, n_branches) = fib_fixture();
        let n_events = original_record.cpu_events.len();

        let chip = CpuChip::<F>::default();

        // Complete the record for CPU computation.
        let mut complete_record = original_record.clone();
        chip.extra_record(&original_record, &mut complete_record);
        // Precompute event sizes for GPU computation and check they track the emitters.
        let counted_record = original_record.clone();
        let event_counter = precompute_event_size::<F>(&counted_record);
        event_counter.assert_event_counts_match(&complete_record);
        assert_eq!(
            event_counter.num_lt_events, n_branches,
            "one lt slot per branch"
        );
        assert!(
            complete_record
                .lt_events
                .as_slice()
                .iter()
                .all(|e| e.is_cmp),
            "every Cpu-emitted lt event is a merged comparison"
        );

        let mut log_height = 1;
        while (1usize << log_height) < n_events {
            log_height += 1;
        }
        complete_record.shape = Some(RiscvPadShape::default());
        complete_record
            .shape
            .as_mut()
            .unwrap()
            .inner
            .insert(chip.name(), log_height);
        let mut counted_record = counted_record;
        counted_record.shape = Some(RiscvPadShape::default());
        counted_record
            .shape
            .as_mut()
            .unwrap()
            .inner
            .insert(chip.name(), log_height);

        // Generate CPU trace.
        let cpu_trace = cpu_generate_main(&chip, &complete_record);
        let byte_chip = ByteChip::<F>::default();
        let cpu_byte_trace =
            byte_chip.generate_main(&complete_record, &mut EmulationRecord::default());

        // Generate GPU trace.
        let stream = init_test_stream();
        let mut prepared_gpu_events =
            PreparedGpuEvents::new(&counted_record, event_counter.clone());
        if packed {
            prepared_gpu_events.packed = Some(Arc::new(force_packed_stage(
                &counted_record,
                &prepared_gpu_events,
            )));
        }
        let mut preallocated_gpu_memory =
            allocate_like_the_prover(stream, &counted_record, &prepared_gpu_events);
        let gpu_trace = gpu_generate_extra_record_and_main(
            &chip,
            &counted_record,
            &prepared_gpu_events,
            &mut preallocated_gpu_memory,
        );

        // Assert trace consistency.
        assert_eq!(cpu_trace, gpu_trace);

        // The chain sink, which the kernel cannot write: `cpu_events_to_trace_kernel` is launched
        // once per slice, so a kernel-side "last index" test would mark the last row of every
        // slice. The fixture is replicated past one slice on purpose, so a regression there shows
        // up as several marks instead of one -- and otherwise only the `is_last` definition
        // (`eval_row_chain`, N4 / N5) would catch it, at proving time.
        let col = crate::chips::chips::riscv_cpu::columns::CPU_COL_MAP.is_last;
        let width = crate::chips::chips::riscv_cpu::columns::NUM_CPU_COLS;
        let marks: Vec<usize> = (0..gpu_trace.values.len() / width)
            .filter(|row| gpu_trace.values[row * width + col] != F::ZERO)
            .collect();
        assert_eq!(
            marks,
            vec![n_events - 1],
            "exactly the last real row must carry is_last (slice size is 1 << 16)"
        );

        // Assert that the extra records are generated correctly (the lt buffer is written by the
        // GPU kernel here, so this is a real emitter check; add/sub may be absent). On the packed
        // path those buffers hold packed entries, which these fat-layout readers cannot decode;
        // the traces above and the fat run cover them.
        if !packed {
            verify_add_sub_events(
                &preallocated_gpu_memory.d_add_sub_events,
                &event_counter,
                &complete_record,
                stream,
            );
            assert!(verify_lt_events(
                &preallocated_gpu_memory.d_lt_events,
                event_counter.num_lt_events,
                &complete_record,
                stream,
            ));
        }

        // Finalize the byte trace and assert that it is consistent.
        gpu_finalize_byte_trace(stream, &mut preallocated_gpu_memory).unwrap();
        stream.synchronize().unwrap();

        let d_byte_trace = preallocated_gpu_memory.d_byte_trace.take().unwrap();
        let host_gpu_byte_trace =
            TraceData::<F>::Gpu(NUM_BYTE_MULT_COLS, d_byte_trace).to_host(stream);
        assert_eq!(host_gpu_byte_trace.values, cpu_byte_trace.values);
    }

    #[cfg(feature = "cuda")]
    /// The MemoryReadWrite chip through the packed mirror. Its kernel indexes the packed cpu
    /// stream the Cpu chip uploaded and reads the dense `MemRecordPacked` side stream, so run
    /// the Cpu chip first exactly as the prover does, then compare this chip's main and byte
    /// traces with the CPU generator.
    #[test]
    fn test_memory_read_write_gpu_generate_extra_record_and_main_packed() {
        let _serial = PACKED_STAGE_SERIAL
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let (mut original_record, _) = fib_fixture();
        original_record.memory_read_write_event_indices = original_record
            .cpu_events
            .as_slice()
            .iter()
            .enumerate()
            .filter(|(_, e)| e.instruction.is_memory_instruction())
            .map(|(i, _)| i)
            .collect();
        let n_mem = original_record.memory_read_write_event_indices.len();
        assert!(n_mem > 0, "fixture has no memory rows");

        let chip = MemoryReadWriteChip::<F>::default();
        let cpu_chip = CpuChip::<F>::default();

        let mut complete_record = original_record.clone();
        chip.extra_record(&original_record, &mut complete_record);
        let mut counted_record = original_record.clone();
        let event_counter = precompute_event_size::<F>(&counted_record);
        assert_eq!(event_counter.num_memory_read_writes, n_mem);

        // Both chips run below, so both heights are pinned (the Cpu chip indexes its shape).
        let n_events = original_record.cpu_events.len();
        let mut cpu_log_height = 1;
        while (1usize << cpu_log_height) < n_events {
            cpu_log_height += 1;
        }
        let mem_log_height = n_mem
            .div_ceil(MEMORY_RW_DATAPAR)
            .next_power_of_two()
            .trailing_zeros() as usize;
        for record in [&mut complete_record, &mut counted_record] {
            record.shape = Some(RiscvPadShape::default());
            let inner = &mut record.shape.as_mut().unwrap().inner;
            inner.insert(cpu_chip.name(), cpu_log_height);
            inner.insert(chip.name(), mem_log_height);
        }

        let cpu_trace = chip.generate_main(&complete_record, &mut EmulationRecord::default());
        let cpu_byte_trace = ByteChip::<F>::default()
            .generate_main(&complete_record, &mut EmulationRecord::default());

        let stream = init_test_stream();
        let mut prepared_gpu_events =
            PreparedGpuEvents::new(&counted_record, event_counter.clone());
        prepared_gpu_events.packed = Some(Arc::new(force_packed_stage(
            &counted_record,
            &prepared_gpu_events,
        )));
        let mut preallocated_gpu_memory =
            allocate_like_the_prover(stream, &counted_record, &prepared_gpu_events);

        // The Cpu chip uploads the packed cpu stream this chip indexes; its own trace is checked
        // by `test_riscv_cpu_gpu_generate_extra_record_and_main_packed`.
        let _ = cpu_chip
            .gpu_generate_extra_record_and_main(
                0,
                &counted_record,
                &prepared_gpu_events,
                &mut preallocated_gpu_memory,
            )
            .to_host(stream);
        // A fresh byte trace, so only this chip's lookups are compared.
        preallocated_gpu_memory.d_byte_trace = gpu_allocate_byte_trace(stream, 0).unwrap();

        let gpu_trace = chip
            .gpu_generate_extra_record_and_main(
                0,
                &counted_record,
                &prepared_gpu_events,
                &mut preallocated_gpu_memory,
            )
            .to_host(stream);
        assert_eq!(cpu_trace, gpu_trace);
        assert!(
            cpu_trace.values.iter().any(|v| *v != F::ZERO),
            "main trace is all zeros — both CPU and GPU may be broken"
        );

        gpu_finalize_byte_trace(stream, &mut preallocated_gpu_memory).unwrap();
        stream.synchronize().unwrap();
        let d_byte_trace = preallocated_gpu_memory.d_byte_trace.take().unwrap();
        let host_gpu_byte_trace =
            TraceData::<F>::Gpu(NUM_BYTE_MULT_COLS, d_byte_trace).to_host(stream);
        assert_eq!(host_gpu_byte_trace.values, cpu_byte_trace.values);
    }
}

#[cfg(test)]
mod interaction_pins {
    use super::CpuChip;
    use crate::primitives::consts::MAX_NUM_PVS;
    use p3_air::BaseAir;
    use p3_koala_bear::KoalaBear;
    use pico_mle_core::{
        air::symbolic::get_symbolic_builder_with_public_values, keygen::types::TraceWidth,
    };

    type F = KoalaBear;

    /// Pins the Cpu chip's interaction count (17: Program, 6 register timestamp lookups, 6
    /// register memory accesses and the MemRW / Alu / CMP / Ecall dispatches; the row chain is
    /// rotation constraints, not messages, the JALR target is proven in-chip and the jump-row
    /// return address is made canonical by the Program table's `pc_carry` column) and its
    /// constraint degree. A change here is a change to the LogUp cost model: the round-0 and
    /// GKR work of every Cpu chunk scales with this count.
    #[test]
    fn cpu_interaction_count_pin() {
        let chip = CpuChip::<F>::default();
        let width = TraceWidth {
            preprocessed: None,
            cached_mains: vec![],
            common_main: BaseAir::<F>::width(&chip),
        };
        let builder = get_symbolic_builder_with_public_values::<F, _>(&chip, &width, MAX_NUM_PVS);
        let constraints = builder.constraints();
        assert_eq!(constraints.max_constraint_degree(), 3);
        assert_eq!(constraints.interactions.len(), 17);
    }
}
