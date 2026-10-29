pub mod columns;
pub mod constraints;
pub mod traces;

/*
#[cfg(test)]
mod tests {
    use crate::{
        chips::{
            chips::{
                alu::sr::traces::ShiftRightChip,
                byte::{columns::NUM_BYTE_MULT_COLS, ByteChip},
                events::AluEvent,
            },
            tests::init_test_stream,
            trace::TraceData,
        },
        compiler::riscv::opcode::Opcode,
        emulator::riscv::record::EmulationRecord,
        instances::{
            compiler::shapes::riscv_shape::RiscvPadShape,
            preparer::{
                gpu_allocate_byte_trace, gpu_finalize_byte_trace, precompute_event_size,
                PreallocatedGpuMemory, PreparedGpuEvents,
            },
        },
        machine::chip::ChipBehavior,
    };
    use p3_koala_bear::KoalaBear;
    use p3_matrix::dense::RowMajorMatrix;
    use rand::{rng, Rng, RngExt};
    use std::sync::LazyLock;

    type F = KoalaBear;

    static SR_SHARD: LazyLock<EmulationRecord> = LazyLock::new(|| generate_record(1 << 4));

    // static LARGE_SR_SHARD: LazyLock<EmulationRecord> = LazyLock::new(|| generate_record(1 << 20));

    fn cpu_generate_main(chip: &ShiftRightChip<F>, input: &EmulationRecord) -> RowMajorMatrix<F> {
        chip.generate_main(input, &mut EmulationRecord::default())
    }

    fn generate_record(size: usize) -> EmulationRecord {
        let mut rng = rng();
        let shift_right_events = (0..size as u32)
            .map(|i| {
                let a: u32 = rng.random();
                let b: u32 = rng.random();
                let shift = b & 0x1F;
                let opcode = if i % 2 == 0 { Opcode::SRL } else { Opcode::SRA };
                let result = match opcode {
                    Opcode::SRL => a >> shift,
                    Opcode::SRA => ((a as i32) >> shift) as u32,
                    _ => unreachable!(),
                };
                AluEvent::new(i, opcode, result, a, b)
            })
            .collect::<Vec<_>>();

        let mut record = EmulationRecord::default();
        record.shift_right_events = shift_right_events;

        record
    }

    fn gpu_generate_extra_record_and_main(
        chip: &ShiftRightChip<F>,
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

    #[test]
    fn test_sr_generate_extra_record_and_main() {
        let original_record = LazyLock::force(&SR_SHARD);

        let chip = ShiftRightChip::default();

        // Complete the record for CPU computation.
        let mut complete_record = original_record.clone();
        chip.extra_record(&original_record, &mut complete_record);
        // Precompute event sizes for GPU computation.
        let mut counted_record = original_record.clone();
        let event_counter = precompute_event_size::<F>(&mut counted_record);
        // Assert that the event counts are the same.
        event_counter.assert_event_counts_match(&complete_record);

        // Shape padding for CPU and GPU computation.
        complete_record.shape = Some(RiscvPadShape::default());
        complete_record
            .shape
            .as_mut()
            .unwrap()
            .inner
            .insert(chip.name(), 4);
        counted_record.shape = Some(RiscvPadShape::default());
        counted_record
            .shape
            .as_mut()
            .unwrap()
            .inner
            .insert(chip.name(), 4);

        // Generate CPU trace.
        let cpu_trace = cpu_generate_main(&chip, &complete_record);
        let byte_chip = ByteChip::<F>::default();
        let cpu_byte_trace =
            byte_chip.generate_main(&complete_record, &mut EmulationRecord::default());

        // Generate GPU trace.
        let stream = init_test_stream();
        let prepared_gpu_events = PreparedGpuEvents::new(&counted_record, event_counter);
        let mut preallocated_gpu_memory = PreallocatedGpuMemory {
            d_byte_trace: gpu_allocate_byte_trace(&stream, 0).unwrap(),
            ..Default::default()
        };
        let gpu_trace = gpu_generate_extra_record_and_main(
            &chip,
            &counted_record,
            &prepared_gpu_events,
            &mut preallocated_gpu_memory,
        );
        // Assert trace consistency.
        assert_eq!(cpu_trace, gpu_trace);

        // Finalize the byte trace. And assert that the byte trace is consistent.
        gpu_finalize_byte_trace(&stream, &mut preallocated_gpu_memory).unwrap();
        stream.synchronize().unwrap();

        let d_byte_trace = preallocated_gpu_memory.d_byte_trace.take().unwrap();

        let host_gpu_byte_trace =
            TraceData::<F>::Gpu(NUM_BYTE_MULT_COLS, d_byte_trace).to_host(&stream);
        assert_eq!(host_gpu_byte_trace.values, cpu_byte_trace.values);
    }
}
*/
