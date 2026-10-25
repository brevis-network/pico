mod columns;
mod constraints;
mod traces;

#[cfg(test)]
mod tests;

use crate::chips::chips::syscall::columns::SyscallCols;
use core::fmt;
use p3_field::PrimeField32;
use std::{marker::PhantomData, mem::size_of};

/// The number of main trace columns for `SyscallChip`.
pub const NUM_SYSCALL_COLS: usize = size_of::<SyscallCols<u8>>();

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum SyscallChunkKind {
    Riscv,
    Precompile,
}

impl fmt::Display for SyscallChunkKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SyscallChunkKind::Riscv => write!(f, "Riscv"),
            SyscallChunkKind::Precompile => write!(f, "Precompile"),
        }
    }
}

/// A chip that stores the syscall invocations.
pub struct SyscallChip<F> {
    chunk_kind: SyscallChunkKind,
    phantom: PhantomData<F>,
}

impl<F: PrimeField32> SyscallChip<F> {
    pub const fn new(chunk_kind: SyscallChunkKind) -> Self {
        Self {
            chunk_kind,
            phantom: PhantomData,
        }
    }

    pub const fn riscv() -> Self {
        Self::new(SyscallChunkKind::Riscv)
    }

    pub const fn precompile() -> Self {
        Self::new(SyscallChunkKind::Precompile)
    }
}

/*
#[cfg(test)]
mod tests {
    use crate::{
        chips::{
            chips::{
                byte::{columns::NUM_BYTE_MULT_COLS, ByteChip},
                syscall::SyscallChunkKind,
            },
            tests::init_test_stream,
            trace::TraceData,
        },
        emulator::{
            opts::EmulatorOpts,
            riscv::{
                emulator::{programs::simple_precompile_program, RiscvEmulator},
                public_values::RecordFinalPvsState,
                record::EmulationRecord,
            },
        },
        instances::{
            compiler::shapes::riscv_shape::RiscvPadShape,
            preparer::{
                gpu_allocate_and_copy_global_events, gpu_allocate_byte_trace,
                gpu_finalize_byte_trace, precompute_event_size, verify_global_events,
                PreallocatedGpuMemory, PreparedGpuEvents,
            },
        },
        machine::chip::ChipBehavior,
    };
    use p3_koala_bear::KoalaBear;
    use p3_matrix::dense::RowMajorMatrix;
    use std::sync::Arc;

    use super::SyscallChip;

    type F = KoalaBear;

    fn cpu_generate_main(chip: &SyscallChip<F>, input: &EmulationRecord) -> RowMajorMatrix<F> {
        chip.generate_main(input, &mut EmulationRecord::default())
    }

    fn gpu_generate_extra_record_and_main(
        chip: &SyscallChip<F>,
        input: &EmulationRecord,
        prepared_gpu_events: &PreparedGpuEvents,
        preallocated_gpu_memory: &mut PreallocatedGpuMemory,
    ) -> RowMajorMatrix<F> {
        let stream = init_test_stream();

        let trace = chip.gpu_generate_extra_record_and_main(
            0,
            input,
            &prepared_gpu_events,
            preallocated_gpu_memory,
        );
        trace.to_host(stream)
    }

    fn prepare_record() -> EmulationRecord {
        let program = simple_precompile_program();
        let final_pvs_state = Arc::new(RecordFinalPvsState::default());
        let mut runtime =
            RiscvEmulator::new_single::<F>(program, final_pvs_state, EmulatorOpts::default(), None);
        let batch_records = runtime.run(None).unwrap().0;
        let chunk = &batch_records[6];
        let precompile_syscall_events = chunk
            .precompile_events
            .events
            .iter()
            .map(|(_, v)| v.iter().map(|(e, _)| *e).collect::<Vec<_>>())
            .flatten()
            .collect::<Vec<_>>();
        let mut result = EmulationRecord::default();
        result.syscall_events = precompile_syscall_events;

        result
    }

    #[test]
    fn test_syscall_generate_extra_record_and_main() {
        let original_record = prepare_record();

        let chip = SyscallChip::<F>::new(SyscallChunkKind::Riscv);

        let mut complete_record = original_record.clone();
        chip.extra_record(&original_record, &mut complete_record);

        let mut counted_record = original_record.clone();
        let mut event_counter = precompute_event_size::<F>(&mut counted_record);
        // Ignore Poseidon2 event counting
        event_counter.num_poseidon2_events = complete_record.poseidon2_events.len();
        event_counter.assert_event_counts_match(&complete_record);

        complete_record.shape = Some(RiscvPadShape::default());
        complete_record
            .shape
            .as_mut()
            .unwrap()
            .inner
            .insert(chip.name(), 10);
        counted_record.shape = Some(RiscvPadShape::default());
        counted_record
            .shape
            .as_mut()
            .unwrap()
            .inner
            .insert(chip.name(), 10);

        let cpu_trace = cpu_generate_main(&chip, &complete_record);
        let byte_chip = ByteChip::<F>::default();
        let cpu_byte_trace =
            byte_chip.generate_main(&complete_record, &mut EmulationRecord::default());

        let stream = init_test_stream();
        let prepared_gpu_events = PreparedGpuEvents::new(&counted_record, event_counter.clone());

        let global_memory =
            gpu_allocate_and_copy_global_events(&stream, 0, &counted_record, &prepared_gpu_events)
                .unwrap();
        let byte_memory = gpu_allocate_byte_trace(&stream, 0).unwrap();
        let mut preallocated_gpu_memory = PreallocatedGpuMemory {
            d_cpu_events: None,
            d_add_sub_events: None,
            d_lt_events: None,
            d_mul_events: None,
            d_global_events: global_memory,
            d_poseidon2_events: None,
            d_byte_trace: byte_memory,
        };

        let gpu_trace = gpu_generate_extra_record_and_main(
            &chip,
            &counted_record,
            &prepared_gpu_events,
            &mut preallocated_gpu_memory,
        );

        // Assert trace consistency.
        assert_eq!(cpu_trace, gpu_trace);

        // Assert global events are consistent.
        verify_global_events(
            &preallocated_gpu_memory.d_global_events,
            &complete_record,
            &stream,
            event_counter
                .start_indices
                .syscall_riscv_extra_global_lookup_start_index,
            event_counter.num_global_lookup_events,
        );

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
