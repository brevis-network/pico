use super::{
    columns::{
        ProgramMultiplicityCols, ProgramPreprocessedCols, NUM_PROGRAM_MULT_COLS,
        NUM_PROGRAM_PREPROCESSED_COLS,
    },
    ProgramChip,
};
#[cfg(feature = "cuda")]
use crate::{
    chips::{trace::TraceData, utils::next_power_of_two},
    cuda_adaptor::{get_global_mem_pool, get_global_stream_pool},
    instances::preparer::PreparedGpuEvents,
    machine::chip::GpuChipBehavior,
};
use crate::{
    compiler::{addr::Pc, riscv::program::Program},
    emulator::riscv::record::EmulationRecord,
    iter::{IndexedPicoIterator, IntoPicoRefIterator, PicoIterator},
    machine::{
        chip::ChipBehavior,
        utils::{pad_to_power_of_two, pad_to_power_of_two_repeating_first_row},
    },
};
#[cfg(feature = "cuda")]
use cudart::{
    memory_pools::DevicePoolAllocation,
    slice::{CudaSlice, CudaSliceMut},
    stream::{CudaStream, CudaStreamCreateFlags},
};
#[cfg(feature = "cuda")]
use cudart_sys::*;
use hashbrown::HashMap;
use p3_field::PrimeField32;
#[cfg(feature = "cuda")]
use p3_koala_bear::KoalaBear;
use p3_matrix::dense::RowMajorMatrix;
#[cfg(feature = "cuda")]
use pico_gpu_api::{
    cuda_riscv_program_generate_main_u64, cuda_riscv_program_generate_main_u64_packed,
    cuda_riscv_program_generate_preprocessed_u64,
};
use std::borrow::BorrowMut;
#[cfg(feature = "cuda")]
use tracing::info;

/// Row 0 is the filler for the padding rows and for every trap (UNIMP / EBREAK) instruction, so
/// it must not be a trap itself: a trap row in the table would be claimable as a no-op once there
/// is no `is_unimpl` selector to reject it. A transpiled program starts at `_start`, so this never
/// fires in production; a program whose first word does not decode (the disassembler emits UNIMP
/// for those) fails here, at keygen.
fn assert_instruction_zero_is_not_a_trap(program: &Program) {
    let first = program
        .instructions
        .first()
        .expect("the Program chip needs at least one instruction");
    assert!(
        !first.opcode.is_trap(),
        "instruction 0 ({:?}) is a trap; the preprocessed table uses row 0 as the filler for trap rows and padding",
        first.opcode
    );
}

impl<F: PrimeField32> ChipBehavior<F> for ProgramChip<F> {
    type Record = EmulationRecord;
    type Program = Program;

    fn name(&self) -> String {
        "Program".to_string()
    }

    fn preprocessed_width(&self) -> usize {
        NUM_PROGRAM_PREPROCESSED_COLS
    }

    fn generate_preprocessed(&self, program: &Program) -> Option<RowMajorMatrix<F>> {
        debug_assert!(!program.instructions.is_empty(), "empty program");
        assert_instruction_zero_is_not_a_trap(program);
        // `jalr_lsb` is pinned by membership because every table pc has the same residue mod 4
        // (`riscv_cpu/jump/constraints.rs`); that needs a 4-aligned base.
        assert!(
            program.pc_base.is_multiple_of(4),
            "pc_base {:#x} is not 4-aligned",
            program.pc_base
        );

        let rows = program
            .instructions
            .iter()
            .enumerate()
            .map(|(i, instruction)| {
                let pc = program.pc_base + (i as u64 * 4);
                let mut row = [F::ZERO; NUM_PROGRAM_PREPROCESSED_COLS];
                let cols: &mut ProgramPreprocessedCols<F> = row.as_mut_slice().borrow_mut();
                // Two limbs: `Pc::try_from` rejects a pc at or above 2^32, and
                // `InstructionCols::populate` rejects an operand whose bits 32..64 are not a
                // sign fill. Both hold for every transpiled program (guest addresses stay below
                // `0x7800_0000`); a program that violates either fails here, at keygen.
                //
                // A Cpu-chip argument leans on this bound and it is asserted here so the premise
                // is checked where the table is built, not only by the ELF loader: a jump row's
                // return address `pc + 4` has a canonical limb 1 because `pc[1] <= 0x77FF` and a
                // canonical limb 0 because the `pc_carry` column below is the carry out of
                // `pc[0] + 4` (`register/constraints.rs`).
                assert!(
                    pc < 0x7800_0000,
                    "program pc {pc:#x} outside the guest address space"
                );
                // A trap instruction (UNIMP / EBREAK) gets row 0's content instead of its own,
                // exactly as the padding rows do: the emulator never executes a trap, so no Cpu
                // row ever needs this pc, and leaving the pc out of the table is what makes a Cpu
                // row that claims it unprovable (there is no `is_unimpl` selector to reject it
                // with). The CUDA kernel applies the same rule (`program.cuh`).
                let (row_pc, source) = if instruction.opcode.is_trap() {
                    (program.pc_base, &program.instructions[0])
                } else {
                    (pc, instruction)
                };
                cols.pc = Pc::try_from(row_pc).unwrap();
                // The carry out of limb 0 in `row_pc + 4`, as a function of the row's own pc
                // (a trap row therefore carries row 0's). The Cpu chip writes the same
                // `[pc[0] >= 0xFFFC]` on every real row and the Program message carries it; the
                // CUDA kernel writes the same value (`program.cuh`).
                cols.pc_carry = F::from_bool((row_pc & 0xFFFF) >= 0xFFFC);
                cols.instruction.populate(*source);
                cols.selectors.populate(*source);

                row
            })
            .collect::<Vec<_>>();

        // Convert the trace to a row major matrix.
        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_PROGRAM_PREPROCESSED_COLS,
        );

        let log_size = program.fixed_log2_rows(&self.name());
        // Pad by repeating instruction 0, not with zeros. A zero row is a valid entry in this
        // table -- it reads as "pc = 0 holds an instruction with no opcode selected and
        // op_a_0 = 0" -- and the multiplicity column is prover-supplied and ungated, so a CPU
        // row could claim to execute it. Repeating a real instruction leaves nothing to claim.
        // Trap rows are filled the same way (see the loop above), which is why instruction 0
        // must not itself be a trap.
        pad_to_power_of_two_repeating_first_row::<NUM_PROGRAM_PREPROCESSED_COLS, F>(
            &mut trace.values,
            log_size,
        );

        Some(trace)
    }

    fn generate_main(&self, input: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {
        // Collect instruction counts in parallel using a thread-safe HashMap
        let instruction_counts: HashMap<u64, usize> = input
            .cpu_events
            .as_slice()
            .pico_iter()
            .pico_fold(HashMap::new, |mut acc, event| {
                let pc = event.pc;
                *acc.entry(pc).or_insert(0) += 1;
                acc
            })
            .pico_reduce(HashMap::new, |mut a, b| {
                b.into_iter().for_each(|(pc, count)| {
                    *a.entry(pc).or_insert(0) += count;
                });
                a
            });

        // Generate rows in parallel
        let rows: Vec<[F; NUM_PROGRAM_MULT_COLS]> = input
            .program
            .instructions
            .pico_iter()
            .enumerate()
            .map(|(i, _)| {
                let pc = input.program.pc_base + (i as u64 * 4);
                let mut row = [F::ZERO; NUM_PROGRAM_MULT_COLS];
                let cols: &mut ProgramMultiplicityCols<F> = row.as_mut_slice().borrow_mut();
                cols.multiplicity = F::from_usize(*instruction_counts.get(&pc).unwrap_or(&0));
                row
            })
            .collect();

        // Convert the trace to a row major matrix
        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_PROGRAM_MULT_COLS,
        );

        // Pad the trace to a power of two
        let log_rows = input.shape_chip_size(&self.name());
        pad_to_power_of_two::<NUM_PROGRAM_MULT_COLS, F>(&mut trace.values, log_rows);

        trace
    }

    fn is_active(&self, _record: &Self::Record) -> bool {
        true
    }
}

#[cfg(feature = "cuda")]
impl<F: PrimeField32> GpuChipBehavior<F> for ProgramChip<F> {
    fn gpu_generate_preprocessed(
        &self,
        device_id: usize,
        program: &Self::Program,
    ) -> Option<TraceData<'_, F>> {
        use p3_koala_bear::KoalaBear;

        let instructions = program.instructions.clone();

        let nb_rows = instructions.len();
        let fixed_log2_rows = program.fixed_log2_rows(&self.name());
        let padded_nb_rows = match fixed_log2_rows {
            Some(log2_rows) => 1 << log2_rows,
            None => next_power_of_two(nb_rows, None),
        };

        let stream = &CudaStream::create_with_flags(CudaStreamCreateFlags::NON_BLOCKING).unwrap();

        // get current memory pool
        let sync_mem_pool = get_global_mem_pool(device_id);
        let mem_pool = &sync_mem_pool.0;

        let trace_size = padded_nb_rows * self.preprocessed_width();
        let mut d_trace =
            DevicePoolAllocation::<KoalaBear>::alloc_from_pool_async(trace_size, mem_pool, stream)
                .unwrap();
        unsafe {
            let _ = cudaMemsetAsync(
                d_trace.as_mut_ptr() as *mut _,
                0,
                trace_size * size_of::<KoalaBear>(),
                stream.into(),
            );
        }

        // The kernel writes row 0 in place of every trap instruction and never checks row 0
        // itself; the check lives here, on both generation paths.
        assert_instruction_zero_is_not_a_trap(program);

        let num_instrs = instructions.len();
        if num_instrs > 0 {
            use crate::compiler::riscv::instruction::Instruction;
            let mut d_instrs = DevicePoolAllocation::<Instruction>::alloc_from_pool_async(
                num_instrs, mem_pool, stream,
            )
            .unwrap();
            unsafe {
                let _ = cudaMemcpyAsync(
                    d_instrs.as_mut_c_void_ptr(),
                    instructions.as_c_void_ptr(),
                    num_instrs * size_of::<Instruction>(),
                    CudaMemoryCopyKind::HostToDevice,
                    stream.into(),
                );

                cuda_riscv_program_generate_preprocessed_u64(
                    d_instrs.as_ptr() as *const _,
                    num_instrs,
                    padded_nb_rows,
                    program.pc_base,
                    d_trace.as_mut_ptr() as *mut _,
                    self.preprocessed_width(),
                    stream.into(),
                );
            }
        }

        let sync_stream = get_global_stream_pool(device_id);
        let main_stream = &sync_stream.0;
        stream.synchronize().unwrap();
        let d_trace = d_trace.swap_stream(main_stream);
        stream.synchronize().unwrap();
        main_stream.synchronize().unwrap();

        info!("[riscv-program-chip] generate_preprocessed on GPU");

        Some(TraceData::Gpu(self.preprocessed_width(), d_trace))
    }

    fn gpu_generate_main(
        &self,
        device_id: usize,
        input: &Self::Record,
        _: &mut Self::Record,
    ) -> TraceData<'_, F> {
        let nb_rows = input.program.instructions.len();
        let log_rows = input.shape_chip_size(&ProgramChip::<F>::default().name());
        let padded_nb_rows = match log_rows {
            Some(log_rows) => 1 << log_rows,
            None => next_power_of_two(nb_rows, None),
        };

        let stream = &CudaStream::create_with_flags(CudaStreamCreateFlags::NON_BLOCKING).unwrap();

        let sync_mem_pool = get_global_mem_pool(device_id);
        let mem_pool = &sync_mem_pool.0;

        let trace_size = padded_nb_rows * NUM_PROGRAM_MULT_COLS;
        let mut d_trace =
            DevicePoolAllocation::<KoalaBear>::alloc_from_pool_async(trace_size, mem_pool, stream)
                .unwrap();
        unsafe {
            let _ = cudaMemsetAsync(
                d_trace.as_mut_ptr() as *mut _,
                0,
                trace_size * size_of::<KoalaBear>(),
                stream.into(),
            );
        }

        let events = &input.cpu_events;
        let event_size = events.len();
        if event_size > 0 {
            use crate::chips::chips::riscv_cpu::event::CpuEvent;
            let mut d_events = DevicePoolAllocation::<CpuEvent>::alloc_from_pool_async(
                event_size, mem_pool, stream,
            )
            .unwrap();
            unsafe {
                let _ = cudaMemcpyAsync(
                    d_events.as_mut_c_void_ptr(),
                    events.as_ptr() as *const _,
                    event_size * size_of::<CpuEvent>(),
                    CudaMemoryCopyKind::HostToDevice,
                    stream.into(),
                );
            }

            unsafe {
                cuda_riscv_program_generate_main_u64(
                    NUM_PROGRAM_MULT_COLS,
                    event_size,
                    trace_size,
                    input.program.pc_base,
                    d_events.as_ptr() as *const _,
                    d_trace.as_mut_ptr() as *mut _,
                    stream.into(),
                    nb_rows,
                );
            }
        }

        let sync_stream = get_global_stream_pool(device_id);
        let main_stream = &sync_stream.0;
        stream.synchronize().unwrap();
        let d_trace = d_trace.swap_stream(main_stream);
        stream.synchronize().unwrap();
        main_stream.synchronize().unwrap();

        info!("[riscv-program-chip] generate_main on GPU");

        TraceData::Gpu(NUM_PROGRAM_MULT_COLS, d_trace)
    }

    fn is_active_for_extra_record(&self, _record: &PreparedGpuEvents) -> bool {
        true
    }

    fn gpu_generate_extra_record_and_main(
        &self,
        device_id: usize,
        input: &Self::Record,
        prepared_gpu_events: &PreparedGpuEvents,
        preallocated_gpu_memory: &mut crate::instances::preparer::PreallocatedGpuMemory,
    ) -> TraceData<'_, F> {
        let event_size = prepared_gpu_events.event_counter.num_cpu_events;

        let nb_rows = input.program.instructions.len();
        let log_rows = input.shape_chip_size(&ProgramChip::<F>::default().name());
        let padded_nb_rows = match log_rows {
            Some(log_rows) => 1 << log_rows,
            None => next_power_of_two(nb_rows, None),
        };

        let stream = &CudaStream::create_with_flags(CudaStreamCreateFlags::NON_BLOCKING).unwrap();

        let sync_mem_pool = get_global_mem_pool(device_id);
        let mem_pool = &sync_mem_pool.0;

        let trace_size = padded_nb_rows * NUM_PROGRAM_MULT_COLS;
        let mut d_trace =
            DevicePoolAllocation::<KoalaBear>::alloc_from_pool_async(trace_size, mem_pool, stream)
                .unwrap();
        unsafe {
            let _ = cudaMemsetAsync(
                d_trace.as_mut_ptr() as *mut _,
                0,
                trace_size * size_of::<KoalaBear>(),
                stream.into(),
            );
        }

        if event_size > 0 {
            let d_cpu_events_ptr = preallocated_gpu_memory
                .d_cpu_events
                .as_ref()
                .unwrap()
                .as_ptr() as *const _;

            if prepared_gpu_events.packed.is_some() {
                // MLE_PACKED_EVENTS: d_cpu_events holds the 80B packed stream.
                unsafe {
                    let err = cuda_riscv_program_generate_main_u64_packed(
                        NUM_PROGRAM_MULT_COLS,
                        event_size,
                        trace_size,
                        input.program.pc_base,
                        d_cpu_events_ptr,
                        d_trace.as_mut_ptr() as *mut _,
                        stream.into(),
                        nb_rows,
                        crate::instances::preparer::PACKED_EVENT_FORMAT_V1,
                    );
                    assert_eq!(
                        err.code, 0,
                        "cuda_riscv_program_generate_main_u64_packed failed (packed format mismatch?)"
                    );
                }
            } else {
                unsafe {
                    cuda_riscv_program_generate_main_u64(
                        NUM_PROGRAM_MULT_COLS,
                        event_size,
                        trace_size,
                        input.program.pc_base,
                        d_cpu_events_ptr,
                        d_trace.as_mut_ptr() as *mut _,
                        stream.into(),
                        nb_rows,
                    );
                }
            }
        }

        let sync_stream = get_global_stream_pool(device_id);
        let main_stream = &sync_stream.0;
        stream.synchronize().unwrap();
        let d_trace = d_trace.swap_stream(main_stream);
        stream.synchronize().unwrap();
        main_stream.synchronize().unwrap();

        info!("[riscv-program-chip] generate_extra_record_and_main on GPU");

        TraceData::Gpu(NUM_PROGRAM_MULT_COLS, d_trace)
    }
}
