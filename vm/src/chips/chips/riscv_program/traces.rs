use super::{
    columns::{
        ProgramMultiplicityCols, ProgramPreprocessedCols, NUM_PROGRAM_MULT_COLS,
        NUM_PROGRAM_PREPROCESSED_COLS,
    },
    ProgramChip,
};
use crate::{
    chips::gadgets::code_range::code_range_lookups,
    compiler::{addr::Pc, riscv::program::Program},
    emulator::riscv::record::EmulationRecord,
    iter::{IndexedPicoIterator, IntoPicoRefIterator, PicoIterator},
    machine::{
        chip::ChipBehavior,
        utils::{pad_to_power_of_two, pad_to_power_of_two_repeating_first_row},
    },
};
#[cfg(feature = "cuda")]
use crate::{
    chips::{
        chips::riscv_cpu::traces::chunk_history_reader, trace::TraceData, utils::next_power_of_two,
    },
    cuda_adaptor::{get_global_mem_pool, get_global_stream_pool},
    emulator::riscv::history_fill::HISTORY_LAYOUT,
    instances::preparer::{PreallocatedGpuMemory, PreparedGpuEvents},
    machine::chip::GpuChipBehavior,
    mle::{machine::trace_oracle::history_launch, spans::device},
};
#[cfg(feature = "cuda")]
use cudart::{
    memory_pools::DevicePoolAllocation,
    slice::{CudaSlice, CudaSliceMut},
    stream::{CudaStream, CudaStreamCreateFlags},
};
#[cfg(feature = "cuda")]
use cudart_sys::*;
#[cfg(feature = "cuda")]
use p3_field::PrimeCharacteristicRing;
use p3_field::PrimeField32;
#[cfg(feature = "cuda")]
use p3_koala_bear::KoalaBear;
use p3_matrix::dense::RowMajorMatrix;
#[cfg(feature = "cuda")]
use pico_gpu_api::{
    cuda_riscv_program_generate_preprocessed_u64,
    history_cpu_memory_lt::cuda_riscv_program_generate_main_history,
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
                // The code's range, the same on every row.
                let limbs = |value: u64| [value as u16, (value >> 16) as u16].map(F::from_u16);
                let code = program.code();
                cols.code_start = limbs(code.start);
                cols.code_end = limbs(code.end);

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
        let instruction_counts = input.cpu_steps().pc_counts();
        let code_range_lookups = code_range_lookups(input);

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
                if i == 0 {
                    cols.code_range_multiplicity = F::from_usize(code_range_lookups);
                }
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

    fn is_active_for_extra_record(&self, _record: &PreparedGpuEvents) -> bool {
        true
    }

    fn gpu_generate_extra_record_and_main(
        &self,
        device_id: usize,
        input: &Self::Record,
        _prepared_gpu_events: &PreparedGpuEvents,
        preallocated_gpu_memory: &mut PreallocatedGpuMemory,
    ) -> TraceData<'_, F> {
        // A deferred record carries no history and runs no instruction: every execution count is 0.
        if preallocated_gpu_memory.d_history.is_some() {
            return self.gpu_generate_from_history(device_id, input, preallocated_gpu_memory);
        }

        let nb_rows = input.program.instructions.len();
        let log_rows = input.shape_chip_size(&self.name());
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
        let fill = device::start(stream);
        unsafe {
            let _ = cudaMemsetAsync(
                d_trace.as_mut_ptr() as *mut _,
                0,
                trace_size * size_of::<KoalaBear>(),
                stream.into(),
            );
        }
        // A deferred record's writing rows are its precompile events'.
        put_code_range_lookups(&mut d_trace, code_range_lookups(input), stream);
        device::filled(fill, stream);

        let sync_stream = get_global_stream_pool(device_id);
        let main_stream = &sync_stream.0;
        device::wait(stream).unwrap();
        let d_trace = d_trace.swap_stream(main_stream);
        device::wait(stream).unwrap();
        device::wait(main_stream).unwrap();

        info!("[riscv-program-chip] generate_extra_record_and_main on GPU, no instruction run");

        TraceData::Gpu(NUM_PROGRAM_MULT_COLS, d_trace)
    }
}

/// Row 0's code-range multiplicity: the record's writing rows, put behind the kernels that
/// zero the trace and count the executions on `stream`, which leave that column alone.
#[cfg(feature = "cuda")]
fn put_code_range_lookups(
    d_trace: &mut DevicePoolAllocation<'_, KoalaBear>,
    lookups: usize,
    stream: &CudaStream,
) {
    let value = KoalaBear::from_usize(lookups);
    // From pageable memory, so the driver has staged `value` by the time this returns.
    unsafe {
        let _ = cudaMemcpyAsync(
            (d_trace.as_mut_ptr() as *mut KoalaBear).add(1) as *mut _,
            (&raw const value).cast(),
            size_of::<KoalaBear>(),
            CudaMemoryCopyKind::HostToDevice,
            stream.into(),
        );
    }
}

#[cfg(feature = "cuda")]
impl<F: PrimeField32> ProgramChip<F> {
    /// The execution counts from the chunk's history on the device: one thread per step of the
    /// fill adds one to its pc's row, so no CPU event is uploaded or read. The trace is the
    /// program's rows.
    fn gpu_generate_from_history(
        &self,
        device_id: usize,
        input: &EmulationRecord,
        preallocated_gpu_memory: &PreallocatedGpuMemory,
    ) -> TraceData<'_, F> {
        let nb_rows = input.program.instructions.len();
        let log_rows = input.shape_chip_size(&self.name());
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

        let reader = chunk_history_reader(preallocated_gpu_memory, stream);
        let args = reader.args();
        let kernels = device::start(stream);
        let err = unsafe {
            cuda_riscv_program_generate_main_history(
                std::ptr::from_ref(&args).cast(),
                HISTORY_LAYOUT,
                NUM_PROGRAM_MULT_COLS,
                trace_size,
                nb_rows,
                d_trace.as_mut_ptr() as *mut _,
                stream.into(),
            )
        };
        assert_eq!(
            err.code, 0,
            "cuda_riscv_program_generate_main_history failed: {err}"
        );
        put_code_range_lookups(&mut d_trace, code_range_lookups(input), stream);
        history_launch::note(&self.name());
        drop(reader);

        let sync_stream = get_global_stream_pool(device_id);
        let main_stream = &sync_stream.0;
        device::launched(kernels, stream);
        device::wait(stream).unwrap();
        let d_trace = d_trace.swap_stream(main_stream);
        device::wait(stream).unwrap();
        device::wait(main_stream).unwrap();

        info!("[riscv-program-chip] generate_extra_record_and_main from the history on GPU");

        TraceData::Gpu(NUM_PROGRAM_MULT_COLS, d_trace)
    }
}
