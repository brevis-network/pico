use super::{
    columns::{ByteMultCols, BytePreprocessedCols, NUM_BYTE_MULT_COLS, NUM_BYTE_PREPROCESSED_COLS},
    event::ByteLookupEvent,
    utils::shr_carry,
    ByteChip,
};
use crate::{
    chips::trace::TraceData,
    compiler::riscv::{opcode::ByteOpcode, program::Program},
    cuda_adaptor::resource_pool::{
        mem_pool::get_global_mem_pool, stream_pool::get_global_stream_pool,
    },
    emulator::riscv::{ffi::FFIEmulationRecord, record::EmulationRecord},
    machine::chip::ChipBehavior,
};
use cudart::{
    memory_pools::DevicePoolAllocation,
    slice::CudaSliceMut,
    stream::{CudaStream, CudaStreamCreateFlags},
};
use itertools::Itertools;
use p3_field::{Field, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;
use p3_maybe_rayon::prelude::{IndexedParallelIterator, ParallelIterator, ParallelSliceMut};
use pico_gpu_api::cuda_byte_generate_preprocessed;
use std::borrow::BorrowMut;
use tracing::info;

pub const NUM_ROWS: usize = 1 << 17;

/// The row of the byte table a lookup's multiplicity is counted on.
///
/// Every producer of the table has to agree on it: [`ByteChip::generate_main`], the device
/// kernels (`handle_byte_lookup_event` / `handle_bit_range_check_event` in pico-gpu's
/// `src/tracegen/riscv/byte.cuh`) and the host lookups `gpu_add_host_byte_lookups` adds to the
/// device table. A lookup counted on another row than the preprocessed one it asserts leaves the
/// byte bus unbalanced.
///
/// Rows `0..2^16` are the `(b << 8) | c` operand pairs, shared by every opcode and by `BitRange`
/// at 16 bits. `BitRange` below 16 bits lives in the second half, at `2^16 + a + 2^bits` with
/// `a = (b << 8) | c`, so each width owns the rows `2^16 + [2^bits, 2^(bits + 1))`.
pub fn byte_lookup_row(lookup: &ByteLookupEvent) -> usize {
    let pair = ((lookup.b as usize) << 8) | lookup.c as usize;
    if lookup.opcode == ByteOpcode::BitRange && lookup.a2 < 16 {
        (1 << 16) + pair + (1 << lookup.a2)
    } else {
        pair
    }
}

impl<F: PrimeField32> ChipBehavior<F> for ByteChip<F> {
    type Record = EmulationRecord;
    type GpuRecord = FFIEmulationRecord;
    type Program = Program;

    fn name(&self) -> String {
        "Byte".to_string()
    }

    fn preprocessed_width(&self) -> usize {
        NUM_BYTE_PREPROCESSED_COLS
    }

    fn generate_preprocessed(&self, _program: &Program) -> Option<RowMajorMatrix<F>> {
        let trace = Self::preprocess();
        Some(trace)
    }

    fn generate_main(&self, input: &EmulationRecord, _: &mut EmulationRecord) -> RowMajorMatrix<F> {
        let mut values = vec![F::ZERO; NUM_BYTE_MULT_COLS * NUM_ROWS];

        // Convert HashMap entries to Vec for parallel iteration
        let lookups: Vec<_> = input.byte_lookups.iter().collect();

        values
            .par_chunks_mut(NUM_BYTE_MULT_COLS)
            .enumerate()
            .for_each(|(row_idx, row)| {
                for (lookup, mult) in lookups.iter() {
                    if row_idx == byte_lookup_row(lookup) {
                        let cols: &mut ByteMultCols<F> = row.borrow_mut();
                        let index = lookup.opcode as usize;
                        cols.multiplicities[index] += F::from_usize(**mult);
                    }
                }
            });

        RowMajorMatrix::new(values, NUM_BYTE_MULT_COLS)
    }

    fn is_active(&self, _record: &Self::Record) -> bool {
        true
    }

    fn gpu_generate_preprocessed(
        &self,
        device_id: usize,
        _program: &Self::Program,
    ) -> Option<TraceData<'_, F>> {
        use p3_koala_bear::KoalaBear;

        let padded_nb_rows = NUM_ROWS;
        let stream = &CudaStream::create_with_flags(CudaStreamCreateFlags::NON_BLOCKING).unwrap();

        // get current memory pool
        let sync_mem_pool = get_global_mem_pool(device_id);
        let mem_pool = &sync_mem_pool.0;

        let trace_size = padded_nb_rows * self.preprocessed_width();
        let mut d_trace =
            DevicePoolAllocation::<KoalaBear>::alloc_from_pool_async(trace_size, mem_pool, stream)
                .unwrap();
        // no need to memset generate_main writes every column of every row
        unsafe {
            cuda_byte_generate_preprocessed(
                d_trace.as_mut_ptr() as *mut _,
                self.preprocessed_width(),
                stream.into(),
            );
        }

        let sync_stream = get_global_stream_pool(device_id);
        let main_stream = &sync_stream.0;
        stream.synchronize().unwrap();
        let d_trace = d_trace.swap_stream(main_stream);
        stream.synchronize().unwrap();
        main_stream.synchronize().unwrap();

        info!("[byte-chip] generate_preprocessed on GPU");

        Some(TraceData::Gpu(self.preprocessed_width(), d_trace))
    }
}

impl<F: Field> ByteChip<F> {
    /// Creates the preprocessed byte trace.
    ///
    /// This function returns a `trace` which is a matrix containing all possible byte operations.
    pub fn preprocess() -> RowMajorMatrix<F> {
        // The trace containing all values, with all multiplicities set to zero.
        let mut initial_trace = RowMajorMatrix::new(
            vec![F::ZERO; NUM_ROWS * NUM_BYTE_PREPROCESSED_COLS],
            NUM_BYTE_PREPROCESSED_COLS,
        );

        // Record all the necessary operations for each byte lookup.
        let opcodes = ByteOpcode::all();

        // Iterate over all options for pairs of bytes `a` and `b`.
        for (row_index, (b, c)) in (0..=u8::MAX).cartesian_product(0..=u8::MAX).enumerate() {
            let col: &mut BytePreprocessedCols<F> = initial_trace.row_mut(row_index).borrow_mut();

            // Set the values of `b` and `c`.
            col.b = F::from_u8(b);
            col.c = F::from_u8(c);

            // Iterate over all operations for results and updating the table map.
            for opcode in opcodes.iter() {
                match opcode {
                    ByteOpcode::AND => {
                        let and = b & c;
                        col.and = F::from_u8(and);
                    }
                    ByteOpcode::OR => {
                        let or = b | c;
                        col.or = F::from_u8(or);
                    }
                    ByteOpcode::XOR => {
                        let xor = b ^ c;
                        col.xor = F::from_u8(xor);
                    }
                    ByteOpcode::SLL => {
                        let sll = b << (c & 7);
                        col.sll = F::from_u8(sll);
                    }
                    ByteOpcode::ShrCarry => {
                        let (res, carry) = shr_carry(b, c);
                        col.shr = F::from_u8(res);
                        col.shr_carry = F::from_u8(carry);
                    }
                    ByteOpcode::LTU => {
                        let ltu = b < c;
                        col.ltu = F::from_bool(ltu);
                    }
                    ByteOpcode::MSB => {
                        let msb = (b & 0b1000_0000) != 0;
                        col.msb = F::from_bool(msb);
                    }
                    ByteOpcode::U8Range => (),
                    ByteOpcode::U16Range => {
                        let v = ((b as u32) << 8) + c as u32;
                        col.value_u16 = F::from_u32(v);
                    }
                    ByteOpcode::BitRange => {
                        let v = ((b as u32) << 8) + c as u32;
                        col.value_u16 = F::from_u32(v);
                        col.bits = F::from_u8(16);
                    }
                };
            }
        }

        // Fill BitRange table for bits = 0..16
        // Rows 65536..131071: bits = 0..15 (bits=16 already filled in first 65536 rows)
        let base_row = 1 << 16;
        for bits in 0..16u8 {
            for a in 0..(1u16 << bits) {
                let row_index = base_row + a as usize + (1usize << bits);
                if row_index < NUM_ROWS {
                    let col: &mut BytePreprocessedCols<F> =
                        initial_trace.row_mut(row_index).borrow_mut();
                    col.value_u16 = F::from_u16(a);
                    col.bits = F::from_u8(bits);
                }
            }
        }
        initial_trace
    }
}
