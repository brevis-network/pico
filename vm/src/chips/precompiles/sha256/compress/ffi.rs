use crate::{
    chips::chips::events::{MemoryReadRecord, MemoryWriteRecord},
    emulator::riscv::syscalls::precompiles::ShaCompressEvent,
};

/// FFI-compatible representation of ShaCompressEvent for CUDA interop
/// This matches the C++ ShaCompressEvent structure exactly
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct ShaCompressFfiEvent {
    pub chunk: u32,
    pub _padding: u32,
    pub clk: u64,
    pub w_ptr: u64,
    pub h_ptr: u64,
    pub h: [u32; 8],                              // Initial hash state values
    pub w: [u32; 64],                             // Message schedule array
    pub h_read_records: [MemoryReadRecord; 8],    // Reading initial H values
    pub w_i_read_records: [MemoryReadRecord; 64], // Reading W[i] values during compression
    pub h_write_records: [MemoryWriteRecord; 8],  // Writing final H values
}

impl From<ShaCompressEvent> for ShaCompressFfiEvent {
    fn from(event: ShaCompressEvent) -> Self {
        Self::from(&event)
    }
}

impl From<&ShaCompressEvent> for ShaCompressFfiEvent {
    fn from(event: &ShaCompressEvent) -> Self {
        // Convert Vec<u32> to [u32; 64] for w array
        let mut w_array = [0u32; 64];
        for (i, &val) in event.w.iter().enumerate().take(64) {
            w_array[i] = val;
        }

        // Convert Vec to fixed-size arrays for FFI compatibility
        let mut w_i_read_records_array = [MemoryReadRecord::default(); 64];
        for (i, &rec) in event.w_i_read_records.iter().enumerate().take(64) {
            w_i_read_records_array[i] = rec;
        }

        Self {
            chunk: event.chunk,
            _padding: 0,
            clk: event.clk,
            w_ptr: event.w_ptr,
            h_ptr: event.h_ptr,
            h: event.h,
            w: w_array,
            h_read_records: event.h_read_records,
            w_i_read_records: w_i_read_records_array,
            h_write_records: event.h_write_records,
        }
    }
}
