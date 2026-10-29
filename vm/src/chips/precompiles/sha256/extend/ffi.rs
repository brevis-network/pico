use crate::{
    chips::chips::events::{MemoryReadRecord, MemoryWriteRecord},
    emulator::riscv::syscalls::precompiles::ShaExtendEvent,
};

/// FFI-compatible representation of ShaExtendEvent for CUDA interop
/// This matches the C++ ShaExtendEvent structure exactly
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct ShaExtendFfiEvent {
    pub chunk: u32,
    pub _pad1: u32,
    pub clk: u64,
    pub w_ptr: u64,
    pub w_i_minus_15_reads: [MemoryReadRecord; 48],
    pub w_i_minus_2_reads: [MemoryReadRecord; 48],
    pub w_i_minus_16_reads: [MemoryReadRecord; 48],
    pub w_i_minus_7_reads: [MemoryReadRecord; 48],
    pub w_i_writes: [MemoryWriteRecord; 48],
}

impl From<ShaExtendEvent> for ShaExtendFfiEvent {
    fn from(event: ShaExtendEvent) -> Self {
        Self::from(&event)
    }
}

impl From<&ShaExtendEvent> for ShaExtendFfiEvent {
    fn from(event: &ShaExtendEvent) -> Self {
        Self {
            chunk: event.chunk,
            _pad1: 0,
            clk: event.clk,
            w_ptr: event.w_ptr,
            w_i_minus_15_reads: event.w_i_minus_15_reads.as_slice().try_into().unwrap(),
            w_i_minus_2_reads: event.w_i_minus_2_reads.as_slice().try_into().unwrap(),
            w_i_minus_16_reads: event.w_i_minus_16_reads.as_slice().try_into().unwrap(),
            w_i_minus_7_reads: event.w_i_minus_7_reads.as_slice().try_into().unwrap(),
            w_i_writes: event.w_i_writes.as_slice().try_into().unwrap(),
        }
    }
}
