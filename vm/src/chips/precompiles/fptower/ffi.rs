use hybrid_array::{Array, ArraySize};

use crate::{
    chips::{
        chips::events::{MemoryReadRecord, MemoryWriteRecord},
        gadgets::field::field_op::FieldOperation,
    },
    emulator::riscv::syscalls::precompiles::{Fp2AddSubEvent, Fp2MulEvent, FpEvent},
};

/// FFI Base field fp event.
///
/// `WordsFieldElement` is the number of u64 dwords (= NumLimbs/8).
/// x/y are stored as u64 dwords matching the Rust RvValue type.
/// Memory records use `WordsFieldElement` entries (one per u64 dword).
#[derive(Default, Debug, Clone)]
#[repr(C)]
pub struct FfiFpEvent<WordsFieldElement: ArraySize> {
    pub chunk: u32,
    pub clk: u32,
    pub x_ptr: u32,
    pub x: Array<u64, WordsFieldElement>,
    pub y_ptr: u32,
    pub y: Array<u64, WordsFieldElement>,
    pub op: FieldOperation,
    pub x_memory_records: Array<MemoryWriteRecord, WordsFieldElement>,
    pub y_memory_records: Array<MemoryReadRecord, WordsFieldElement>,
}

impl<WordsFieldElement: ArraySize> From<&FpEvent> for FfiFpEvent<WordsFieldElement> {
    fn from(event: &FpEvent) -> Self {
        Self {
            chunk: event.chunk,
            clk: event.clk.try_into().unwrap(),
            x_ptr: event.x_ptr.try_into().unwrap(),
            x: Array::try_from(&*event.x).expect("Failed to convert event.x"),
            y_ptr: event.y_ptr.try_into().unwrap(),
            y: Array::try_from(&*event.y).expect("Failed to convert event.y"),
            op: event.op,
            x_memory_records: Array::try_from(&*event.x_memory_records)
                .expect("Failed to convert event.x_memory_records"),
            y_memory_records: Array::try_from(&*event.y_memory_records)
                .expect("Failed to convert event.y_memory_records"),
        }
    }
}

/// FFI Base field fp2 addition and subtraction events
#[derive(Default, Debug, Clone)]
#[repr(C)]
pub struct FfiFp2AddSubEvent<WordsCurvePoint: ArraySize> {
    pub chunk: u32,
    pub clk: u32,
    pub x_ptr: u32,
    pub x: Array<u64, WordsCurvePoint>,
    pub y_ptr: u32,
    pub y: Array<u64, WordsCurvePoint>,
    pub op: FieldOperation,
    pub x_memory_records: Array<MemoryWriteRecord, WordsCurvePoint>,
    pub y_memory_records: Array<MemoryReadRecord, WordsCurvePoint>,
}

impl<WordsCurvePoint: ArraySize> From<&Fp2AddSubEvent> for FfiFp2AddSubEvent<WordsCurvePoint> {
    fn from(event: &Fp2AddSubEvent) -> Self {
        Self {
            chunk: event.chunk,
            clk: event.clk.try_into().unwrap(),
            x_ptr: event.x_ptr.try_into().unwrap(),
            x: Array::try_from(&*event.x).expect("Failed to convert event.x"),
            y_ptr: event.y_ptr.try_into().unwrap(),
            y: Array::try_from(&*event.y).expect("Failed to convert event.y"),
            op: event.op,
            x_memory_records: Array::try_from(&*event.x_memory_records)
                .expect("Failed to convert event.x_memory_records"),
            y_memory_records: Array::try_from(&*event.y_memory_records)
                .expect("Failed to convert event.y_memory_records"),
        }
    }
}

/// Fp2 multiplication events
#[derive(Default, Debug, Clone)]
#[repr(C)]
pub struct FfiFp2MulEvent<WordsCurvePoint: ArraySize> {
    pub chunk: u32,
    pub clk: u32,
    pub x_ptr: u32,
    pub x: Array<u64, WordsCurvePoint>,
    pub y_ptr: u32,
    pub y: Array<u64, WordsCurvePoint>,
    pub x_memory_records: Array<MemoryWriteRecord, WordsCurvePoint>,
    pub y_memory_records: Array<MemoryReadRecord, WordsCurvePoint>,
}

impl<WordsCurvePoint: ArraySize> From<&Fp2MulEvent> for FfiFp2MulEvent<WordsCurvePoint> {
    fn from(event: &Fp2MulEvent) -> Self {
        Self {
            chunk: event.chunk,
            clk: event.clk.try_into().unwrap(),
            x_ptr: event.x_ptr.try_into().unwrap(),
            x: Array::try_from(&*event.x).expect("Failed to convert event.x"),
            y_ptr: event.y_ptr.try_into().unwrap(),
            y: Array::try_from(&*event.y).expect("Failed to convert event.y"),
            x_memory_records: Array::try_from(&*event.x_memory_records)
                .expect("Failed to convert event.x_memory_records"),
            y_memory_records: Array::try_from(&*event.y_memory_records)
                .expect("Failed to convert event.y_memory_records"),
        }
    }
}
