use hybrid_array::Array;
use serde::{Deserialize, Serialize};
use typenum::Unsigned;

use crate::{
    chips::{
        chips::riscv_memory::event::{MemoryLocalEvent, MemoryReadRecord, MemoryWriteRecord},
        gadgets::{
            curves::{
                edwards::WORDS_FIELD_ELEMENT, AffinePoint, EllipticCurve, COMPRESSED_POINT_BYTES,
                NUM_BYTES_FIELD_ELEMENT,
            },
            utils::field_params::{FieldParameters, NumWords},
        },
    },
    emulator::riscv::{
        event_types::{RvAddr, RvChunk, RvClk, RvValue},
        syscalls::syscall_context::SyscallContext,
    },
};

/// Elliptic Curve Add Event.
///
/// This event is emitted when an elliptic curve addition operation is performed.
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
#[repr(C)]
pub struct EllipticCurveAddEvent {
    /// The chunk number.
    pub chunk: RvChunk,
    /// The clock cycle.
    pub clk: RvClk,
    /// The pointer to the first point.
    pub p_ptr: RvAddr,
    /// The first point in native guest-memory dword form.
    pub p: Vec<RvValue>,
    /// The pointer to the second point.
    pub q_ptr: RvAddr,
    /// The second point in native guest-memory dword form.
    pub q: Vec<RvValue>,
    /// The memory records for the first point.
    pub p_memory_records: Vec<MemoryWriteRecord>,
    /// The memory records for the second point.
    pub q_memory_records: Vec<MemoryReadRecord>,
    /// The local memory access records.
    pub local_mem_access: Vec<MemoryLocalEvent>,
}

/// Memory write record for EC FFI events (u64 values).
#[derive(Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct FfiEcMemoryWriteRecord {
    pub value: u64,
    pub prev_value: u64,
    pub chunk: u32,
    pub timestamp: u32,
    pub prev_chunk: u32,
    pub prev_timestamp: u32,
}

/// Memory read record for EC FFI events (u64 value).
#[derive(Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct FfiEcMemoryReadRecord {
    pub value: u64,
    pub chunk: u32,
    pub timestamp: u32,
    pub prev_chunk: u32,
    pub prev_timestamp: u32,
}

/// FFI version of EllipticCurveAddEvent.
///
/// Point data is passed through as u64 dwords (same count as `WordsCurvePoint`).
/// Memory records are split from u64 into paired u32 records (2 per dword).
/// The GPU code reinterprets the u64 dwords as u32 word pairs.
#[derive(Debug, Clone)]
#[repr(C)]
pub struct EllipticCurveAddEventFFI<P: FieldParameters + NumWords> {
    pub chunk: u32,
    pub clk: u32,
    pub p_ptr: u32,
    /// Point data as u64 dwords (WordsCurvePoint elements).
    /// GPU code reinterprets each u64 as two u32 words.
    pub p: Array<u64, P::WordsCurvePoint>,
    pub q_ptr: u32,
    /// Point data as u64 dwords (WordsCurvePoint elements).
    pub q: Array<u64, P::WordsCurvePoint>,
    /// Memory write records, 2 per dword (lo/hi u32 halves).
    /// Total = 2 * WordsCurvePoint entries.
    pub p_memory_records: Array<FfiEcMemoryWriteRecord, P::WordsCurvePoint>,
    /// Memory read records, 2 per dword (lo/hi u32 halves).
    pub q_memory_records: Array<FfiEcMemoryReadRecord, P::WordsCurvePoint>,
}

impl<P: FieldParameters + NumWords> From<EllipticCurveAddEvent> for EllipticCurveAddEventFFI<P> {
    fn from(event: EllipticCurveAddEvent) -> Self {
        Self::from(&event)
    }
}

impl<P: FieldParameters + NumWords> From<&EllipticCurveAddEvent> for EllipticCurveAddEventFFI<P> {
    fn from(event: &EllipticCurveAddEvent) -> Self {
        let n = P::WordsCurvePoint::USIZE;

        // Point data: copy u64 dwords directly.
        let p = Array::<u64, P::WordsCurvePoint>::try_from(event.p.as_slice()).unwrap();
        let q = Array::<u64, P::WordsCurvePoint>::try_from(event.q.as_slice()).unwrap();

        // Memory write records: one per dword.
        let mut p_memory_records = Array::<FfiEcMemoryWriteRecord, P::WordsCurvePoint>::default();
        for i in 0..n {
            let rec = event.p_memory_records[i];
            p_memory_records[i] = FfiEcMemoryWriteRecord {
                value: rec.value,
                prev_value: rec.prev_value,
                chunk: rec.chunk,
                timestamp: rec.timestamp,
                prev_chunk: rec.prev_chunk,
                prev_timestamp: rec.prev_timestamp,
            };
        }

        // Memory read records: one per dword.
        let mut q_memory_records = Array::<FfiEcMemoryReadRecord, P::WordsCurvePoint>::default();
        for i in 0..n {
            let rec = event.q_memory_records[i];
            q_memory_records[i] = FfiEcMemoryReadRecord {
                value: rec.value,
                chunk: rec.chunk,
                timestamp: rec.timestamp,
                prev_chunk: rec.prev_chunk,
                prev_timestamp: rec.prev_timestamp,
            };
        }

        Self {
            chunk: event.chunk,
            clk: event.clk as u32,
            p_ptr: event.p_ptr as u32,
            p,
            q_ptr: event.q_ptr as u32,
            q,
            p_memory_records,
            q_memory_records,
        }
    }
}

/// Edwards Decompress Event.
///
/// This event is emitted when an edwards decompression operation is performed.
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct EdDecompressEvent {
    /// The chunk number.
    pub chunk: RvChunk,
    /// The clock cycle.
    pub clk: RvClk,
    /// The pointer to the point.
    pub ptr: RvAddr,
    /// The sign bit of the point.
    pub sign: bool,
    /// The compressed y coordinate in native guest-memory dword form.
    pub y_words: [RvValue; WORDS_FIELD_ELEMENT],
    /// The decompressed x coordinate in native guest-memory dword form.
    pub decompressed_x_words: [RvValue; WORDS_FIELD_ELEMENT],
    /// The memory records for the x coordinate.
    pub x_memory_records: [MemoryWriteRecord; WORDS_FIELD_ELEMENT],
    /// The memory records for the y coordinate.
    pub y_memory_records: [MemoryReadRecord; WORDS_FIELD_ELEMENT],
    /// The local memory access events.
    pub local_mem_access: Vec<MemoryLocalEvent>,
}

/// Edwards Decompress Event FFI.
///
/// This event is emitted when an edwards decompression operation is performed.
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
#[repr(C)]
pub struct EdDecompressEventFFI {
    /// The chunk number.
    pub chunk: u32,
    /// The clock cycle.
    pub clk: u32,
    /// The pointer to the point.
    pub ptr: u32,
    /// The sign bit of the point.
    pub sign: bool,
    /// The comprssed y coordinate as a list of bytes.
    pub y_bytes: [u8; COMPRESSED_POINT_BYTES],
    /// The decompressed x coordinate as a list of bytes.
    pub decompressed_x_bytes: [u8; NUM_BYTES_FIELD_ELEMENT],
    /// The memory records for the x coordinate.
    pub x_memory_records: [MemoryWriteRecord; WORDS_FIELD_ELEMENT],
    /// The memory records for the y coordinate.
    pub y_memory_records: [MemoryReadRecord; WORDS_FIELD_ELEMENT],
}

impl From<&EdDecompressEvent> for EdDecompressEventFFI {
    fn from(_value: &EdDecompressEvent) -> Self {
        todo!("fix required fields to u64");
        /*
        Self {
            chunk: value.chunk,
            clk: value.clk.try_into().unwrap(),
            ptr: value.ptr.try_into().unwrap(),
            sign: value.sign,
            y_bytes: value.y_bytes,
            decompressed_x_bytes: value.decompressed_x_bytes,
            x_memory_records: value.x_memory_records,
            y_memory_records: value.y_memory_records,
        }
        */
    }
}

/// Create an elliptic curve add event. It takes two pointers to memory locations, reads the points
/// from memory, adds them together, and writes the result back to the first memory location.
/// The generic parameter `N` is the number of u32 words in the point representation. For example,
/// for the secp256k1 curve, `N` would be 16 (64 bytes) because the x and y coordinates are 32 bytes
/// each.
pub fn create_ec_add_event<E: EllipticCurve>(
    ctx: &mut SyscallContext,
    arg1: RvAddr,
    arg2: RvAddr,
) -> EllipticCurveAddEvent {
    let start_clk = ctx.clk;
    let p_ptr = arg1;
    SyscallContext::assert_dword_aligned_precompile(p_ptr, "edwards add p_ptr");
    let q_ptr = arg2;
    SyscallContext::assert_dword_aligned_precompile(q_ptr, "edwards add q_ptr");

    let num_words = <E::BaseField as NumWords>::WordsCurvePoint::USIZE;
    // WordsCurvePoint is now the u64 dword count directly.
    let num_memory_words = num_words;

    let p = ctx.dword_slice_unsafe(p_ptr, num_memory_words);
    let (q_memory_records, q) = ctx.mr_dword_slice(q_ptr, num_memory_words);

    // When we write to p, we want the clk to be incremented because p and q could be the same.
    ctx.clk += 1;

    let p_words = p
        .iter()
        .flat_map(|&word| [word as u32, (word >> 32) as u32])
        .collect::<Vec<u32>>();
    let q_words = q
        .iter()
        .flat_map(|&word| [word as u32, (word >> 32) as u32])
        .collect::<Vec<u32>>();
    let p_affine = AffinePoint::<E>::from_words_le(&p_words);
    let q_affine = AffinePoint::<E>::from_words_le(&q_words);
    let result_affine = p_affine + q_affine;

    let result_words = result_affine.to_words_le();
    let result_dwords = result_words
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u64::from(pair[0]) | (u64::from(pair[1]) << 32))
        .collect::<Vec<u64>>();

    let p_memory_records = ctx.mw_dword_slice(p_ptr, &result_dwords);

    EllipticCurveAddEvent {
        chunk: ctx.current_chunk(),
        clk: start_clk,
        p_ptr,
        p,
        q_ptr,
        q,
        p_memory_records,
        q_memory_records,
        local_mem_access: ctx.postprocess(),
    }
}
