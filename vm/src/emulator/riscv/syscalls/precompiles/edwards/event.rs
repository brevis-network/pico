use serde::{Deserialize, Serialize};
use typenum::Unsigned;

use crate::{
    chips::{
        chips::riscv_memory::event::{MemoryLocalEvent, MemoryReadRecord, MemoryWriteRecord},
        gadgets::{
            curves::{edwards::WORDS_FIELD_ELEMENT, AffinePoint, EllipticCurve},
            utils::field_params::NumWords,
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
        .chunks_exact(2)
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
