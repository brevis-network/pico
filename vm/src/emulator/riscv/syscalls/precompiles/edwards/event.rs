use serde::{Deserialize, Serialize};
use typenum::Unsigned;

use crate::{
    chips::{
        chips::riscv_memory::event::{MemoryReadRecord, MemoryWriteRecord},
        gadgets::{
            curves::{
                edwards::WORDS_FIELD_ELEMENT, AffinePoint, EllipticCurve, COMPRESSED_POINT_BYTES,
                NUM_BYTES_FIELD_ELEMENT,
            },
            utils::field_params::NumWords,
        },
    },
    emulator::riscv::syscalls::syscall_context::SyscallContext,
};

/// Elliptic Curve Add Event.
///
/// This event is emitted when an elliptic curve addition operation is performed.
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct EllipticCurveAddEvent {
    pub(crate) lookup_id: u128,
    /// The chunk number.
    pub chunk: u32,
    /// The clock cycle.
    pub clk: u32,
    /// The pointer to the first point.
    pub p_ptr: u32,
    /// The first point as a list of words.
    pub p: Vec<u32>,
    /// The pointer to the second point.
    pub q_ptr: u32,
    /// The second point as a list of words.
    pub q: Vec<u32>,
    /// The memory records for the first point.
    pub p_memory_records: Vec<MemoryWriteRecord>,
    /// The memory records for the second point.
    pub q_memory_records: Vec<MemoryReadRecord>,
}

/// Edwards Decompress Event.
///
/// This event is emitted when an edwards decompression operation is performed.
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct EdDecompressEvent {
    /// The lookup identifier.
    pub lookup_id: u128,
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

/// Create an elliptic curve add event. It takes two pointers to memory locations, reads the points
/// from memory, adds them together, and writes the result back to the first memory location.
/// The generic parameter `N` is the number of u32 words in the point representation. For example,
/// for the secp256k1 curve, `N` would be 16 (64 bytes) because the x and y coordinates are 32 bytes
/// each.
pub fn create_ec_add_event<E: EllipticCurve>(
    ctx: &mut SyscallContext,
    arg1: u32,
    arg2: u32,
) -> EllipticCurveAddEvent {
    let start_clk = ctx.clk;
    let p_ptr = arg1;
    if p_ptr % 4 != 0 {
        panic!();
    }
    let q_ptr = arg2;
    if q_ptr % 4 != 0 {
        panic!();
    }

    let num_words = <E::BaseField as NumWords>::WordsCurvePoint::USIZE;

    let p = ctx.slice_unsafe(p_ptr, num_words);

    let (q_memory_records, q) = ctx.mr_slice(q_ptr, num_words);

    // When we write to p, we want the clk to be incremented because p and q could be the same.
    ctx.clk += 1;

    let p_affine = AffinePoint::<E>::from_words_le(&p);
    let q_affine = AffinePoint::<E>::from_words_le(&q);
    let result_affine = p_affine + q_affine;

    let result_words = result_affine.to_words_le();

    let p_memory_records = ctx.mw_slice(p_ptr, &result_words);

    EllipticCurveAddEvent {
        lookup_id: ctx.syscall_lookup_id,
        chunk: ctx.current_chunk(),
        clk: start_clk,
        p_ptr,
        p,
        q_ptr,
        q,
        p_memory_records,
        q_memory_records,
    }
}
