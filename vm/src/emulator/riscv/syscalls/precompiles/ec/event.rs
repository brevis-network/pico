use crate::{
    chips::{
        chips::riscv_memory::event::{MemoryLocalEvent, MemoryReadRecord, MemoryWriteRecord},
        gadgets::{
            curves::{
                weierstrass::{
                    bls381::bls12381_decompress, secp256k1::secp256k1_decompress,
                    secp256r1::secp256r1_decompress,
                },
                AffinePoint, CurveType, EllipticCurve,
            },
            utils::{
                conversions::{bytes_to_words_le_vec, words_to_bytes_le_vec},
                field_params::{NumLimbs, NumWords},
            },
        },
    },
    emulator::riscv::{
        event_types::{RvAddr, RvChunk, RvClk, RvValue},
        syscalls::syscall_context::SyscallContext,
    },
};
use serde::{Deserialize, Serialize};
use typenum::Unsigned;

/// Elliptic Curve Double Event.
///
/// This event is emitted when an elliptic curve doubling operation is performed.
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct EllipticCurveDoubleEvent {
    /// The chunk number.
    pub chunk: RvChunk,
    /// The clock cycle.
    pub clk: RvClk,
    /// The pointer to the point.
    pub p_ptr: RvAddr,
    /// The point in native guest-memory dword form.
    pub p: Vec<RvValue>,
    /// The memory records for the point.
    pub p_memory_records: Vec<MemoryWriteRecord>,
    /// The local memory access records.
    pub local_mem_access: Vec<MemoryLocalEvent>,
}

/// Elliptic Curve Point Decompress Event.
///
/// This event is emitted when an elliptic curve point decompression operation is performed.
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct EllipticCurveDecompressEvent {
    /// The chunk number.
    pub chunk: RvChunk,
    /// The clock cycle.
    pub clk: RvClk,
    /// The pointer to the point.
    pub ptr: RvAddr,
    /// The sign bit of the point.
    pub sign_bit: bool,
    /// The x coordinate in native guest-memory dword form.
    pub x_words: Vec<RvValue>,
    /// The decompressed y coordinate in native guest-memory dword form.
    pub decompressed_y_words: Vec<RvValue>,
    /// The memory records for the x coordinate.
    pub x_memory_records: Vec<MemoryReadRecord>,
    /// The memory records for the y coordinate.
    pub y_memory_records: Vec<MemoryWriteRecord>,
    /// The local memory access records.
    pub local_mem_access: Vec<MemoryLocalEvent>,
}

/// Create an elliptic curve double event.
///
/// It takes a pointer to a memory location, reads the point from memory, doubles it, and writes the
/// result back to the memory location.
pub fn create_ec_double_event<E: EllipticCurve>(
    rt: &mut SyscallContext,
    arg1: RvAddr,
    _: u64,
) -> EllipticCurveDoubleEvent {
    let start_clk = rt.clk;
    let p_ptr = arg1;
    SyscallContext::assert_dword_aligned_precompile(p_ptr, "ec double p_ptr");

    let num_words = <E::BaseField as NumWords>::WordsCurvePoint::USIZE;
    // WordsCurvePoint is now the u64 dword count directly.
    let num_memory_words = num_words;

    let p = rt.dword_slice_unsafe(p_ptr, num_memory_words);
    let p_words = p
        .iter()
        .flat_map(|&word| [word as u32, (word >> 32) as u32])
        .collect::<Vec<u32>>();

    let p_affine = AffinePoint::<E>::from_words_le(&p_words);

    let result_affine = E::ec_double(&p_affine);

    let result_words = result_affine.to_words_le();
    let result_dwords = result_words
        .chunks_exact(2)
        .map(|pair| u64::from(pair[0]) | (u64::from(pair[1]) << 32))
        .collect::<Vec<u64>>();

    let p_memory_records = rt.mw_dword_slice(p_ptr, &result_dwords);

    EllipticCurveDoubleEvent {
        chunk: rt.current_chunk(),
        clk: start_clk,
        p_ptr,
        p,
        p_memory_records,
        local_mem_access: rt.postprocess(),
    }
}

/// Create an elliptic curve decompress event.
///
/// It takes a pointer to a memory location, reads the point from memory, decompresses it, and
/// writes the result back to the memory location.
pub fn create_ec_decompress_event<E: EllipticCurve>(
    rt: &mut SyscallContext,
    slice_ptr: RvAddr,
    sign_bit: u64,
) -> EllipticCurveDecompressEvent {
    let start_clk = rt.clk;
    SyscallContext::assert_dword_aligned_precompile(slice_ptr, "ec decompress slice_ptr");
    let sign_bit_u32 = u32::try_from(sign_bit)
        .unwrap_or_else(|_| panic!("ec decompress sign_bit overflow: {sign_bit}"));
    assert!(sign_bit_u32 <= 1, "is_odd must be 0 or 1");

    let num_limbs = <E::BaseField as NumLimbs>::Limbs::USIZE;
    let num_words_field_element = num_limbs / 4;
    // num_words_field_element is derived from num_limbs / 4 (NOT NumWords), so it is still a u32
    // word count. The in-memory dword count is half of that.
    let num_memory_words_field_element = num_words_field_element / 2;

    let x_ptr = slice_ptr + (num_memory_words_field_element as u64) * 8;
    let (x_memory_records, x_words) = rt.mr_dword_slice(x_ptr, num_memory_words_field_element);
    let x_vec = x_words
        .iter()
        .flat_map(|&word| [word as u32, (word >> 32) as u32])
        .collect::<Vec<u32>>();

    let x_bytes = words_to_bytes_le_vec(&x_vec);
    let mut x_bytes_be = x_bytes.clone();
    x_bytes_be.reverse();

    let decompress_fn = match E::CURVE_TYPE {
        CurveType::Bls12381 => bls12381_decompress::<E>,
        CurveType::Secp256k1 => secp256k1_decompress::<E>,
        CurveType::Secp256r1 => secp256r1_decompress::<E>,
        _ => panic!("Unsupported curve: {}", E::CURVE_TYPE),
    };

    let computed_point: AffinePoint<E> = decompress_fn(&x_bytes_be, sign_bit_u32);

    let mut decompressed_y_bytes = computed_point.y.to_bytes_le();
    decompressed_y_bytes.resize(num_limbs, 0u8);
    let y_words = bytes_to_words_le_vec(&decompressed_y_bytes);
    let decompressed_y_words = y_words
        .chunks_exact(2)
        .map(|pair| u64::from(pair[0]) | (u64::from(pair[1]) << 32))
        .collect::<Vec<u64>>();

    let y_memory_records = rt.mw_dword_slice(slice_ptr, &decompressed_y_words);

    EllipticCurveDecompressEvent {
        chunk: rt.current_chunk(),
        clk: start_clk,
        ptr: slice_ptr,
        sign_bit: sign_bit_u32 != 0,
        x_words,
        decompressed_y_words,
        x_memory_records,
        y_memory_records,
        local_mem_access: rt.postprocess(),
    }
}
