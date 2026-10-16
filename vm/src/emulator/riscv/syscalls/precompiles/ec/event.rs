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
                field_params::{FieldParameters, NumLimbs, NumWords},
            },
        },
    },
    emulator::riscv::{
        event_types::{RvAddr, RvChunk, RvClk, RvValue},
        syscalls::{
            precompiles::edwards::event::{FfiEcMemoryReadRecord, FfiEcMemoryWriteRecord},
            syscall_context::SyscallContext,
        },
    },
};
use hybrid_array::Array;
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

#[derive(Debug, Clone)]
#[repr(C)]
pub struct EllipticCurveDoubleFfiEvent<P: FieldParameters + NumWords> {
    pub chunk: u32,
    pub clk: u32,
    pub p_ptr: u32,
    /// Point data as u64 dwords (WordsCurvePoint elements).
    pub p: Array<u64, P::WordsCurvePoint>,
    /// Memory write records with u64 value/prev_value, one per dword.
    pub p_memory_records: Array<FfiEcMemoryWriteRecord, P::WordsCurvePoint>,
}

impl<P: FieldParameters + NumWords> From<&EllipticCurveDoubleEvent>
    for EllipticCurveDoubleFfiEvent<P>
{
    fn from(value: &EllipticCurveDoubleEvent) -> Self {
        let n = P::WordsCurvePoint::USIZE;

        let p = Array::<u64, P::WordsCurvePoint>::try_from(&value.p[..n]).unwrap();

        let mut p_memory_records = Array::<FfiEcMemoryWriteRecord, P::WordsCurvePoint>::default();
        for i in 0..n {
            let rec = value.p_memory_records[i];
            p_memory_records[i] = FfiEcMemoryWriteRecord {
                value: rec.value,
                prev_value: rec.prev_value,
                chunk: rec.chunk,
                timestamp: rec.timestamp,
                prev_chunk: rec.prev_chunk,
                prev_timestamp: rec.prev_timestamp,
            };
        }

        Self {
            chunk: value.chunk,
            clk: value.clk as u32,
            p_ptr: value.p_ptr as u32,
            p,
            p_memory_records,
        }
    }
}

impl<P: FieldParameters + NumWords> From<EllipticCurveDoubleEvent>
    for EllipticCurveDoubleFfiEvent<P>
{
    fn from(value: EllipticCurveDoubleEvent) -> Self {
        Self::from(&value)
    }
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

/// Elliptic Curve Point Decompress Event FFI.
///
/// This event is emitted when an elliptic curve point decompression operation is performed.
#[derive(Default, Debug, Clone)]
#[repr(C)]
pub struct EllipticCurveDecompressEventFFI<P: FieldParameters + NumWords> {
    /// The chunk number.
    pub chunk: u32,
    /// The clock cycle.
    pub clk: u32,
    /// The pointer to the point.
    pub ptr: u32,
    /// The sign bit of the point.
    pub sign_bit: bool,
    /// The x coordinate as a list of bytes.
    pub x_bytes: Array<u8, P::Limbs>,
    /// The decompressed y coordinate as a list of bytes.
    pub decompressed_y_bytes: Array<u8, P::Limbs>,
    /// The memory records for the x coordinate (u64 values).
    pub x_memory_records: Array<FfiEcMemoryReadRecord, P::WordsFieldElement>,
    /// The memory records for the y coordinate (u64 values).
    pub y_memory_records: Array<FfiEcMemoryWriteRecord, P::WordsFieldElement>,
}

impl<P: FieldParameters + NumWords> From<&EllipticCurveDecompressEvent>
    for EllipticCurveDecompressEventFFI<P>
{
    fn from(value: &EllipticCurveDecompressEvent) -> Self {
        // Convert u64 x_words to u8 bytes (little-endian)
        let x_bytes: Vec<u8> = value.x_words.iter().flat_map(|w| w.to_le_bytes()).collect();
        // Convert u64 decompressed_y_words to u8 bytes (little-endian)
        let decompressed_y_bytes: Vec<u8> = value
            .decompressed_y_words
            .iter()
            .flat_map(|w| w.to_le_bytes())
            .collect();

        let n = P::WordsFieldElement::USIZE;
        let mut x_memory_records = Array::<FfiEcMemoryReadRecord, P::WordsFieldElement>::default();
        for i in 0..n {
            let rec = value.x_memory_records[i];
            x_memory_records[i] = FfiEcMemoryReadRecord {
                value: rec.value,
                chunk: rec.chunk,
                timestamp: rec.timestamp,
                prev_chunk: rec.prev_chunk,
                prev_timestamp: rec.prev_timestamp,
            };
        }
        let mut y_memory_records = Array::<FfiEcMemoryWriteRecord, P::WordsFieldElement>::default();
        for i in 0..n {
            let rec = value.y_memory_records[i];
            y_memory_records[i] = FfiEcMemoryWriteRecord {
                value: rec.value,
                prev_value: rec.prev_value,
                chunk: rec.chunk,
                timestamp: rec.timestamp,
                prev_chunk: rec.prev_chunk,
                prev_timestamp: rec.prev_timestamp,
            };
        }

        Self {
            chunk: value.chunk,
            clk: value.clk.try_into().unwrap(),
            ptr: value.ptr.try_into().unwrap(),
            sign_bit: value.sign_bit,
            x_bytes: Array::try_from_iter(x_bytes.iter().copied()).unwrap(),
            decompressed_y_bytes: Array::try_from_iter(decompressed_y_bytes.iter().copied())
                .unwrap(),
            x_memory_records,
            y_memory_records,
        }
    }
}

impl<P: FieldParameters + NumWords> From<EllipticCurveDecompressEvent>
    for EllipticCurveDecompressEventFFI<P>
{
    fn from(value: EllipticCurveDecompressEvent) -> Self {
        Self::from(&value)
    }
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
        .as_chunks::<2>()
        .0
        .iter()
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
        .as_chunks::<2>()
        .0
        .iter()
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
