//! Rust FFI bindings for the KoalaBear supra NTT kernels (in `cuda_kb_all`).
//!
//! All symbols carry the `_kb_` prefix the kernel sources give them.

#![allow(clippy::missing_safety_doc)]
#![allow(clippy::too_many_arguments)]

use crate::runtime::{d_buffer::DeviceBuffer, error::CudaError};
use p3_koala_bear::KoalaBear;

/// Maximum log2 domain size supported by the KoalaBear NTT.
/// KoalaBear has 2-adicity 24 (P-1 = 2^24 * 127).
pub const MAX_CUDA_KB_NTT_LOG_DOMAIN_SIZE: u32 = 24;

// ── FFI declarations ──────────────────────────────────────────────────────────

#[link(name = "cuda_kb_all", kind = "static")]
extern "C" {
    fn _kb_generate_all_twiddles(twiddles: *mut std::ffi::c_void, inverse: bool) -> i32;
    fn _kb_generate_partial_twiddles(partial_twiddles: *mut std::ffi::c_void, inverse: bool)
        -> i32;
    fn _kb_bit_rev(
        d_out: *mut std::ffi::c_void,
        d_inp: *const std::ffi::c_void,
        lg_domain_size: u32,
        padded_poly_size: u32,
        poly_count: u32,
    ) -> i32;
    fn _kb_bit_rev_frac_ext(
        d_out: *mut std::ffi::c_void,
        d_inp: *const std::ffi::c_void,
        lg_domain_size: u32,
        padded_poly_size: u32,
        poly_count: u32,
    ) -> i32;
    fn _kb_ct_mixed_radix_narrow(
        d_inout: *mut std::ffi::c_void,
        radix: u32,
        lg_domain_size: u32,
        stage: u32,
        iterations: u32,
        padded_poly_size: u32,
        poly_count: u32,
        is_intt: bool,
    ) -> i32;
    fn _kb_rs_open_pass_a(
        d_inout: *mut std::ffi::c_void,
        d_compact: *mut std::ffi::c_void,
        d_res: *const u32,
        n_res: u32,
        padded_poly_size: u32,
        poly_count: u32,
        handled: *mut i32,
    ) -> i32;
    fn _kb_rs_open_gather_rows(
        d_out: *mut std::ffi::c_void,
        d_src: *const std::ffi::c_void,
        d_rows: *const u32,
        d_qslot: *const u32,
        n_queries: u32,
        rows_per_query: u32,
        n_res: u32,
        padded_poly_size: u32,
        poly_count: u32,
        pruned: i32,
    ) -> i32;
}

// ── Safe wrappers ─────────────────────────────────────────────────────────────

pub unsafe fn kb_generate_all_twiddles<T>(
    twiddles: &DeviceBuffer<T>,
    inverse: bool,
) -> Result<(), CudaError> {
    CudaError::from_result(_kb_generate_all_twiddles(
        twiddles.as_mut_raw_ptr(),
        inverse,
    ))
}

/// Generic wrapper — `partial_twiddles` is interpreted by the kernel as a
/// `fr_t[WINDOW_NUM][WINDOW_SIZE]` array regardless of the Rust element type.
pub unsafe fn kb_generate_partial_twiddles<T>(
    partial_twiddles: &DeviceBuffer<T>,
    inverse: bool,
) -> Result<(), CudaError> {
    CudaError::from_result(_kb_generate_partial_twiddles(
        partial_twiddles.as_mut_raw_ptr(),
        inverse,
    ))
}

pub unsafe fn kb_bit_rev(
    d_out: &DeviceBuffer<KoalaBear>,
    d_inp: &DeviceBuffer<KoalaBear>,
    lg_domain_size: u32,
    padded_poly_size: u32,
    poly_count: u32,
) -> Result<(), CudaError> {
    CudaError::from_result(_kb_bit_rev(
        d_out.as_mut_raw_ptr(),
        d_inp.as_raw_ptr(),
        lg_domain_size,
        padded_poly_size,
        poly_count,
    ))
}

/// Bit-reverses `(numerator, denominator)` pairs of degree-4 extension elements. The kernel
/// permutes each 32-byte pair as opaque words (no field arithmetic), so the pair type only has to
/// be the size of `(EF, EF)`.
pub unsafe fn kb_bit_rev_frac_ext<E>(
    d_out: &DeviceBuffer<(E, E)>,
    d_inp: &DeviceBuffer<(E, E)>,
    lg_domain_size: u32,
    padded_poly_size: u32,
    poly_count: u32,
) -> Result<(), CudaError> {
    assert_eq!(std::mem::size_of::<(E, E)>(), 32);
    CudaError::from_result(_kb_bit_rev_frac_ext(
        d_out.as_mut_raw_ptr(),
        d_inp.as_raw_ptr(),
        lg_domain_size,
        padded_poly_size,
        poly_count,
    ))
}

/// Streamed-open, stage 1: if the dense RS-encode handshake is pending (set by
/// `kb_batch_intt_zeta_fused` + `kb_bit_rev` on the 2^24 in-place shape), run NTT
/// pass A only (levels 0..13) and return `Ok(true)`. With `compact = None` (D-lite)
/// the full pass-A intermediate is written into `d_inout`; with
/// `compact = Some((buf, residues))` (D-full) only the `residues.len()` requested
/// low-14-bit fibers are written into `buf`, laid out `[col][residue][segment]`.
/// Returns `Ok(false)` — and performs no work — when the fast path did not engage;
/// the caller must then finish the classic full NTT instead.
pub unsafe fn kb_rs_open_pass_a(
    d_inout: &DeviceBuffer<KoalaBear>,
    compact: Option<(&DeviceBuffer<KoalaBear>, &DeviceBuffer<u32>)>,
    padded_poly_size: u32,
    poly_count: u32,
) -> Result<bool, CudaError> {
    let (c_ptr, res_ptr, n_res) = match compact {
        Some((buf, residues)) => (
            buf.as_mut_raw_ptr(),
            residues.as_ptr(),
            residues.len() as u32,
        ),
        None => (std::ptr::null_mut(), std::ptr::null(), 0),
    };
    let mut handled: i32 = 0;
    CudaError::from_result(_kb_rs_open_pass_a(
        d_inout.as_mut_raw_ptr(),
        c_ptr,
        res_ptr,
        n_res,
        padded_poly_size,
        poly_count,
        &mut handled,
    ))?;
    Ok(handled != 0)
}

/// Streamed-open, stage 2: gather-dot the queried codeword rows straight from
/// the pass-A intermediate written by [`kb_rs_open_pass_a`]. `d_rows` holds
/// `n_queries * rows_per_query` row indices (query-major); the `rows_per_query`
/// sibling rows of one query must share their index mod 2^14 (the caller gates
/// `query_stride % 2^14 == 0`). `d_qslot = Some(slots)` means `d_src` is the D-full
/// compact buffer with `n_res` residue fibers per column and `slots[qi]` selecting
/// each query's fiber; `None` means `d_src` is the full pass-A block (D-lite).
/// Output layout matches `matrix_get_rows_fp_kernel`.
#[allow(clippy::too_many_arguments)]
pub unsafe fn kb_rs_open_gather_rows(
    d_out: &DeviceBuffer<KoalaBear>,
    d_src: &DeviceBuffer<KoalaBear>,
    d_rows: &DeviceBuffer<u32>,
    d_qslot: Option<&DeviceBuffer<u32>>,
    n_res: u32,
    n_queries: u32,
    rows_per_query: u32,
    padded_poly_size: u32,
    poly_count: u32,
) -> Result<(), CudaError> {
    let (qslot_ptr, pruned) = match d_qslot {
        Some(slots) => (slots.as_ptr(), 1),
        None => (std::ptr::null(), 0),
    };
    CudaError::from_result(_kb_rs_open_gather_rows(
        d_out.as_mut_raw_ptr(),
        d_src.as_raw_ptr(),
        d_rows.as_ptr(),
        qslot_ptr,
        n_queries,
        rows_per_query,
        n_res,
        padded_poly_size,
        poly_count,
        pruned,
    ))
}

pub unsafe fn kb_ct_mixed_radix_narrow(
    d_inout: &DeviceBuffer<KoalaBear>,
    radix: u32,
    lg_domain_size: u32,
    stage: u32,
    iterations: u32,
    padded_poly_size: u32,
    poly_count: u32,
    is_intt: bool,
) -> Result<(), CudaError> {
    if lg_domain_size > MAX_CUDA_KB_NTT_LOG_DOMAIN_SIZE {
        return Err(CudaError::new(1));
    }
    CudaError::from_result(_kb_ct_mixed_radix_narrow(
        d_inout.as_mut_raw_ptr(),
        radix,
        lg_domain_size,
        stage,
        iterations,
        padded_poly_size,
        poly_count,
        is_intt,
    ))
}
