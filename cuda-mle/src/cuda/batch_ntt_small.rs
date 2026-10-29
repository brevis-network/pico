use std::{
    collections::BTreeSet,
    ffi::c_void,
    sync::{Mutex, OnceLock},
};

use crate::runtime::{
    context::{device_reset_epoch, get_device},
    d_buffer::DeviceBuffer,
    error::{check, CudaError},
};

use crate::prelude::F;

/// Maximum `l_skip` supported by the small-NTT CUDA kernel.
pub const MAX_SMALL_NTT_LEVEL: usize = 9;

/// Validate the GPU small-NTT domain size.
///
/// `l_skip == 0` is accepted: a size-1 domain needs no transform, so callers may skip the kernel
/// launch entirely.
pub fn validate_gpu_l_skip(l_skip: usize) -> Result<(), CudaError> {
    if l_skip > MAX_SMALL_NTT_LEVEL {
        return Err(CudaError::new(1));
    }
    Ok(())
}

/// Size of the device NTT twiddle table (2^11 - 2 = 2046 elements for MAX_NTT_LEVEL=10)
pub const DEVICE_NTT_TWIDDLES_SIZE: usize = (1 << 11) - 2;

extern "C" {
    // The DEVICE_NTT_TWIDDLES constant array of the cuda_kb_all build of batch_ntt_small.cu.
    fn _kb_generate_device_ntt_twiddles(d_twiddles: *mut c_void) -> i32;

    // KoalaBear small-NTT kernel (same batch_ntt_small.cu, KB-typed via cuda_kb_all). Uses the
    // KB DEVICE_NTT_TWIDDLES table (correct KB roots), initialized above.
    fn _kb_batch_ntt_small(
        d_buffer: *mut p3_koala_bear::KoalaBear,
        l_skip: usize,
        cnt_blocks: usize,
        is_intt: bool,
    ) -> i32;

    fn _kb_batch_intt_zeta_fused(
        d_buffer: *mut p3_koala_bear::KoalaBear,
        l_skip: usize,
        chunks_per_col: usize,
        real_chunks_per_col: usize,
        width: usize,
    ) -> i32;
}

/// `(device ordinal, reset epoch)` pairs whose constant-memory twiddle table is already filled.
static TWIDDLES_READY_ON: OnceLock<Mutex<BTreeSet<(i32, u64)>>> = OnceLock::new();

/// Fills the constant-memory NTT twiddle table of the current device if that has not happened
/// yet. Idempotent: the work is done at most once per (device, reset epoch).
pub fn ensure_device_ntt_twiddles_initialized() -> Result<(), CudaError> {
    let this_dev = (get_device()?, device_reset_epoch());
    let ready_set = TWIDDLES_READY_ON.get_or_init(|| Mutex::new(BTreeSet::<(i32, u64)>::new()));
    let mut ready_guard = ready_set.lock().unwrap();
    if ready_guard.contains(&this_dev) {
        return Ok(());
    }

    {
        // Short-lived staging buffer: the launcher writes the twiddles here, copies them into
        // constant memory and synchronizes before it returns, so dropping the buffer at the end
        // of this block is fine. Skipping this step would leave DEVICE_NTT_TWIDDLES all zero, so
        // get_twiddle() would return 0 and the round-0 zerocheck/logup small-NTT evaluations
        // would collapse whenever l_skip > 0.
        let kb_twiddles = DeviceBuffer::<F>::with_capacity(DEVICE_NTT_TWIDDLES_SIZE);
        unsafe {
            CudaError::from_result(_kb_generate_device_ntt_twiddles(
                kb_twiddles.as_mut_raw_ptr(),
            ))?;
        }
    }
    ready_guard.insert(this_dev);
    Ok(())
}

/// Fused per-chunk iNTT + subset-zeta: one pass replacing
/// `batch_ntt_small(intt) ; mle_interpolate_stages(coeffs→evals, 0..l_skip-1)` in
/// `rs_code_matrix`, skipping the all-zero RS blowup chunks.
pub unsafe fn batch_intt_zeta_fused_kb(
    buffer: &mut DeviceBuffer<p3_koala_bear::KoalaBear>,
    l_skip: usize,
    chunks_per_col: usize,
    real_chunks_per_col: usize,
    width: usize,
) -> Result<(), CudaError> {
    if l_skip == 0 || width == 0 {
        return Ok(());
    }
    ensure_device_ntt_twiddles_initialized()?;
    check(_kb_batch_intt_zeta_fused(
        buffer.as_mut_ptr(),
        l_skip,
        chunks_per_col,
        real_chunks_per_col,
        width,
    ))
}

/// KoalaBear GPU small-NTT over `cnt_blocks` consecutive `2^l_skip` chunks, using the
/// `DEVICE_NTT_TWIDDLES` table. Composes with `mle_interpolate_stages`.
pub unsafe fn batch_ntt_small_kb(
    buffer: &mut DeviceBuffer<p3_koala_bear::KoalaBear>,
    l_skip: usize,
    cnt_blocks: usize,
    is_intt: bool,
) -> Result<(), CudaError> {
    if l_skip == 0 || cnt_blocks == 0 {
        return Ok(());
    }
    validate_gpu_l_skip(l_skip)?;

    ensure_device_ntt_twiddles_initialized()?;
    check(_kb_batch_ntt_small(
        buffer.as_mut_ptr(),
        l_skip,
        cnt_blocks,
        is_intt,
    ))
}
