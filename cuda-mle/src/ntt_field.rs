//! `GpuNttField` — dispatch trait for field-specific GPU NTT operations.
//!
//! The KoalaBear implementation routes `batch_ntt` / `batch_ntt_small` to the supra NTT
//! kernels in `cuda_kb_all`.

use std::{
    collections::BTreeSet,
    sync::{Mutex, OnceLock},
};

use crate::runtime::{
    context::{device_reset_epoch, get_device},
    d_buffer::DeviceBuffer,
};

use crate::cuda::batch_ntt_small;

/// Dispatch trait for GPU NTT over a specific field.
///
/// Implementors supply field-specific twiddle initialisation and the two NTT
/// entry points used by `stacked_pcs` and `whir`.
pub trait GpuNttField:
    Sized + Copy + Send + Sync + 'static + std::ops::Add<Output = Self> + std::ops::AddAssign
{
    /// Performs column-wise batch NTT on `buffer`, where `buffer` is assumed to be column-major
    /// with columns of height `2^(log_trace_height + log_blowup)`. The NTT are performed on the
    /// first `2^log_trace_height` elements of each column. If `bit_reverse` is true, then the input
    /// columns are assumed to be ordered in **natural** ordering, and a bit-reversal permutation is
    /// applied for the internal algorithm of the NTT. If `bit_reverse` is false, then the input
    /// columns are assumed to be in bit-reverse ordering. If `is_intt` is true, the inverse NTT is
    /// performed; otherwise, the forward NTT is performed.
    fn batch_ntt(
        buffer: &DeviceBuffer<Self>,
        log_trace_height: u32,
        log_blowup: u32,
        width: u32,
        bit_reverse: bool,
        is_intt: bool,
    );

    /// Perform a small-domain column-wise batch NTT on `buffer`.
    fn batch_ntt_small(
        buffer: &mut DeviceBuffer<Self>,
        l_skip: usize,
        cnt_blocks: usize,
        is_intt: bool,
    ) -> Result<(), crate::runtime::error::CudaError>;

    /// Fused per-chunk iNTT + coeffs→evals zeta stages with RS pad-skip:
    /// one pass replacing `batch_ntt_small(intt=true)` followed by
    /// `mle_interpolate_stages(0..l_skip-1, coeffs→evals)` in `rs_code_matrix`.
    fn batch_intt_zeta_fused(
        buffer: &mut DeviceBuffer<Self>,
        l_skip: usize,
        chunks_per_col: usize,
        real_chunks_per_col: usize,
        width: usize,
    ) -> Result<(), crate::runtime::error::CudaError>;

    /// Perform an in-place bit-reversal permutation on `buffer`.
    fn bit_rev(
        d_out: &DeviceBuffer<Self>,
        d_inp: &DeviceBuffer<Self>,
        lg_domain_size: u32,
        padded_poly_size: u32,
        poly_count: u32,
    ) -> Result<(), crate::runtime::error::CudaError>;

    /// Apply MLE-interpolate butterfly stages `[start_log_step, end_log_step]` (inclusive) on a
    /// column-major `padded_height x width` device buffer (used by `rs_code_matrix`). Routes to the
    /// field's own base-field kernels (KoalaBear → the `_kb_` launchers).
    ///
    /// # Safety
    /// `buffer` must be valid on device with length `>= padded_height * width`.
    #[allow(clippy::too_many_arguments)]
    unsafe fn mle_interpolate_stages(
        buffer: *mut Self,
        width: usize,
        padded_height: u32,
        log_blowup: u32,
        start_log_step: u32,
        end_log_step: u32,
        is_eval_to_coeff: bool,
        right_pad: bool,
    ) -> Result<(), crate::runtime::error::CudaError>;

    /// Streamed-open fast path, stage 1 (see
    /// `src/prover/ntt/rs_ntt_fastpath.cu`): when the dense RS-encode handshake is
    /// pending after `batch_intt_zeta_fused` + `bit_rev`, run big-NTT pass A only
    /// (levels 0..13) and return `Ok(true)`. With `compact = None` (D-lite) the full
    /// pass-A intermediate is written into `buffer`; with
    /// `compact = Some((buf, residues))` (D-full) only the requested low-14-bit
    /// residue fibers are written into `buf` (layout `[col][residue][segment]`).
    /// Returns `Ok(false)` — and performs no work — when the fast path did not engage
    /// (e.g. `RS_DENSE=0`, a non-2^24 shape, or a field without the streamed-open
    /// kernels); the caller must then finish the classic full NTT instead.
    ///
    /// # Safety
    /// Must be called directly after `batch_intt_zeta_fused` + `bit_rev` on `buffer`
    /// (the pipeline `rs_code_streamed_open` runs); `buffer` must hold `poly_count`
    /// columns of `padded_poly_size` elements, and `buf` (if given) must hold
    /// `poly_count * residues.len() * (padded_poly_size >> 14)` elements.
    unsafe fn rs_open_pass_a(
        _buffer: &mut DeviceBuffer<Self>,
        _compact: Option<(&DeviceBuffer<Self>, &DeviceBuffer<u32>)>,
        _padded_poly_size: u32,
        _poly_count: u32,
    ) -> Result<bool, crate::runtime::error::CudaError> {
        Ok(false)
    }

    /// Streamed-open fast path, stage 2: compute the queried codeword rows as
    /// dot products over the pass-A intermediate (see `_rs2_open_dot` for the twiddle
    /// derivation) — bit-exact with finishing pass B and gathering the rows. Only
    /// valid after [`GpuNttField::rs_open_pass_a`] returned `true`, which the default
    /// implementation never does. `d_qslot = Some(slots)` means `d_src` is the D-full
    /// compact buffer (`n_res` residue fibers per column, `slots[qi]` selecting each
    /// query's fiber); `None` means `d_src` is the full pass-A block (D-lite).
    ///
    /// # Safety
    /// `d_out` must hold `n_queries * rows_per_query * poly_count` elements; `d_rows`
    /// holds the row indices (query-major, sibling-minor) and all siblings of one
    /// query must share their index mod 2^14.
    #[allow(clippy::too_many_arguments)]
    unsafe fn rs_open_gather_rows(
        _d_out: &DeviceBuffer<Self>,
        _d_src: &DeviceBuffer<Self>,
        _d_rows: &DeviceBuffer<u32>,
        _d_qslot: Option<&DeviceBuffer<u32>>,
        _n_res: usize,
        _n_queries: usize,
        _rows_per_query: usize,
        _padded_poly_size: u32,
        _poly_count: u32,
    ) -> Result<(), crate::runtime::error::CudaError> {
        // Unreachable unless `rs_open_pass_a` returned true. cudaErrorNotSupported.
        Err(crate::runtime::error::CudaError::new(801))
    }
}

// ── KoalaBear ─────────────────────────────────────────────────────────────────

mod kb_ntt {
    use super::*;
    use crate::cuda::ntt_kb;

    // KoalaBear NTT twiddle table constants (matching KB parameters.cuh).
    const KB_MAX_LG_DOMAIN_SIZE: usize = ntt_kb::MAX_CUDA_KB_NTT_LOG_DOMAIN_SIZE as usize;
    const KB_LG_WINDOW_SIZE: usize = (KB_MAX_LG_DOMAIN_SIZE + 4) / 5;
    const KB_WINDOW_SIZE: usize = 1 << KB_LG_WINDOW_SIZE;
    const KB_WINDOW_NUM: usize =
        (KB_MAX_LG_DOMAIN_SIZE + KB_LG_WINDOW_SIZE - 1) / KB_LG_WINDOW_SIZE;
    const KB_RADIX_TWIDDLES_SIZE: usize = 32 + 64 + 128 + 256 + 512;

    static KB_INIT_FORWARD: OnceLock<Mutex<BTreeSet<(i32, u64)>>> = OnceLock::new();
    static KB_INIT_INVERSE: OnceLock<Mutex<BTreeSet<(i32, u64)>>> = OnceLock::new();

    fn kb_ensure_initialized(inverse: bool) -> Result<(), crate::runtime::error::CudaError> {
        let device_key = (get_device()?, device_reset_epoch());
        let initialized = if inverse {
            &KB_INIT_INVERSE
        } else {
            &KB_INIT_FORWARD
        };
        let initialized = initialized.get_or_init(|| Mutex::new(BTreeSet::new()));
        let mut initialized = initialized.lock().unwrap();
        if initialized.contains(&device_key) {
            return Ok(());
        }

        {
            let partial_twiddles =
                DeviceBuffer::<[p3_koala_bear::KoalaBear; KB_WINDOW_SIZE]>::with_capacity(
                    KB_WINDOW_NUM,
                );
            let twiddles =
                DeviceBuffer::<p3_koala_bear::KoalaBear>::with_capacity(KB_RADIX_TWIDDLES_SIZE);
            unsafe {
                ntt_kb::kb_generate_all_twiddles(&twiddles, inverse)?;
                ntt_kb::kb_generate_partial_twiddles(&partial_twiddles, inverse)?;
            }
        }
        // No sync before publishing `initialized`: both generators already end with
        // `cudaStreamSynchronize` on this thread's stream (supra/ntt_params.cu), so the tables are
        // live. Do not put a device-wide sync here: it fails against another lane's open graph
        // capture.
        tracing::warn!("KB NTT twiddles initialized (inverse={})", inverse);
        initialized.insert(device_key);
        Ok(())
    }

    struct KbNttImpl<'a> {
        buffer: &'a DeviceBuffer<p3_koala_bear::KoalaBear>,
        lg_domain_size: u32,
        padded_poly_size: u32,
        poly_count: u32,
        is_intt: bool,
        stage: u32,
    }

    impl<'a> KbNttImpl<'a> {
        fn new(
            buffer: &'a DeviceBuffer<p3_koala_bear::KoalaBear>,
            lg_domain_size: u32,
            padded_poly_size: u32,
            poly_count: u32,
            is_intt: bool,
        ) -> Self {
            kb_ensure_initialized(is_intt)
                .expect("failed to initialize KB CUDA NTT twiddle tables");
            Self {
                buffer,
                lg_domain_size,
                padded_poly_size,
                poly_count,
                is_intt,
                stage: 0,
            }
        }

        fn step(&mut self, iterations: u32) {
            assert!(iterations <= 10);
            let radix = if iterations < 6 { 6 } else { iterations };
            unsafe {
                ntt_kb::kb_ct_mixed_radix_narrow(
                    self.buffer,
                    radix,
                    self.lg_domain_size,
                    self.stage,
                    iterations,
                    self.padded_poly_size,
                    self.poly_count,
                    self.is_intt,
                )
                .expect("failed to launch KB CUDA mixed-radix NTT step");
            }
            self.stage += iterations;
        }
    }

    pub fn batch_ntt_kb(
        buffer: &DeviceBuffer<p3_koala_bear::KoalaBear>,
        log_trace_height: u32,
        log_blowup: u32,
        width: u32,
        bit_reverse: bool,
        is_intt: bool,
    ) {
        if log_trace_height == 0 {
            return;
        }
        assert!(
            log_trace_height <= ntt_kb::MAX_CUDA_KB_NTT_LOG_DOMAIN_SIZE,
            "CUDA KB batch_ntt supports log_trace_height <= {}",
            ntt_kb::MAX_CUDA_KB_NTT_LOG_DOMAIN_SIZE
        );

        let padded_poly_size = 1 << (log_trace_height + log_blowup);

        if bit_reverse {
            unsafe {
                ntt_kb::kb_bit_rev(buffer, buffer, log_trace_height, padded_poly_size, width)
                    .expect("failed to launch KB CUDA bit-reversal permutation");
            }
        }

        let mut _impl = KbNttImpl::new(buffer, log_trace_height, padded_poly_size, width, is_intt);
        if log_trace_height <= 10 {
            _impl.step(log_trace_height);
        } else if log_trace_height <= 17 {
            let step = log_trace_height / 2;
            _impl.step(step + log_trace_height % 2);
            _impl.step(step);
        } else if log_trace_height <= ntt_kb::MAX_CUDA_KB_NTT_LOG_DOMAIN_SIZE {
            let step = log_trace_height / 3;
            let rem = log_trace_height % 3;
            _impl.step(step);
            _impl.step(step);
            _impl.step(step + rem);
        } else {
            unreachable!("log_trace_height is bounded above");
        }
    }

    // KoalaBear small-NTT. The buffer layout for `batch_ntt_small` is `cnt_blocks` consecutive
    // chunks, each of `2^l_skip` elements.
    pub fn batch_ntt_small_kb(
        buffer: &mut DeviceBuffer<p3_koala_bear::KoalaBear>,
        l_skip: usize,
        cnt_blocks: usize,
        is_intt: bool,
    ) -> Result<(), crate::runtime::error::CudaError> {
        // The KB `_kb_batch_ntt_small` launcher with the KB DEVICE_NTT_TWIDDLES table.
        unsafe { batch_ntt_small::batch_ntt_small_kb(buffer, l_skip, cnt_blocks, is_intt) }
    }

    /// Wrapper for ntt_kb::kb_bit_rev, accessible from the parent module.
    pub(super) fn kb_ntt_bit_rev(
        d_out: &DeviceBuffer<p3_koala_bear::KoalaBear>,
        d_inp: &DeviceBuffer<p3_koala_bear::KoalaBear>,
        lg_domain_size: u32,
        padded_poly_size: u32,
        poly_count: u32,
    ) -> Result<(), crate::runtime::error::CudaError> {
        unsafe { ntt_kb::kb_bit_rev(d_out, d_inp, lg_domain_size, padded_poly_size, poly_count) }
    }
}

impl GpuNttField for p3_koala_bear::KoalaBear {
    fn batch_ntt(
        buffer: &DeviceBuffer<Self>,
        log_trace_height: u32,
        log_blowup: u32,
        width: u32,
        bit_reverse: bool,
        is_intt: bool,
    ) {
        kb_ntt::batch_ntt_kb(
            buffer,
            log_trace_height,
            log_blowup,
            width,
            bit_reverse,
            is_intt,
        );
    }

    fn batch_ntt_small(
        buffer: &mut DeviceBuffer<Self>,
        l_skip: usize,
        cnt_blocks: usize,
        is_intt: bool,
    ) -> Result<(), crate::runtime::error::CudaError> {
        kb_ntt::batch_ntt_small_kb(buffer, l_skip, cnt_blocks, is_intt)
    }

    fn batch_intt_zeta_fused(
        buffer: &mut DeviceBuffer<Self>,
        l_skip: usize,
        chunks_per_col: usize,
        real_chunks_per_col: usize,
        width: usize,
    ) -> Result<(), crate::runtime::error::CudaError> {
        unsafe {
            crate::cuda::batch_ntt_small::batch_intt_zeta_fused_kb(
                buffer,
                l_skip,
                chunks_per_col,
                real_chunks_per_col,
                width,
            )
        }
    }

    fn bit_rev(
        d_out: &DeviceBuffer<Self>,
        d_inp: &DeviceBuffer<Self>,
        lg_domain_size: u32,
        padded_poly_size: u32,
        poly_count: u32,
    ) -> Result<(), crate::runtime::error::CudaError> {
        unsafe {
            kb_ntt::kb_ntt_bit_rev(d_out, d_inp, lg_domain_size, padded_poly_size, poly_count)
        }
    }

    unsafe fn mle_interpolate_stages(
        buffer: *mut Self,
        width: usize,
        padded_height: u32,
        log_blowup: u32,
        start_log_step: u32,
        end_log_step: u32,
        is_eval_to_coeff: bool,
        right_pad: bool,
    ) -> Result<(), crate::runtime::error::CudaError> {
        use crate::cuda::mle_interpolate::{mle_interpolate_stages, StageRange};
        let range = StageRange::new(start_log_step, end_log_step)?;
        mle_interpolate_stages::<p3_koala_bear::KoalaBear>(
            buffer,
            width,
            padded_height,
            log_blowup,
            range,
            is_eval_to_coeff,
            right_pad,
        )
    }

    unsafe fn rs_open_pass_a(
        buffer: &mut DeviceBuffer<Self>,
        compact: Option<(&DeviceBuffer<Self>, &DeviceBuffer<u32>)>,
        padded_poly_size: u32,
        poly_count: u32,
    ) -> Result<bool, crate::runtime::error::CudaError> {
        crate::cuda::ntt_kb::kb_rs_open_pass_a(buffer, compact, padded_poly_size, poly_count)
    }

    unsafe fn rs_open_gather_rows(
        d_out: &DeviceBuffer<Self>,
        d_src: &DeviceBuffer<Self>,
        d_rows: &DeviceBuffer<u32>,
        d_qslot: Option<&DeviceBuffer<u32>>,
        n_res: usize,
        n_queries: usize,
        rows_per_query: usize,
        padded_poly_size: u32,
        poly_count: u32,
    ) -> Result<(), crate::runtime::error::CudaError> {
        crate::cuda::ntt_kb::kb_rs_open_gather_rows(
            d_out,
            d_src,
            d_rows,
            d_qslot,
            n_res as u32,
            n_queries as u32,
            rows_per_query as u32,
            padded_poly_size,
            poly_count,
        )
    }
}
