//! The device-buffer polynomial layer: PLE mixed↔evals conversion plus the eq-hypercube table
//! builders that feed the zerocheck/stacked-reduction provers.
//!
//! - [`PleMatrix`] converts between PLE mixed (coefficient) and evaluation form via a
//!   per-`2^l_skip`-chunk small-NTT ([`PleMatrix::from_evals`] / [`PleMatrix::to_evals`]).
//! - Three eq-hypercube table builders, each with one production consumer:
//!   - [`EqEvalSegments`]: a single flat prefix buffer holding every layer contiguously; consumed
//!     by `stacked_reduction.rs`.
//!   - [`EqEvalLayers`]: one buffer per layer, independently droppable; consumed by
//!     `logup_zerocheck/mod.rs`.
//!   - [`SqrtEqLayersFor`]: the √-decomposed low/high pair of `EqEvalLayers`; consumed by
//!     `logup_zerocheck/fractional.rs`.
//!
//! State invariants:
//! - Bit-ordering is per-builder: the *nonoverlapping* stage kernel (used by `EqEvalSegments` and
//!   `EqEvalLayers::new_with_kernels`) inserts each new variable at the HIGH bit, so layer `n` is
//!   the little-endian eq table of the fed prefix; the *interleaved* stage kernel (used by
//!   `EqEvalLayers::new_rev_with_kernels`) inserts at the LOW bit instead.
//! - Buffer-length preconditions: `EqEvalSegments`'s buffer has length `2^{max_n+1}`, and
//!   `get_ptr(n)` returns the offset `2^n` into it.
//! - Everything below runs on the per-thread default CUDA stream: each builder's H2D seed copy
//!   is ordered before the stage kernels that read it, so no explicit stream sync is needed
//!   between them.
//!
//! CPU counterparts: `mle-core`'s `poly::{eq, mle, ple}`.

use std::sync::Arc;

use crate::runtime::{copy::MemCopyD2D, d_buffer::DeviceBuffer};
use getset::Getters;
use mle_core::poly::matrix::MatrixDimensions;

use crate::{
    base::DeviceMatrix, cuda::batch_ntt_small::validate_gpu_l_skip, prelude::EF, KernelError,
};

#[derive(derive_new::new, Getters)]
pub struct PleMatrix<F> {
    /// Mixed form: for every hypercube point `\vect x in H_n`, the coefficients of the univariate
    /// polynomial `Z -> f(Z, \vect x)`. Same buffer size as the evaluation form.
    #[getset(get = "pub")]
    pub(crate) mixed: DeviceBuffer<F>,
    height: usize,
    width: usize,
}

impl<F> MatrixDimensions for PleMatrix<F> {
    fn height(&self) -> usize {
        self.height
    }

    fn width(&self) -> usize {
        self.width
    }
}

/// Generic `PleMatrix::from_evals` / `to_evals` for any field implementing `GpuNttField`, through
/// its field-specific `batch_ntt_small` dispatch.
impl<FieldT: crate::ntt_field::GpuNttField> PleMatrix<FieldT> {
    pub fn from_evals(
        l_skip: usize,
        evals: DeviceBuffer<FieldT>,
        height: usize,
        width: usize,
    ) -> Self {
        validate_gpu_l_skip(l_skip).expect("GPU PleMatrix requires l_skip <= 10");
        let mut mixed = evals;
        if l_skip > 0 {
            let num_uni_poly = width * (height >> l_skip);
            FieldT::batch_ntt_small(&mut mixed, l_skip, num_uni_poly, true)
                .expect("PleMatrix::from_evals: batch_ntt_small failed");
        }
        Self {
            mixed,
            height,
            width,
        }
    }

    /// Inverse of [`Self::from_evals`]: forward small-NTT per `2^l_skip` chunk back to
    /// evaluation form. D2D-copies `mixed` so the cached coefficient form is preserved.
    pub fn to_evals(&self, l_skip: usize) -> Result<DeviceMatrix<FieldT>, KernelError> {
        validate_gpu_l_skip(l_skip)?;
        let width = self.width();
        let height = self.height();
        let mut evals = self.mixed.device_copy()?;
        if l_skip > 0 {
            let num_uni_poly = width * (height >> l_skip);
            FieldT::batch_ntt_small(&mut evals, l_skip, num_uni_poly, false)
                .map_err(KernelError::Kernel)?;
        }
        Ok(DeviceMatrix::new(Arc::new(evals), height, width))
    }
}

/// Number of leading ladder stages computed on the host and uploaded as ONE seed buffer, instead
/// of one kernel launch (and, for [`EqEvalLayers`], one device allocation) each.
///
/// Stage `i` of the doubling ladder only touches `2^i` elements, so the first `k` stages together
/// touch `2^{k+1}` values: at `k = 8` that is 512 field elements (8 KiB), which the host builds in
/// ~8 us and uploads in a single H2D, against ~23 us of `cudaLaunchKernel` for the 8 launches it
/// replaces. Past ~10 the host arithmetic doubles past what the launches cost, so this does not
/// want to grow. Measured ladder lengths on the reth prove path: mean 5.8 stages for
/// `EqEvalLayers::new_with_kernels`, 9.3 for `new_rev_with_kernels`, 15.0 for
/// `EqEvalSegments::new_with_kernels` — 58 649 stage launches per run in total.
const HOST_SEED_STAGES: usize = 8;

/// Host-side prefix of the doubling ladder, laid out in the segment convention [`EqEvalSegments`]
/// uses: index 0 unused, layer `k` occupying `[2^k, 2^{k+1})`. Returns `2^{x.len()+1}` elements.
///
/// `INTERLEAVED` selects which stage kernel is being stood in for, and each arm mirrors that
/// kernel operation for operation (`hi = prev * x_i`, `hi` to the high/odd slot and `prev - hi` to
/// the low/even slot), so the seed is bit-identical to the launches it replaces.
fn host_eq_seed<F: p3_field::PrimeCharacteristicRing + Copy, const INTERLEAVED: bool>(
    x: &[F],
) -> Vec<F> {
    let mut buf = vec![F::ZERO; 2 << x.len()];
    buf[1] = F::ONE;
    for (i, &x_i) in x.iter().enumerate() {
        let step = 1 << i;
        let (src, dst) = (step, 2 * step);
        for y in 0..step {
            let prev = buf[src + y];
            let hi = prev * x_i;
            if INTERLEAVED {
                buf[dst + 2 * y] = prev - hi;
                buf[dst + 2 * y + 1] = hi;
            } else {
                buf[dst + y] = prev - hi;
                buf[dst + y + step] = hi;
            }
        }
    }
    buf
}

/// All prefix eq tables of one point `x in F^max_n`: for each `n` in `0..=max_n`, the values of
/// `eq_n(x[..n], -)` over `H_n`, packed back to back in one buffer of `2^(max_n + 1)` entries
/// (segment `n` starts at offset `2^n`). By convention `eq_0 = 1`.
#[derive(Getters)]
pub struct EqEvalSegments<F> {
    /// Slot 0 belongs to no segment; it is zero-initialised and never read.
    #[getset(get = "pub")]
    pub(crate) buffer: DeviceBuffer<F>,
    max_n: usize,
}

impl<F> EqEvalSegments<F> {
    /// Device pointer to the `2^k` values of `eq(x[..k], -)` over `H_k`.
    pub fn get_ptr(&self, k: usize) -> *const F {
        assert!(k <= self.max_n);
        // SAFETY: the buffer holds `2^{max_n + 1}` entries and `k <= max_n`
        unsafe { self.buffer.as_ptr().add(1 << k) }
    }

    /// # Safety
    /// `buf` must hold `2^{top_n + 1}` fully initialised entries laid out as described on the type.
    pub unsafe fn from_raw_parts(buf: DeviceBuffer<F>, top_n: usize) -> Self {
        Self {
            buffer: buf,
            max_n: top_n,
        }
    }
}

impl<ValExt: p3_field::PrimeCharacteristicRing + Copy> EqEvalSegments<ValExt> {
    /// Creates a new `EqEvalSegments` instance with `max_n = x.len()`, using a generic
    /// `FieldKernels` dispatch.
    pub fn new_with_kernels<FK: crate::cuda::field_kernels::FieldKernels<ValExt = ValExt>>(
        x: &[ValExt],
    ) -> Result<Self, KernelError> {
        use crate::runtime::copy::MemCopyH2D;
        use p3_field::PrimeCharacteristicRing;
        let max_n = x.len();
        let mut buffer: DeviceBuffer<ValExt> = DeviceBuffer::with_capacity(2 << max_n);
        // The first `seed_n` stages are computed on the host and uploaded as one seed covering
        // `[0, 2^{seed_n+1})`; `seed_n = 0` is exactly the old `[ZERO, ONE]` seed, and the loop
        // below then runs the remaining stages unchanged. See [`HOST_SEED_STAGES`].
        let seed_n = max_n.min(HOST_SEED_STAGES);
        let seed = host_eq_seed::<ValExt, false>(&x[..seed_n]);
        seed.copy_to(&mut buffer).map_err(KernelError::MemCopy)?;
        for (i, &x_i) in x.iter().enumerate().skip(seed_n) {
            let step = 1 << i;
            // SAFETY: `buffer` was allocated with capacity `2 << max_n = 2^{max_n+1}`, and for
            // every `step = 1 << i` with `i < max_n` we have `2 * (2 * step) <= 2^{max_n+1}`, so
            // `dst` and `src` (and the kernel's writes/reads relative to them) stay in-bounds.
            // The H2D seed `copy_to` above orders before this kernel on the per-thread default
            // stream, so the seed values are visible to it.
            unsafe {
                let dst = buffer.as_mut_ptr().add(2 * step);
                let src = buffer.as_ptr().add(step);
                FK::eq_hypercube_nonoverlapping_stage_ext(dst, src, x_i, step as u32)
                    .map_err(KernelError::Kernel)?;
            }
        }
        // `seed` is the source of an async H2D; hold it until every stage above is enqueued.
        drop(seed);
        Ok(Self { buffer, max_n })
    }
}

/// Like [EqEvalSegments], but the large top layers live in their own buffers so they can be
/// released one by one (see [`EqEvalLayers::pop_layer`]).
pub struct EqEvalLayers<F> {
    /// Layers `0..=seed_n`, packed contiguously in the same segment convention as
    /// [`EqEvalSegments`]: one buffer of length `2^{seed_n+1}` with layer `k` at offset `2^k`
    /// (index 0 is never read). One host computation + one H2D builds all of them, in place of
    /// `seed_n` kernel launches and `seed_n` device allocations.
    seed: crate::scratch::Scratch<F>,
    seed_n: usize,
    /// Layers `seed_n + 1 ..`, one owned buffer each: `tail[j]` holds layer `seed_n + 1 + j`.
    /// These stay per-layer rather than joining `seed` so [`Self::pop_layer`] still RELEASES the
    /// large top layers, which the zerocheck's per-round trim relies on for its peak.
    tail: Vec<crate::scratch::Scratch<F>>,
}

impl<F> EqEvalLayers<F> {
    /// Pointer to layer `n`: the `2^n` values of `eq(x[..n], -)` over the hypercube `H_n`.
    pub fn get_ptr(&self, n: usize) -> *const F {
        if n <= self.seed_n {
            debug_assert!(self.seed.len() >= 2 << self.seed_n);
            // SAFETY: `seed` has length `2^{seed_n+1}` and `n <= seed_n`, so offset `2^n` and the
            // `2^n` elements following it are in bounds.
            unsafe { self.seed.as_ptr().add(1 << n) }
        } else {
            let layer = &self.tail[n - self.seed_n - 1];
            debug_assert_eq!(layer.len(), 1 << n);
            layer.as_ptr()
        }
    }

    /// Index of the top layer held: the ladder covers layers `0..=n()`.
    pub fn n(&self) -> usize {
        self.seed_n + self.tail.len()
    }

    /// Drops the top layer, releasing its allocation when it is one of the per-layer `tail`
    /// buffers. Layer 0 is never dropped.
    pub fn pop_layer(&mut self) {
        if self.tail.pop().is_none() && self.seed_n > 0 {
            self.seed_n -= 1;
        }
    }

    /// Host copy of layer `k` (`2^k` elements). Diagnostic / test helper.
    pub fn layer_to_host(&self, k: usize) -> Result<Vec<F>, KernelError> {
        use crate::runtime::copy::MemCopyD2H;
        if k <= self.seed_n {
            let mut seed = self.seed.to_host().map_err(KernelError::MemCopy)?;
            seed.truncate(2 << k);
            Ok(seed.split_off(1 << k))
        } else {
            self.tail[k - self.seed_n - 1]
                .to_host()
                .map_err(KernelError::MemCopy)
        }
    }
}

impl<ValExt: p3_field::PrimeCharacteristicRing + Copy> EqEvalLayers<ValExt> {
    /// Generic `new_rev` that works for any field using `FK::eq_hypercube_interleaved_stage_ext`.
    pub fn new_rev_with_kernels<'a, FK: crate::cuda::field_kernels::FieldKernels<ValExt = ValExt>>(
        n: usize,
        x: impl IntoIterator<Item = &'a ValExt>,
    ) -> Result<Self, KernelError>
    where
        ValExt: 'a,
    {
        Self::build::<FK, true>(n, &x.into_iter().copied().collect::<Vec<_>>())
    }

    /// Generic `new` that works for any field using `FK::eq_hypercube_nonoverlapping_stage_ext`.
    pub fn new_with_kernels<'a, FK: crate::cuda::field_kernels::FieldKernels<ValExt = ValExt>>(
        n: usize,
        x: impl IntoIterator<Item = &'a ValExt>,
    ) -> Result<Self, KernelError>
    where
        ValExt: 'a,
    {
        Self::build::<FK, false>(n, &x.into_iter().copied().collect::<Vec<_>>())
    }

    /// Shared ladder builder for both bit-orders. Layers `0..=seed_n` come from one host
    /// computation and one H2D (see [`HOST_SEED_STAGES`]); the remaining stages launch the same
    /// stage kernel over the same operands as before, so the result is bit-identical.
    ///
    /// `n` is only the `tail` capacity hint; the ladder length is `xs.len()`, exactly as the old
    /// body took it from the iterator rather than from `n`.
    fn build<
        FK: crate::cuda::field_kernels::FieldKernels<ValExt = ValExt>,
        const INTERLEAVED: bool,
    >(
        n: usize,
        xs: &[ValExt],
    ) -> Result<Self, KernelError> {
        use crate::runtime::copy::MemCopyH2D;
        let seed_n = xs.len().min(HOST_SEED_STAGES);
        let seed_host = host_eq_seed::<ValExt, INTERLEAVED>(&xs[..seed_n]);
        let mut seed = crate::scratch::alloc::<ValExt>(2 << seed_n);
        seed_host.copy_to(&mut seed).map_err(KernelError::MemCopy)?;

        let mut tail: Vec<crate::scratch::Scratch<ValExt>> =
            Vec::with_capacity(n.saturating_sub(seed_n));
        for (i, &x_i) in xs.iter().enumerate().skip(seed_n) {
            let step = 1 << i;
            let buffer = crate::scratch::alloc::<ValExt>(2 * step);
            // SAFETY: `buffer` is freshly allocated with capacity `2 * step`; `src` is layer `i`,
            // which has length `step` — either the top segment of `seed` (in bounds because
            // `seed` has length `2^{seed_n+1}` and `i == seed_n` on the first iteration) or the
            // previous `tail` buffer; `dst`/`src` point at disjoint allocations, satisfying the
            // out-of-place kernel's non-overlap requirement. The previous layer's writes (the
            // H2D seed copy or an earlier iteration of this kernel) order before this call on the
            // per-thread default stream.
            unsafe {
                let dst = buffer.as_mut_ptr();
                let src = match tail.last() {
                    Some(prev) => prev.as_ptr(),
                    None => seed.as_ptr().add(step),
                };
                if INTERLEAVED {
                    FK::eq_hypercube_interleaved_stage_ext(dst, src, x_i, step as u32)
                } else {
                    FK::eq_hypercube_nonoverlapping_stage_ext(dst, src, x_i, step as u32)
                }
                .map_err(KernelError::Kernel)?;
            }
            tail.push(buffer);
        }
        // `seed_host` is the source of an async H2D; hold it until every stage above is enqueued.
        drop(seed_host);
        Ok(Self { seed, seed_n, tail })
    }
}

/// The eq table split into a low and a high half, each kept as a precomputed ladder of eq
/// layers.
///
/// Moving to the next round costs no GPU work: the top layer of the ladder is just dropped,
/// rather than folding a column on the device.
///
/// Type alias: `SqrtEqLayers` = `SqrtEqLayersFor<EF>`.
pub type SqrtEqLayers = SqrtEqLayersFor<EF>;

/// Generic version of `SqrtEqLayers` parametric over the extension field element type.
pub struct SqrtEqLayersFor<ValExt> {
    pub low: EqEvalLayers<ValExt>,
    pub high: EqEvalLayers<ValExt>,
}

impl<ValExt: p3_field::PrimeCharacteristicRing + Copy> SqrtEqLayersFor<ValExt> {
    pub fn from_xi_with_kernels<FK: crate::cuda::field_kernels::FieldKernels<ValExt = ValExt>>(
        xi: &[ValExt],
    ) -> Result<Self, KernelError> {
        let n = xi.len();
        let low_n = n / 2;
        let high_n = n - low_n;
        let low = EqEvalLayers::new_with_kernels::<FK>(low_n, xi[high_n..].iter().rev())?;
        let high = EqEvalLayers::new_with_kernels::<FK>(high_n, xi[..high_n].iter().rev())?;
        Ok(Self { low, high })
    }

    pub fn low_n(&self) -> usize {
        self.low.n()
    }
    pub fn high_n(&self) -> usize {
        self.high.n()
    }

    pub fn drop_layer(&mut self) {
        if self.high.n() > 0 {
            self.high.pop_layer();
        } else {
            self.low.pop_layer();
        }
    }
}
