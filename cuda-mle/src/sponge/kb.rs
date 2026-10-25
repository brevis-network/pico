//! GPU-accelerated KoalaBear duplex sponge — the production Fiat-Shamir transcript
//! (the engine the RISCV path proves on).
//!
//! A host [`KbDuplexSponge`] that owns the transcript state, a `#[repr(C)]` device mirror,
//! explicit `sync_h2d`, and witness validation, over KoalaBear with Poseidon2 (alpha=3, 20
//! partial rounds); GPU grinding uses the `_kb_sponge_grind` kernel.
//!
//! # Grind history
//!
//! [`grind_gpu`] has a ≤12-bit CPU fast path, and its kernel checks canonical bits. The KB GPU
//! kernel once checked Montgomery-form bits while the verifier checks canonical bits, so the
//! transcript fell back to the rayon CPU `grind` for everything; `sponge.cu` now checks
//! canonical bits, re-enabling the GPU path.
//!
//! For small difficulty the trait `grind` is pathological: it fans the full 2^31 witness range
//! out via rayon `find_any`, paying ~1-2 ms of pool setup/cancellation per call with heavy
//! scheduling jitter (~26 calls per prove → the entire 28-52 ms whir_open variance), while the
//! expected work at `b` pow bits is just 2^b hash attempts. A sequential minimal-witness scan
//! is microseconds for the 1-3 bits WHIR/logup use, and makes the witness deterministic as a
//! bonus. The GPU path handles large difficulty (e.g. the WHIR query-phase 20 bits): one window
//! of 2^bits threads usually suffices, vs ~3-4 ms per call for the rayon full-range fan-out.

use std::ffi::c_void;

use mle_core::{
    config::koala_bear_poseidon2::{
        default_koalabear_poseidon2_16, DuplexSponge as KbDuplexSponge, KoalaBearPoseidon2Config,
    },
    FiatShamirTranscript,
};
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_koala_bear::KoalaBear;
use p3_symmetric::Permutation;

use super::{GpuFiatShamirTranscript, GrindError};
use crate::runtime::{copy::cuda_memcpy, d_buffer::DeviceBuffer, error::MemCopyError};

const KB_WIDTH: usize = 16;
const KB_CHUNK: usize = 8;

/// Device-side KoalaBear sponge state — matches `KbDeviceSpongeState` in sponge.cu.
#[repr(C)]
#[derive(Clone, Debug)]
pub struct KbDeviceSpongeState {
    pub state: [KoalaBear; KB_WIDTH],
    pub absorb_idx: u32,
    pub sample_idx: u32,
}

impl Default for KbDeviceSpongeState {
    fn default() -> Self {
        Self {
            state: [KoalaBear::default(); KB_WIDTH],
            absorb_idx: 0,
            sample_idx: 0,
        }
    }
}

impl KbDeviceSpongeState {
    pub fn observe(&mut self, value: KoalaBear) {
        self.state[self.absorb_idx as usize] = value;
        self.absorb_idx += 1;
        if self.absorb_idx == KB_CHUNK as u32 {
            default_koalabear_poseidon2_16().permute_mut(&mut self.state);
            self.absorb_idx = 0;
            self.sample_idx = KB_CHUNK as u32;
        }
    }

    pub fn sample(&mut self) -> KoalaBear {
        if self.absorb_idx != 0 || self.sample_idx == 0 {
            default_koalabear_poseidon2_16().permute_mut(&mut self.state);
            self.absorb_idx = 0;
            self.sample_idx = KB_CHUNK as u32;
        }
        self.sample_idx -= 1;
        self.state[self.sample_idx as usize]
    }
}

/// KoalaBear GPU-accelerated duplex sponge.
///
/// KoalaBear field and Poseidon2 (alpha=3, 20 partial rounds). GPU grinding uses the
/// `_kb_sponge_grind` kernel.
#[derive(Debug)]
pub struct KoalaBearDuplexSpongeGpu {
    host: KbDuplexSponge,
    device: DeviceBuffer<KbDeviceSpongeState>,
}

impl Default for KoalaBearDuplexSpongeGpu {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for KoalaBearDuplexSpongeGpu {
    fn clone(&self) -> Self {
        Self {
            host: self.host.clone(),
            device: DeviceBuffer::new(),
        }
    }
}

impl KoalaBearDuplexSpongeGpu {
    pub fn new() -> Self {
        Self {
            host: KbDuplexSponge::from(default_koalabear_poseidon2_16()),
            device: DeviceBuffer::new(),
        }
    }

    fn ensure_device_allocated(&mut self) {
        if self.device.is_empty() {
            self.device = DeviceBuffer::with_capacity(1);
        }
    }

    /// Sync host KbDuplexSponge state to the device-side KbDeviceSpongeState.
    pub fn sync_h2d(&mut self) -> Result<(), MemCopyError> {
        self.ensure_device_allocated();
        // DuplexSponge exposes state(), absorb_idx(), sample_idx() accessors.
        // Copy the current host transcript state to device so the GPU grinding
        // kernel operates on the correct Fiat-Shamir state.
        let device_state = KbDeviceSpongeState {
            state: *self.host.state(),
            absorb_idx: self.host.absorb_idx() as u32,
            sample_idx: self.host.sample_idx() as u32,
        };
        // SAFETY: copy a single `KbDeviceSpongeState` (`size_of::<KbDeviceSpongeState>()`
        // bytes) from the host stack to the device buffer.
        // - `self.device` was allocated with capacity 1 above, so `as_mut_ptr()` is a valid,
        //   properly-aligned device pointer for one `KbDeviceSpongeState`; `&device_state` is a
        //   valid, aligned host pointer to the same `#[repr(C)]` type.
        // - The copy length equals the struct size on both host and device.
        // - Ordering: the copy runs on the per-thread default stream, which orders it before
        //   the grinding kernel launched next on the same stream.
        unsafe {
            cuda_memcpy::<false, true>(
                self.device.as_mut_ptr() as *mut c_void,
                &device_state as *const KbDeviceSpongeState as *const c_void,
                std::mem::size_of::<KbDeviceSpongeState>(),
            )
        }
    }
}

impl FiatShamirTranscript<KoalaBearPoseidon2Config> for KoalaBearDuplexSpongeGpu {
    #[inline]
    fn observe(&mut self, value: KoalaBear) {
        FiatShamirTranscript::<KoalaBearPoseidon2Config>::observe(&mut self.host, value);
    }

    #[inline]
    fn sample(&mut self) -> KoalaBear {
        FiatShamirTranscript::<KoalaBearPoseidon2Config>::sample(&mut self.host)
    }

    #[inline]
    fn observe_commit(&mut self, digest: [KoalaBear; 8]) {
        for x in digest {
            self.observe(x);
        }
    }
}

impl GpuFiatShamirTranscript<KoalaBearPoseidon2Config> for KoalaBearDuplexSpongeGpu {
    /// Proof-of-work grinding: a sequential minimal-witness CPU scan for small difficulty
    /// (≤12 bits), the `_kb_sponge_grind` kernel for large. See the module docs for the
    /// history behind the split.
    fn grind_gpu(&mut self, bits: usize) -> Result<KoalaBear, GrindError> {
        if bits == 0 {
            return Ok(KoalaBear::ZERO);
        }
        if bits <= 12 {
            let mut w = 0u64;
            loop {
                let witness = KoalaBear::from_u64(w);
                if FiatShamirTranscript::<KoalaBearPoseidon2Config>::check_witness(
                    &mut self.host.clone(),
                    bits,
                    witness,
                ) {
                    // Advance the real transcript exactly like the trait `grind` does
                    // (observe(witness) + one sample consumed).
                    assert!(
                        FiatShamirTranscript::<KoalaBearPoseidon2Config>::check_witness(
                            &mut self.host,
                            bits,
                            witness,
                        )
                    );
                    return Ok(witness);
                }
                w += 1;
            }
        }
        // GPU path for large difficulty (e.g. the WHIR query-phase 20 bits): one window of
        // 2^bits threads usually suffices, vs ~3-4 ms per call for the rayon full-range
        // fan-out. Valid since the kernel now checks canonical bits (see the module docs).
        self.sync_h2d().map_err(GrindError::MemCopy)?;
        let witness_u32 = unsafe {
            crate::cuda::sponge_kb::kb_sponge_grind(
                self.device.as_ptr(),
                bits as u32,
                KoalaBear::ORDER_U32 - 1,
            )?
        };
        let witness = KoalaBear::from_u32(witness_u32);
        // Advance the real transcript (observe + sample) and validate the witness against
        // the host check the verifier uses.
        assert!(
            FiatShamirTranscript::<KoalaBearPoseidon2Config>::check_witness(
                &mut self.host,
                bits,
                witness,
            )
        );
        Ok(witness)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::copy::{MemCopyD2H, MemCopyH2D};

    /// Element-wise CPU<->GPU parity of the KoalaBear Poseidon2 permutation.
    /// KB is the production transcript; its header carries the Plonky3 0.5 KoalaBear schedule,
    /// so this must pass at baseline.
    #[test]
    fn test_kb_permutation_gpu_matches_cpu() {
        let state: [KoalaBear; KB_WIDTH] =
            core::array::from_fn(|i| KoalaBear::from_u32(i as u32 * 31 + 7));
        let mut expected = state;
        default_koalabear_poseidon2_16().permute_mut(&mut expected);

        let d_state = state.as_slice().to_device().expect("H2D");
        unsafe { crate::cuda::sponge_kb::kb_poseidon2_permute_device(d_state.as_mut_ptr()) }
            .expect("permute kernel");
        let gpu = d_state.to_host().expect("D2H");

        for i in 0..KB_WIDTH {
            assert_eq!(
                gpu[i], expected[i],
                "KB permutation diverges at element {i}"
            );
        }
    }

    /// The host-side `KbDeviceSpongeState` mirror must match mle-core's `DuplexSponge` exactly. The KB production
    /// transcript had no such parity test before 2c.
    #[test]
    fn test_kb_device_sponge_state_matches_duplex_sponge() {
        let mut device_state = KbDeviceSpongeState::default();
        let mut duplex: KbDuplexSponge = default_koalabear_poseidon2_16().into();

        for i in 0..20 {
            let val = KoalaBear::from_u32(i * 42 + 17);
            device_state.observe(val);
            FiatShamirTranscript::<KoalaBearPoseidon2Config>::observe(&mut duplex, val);
        }
        for _ in 0..10 {
            assert_eq!(
                device_state.sample(),
                FiatShamirTranscript::<KoalaBearPoseidon2Config>::sample(&mut duplex)
            );
        }
        // Interleaved observe/sample
        for i in 0..5 {
            let val = KoalaBear::from_u32(i * 100);
            device_state.observe(val);
            FiatShamirTranscript::<KoalaBearPoseidon2Config>::observe(&mut duplex, val);
            assert_eq!(
                device_state.sample(),
                FiatShamirTranscript::<KoalaBearPoseidon2Config>::sample(&mut duplex)
            );
        }
        // Sample runs crossing the rate boundary
        for _ in 0..15 {
            assert_eq!(
                device_state.sample(),
                FiatShamirTranscript::<KoalaBearPoseidon2Config>::sample(&mut duplex)
            );
        }
    }

    /// Forces the `_kb_sponge_grind` kernel path (bits > 12 skips the CPU scan) and validates the
    /// witness against an INDEPENDENT CPU transcript — the exact contract WHIR's query-phase pow
    /// relies on in production. Uses the trait `grind_gpu` — the single grind entry point after
    /// the field-specific implementation was folded into it.
    #[test]
    fn test_kb_grind_gpu_kernel_witness_valid_on_cpu() {
        let bits = 16;
        let mut gpu = KoalaBearDuplexSpongeGpu::new();
        let mut cpu: KbDuplexSponge = default_koalabear_poseidon2_16().into();

        for i in 0..7 {
            let val = KoalaBear::from_u32(i * 41 + 3);
            FiatShamirTranscript::<KoalaBearPoseidon2Config>::observe(&mut gpu, val);
            FiatShamirTranscript::<KoalaBearPoseidon2Config>::observe(&mut cpu, val);
        }

        let witness = gpu.grind_gpu(bits).expect("KB GPU grind failed");
        assert!(
            FiatShamirTranscript::<KoalaBearPoseidon2Config>::check_witness(
                &mut cpu, bits, witness
            ),
            "KB GPU witness {witness:?} invalid on independent CPU transcript"
        );
    }
}
