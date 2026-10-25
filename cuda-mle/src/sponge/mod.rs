//! GPU-accelerated Fiat-Shamir transcripts (duplex sponges with device-side grinding).
//!
//! KoalaBear ([`kb`]) is the transcript (the engine the RISCV path proves on): a host-side
//! transcript that owns Fiat-Shamir state, a `#[repr(C)]` device mirror for the CUDA grinding
//! kernel, explicit `sync_h2d`, and witness validation against the same `check_witness` the
//! verifier runs. The Poseidon2 permutation on both sides is Plonky3 0.5's width-16 instance
//! (`default_koalabear_poseidon2_16`) — see `hash/poseidon2/poseidon2.cuh`.

use mle_core::{FiatShamirTranscript, StarkProtocolConfig};

use crate::runtime::error::{CudaError, MemCopyError};

mod kb;

pub use kb::{KbDeviceSpongeState, KoalaBearDuplexSpongeGpu};

/// Validate that a `bits`-bit GPU proof-of-work grind over a field of order `field_order`
/// is representable: the window stride `1 << bits` must fit `u32`, and the witness search
/// space `[0, field_order)` must be large enough to contain a `bits`-bit target.
///
/// The field order is passed explicitly rather than read from a `types`-prelude `F`, so the
/// transcript validates against its own `F::ORDER_U32` instead of whichever field the prelude
/// happens to re-export.
pub(crate) fn validate_gpu_grind_bits(bits: usize, field_order: u32) -> Result<(), GrindError> {
    if bits >= u32::BITS as usize || (1u64 << bits) >= u64::from(field_order) {
        return Err(CudaError::new(1).into());
    }
    Ok(())
}

/// Ways a device-side proof-of-work grind can fail.
#[derive(Debug, thiserror::Error)]
pub enum GrindError {
    #[error("grind: host/device memory copy failed: {0}")]
    MemCopy(#[from] MemCopyError),

    #[error("grind: CUDA call failed: {0}")]
    Cuda(#[from] CudaError),

    #[error("grind: no proof-of-work witness exists in the searched range")]
    WitnessNotFound,
}

/// A [`FiatShamirTranscript`] that can also run its proof-of-work search on the GPU.
///
/// Implementors keep a copy of the sponge state in device memory so the brute-force witness
/// search can be handed to a CUDA kernel.
pub trait GpuFiatShamirTranscript<Config: StarkProtocolConfig>:
    FiatShamirTranscript<Config>
{
    /// Proof-of-work grind on the device.
    ///
    /// Searches for a `Config::F` witness `w` such that observing `w` and then sampling yields a
    /// value with `bits` trailing zero bits. The expected flow: push the host state to the
    /// device, run the grinding kernel, then advance the host transcript the same way (observe
    /// the witness, draw one sample).
    fn grind_gpu(&mut self, bits: usize) -> Result<Config::F, GrindError>;
}
