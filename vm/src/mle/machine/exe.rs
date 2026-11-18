//! `RiscvVmVk` — the VM-layer RISC-V verifying key (the "exe" identity object).
//!
//! The MLE protocol vk (`MultiStarkVerifyingKey`) carries only STARK structure: it has no
//! `pc_start` / initial-memory fields, and its (lean) pre-hash deliberately does not cover the
//! program commitment (see `compute_vk_pre_hash`). `RiscvVmVk` bundles the application-identity
//! fields the recursion needs — program table commitment, guest entry pc, and the commitment
//! and height tier of the program's memory image table — and folds them into a single
//! `riscv_vk_digest`.
//!
//! The digest is `pico_verifier::VmVk`'s: the padding-free rate-8/width-16 overwrite sponge used
//! for the recursion PV digest and mirrored in-circuit by `Builder::hash_poseidon2_fresh`, so the
//! host value and the in-circuit recomputation agree bit-for-bit. Field order:
//! `[DOMAIN, program_commit(8), pc_start(3), image_commit(8), image_log_height(1)]`.
//!
//! The image table is committed under the RISC-V machine's parameters, so the identity is of a
//! program at one operating point: the same ELF at another stacked height has another digest,
//! as it already had through the program-table commitment.

use p3_field::{PrimeCharacteristicRing, PrimeField32};
use pico_mle_core::{keygen::types::MultiStarkVerifyingKey, StarkProtocolConfig};
pub(crate) use pico_verifier::hash::sponge_hash;
pub use pico_verifier::vm_vk::RISCV_VK_DIGEST_DOMAIN;
use pico_verifier::{vm_vk::VM_VK_LEN, VmVk};
use static_assertions::const_assert_eq;

use crate::{
    compiler::riscv::program::Program,
    mle::machine::{
        global_logup::ImageCommitment,
        riscv::{riscv_program_commit, Kb, ProgramIdentity, Sc},
    },
};

// `VmVk` is the same 20 limbs (program commit 8, pc 3, image commitment 8, image tier 1); any
// drift must fail the build here.
const_assert_eq!(
    size_of::<<Sc as StarkProtocolConfig>::Digest>(),
    8 * size_of::<Kb>()
);
const_assert_eq!(size_of::<RiscvVmVk>(), VM_VK_LEN * size_of::<Kb>());
const_assert_eq!(size_of::<VmVk>(), size_of::<RiscvVmVk>());

/// VM-layer RISC-V verifying key: the application identity folded into `riscv_vk_digest`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RiscvVmVk {
    /// Program-table preprocessed commitment. Dual-role bridge value: a WHIR stacking (Merkle)
    /// root in the STARK layer, and the program identity in the VM layer.
    pub program_commit: <Sc as StarkProtocolConfig>::Digest,
    /// Guest entry pc, 48-bit split into 3 limbs (matches `encode_public_value_pc_limbs`).
    pub pc_start: [Kb; 3],
    /// Commitment of the program's memory image table: the initial memory, as the global LogUp
    /// reads it.
    pub image_commit: <Sc as StarkProtocolConfig>::Digest,
    /// The height tier the image table is committed at (log2 of its rows), as a field element.
    pub image_log_height: Kb,
}

impl RiscvVmVk {
    /// [`Self::digest`] as `0x` followed by 64 hex characters: the `verifier_id` a submission
    /// carries. The spelling is [`VmVk::digest_hex`]'s.
    pub fn digest_hex(&self) -> String {
        self.vm_vk().digest_hex()
    }

    /// Assemble from the guest program (entry pc + initial memory) and its RISC-V verifying key
    /// (program-table commitment). Commits the program's memory image table, which is a
    /// Reed–Solomon encoding and a Merkle tree: a caller that already holds the program's
    /// [`ProgramIdentity`] uses [`Self::from_identity`].
    ///
    /// # Panics
    /// If the memory image is larger than the largest image table.
    pub fn from_program_and_vk(program: &Program, riscv_vk: &MultiStarkVerifyingKey<Sc>) -> Self {
        let identity =
            ProgramIdentity::new(program, &riscv_vk.inner.params).unwrap_or_else(|e| panic!("{e}"));
        Self::from_identity(riscv_vk, &identity)
    }

    /// Assemble from the RISC-V verifying key (program-table commitment) and what
    /// [`ProgramIdentity`] holds of the program.
    pub fn from_identity(
        riscv_vk: &MultiStarkVerifyingKey<Sc>,
        identity: &ProgramIdentity,
    ) -> Self {
        Self {
            program_commit: riscv_program_commit(riscv_vk),
            pc_start: identity.pc_start,
            image_commit: identity.image.commit,
            image_log_height: Kb::from_usize(identity.image.log_height),
        }
    }

    /// The entry pc and the image commitment: what the native RISC-V verifier trusts about the
    /// program beyond its verifying key.
    pub fn identity(&self) -> ProgramIdentity {
        ProgramIdentity {
            pc_start: self.pc_start,
            image: ImageCommitment {
                commit: self.image_commit,
                log_height: self.image_log_height.as_canonical_u32() as usize,
            },
        }
    }

    /// The form the verifier works with: the same 20 limbs.
    pub fn vm_vk(&self) -> VmVk {
        VmVk {
            program_commit: self.program_commit,
            pc_start: self.pc_start,
            image_commit: self.image_commit,
            image_log_height: self.image_log_height,
        }
    }

    /// Inverse of [`Self::vm_vk`].
    pub fn from_vm_vk(vm_vk: &VmVk) -> Self {
        Self {
            program_commit: vm_vk.program_commit,
            pc_start: vm_vk.pc_start,
            image_commit: vm_vk.image_commit,
            image_log_height: vm_vk.image_log_height,
        }
    }

    /// The 21 preimage field elements in canonical order, matching the in-circuit hash input.
    pub fn digest_preimage(&self) -> Vec<Kb> {
        self.vm_vk().digest_preimage()
    }

    /// `riscv_vk_digest = sponge(preimage)`, byte-identical to the in-circuit recomputation.
    pub fn digest(&self) -> <Sc as StarkProtocolConfig>::Digest {
        self.vm_vk().digest()
    }
}

impl From<&RiscvVmVk> for VmVk {
    fn from(vk: &RiscvVmVk) -> Self {
        vk.vm_vk()
    }
}

impl From<RiscvVmVk> for VmVk {
    fn from(vk: RiscvVmVk) -> Self {
        vk.vm_vk()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_vk() -> RiscvVmVk {
        RiscvVmVk {
            program_commit: std::array::from_fn(|i| Kb::from_u32(100 + i as u32)),
            pc_start: [Kb::from_u32(7), Kb::from_u32(0), Kb::from_u32(0)],
            image_commit: std::array::from_fn(|i| Kb::from_u32(200 + i as u32)),
            image_log_height: Kb::from_u32(19),
        }
    }

    /// The image's commitment and tier land in the preimage after program commit and entry pc;
    /// the rest of the digest is `pico_verifier::vm_vk`'s and tested there.
    #[test]
    fn preimage_shape_is_21_ordered_elements() {
        let vk = sample_vk();
        let p = vk.digest_preimage();
        assert_eq!(p.len(), 21);
        assert_eq!(p[0], Kb::from_u32(RISCV_VK_DIGEST_DOMAIN));
        assert_eq!(&p[1..9], &vk.program_commit[..]);
        assert_eq!(&p[9..12], &vk.pc_start[..]);
        assert_eq!(&p[12..20], &vk.image_commit[..]);
        assert_eq!(p[20], vk.image_log_height);
        assert_eq!(RiscvVmVk::from_vm_vk(&vk.vm_vk()), vk);
        assert_eq!(vk.identity().image.log_height, 19);
    }
}
