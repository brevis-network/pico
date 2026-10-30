//! `RiscvVmVk` — the VM-layer RISC-V verifying key (the "exe" identity object).
//!
//! The MLE protocol vk (`MultiStarkVerifyingKey`) carries only STARK structure: it has no
//! `pc_start` / initial-memory fields, and its (lean) pre-hash deliberately does not cover the
//! program commitment (see `compute_vk_pre_hash`). `RiscvVmVk` bundles the
//! three application-identity fields the recursion needs — program table commitment, guest entry
//! pc, and initial global-cumulative-sum (the septic initial-memory summary) — and folds them
//! into a single `riscv_vk_digest`.
//!
//! The digest is `pico_verifier::VmVk`'s: the padding-free rate-8/width-16 overwrite sponge used
//! for the recursion PV digest and mirrored in-circuit by `Builder::hash_poseidon2_fresh`, so the
//! host value and the in-circuit recomputation agree bit-for-bit. Field order:
//! `[DOMAIN, program_commit(8), pc_start(3), gcs.x(7), gcs.y(7)]`.

use p3_field::PrimeCharacteristicRing;
use pico_mle_core::StarkProtocolConfig;
pub(crate) use pico_verifier::hash::sponge_hash;
pub use pico_verifier::vm_vk::RISCV_VK_DIGEST_DOMAIN;
use pico_verifier::{vm_vk::VM_VK_LEN, VmVk};
use static_assertions::const_assert_eq;

use crate::{
    compiler::{program::ProgramBehavior, riscv::program::Program},
    emulator::riscv::public_values_compat::encode_public_value_pc_limbs,
    machine::septic::{SepticCurve, SepticDigest, SepticExtension},
    mle::machine::riscv::{riscv_program_commit, Kb, Sc},
};

// `VmVk` hard-codes the 25-limb layout (program commit 8, pc 3, gcs x 7, gcs y 7) because the
// septic types need nightly; any drift must fail the build here.
const_assert_eq!(
    size_of::<<Sc as StarkProtocolConfig>::Digest>(),
    8 * size_of::<Kb>()
);
const_assert_eq!(size_of::<SepticExtension<Kb>>(), 7 * size_of::<Kb>());
const_assert_eq!(size_of::<RiscvVmVk>(), VM_VK_LEN * size_of::<Kb>());
const_assert_eq!(size_of::<VmVk>(), size_of::<RiscvVmVk>());

/// VM-layer RISC-V verifying key: the application-identity triple folded into `riscv_vk_digest`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RiscvVmVk {
    /// Program-table preprocessed commitment. Dual-role bridge value: a WHIR stacking (Merkle)
    /// root in the STARK layer, and the program identity in the VM layer.
    pub program_commit: <Sc as StarkProtocolConfig>::Digest,
    /// Guest entry pc, 48-bit split into 3 limbs (matches `encode_public_value_pc_limbs`).
    pub pc_start: [Kb; 3],
    /// Initial global-cumulative-sum (septic point) = the initial-memory summary term.
    pub initial_gcs: SepticDigest<Kb>,
}

impl RiscvVmVk {
    /// [`Self::digest`] as `0x` followed by 64 hex characters: the `verifier_id` a submission
    /// carries. The spelling is [`VmVk::digest_hex`]'s.
    pub fn digest_hex(&self) -> String {
        self.vm_vk().digest_hex()
    }

    /// Assemble from the guest program (entry pc + initial memory) and its RISC-V verifying key
    /// (program-table commitment).
    pub fn from_program_and_vk(
        program: &Program,
        riscv_vk: &pico_mle_core::keygen::types::MultiStarkVerifyingKey<Sc>,
    ) -> Self {
        Self {
            program_commit: riscv_program_commit(riscv_vk),
            pc_start: encode_public_value_pc_limbs(program.pc_start).map(Kb::from_u32),
            initial_gcs: program.initial_global_cumulative_sum(),
        }
    }

    /// The septic-free form the verifier works with: the same 25 limbs, flat.
    pub fn vm_vk(&self) -> VmVk {
        VmVk {
            program_commit: self.program_commit,
            pc_start: self.pc_start,
            initial_gcs_x: self.initial_gcs.0.x.0,
            initial_gcs_y: self.initial_gcs.0.y.0,
        }
    }

    /// Inverse of [`Self::vm_vk`].
    pub fn from_vm_vk(vm_vk: &VmVk) -> Self {
        Self {
            program_commit: vm_vk.program_commit,
            pc_start: vm_vk.pc_start,
            initial_gcs: SepticDigest(SepticCurve {
                x: SepticExtension(vm_vk.initial_gcs_x),
                y: SepticExtension(vm_vk.initial_gcs_y),
            }),
        }
    }

    /// The 26 preimage field elements in canonical order, matching the in-circuit hash input.
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
            initial_gcs: SepticDigest(SepticCurve {
                x: SepticExtension(std::array::from_fn(|i| Kb::from_u32(200 + i as u32))),
                y: SepticExtension(std::array::from_fn(|i| Kb::from_u32(300 + i as u32))),
            }),
        }
    }

    /// The septic point lands in the preimage x then y, after program commit and entry pc; the
    /// rest of the digest is `pico_verifier::vm_vk`'s and tested there.
    #[test]
    fn preimage_shape_is_26_ordered_elements() {
        let vk = sample_vk();
        let p = vk.digest_preimage();
        assert_eq!(p.len(), 26);
        assert_eq!(p[0], Kb::from_u32(RISCV_VK_DIGEST_DOMAIN));
        assert_eq!(&p[1..9], &vk.program_commit[..]);
        assert_eq!(&p[9..12], &vk.pc_start[..]);
        assert_eq!(&p[12..19], &vk.initial_gcs.0.x.0[..]);
        assert_eq!(&p[19..26], &vk.initial_gcs.0.y.0[..]);
        assert_eq!(RiscvVmVk::from_vm_vk(&vk.vm_vk()), vk);
    }
}
