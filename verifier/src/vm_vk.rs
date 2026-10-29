//! The exe identity as plain limbs, and its `riscv_vk_digest`.
//!
//! `pico-vm`'s `RiscvVmVk` holds the initial global cumulative sum as a septic curve point, a type
//! that needs nightly; [`VmVk`] holds the same 25 field elements flat, and owns the digest that
//! `RiscvVmVk::digest` delegates to.

use p3_field::{PrimeCharacteristicRing, PrimeField32};

use crate::{hash::sponge_hash, Kb, VerifyError};

/// Domain separator for `riscv_vk_digest` (distinguishes this sponge from the PV-digest sponge,
/// which absorbs no domain tag). Arbitrary fixed constant below the KoalaBear modulus.
pub const RISCV_VK_DIGEST_DOMAIN: u32 = 0x5256_766B; // "RVvk"

/// Field elements in a [`VmVk`]: program commit (8), entry pc (3), initial GCS x (7) and y (7).
pub const VM_VK_LEN: usize = 25;

/// The VM-layer RISC-V verifying key: the application identity folded into `riscv_vk_digest`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VmVk {
    /// Program-table preprocessed commitment.
    pub program_commit: [Kb; 8],
    /// Guest entry pc, 48-bit split into 3 limbs.
    pub pc_start: [Kb; 3],
    /// Initial global cumulative sum, x coordinate (septic extension limbs).
    pub initial_gcs_x: [Kb; 7],
    /// Initial global cumulative sum, y coordinate.
    pub initial_gcs_y: [Kb; 7],
}

impl VmVk {
    /// The 26 preimage elements, `[DOMAIN, program_commit, pc_start, gcs.x, gcs.y]`, matching the
    /// in-circuit hash input.
    pub fn digest_preimage(&self) -> Vec<Kb> {
        let mut elems = Vec::with_capacity(1 + VM_VK_LEN);
        elems.push(Kb::from_u32(RISCV_VK_DIGEST_DOMAIN));
        elems.extend_from_slice(&self.limbs());
        elems
    }

    /// `riscv_vk_digest = sponge(preimage)`, byte-identical to the in-circuit recomputation.
    pub fn digest(&self) -> [Kb; 8] {
        sponge_hash(&self.digest_preimage())
    }

    /// [`Self::digest`] as `0x` and 64 hex characters: each element's canonical `u32`, big-endian.
    /// This is the `verifier_id` a submission carries, so its spelling must not drift.
    pub fn digest_hex(&self) -> String {
        let digest = self.digest();
        let mut out = String::with_capacity(2 + digest.len() * 8);
        out.push_str("0x");
        for element in digest.iter() {
            out.push_str(&format!("{:08x}", element.as_canonical_u32()));
        }
        out
    }

    /// The 25 limbs in preimage order, without the domain tag.
    pub fn limbs(&self) -> [Kb; VM_VK_LEN] {
        let mut out = [Kb::ZERO; VM_VK_LEN];
        out[..8].copy_from_slice(&self.program_commit);
        out[8..11].copy_from_slice(&self.pc_start);
        out[11..18].copy_from_slice(&self.initial_gcs_x);
        out[18..].copy_from_slice(&self.initial_gcs_y);
        out
    }

    /// Inverse of [`Self::limbs`].
    pub fn from_limbs(e: &[Kb; VM_VK_LEN]) -> Self {
        Self {
            program_commit: std::array::from_fn(|i| e[i]),
            pc_start: std::array::from_fn(|i| e[8 + i]),
            initial_gcs_x: std::array::from_fn(|i| e[11 + i]),
            initial_gcs_y: std::array::from_fn(|i| e[18 + i]),
        }
    }

    /// The limbs as canonical `u32`s: the VK bundle's `vm_vk` field.
    pub fn to_u32s(&self) -> Vec<u32> {
        self.limbs().iter().map(|f| f.as_canonical_u32()).collect()
    }

    /// Inverse of [`Self::to_u32s`].
    pub fn from_u32s(e: &[u32]) -> Result<Self, VerifyError> {
        let e: &[u32; VM_VK_LEN] = e.try_into().map_err(|_| {
            VerifyError::Bundle(format!(
                "the guest identity needs {VM_VK_LEN} field elements, got {}",
                e.len()
            ))
        })?;
        Ok(Self::from_limbs(&e.map(Kb::from_u32)))
    }
}

#[cfg(test)]
mod tests {
    use p3_symmetric::Permutation;
    use pico_mle_core::config::koala_bear_poseidon2::default_koalabear_poseidon2_16;

    use super::*;

    fn sample_vk() -> VmVk {
        VmVk {
            program_commit: std::array::from_fn(|i| Kb::from_u32(100 + i as u32)),
            pc_start: [Kb::from_u32(7), Kb::from_u32(0), Kb::from_u32(0)],
            initial_gcs_x: std::array::from_fn(|i| Kb::from_u32(200 + i as u32)),
            initial_gcs_y: std::array::from_fn(|i| Kb::from_u32(300 + i as u32)),
        }
    }

    /// The preimage is exactly the 26 elements in the documented order.
    #[test]
    fn preimage_shape_is_26_ordered_elements() {
        let vk = sample_vk();
        let p = vk.digest_preimage();
        assert_eq!(p.len(), 26);
        assert_eq!(p[0], Kb::from_u32(RISCV_VK_DIGEST_DOMAIN));
        assert_eq!(&p[1..9], &vk.program_commit[..]);
        assert_eq!(&p[9..12], &vk.pc_start[..]);
        assert_eq!(&p[12..19], &vk.initial_gcs_x[..]);
        assert_eq!(&p[19..26], &vk.initial_gcs_y[..]);
    }

    /// `digest()` matches an independent inline reference sponge (pins the exact construction that
    /// the in-circuit `hash_poseidon2_fresh` must reproduce).
    #[test]
    fn digest_matches_reference_sponge() {
        let vk = sample_vk();
        let elems = vk.digest_preimage();
        let perm = default_koalabear_poseidon2_16();
        let mut state = [Kb::ZERO; 16];
        // 26 = 3*8 + 2 → three in-loop permutes + one trailing permute for the 2-element tail.
        let mut i = 0;
        while i < elems.len() {
            let end = (i + 8).min(elems.len());
            for (k, &v) in elems[i..end].iter().enumerate() {
                state[k] = v;
            }
            perm.permute_mut(&mut state);
            i = end;
        }
        let expect: [Kb; 8] = std::array::from_fn(|i| state[i]);
        assert_eq!(vk.digest(), expect);
    }

    /// Every field is bound: perturbing any one changes the digest.
    #[test]
    fn digest_is_sensitive_to_every_field() {
        let base = sample_vk().digest();

        let mut v = sample_vk();
        v.program_commit[0] += Kb::ONE;
        assert_ne!(v.digest(), base, "program_commit not bound");

        let mut v = sample_vk();
        v.pc_start[0] += Kb::ONE;
        assert_ne!(v.digest(), base, "pc_start not bound");

        let mut v = sample_vk();
        v.initial_gcs_x[0] += Kb::ONE;
        assert_ne!(v.digest(), base, "initial_gcs.x not bound");

        let mut v = sample_vk();
        v.initial_gcs_y[6] += Kb::ONE;
        assert_ne!(v.digest(), base, "initial_gcs.y not bound");
    }

    /// The 25 limbs survive the u32 round trip in preimage order; any other length is refused.
    #[test]
    fn u32s_round_trip() {
        let limbs: Vec<u32> = (1..=25).collect();
        let vk = VmVk::from_u32s(&limbs).unwrap();
        assert_eq!(vk.to_u32s(), limbs);
        assert_eq!(&vk.digest_preimage()[1..], &vk.limbs()[..]);
        assert!(VmVk::from_u32s(&limbs[..24]).is_err());
    }
}
