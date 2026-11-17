//! The exe identity as plain limbs, and its `riscv_vk_digest`.
//!
//! [`VmVk`] holds the 20 field elements that identify a guest program at one operating point:
//! the program-table commitment, the entry pc, and the commitment and height tier of the
//! program's memory image table. It owns the digest `pico-vm`'s `RiscvVmVk::digest` delegates to.

use p3_field::{PrimeCharacteristicRing, PrimeField32};

use crate::{hash::sponge_hash, Kb, VerifyError};

/// Domain separator for `riscv_vk_digest`, `"RVv2"` (distinguishes this sponge from the PV-digest
/// sponge, which absorbs no domain tag). Version 2: the preimage carries the memory image's
/// commitment and tier where version 1 (`"RVvk"`) carried the initial cumulative sum.
pub const RISCV_VK_DIGEST_DOMAIN: u32 = 0x5256_7632;

// Every digest of the global LogUp leads its preimage with a tag of its own, one field element,
// and so do this crate's digests: no two families share one. The keygen's two digests take
// their preimage a byte an element, so theirs starts with an element below 256, which none of
// the others is; their words are listed to keep the names apart as well.
const _: () = {
    use pico_mle_core::{
        global_logup::{TAG_CHALLENGE, TAG_IV, TAG_LEAF, TAG_PARAMS, TAG_TOP, TAG_WRAP},
        keygen::{CONSTRAINT_DIGEST_DOMAIN, LEAN_VK_PRE_HASH_DOMAIN},
    };
    let tags = [
        RISCV_VK_DIGEST_DOMAIN,
        crate::whitelist::VK_MAP_LEAF_DOMAIN,
        LEAN_VK_PRE_HASH_DOMAIN,
        CONSTRAINT_DIGEST_DOMAIN,
        TAG_IV,
        TAG_LEAF,
        TAG_WRAP,
        TAG_TOP,
        TAG_CHALLENGE,
        TAG_PARAMS,
    ];
    let mut i = 0;
    while i < tags.len() {
        assert!(tags[i] > 255, "a domain tag is a byte");
        let mut j = i + 1;
        while j < tags.len() {
            assert!(tags[i] != tags[j], "two domain tags are equal");
            j += 1;
        }
        i += 1;
    }
};

/// Field elements in a [`VmVk`]: program commit (8), entry pc (3), image commitment (8), image
/// tier (1).
pub const VM_VK_LEN: usize = 20;

/// The VM-layer RISC-V verifying key: the application identity folded into `riscv_vk_digest`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VmVk {
    /// Program-table preprocessed commitment.
    pub program_commit: [Kb; 8],
    /// Guest entry pc, 48-bit split into 3 limbs.
    pub pc_start: [Kb; 3],
    /// Commitment of the program's memory image table.
    pub image_commit: [Kb; 8],
    /// The height tier the image table is committed at: log2 of its rows.
    ///
    /// Part of the identity, not only the commitment: one commitment can be read as a table of
    /// another tier, and the tier in the digest is what pins a program to its own.
    pub image_log_height: Kb,
}

impl VmVk {
    /// The 21 preimage elements,
    /// `[DOMAIN, program_commit, pc_start, image_commit, image_log_height]`, matching the
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

    /// The 20 limbs in preimage order, without the domain tag.
    pub fn limbs(&self) -> [Kb; VM_VK_LEN] {
        let mut out = [Kb::ZERO; VM_VK_LEN];
        out[..8].copy_from_slice(&self.program_commit);
        out[8..11].copy_from_slice(&self.pc_start);
        out[11..19].copy_from_slice(&self.image_commit);
        out[19] = self.image_log_height;
        out
    }

    /// Inverse of [`Self::limbs`].
    pub fn from_limbs(e: &[Kb; VM_VK_LEN]) -> Self {
        Self {
            program_commit: std::array::from_fn(|i| e[i]),
            pc_start: std::array::from_fn(|i| e[8 + i]),
            image_commit: std::array::from_fn(|i| e[11 + i]),
            image_log_height: e[19],
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
            image_commit: std::array::from_fn(|i| Kb::from_u32(200 + i as u32)),
            image_log_height: Kb::from_u32(19),
        }
    }

    /// The preimage is exactly the 21 elements in the documented order.
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
    }

    /// `digest()` matches an independent inline reference sponge (pins the exact construction that
    /// the in-circuit `hash_poseidon2_fresh` must reproduce).
    #[test]
    fn digest_matches_reference_sponge() {
        let vk = sample_vk();
        let elems = vk.digest_preimage();
        let perm = default_koalabear_poseidon2_16();
        let mut state = [Kb::ZERO; 16];
        // 21 = 2*8 + 5 → two in-loop permutes + one trailing permute for the 5-element tail.
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

    /// Every field is bound: perturbing any one changes the digest. The image's tier is one of
    /// them, apart from its commitment.
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
        v.image_commit[7] += Kb::ONE;
        assert_ne!(v.digest(), base, "image_commit not bound");

        let mut v = sample_vk();
        v.image_log_height += Kb::ONE;
        assert_ne!(v.digest(), base, "image_log_height not bound");
    }

    /// The 20 limbs survive the u32 round trip in preimage order; any other length is refused.
    #[test]
    fn u32s_round_trip() {
        let limbs: Vec<u32> = (1..=20).collect();
        let vk = VmVk::from_u32s(&limbs).unwrap();
        assert_eq!(vk.to_u32s(), limbs);
        assert_eq!(&vk.digest_preimage()[1..], &vk.limbs()[..]);
        assert!(VmVk::from_u32s(&limbs[..19]).is_err());
    }
}
