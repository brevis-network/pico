//! The recursion public values a verifier reads, and the checks every complete root must pass.
//!
//! The layout itself is `pico-vm`'s `RecursionPublicValues` (it holds a septic type, which needs
//! nightly); this module hard-codes the offsets the checks read, and `pico-vm` asserts at
//! compile time that each one equals its `RECURSION_PUBLIC_VALUES_COL_MAP` entry.

use p3_field::{PrimeCharacteristicRing, PrimeField32};
use sha2::{Digest, Sha256};

use crate::{hash::sponge_hash, Kb, VerifyError};

/// Length of the recursion public-value vector.
pub const RECURSION_NUM_PVS: usize = 119;
/// Every element before `digest` is hashed into it.
pub const NUM_PV_ELMS_TO_HASH: usize = 110;

/// Offsets into the recursion public-value vector of the values the verifier reads (not trace
/// columns).
#[derive(Clone, Copy, Debug)]
pub struct RecursionPvOffsets {
    /// SHA-256 of the guest's committed bytes, one byte per element (8 words × 4 bytes).
    pub committed_value_digest: [usize; 32],
    pub riscv_vk_digest: [usize; 8],
    pub vk_root: [usize; 8],
    pub flag_complete: usize,
    pub digest: [usize; 8],
}

const fn range<const N: usize>(start: usize) -> [usize; N] {
    let mut out = [0; N];
    let mut i = 0;
    while i < N {
        out[i] = start + i;
        i += 1;
    }
    out
}

/// The offsets, as `pico-vm`'s `RecursionPublicValues` lays them out.
pub const RECURSION_PV_OFFSETS: RecursionPvOffsets = RecursionPvOffsets {
    committed_value_digest: range(0),
    riscv_vk_digest: range(78),
    vk_root: range(86),
    flag_complete: 108,
    digest: range(110),
};

/// The recursion public-value vector among a proof's per-AIR ones: the only one of length
/// [`RECURSION_NUM_PVS`].
pub fn recursion_public_values(pv_sets: &[Vec<Kb>]) -> Result<&[Kb], VerifyError> {
    pv_sets
        .iter()
        .find(|p| p.len() == RECURSION_NUM_PVS)
        .map(|p| p.as_slice())
        .ok_or(VerifyError::NoRecursionPublicValues)
}

/// The four public-value checks every complete root must pass, whatever config proved it.
///
/// 1. `flag_complete == 1`: arms the in-circuit completeness assertions.
/// 2. `riscv_vk_digest` equals the trusted exe identity's digest: pins program, entry pc and
///    initial memory.
/// 3. `vk_root` equals the trusted whitelist root, when whitelist mode is on; the in-circuit
///    checks propagate it to every node.
/// 4. The PV digest recomputes from the hashed prefix.
///
/// `label` names the layer in error messages ("root", "embed"). `pvs` must be
/// [`RECURSION_NUM_PVS`] long (see [`recursion_public_values`]).
pub fn check_complete_root_public_values(
    label: &str,
    pvs: &[Kb],
    trusted_riscv_vk_digest: &[Kb; 8],
    trusted_vk_root: Option<&[Kb; 8]>,
) -> Result<(), VerifyError> {
    let at = RECURSION_PV_OFFSETS;
    let label = || label.to_string();

    if pvs[at.flag_complete] != Kb::ONE {
        return Err(VerifyError::Incomplete { label: label() });
    }
    for (limb, &idx) in at.riscv_vk_digest.iter().enumerate() {
        if pvs[idx] != trusted_riscv_vk_digest[limb] {
            return Err(VerifyError::RiscvVkDigestMismatch {
                label: label(),
                limb,
            });
        }
    }
    if let Some(trusted_root) = trusted_vk_root {
        for (limb, &idx) in at.vk_root.iter().enumerate() {
            if pvs[idx] != trusted_root[limb] {
                return Err(VerifyError::VkRootMismatch {
                    label: label(),
                    limb,
                });
            }
        }
    }
    let digest = sponge_hash(&pvs[..NUM_PV_ELMS_TO_HASH]);
    for (limb, &idx) in at.digest.iter().enumerate() {
        if pvs[idx] != digest[limb] {
            return Err(VerifyError::PvDigestMismatch {
                label: label(),
                limb,
            });
        }
    }
    Ok(())
}

/// The `committed_value_digest` a recursion public-value vector attests to. Each element holds one
/// byte (not a u16 limb pair), so anything above 255 is refused.
pub fn committed_value_digest(pvs: &[Kb]) -> Result<[u8; 32], VerifyError> {
    let mut out = [0u8; 32];
    for (slot, &index) in out
        .iter_mut()
        .zip(&RECURSION_PV_OFFSETS.committed_value_digest)
    {
        let value = pvs
            .get(index)
            .ok_or(VerifyError::NoRecursionPublicValues)?
            .as_canonical_u32();
        *slot = u8::try_from(value).map_err(|_| VerifyError::DigestLimbNotByte { index, value })?;
    }
    Ok(out)
}

/// Whether `committed` are the bytes a proof with `digest` attests to. An all-zero digest is a
/// guest that never committed, so only empty bytes match it.
pub fn committed_values_bound(committed: &[u8], digest: &[u8; 32]) -> bool {
    if *digest == [0u8; 32] {
        committed.is_empty()
    } else {
        <[u8; 32]>::from(Sha256::digest(committed)) == *digest
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A public-value vector that passes every check, built the way an honest prover would.
    fn honest_pvs(vk_root: [Kb; 8]) -> Vec<Kb> {
        let at = RECURSION_PV_OFFSETS;
        let mut pvs = vec![Kb::ZERO; RECURSION_NUM_PVS];
        pvs[at.flag_complete] = Kb::ONE;
        for (j, &idx) in at.riscv_vk_digest.iter().enumerate() {
            pvs[idx] = Kb::from_u32(1000 + j as u32);
        }
        for (j, &idx) in at.vk_root.iter().enumerate() {
            pvs[idx] = vk_root[j];
        }
        redigest(&mut pvs);
        pvs
    }

    fn redigest(pvs: &mut [Kb]) {
        let digest = sponge_hash(&pvs[..NUM_PV_ELMS_TO_HASH]);
        for (j, &idx) in RECURSION_PV_OFFSETS.digest.iter().enumerate() {
            pvs[idx] = digest[j];
        }
    }

    fn trusted_digest() -> [Kb; 8] {
        std::array::from_fn(|j| Kb::from_u32(1000 + j as u32))
    }

    fn vk_root() -> [Kb; 8] {
        std::array::from_fn(|j| Kb::from_u32(77 + j as u32))
    }

    #[test]
    fn honest_public_values_pass() {
        let pvs = honest_pvs(vk_root());
        check_complete_root_public_values("test", &pvs, &trusted_digest(), Some(&vk_root()))
            .expect("honest public values must pass");
        // Whitelist mode off skips only check (3).
        check_complete_root_public_values("test", &pvs, &trusted_digest(), None).unwrap();
    }

    /// Each check must be the thing that rejects: tamper with one field at a time and require the
    /// matching error.
    #[test]
    fn each_check_rejects_its_own_tampering() {
        let at = RECURSION_PV_OFFSETS;
        let root = vk_root();

        let mut pvs = honest_pvs(root);
        pvs[at.flag_complete] = Kb::ZERO;
        redigest(&mut pvs);
        let err = check_complete_root_public_values("test", &pvs, &trusted_digest(), Some(&root))
            .unwrap_err()
            .to_string();
        assert!(err.contains("not complete"), "got: {err}");

        let pvs = honest_pvs(root);
        let mut wrong = trusted_digest();
        wrong[3] += Kb::ONE;
        let err = check_complete_root_public_values("test", &pvs, &wrong, Some(&root))
            .unwrap_err()
            .to_string();
        assert!(err.contains("riscv_vk_digest limb 3"), "got: {err}");

        let mut other = root;
        other[5] += Kb::ONE;
        let err = check_complete_root_public_values("test", &pvs, &trusted_digest(), Some(&other))
            .unwrap_err()
            .to_string();
        assert!(err.contains("vk_root limb 5"), "got: {err}");

        let mut pvs = honest_pvs(root);
        pvs[at.digest[2]] += Kb::ONE;
        let err = check_complete_root_public_values("test", &pvs, &trusted_digest(), Some(&root))
            .unwrap_err()
            .to_string();
        assert!(err.contains("PV digest limb 2"), "got: {err}");
    }

    /// Tampering anywhere in the hashed prefix must break the digest check.
    #[test]
    fn digest_binds_the_whole_hashed_prefix() {
        let root = vk_root();
        for idx in [0usize, 7, NUM_PV_ELMS_TO_HASH - 1] {
            let mut pvs = honest_pvs(root);
            pvs[idx] += Kb::ONE;
            let res =
                check_complete_root_public_values("test", &pvs, &trusted_digest(), Some(&root));
            assert!(res.is_err(), "tampering pv[{idx}] went undetected");
        }
    }

    #[test]
    fn recursion_public_values_picks_the_right_vector() {
        let pvs = honest_pvs(vk_root());
        let sets = vec![vec![], vec![Kb::ZERO; 4], pvs.clone(), vec![Kb::ZERO; 3]];
        assert_eq!(recursion_public_values(&sets).unwrap(), pvs.as_slice());
        assert!(recursion_public_values(&[vec![Kb::ZERO; 4]]).is_err());
    }

    /// The digest is read one byte per element, in order; an element above 255 is refused.
    #[test]
    fn committed_digest_is_read_byte_by_byte() {
        let mut pvs = vec![Kb::ZERO; RECURSION_NUM_PVS];
        for (j, &idx) in RECURSION_PV_OFFSETS
            .committed_value_digest
            .iter()
            .enumerate()
        {
            pvs[idx] = Kb::from_u32(j as u32 * 7);
        }
        let digest = committed_value_digest(&pvs).unwrap();
        assert_eq!(digest, std::array::from_fn(|j| j as u8 * 7));
        pvs[RECURSION_PV_OFFSETS.committed_value_digest[5]] = Kb::from_u32(256);
        assert!(matches!(
            committed_value_digest(&pvs),
            Err(VerifyError::DigestLimbNotByte {
                index: 5,
                value: 256
            })
        ));
    }

    #[test]
    fn committed_values_bind_only_their_bytes() {
        let bytes = b"the guest wrote this".to_vec();
        let digest: [u8; 32] = Sha256::digest(&bytes).into();
        assert!(committed_values_bound(&bytes, &digest));
        let mut forged = bytes.clone();
        forged[0] ^= 1;
        assert!(!committed_values_bound(&forged, &digest));
        assert!(!committed_values_bound(&[], &digest));
        assert!(committed_values_bound(&[], &[0u8; 32]));
        assert!(!committed_values_bound(b"forged", &[0u8; 32]));
    }
}
