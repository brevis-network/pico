//! Host-side acceptance checks on a COMPLETE recursion root proof's public values.
//!
//! Deliberately **config-free**: the recursion public values are `Kb` elements whatever protocol
//! config committed to them, so the same checks serve the combine root (Poseidon2-KoalaBear) and the
//! embed re-proof of that root (BN254-Poseidon2). Keeping one copy matters because these are the
//! checks that give the proof its meaning — two copies would drift.
//!
//! What is NOT here, because it is per-machine: verifying the proof against the *honestly keygen'd*
//! VK (each machine searches its own `pks`), and whitelist membership of the outermost VK (only the
//! inner config's keys are whitelist members at all).

use p3_field::PrimeCharacteristicRing;

use super::Kb;
use crate::{
    emulator::recursion::public_values::{NUM_PV_ELMS_TO_HASH, RECURSION_PUBLIC_VALUES_COL_MAP},
    mle::machine::exe::sponge_hash,
    primitives::consts::RECURSION_NUM_PVS,
};

/// Pull the recursion public-value vector out of a proof's public values.
///
/// A recursion proof carries one public-value vector per AIR; only the `PublicValues` chip's is
/// `RECURSION_NUM_PVS` long.
pub fn recursion_public_values(pv_sets: &[Vec<Kb>]) -> eyre::Result<&[Kb]> {
    pv_sets
        .iter()
        .find(|p| p.len() == RECURSION_NUM_PVS)
        .map(|p| p.as_slice())
        .ok_or_else(|| eyre::eyre!("proof carries no recursion public values"))
}

/// The four public-value checks every complete root must pass, whatever config proved it.
///
/// 1. `flag_complete == 1` — arms the in-circuit universal completeness assertions. Without it the
///    proof is a mid-tree node and none of them ran.
/// 2. `riscv_vk_digest` equals the trusted exe identity. This single comparison is what pins the
///    program, its entry pc, and the cross-chunk memory closure: the convert layer computes
///    `H(DOMAIN ‖ program_commit ‖ pc_start ‖ initial_gcs)` in-circuit from witnessed values, and
///    the chunk-1 gate, the initial-GCS injection, and the root's in-circuit GCS closure bind those
///    witnesses to the actual execution.
/// 3. `vk_root` equals the trusted whitelist root, when whitelist mode is on. The in-circuit
///    child-root equality plus membership checks propagate this down every node, so pinning it at
///    the root pins the whole tree's whitelist.
/// 4. The PV digest recomputes. Same sponge as [`sponge_hash`] — the AIR's digest columns must equal
///    the host's hash of the preimage prefix.
///
/// `label` names the layer in error messages ("root", "embed") since both call this.
pub fn check_complete_root_public_values(
    label: &str,
    pvs: &[Kb],
    trusted_riscv_vk_digest: &[Kb; 8],
    trusted_vk_root: Option<&[Kb; 8]>,
) -> eyre::Result<()> {
    let col = RECURSION_PUBLIC_VALUES_COL_MAP;

    // (1) Completeness gate.
    if pvs[col.flag_complete] != Kb::ONE {
        eyre::bail!("{label} proof is not complete (flag_complete != 1)");
    }

    // (2) Exe-identity anchor.
    for (j, &limb_idx) in col.riscv_vk_digest.iter().enumerate() {
        if pvs[limb_idx] != trusted_riscv_vk_digest[j] {
            eyre::bail!(
                "{label} riscv_vk_digest limb {j} does not match the trusted RiscvVmVk digest"
            );
        }
    }
    // Entry pc and GCS closure need no host checks of their own: see (2) above.

    // (3) Whitelist root.
    if let Some(trusted_root) = trusted_vk_root {
        for (j, &idx) in col.vk_root.iter().enumerate() {
            if pvs[idx] != trusted_root[j] {
                eyre::bail!("{label} vk_root limb {j} does not match the trusted whitelist root");
            }
        }
    }

    // (4) PV digest.
    let digest = sponge_hash(&pvs[..NUM_PV_ELMS_TO_HASH]);
    for (j, &digest_idx) in col.digest.iter().enumerate() {
        if pvs[digest_idx] != digest[j] {
            eyre::bail!("{label} PV digest limb {j} does not match the recomputed hash");
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A public-value vector that passes every check, built the way an honest prover would.
    fn honest_pvs(vk_root: [Kb; 8]) -> Vec<Kb> {
        let col = RECURSION_PUBLIC_VALUES_COL_MAP;
        let mut pvs = vec![Kb::ZERO; RECURSION_NUM_PVS];
        pvs[col.flag_complete] = Kb::ONE;
        for (j, &idx) in col.riscv_vk_digest.iter().enumerate() {
            pvs[idx] = Kb::from_u32(1000 + j as u32);
        }
        for (j, &idx) in col.vk_root.iter().enumerate() {
            pvs[idx] = vk_root[j];
        }
        let digest = sponge_hash(&pvs[..NUM_PV_ELMS_TO_HASH]);
        for (j, &idx) in col.digest.iter().enumerate() {
            pvs[idx] = digest[j];
        }
        pvs
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

    /// Each check must be the thing that rejects — a helper whose asserts silently pass is worse
    /// than no helper, so tamper with one field at a time and require the matching error.
    #[test]
    fn each_check_rejects_its_own_tampering() {
        let col = RECURSION_PUBLIC_VALUES_COL_MAP;
        let root = vk_root();

        // (1) not complete
        let mut pvs = honest_pvs(root);
        pvs[col.flag_complete] = Kb::ZERO;
        // Re-digest so ONLY the completeness check can fire.
        let d = sponge_hash(&pvs[..NUM_PV_ELMS_TO_HASH]);
        for (j, &idx) in col.digest.iter().enumerate() {
            pvs[idx] = d[j];
        }
        let err = check_complete_root_public_values("test", &pvs, &trusted_digest(), Some(&root))
            .unwrap_err()
            .to_string();
        assert!(err.contains("not complete"), "got: {err}");

        // (2) wrong exe identity
        let pvs = honest_pvs(root);
        let mut wrong = trusted_digest();
        wrong[3] += Kb::ONE;
        let err = check_complete_root_public_values("test", &pvs, &wrong, Some(&root))
            .unwrap_err()
            .to_string();
        assert!(err.contains("riscv_vk_digest limb 3"), "got: {err}");

        // (3) wrong whitelist root
        let mut other = root;
        other[5] += Kb::ONE;
        let err = check_complete_root_public_values("test", &pvs, &trusted_digest(), Some(&other))
            .unwrap_err()
            .to_string();
        assert!(err.contains("vk_root limb 5"), "got: {err}");

        // (4) digest does not match the preimage
        let mut pvs = honest_pvs(root);
        pvs[col.digest[2]] += Kb::ONE;
        let err = check_complete_root_public_values("test", &pvs, &trusted_digest(), Some(&root))
            .unwrap_err()
            .to_string();
        assert!(err.contains("PV digest limb 2"), "got: {err}");
    }

    /// Tampering anywhere in the hashed prefix must break the digest check — that is what makes the
    /// digest bind the whole public-value vector rather than the few fields checked explicitly.
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
}
