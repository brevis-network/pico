//! `RiscvVmVk` — the VM-layer RISC-V verifying key (the "exe" identity object).
//!
//! The MLE protocol vk (`MultiStarkVerifyingKey`) carries only STARK structure: it has no
//! `pc_start` / initial-memory fields, and its (lean) pre-hash deliberately does not cover the
//! program commitment (see `compute_vk_pre_hash`). `RiscvVmVk` bundles the
//! three application-identity fields the recursion needs — program table commitment, guest entry
//! pc, and initial global-cumulative-sum (the septic initial-memory summary) — and folds them
//! into a single `riscv_vk_digest`.
//!
//! The digest is computed with EXACTLY the padding-free rate-8/width-16 overwrite sponge used for
//! the recursion PV digest (`CombineMachine::verify`) and mirrored in-circuit by
//! `Builder::hash_poseidon2_fresh`, so the host value and the in-circuit recomputation agree
//! bit-for-bit. Field order: `[DOMAIN, program_commit(8), pc_start(3), gcs.x(7), gcs.y(7)]`.

use p3_field::PrimeCharacteristicRing;
use p3_symmetric::Permutation;
use pico_mle_core::{
    config::koala_bear_poseidon2::default_koalabear_poseidon2_16, StarkProtocolConfig,
};

use crate::{
    compiler::{program::ProgramBehavior, riscv::program::Program},
    emulator::riscv::public_values_compat::encode_public_value_pc_limbs,
    machine::septic::SepticDigest,
    mle::machine::riscv::{riscv_program_commit, Kb, Sc},
};

/// Domain separator for `riscv_vk_digest` (distinguishes this sponge from the PV-digest sponge,
/// which absorbs no domain tag). Arbitrary fixed constant below the KoalaBear modulus.
pub const RISCV_VK_DIGEST_DOMAIN: u32 = 0x5256_766B; // "RVvk"

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

    /// The 26 preimage field elements in canonical order, matching the in-circuit hash input.
    pub fn digest_preimage(&self) -> Vec<Kb> {
        let mut elems = Vec::with_capacity(26);
        elems.push(Kb::from_u32(RISCV_VK_DIGEST_DOMAIN));
        elems.extend_from_slice(&self.program_commit);
        elems.extend_from_slice(&self.pc_start);
        elems.extend_from_slice(&self.initial_gcs.0.x.0);
        elems.extend_from_slice(&self.initial_gcs.0.y.0);
        elems
    }

    /// `riscv_vk_digest = sponge(preimage)`. Padding-free rate-8/width-16 overwrite sponge with
    /// the default KoalaBear Poseidon2 permutation; digest = first 8 lanes. Byte-identical to the
    /// in-circuit `hash_poseidon2_fresh` over the same preimage (and to the PV-digest recompute in
    /// `CombineMachine::verify`).
    pub fn digest(&self) -> <Sc as StarkProtocolConfig>::Digest {
        sponge_hash(&self.digest_preimage())
    }
}

/// Padding-free rate-8/width-16 overwrite-mode Poseidon2 sponge (SSOT shared with the PV digest
/// and the vk-map leaf hash; see `CombineMachine::verify`). No trailing permute when the input
/// length is an exact multiple of the rate. Byte-identical to the in-circuit
/// `hash_poseidon2_fresh` over the same elements.
pub(crate) fn sponge_hash(elems: &[Kb]) -> [Kb; 8] {
    let perm = default_koalabear_poseidon2_16();
    let mut state = [Kb::ZERO; 16];
    let mut absorb_idx = 0usize;
    for &v in elems {
        state[absorb_idx] = v;
        absorb_idx += 1;
        if absorb_idx == 8 {
            perm.permute_mut(&mut state);
            absorb_idx = 0;
        }
    }
    if absorb_idx != 0 {
        perm.permute_mut(&mut state);
    }
    std::array::from_fn(|i| state[i])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::machine::septic::{SepticCurve, SepticExtension};

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

    /// The preimage is exactly the 26 elements in the documented order.
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
        v.initial_gcs.0.x.0[0] += Kb::ONE;
        assert_ne!(v.digest(), base, "initial_gcs.x not bound");

        let mut v = sample_vk();
        v.initial_gcs.0.y.0[6] += Kb::ONE;
        assert_ne!(v.digest(), base, "initial_gcs.y not bound");
    }
}
