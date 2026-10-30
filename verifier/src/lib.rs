//! Verification of Pico MLE whitelist-mode root proofs, on stable Rust.
//!
//! Everything a verifier outside the prover needs: the standalone apex ([`apex`]), the whitelist
//! Merkle tree it authenticates keys against ([`whitelist`]), the exe identity ([`vm_vk`]), the
//! recursion public-value checks ([`public_values`]), and the two wire formats a verifier is
//! handed ([`bundle`], [`envelope`]). `pico-vm` re-exports these rather than keeping its own
//! copies, so this crate is the single implementation.
//!
//! [`verify`] is the one-call entry point: VK bundle + v3 envelope + committed bytes, under the
//! shipped whitelist root; [`verify_with_root`] takes another.
//!
//! The wire formats and the entry points that take their bytes need the default `codec` feature,
//! which pulls in zstd; without it the crate builds for a zkVM guest.

pub mod apex;
#[cfg(feature = "codec")]
pub mod bundle;
#[cfg(feature = "codec")]
pub mod envelope;
mod error;
pub mod hash;
pub mod public_values;
pub mod vm_vk;
pub mod whitelist;

use std::sync::Arc;

use pico_mle_core::{keygen::types::MultiStarkVerifyingKey, proof::Proof, StarkEngine};

pub use apex::MleApexVerifier;
pub use error::VerifyError;
pub use vm_vk::VmVk;
pub use whitelist::shipped_vk_root;

/// Base field of every MLE proof.
pub type Kb = p3_koala_bear::KoalaBear;
/// The engine the apex verifies with. Pinned to the CPU engine: the GPU engine shares its config
/// type, so proofs and keys from either verify here.
pub type Engine = pico_mle_cpu::KoalaBearPoseidon2CpuEngine;
/// The protocol config of [`Engine`].
pub type Sc = <Engine as StarkEngine>::SC;
/// A proof together with the verifying key it claims.
pub type ProofWithVk = (Proof<Sc>, Arc<MultiStarkVerifyingKey<Sc>>);

/// Verify a whitelist-mode root proof and the bytes it commits to, under the whitelist this repo
/// ships ([`shipped_vk_root`]).
///
/// `vk_bundle` is a v2 VK bundle ([`bundle`]), `envelope` a v3 proof envelope ([`envelope`]), and
/// `committed` the bytes the guest wrote to its public-values stream. Accepts only if the bundle
/// names the shipped root, the root passes every apex check under it and the bundle's exe
/// identity, and its `committed_value_digest` is the SHA-256 of `committed`.
///
/// Envelope bytes are malleable without affecting soundness: in merged mode the per-AIR
/// `preprocessed_data.commit` inside `root_vk` is neither covered by the vk pre-hash nor read here.
/// Do not identify or dedupe proofs by the envelope's hash.
#[cfg(feature = "codec")]
pub fn verify(vk_bundle: &[u8], envelope: &[u8], committed: &[u8]) -> Result<(), VerifyError> {
    verify_with_root(shipped_vk_root(), vk_bundle, envelope, committed)
}

/// [`verify`] under another whitelist, pinned by `trusted_root`. The root must come from the
/// caller, never from the bundle: a bundle can name any root it builds.
#[cfg(feature = "codec")]
pub fn verify_with_root(
    trusted_root: [Kb; 8],
    vk_bundle: &[u8],
    envelope: &[u8],
    committed: &[u8],
) -> Result<(), VerifyError> {
    let bundle = bundle::decode_vk_bundle_v2(vk_bundle)?;
    let apex = bundle::apex_from_bundle(&bundle, trusted_root)?;
    verify_with(&apex, envelope, committed)
}

/// [`verify`] with an apex already built, for a caller verifying many proofs of one guest.
#[cfg(feature = "codec")]
pub fn verify_with(
    apex: &MleApexVerifier,
    envelope: &[u8],
    committed: &[u8],
) -> Result<(), VerifyError> {
    let root = envelope::decode_root_proof_v3(envelope)?;
    apex.verify(&root)?;
    let pvs = public_values::recursion_public_values(&root.0.public_values)?;
    let digest = public_values::committed_value_digest(pvs)?;
    if public_values::committed_values_bound(committed, &digest) {
        Ok(())
    } else {
        Err(VerifyError::CommittedValuesUnbound)
    }
}

/// End to end over a real STARK proof: a tiny AIR whose public values are the recursion layout,
/// proved, enveloped and checked against a bundle. Small test params stand in for the recursion
/// ones, so the apex is built here the way [`bundle::apex_from_bundle`] builds it.
#[cfg(all(test, feature = "codec"))]
mod tests {
    use std::{borrow::Borrow, sync::Arc};

    use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
    use p3_field::PrimeCharacteristicRing;
    use p3_matrix::dense::RowMajorMatrix;
    use pico_mle_core::{
        air::any_air::BaseAirWithPublicValues,
        builder::LookupBuilder,
        lookup::SymbolicLookup,
        poly::matrix::ColMajorMatrix,
        prover::{AirProvingContext, DeviceDataTransporter, Prover, ProvingContext},
        test_utils::{
            dummy_airs::{
                fib_air::columns::{FibonacciCols, NUM_FIBONACCI_COLS},
                fib_selector_air::{columns::FibonacciSelectorCols, trace::generate_trace_rows},
            },
            test_system_params_small,
        },
        AirRef, PartitionedBaseAir, SystemParams,
    };
    use sha2::{Digest, Sha256};

    use super::*;
    use crate::{
        bundle::{decode_vk_bundle_v2, encode_vk_bundle_v2},
        envelope::{encode_v3, MleRootProofV3},
        hash::sponge_hash,
        public_values::{NUM_PV_ELMS_TO_HASH, RECURSION_NUM_PVS, RECURSION_PV_OFFSETS},
        whitelist::{vk_identity, VkIdentity, VkMerkleTree},
    };

    const COMMITTED: &[u8] = b"the guest wrote this";

    /// Fibonacci over a preprocessed selector, with the recursion public values unconstrained.
    struct PvAir {
        sels: Vec<bool>,
    }

    impl<F: p3_field::Field> PartitionedBaseAir<F> for PvAir {}
    impl<F: p3_field::Field> BaseAir<F> for PvAir {
        fn width(&self) -> usize {
            NUM_FIBONACCI_COLS
        }
        fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
            let sels = self.sels.iter().map(|&s| F::from_bool(s)).collect();
            Some(RowMajorMatrix::new_col(sels))
        }
    }
    impl<F: p3_field::Field> BaseAirWithPublicValues<F> for PvAir {
        fn num_public_values(&self) -> usize {
            RECURSION_NUM_PVS
        }
    }
    impl<AB: AirBuilder + LookupBuilder<SymbolicLookup<AB::Expr>>> Air<AB> for PvAir
    where
        AB::F: p3_field::Field,
    {
        fn eval(&self, builder: &mut AB) {
            let preprocessed = builder.preprocessed().clone();
            let sel: &FibonacciSelectorCols<AB::Var> = (*preprocessed.current_slice()).borrow();
            let main = builder.main();
            let (local, next) = (main.current_slice(), main.next_slice());
            let local: &FibonacciCols<AB::Var> = (*local).borrow();
            let next: &FibonacciCols<AB::Var> = (*next).borrow();

            let mut first = builder.when_first_row();
            first.assert_zero(local.left);
            first.assert_one(local.right);
            builder
                .when_transition()
                .when(sel.sel)
                .assert_eq(local.right, next.left);
            builder
                .when_transition()
                .when(sel.sel)
                .assert_eq(local.left + local.right, next.right);
        }
    }

    fn params() -> SystemParams {
        test_system_params_small(2, 5, 3)
    }

    fn sels() -> Vec<bool> {
        vec![true; 1 << 5]
    }

    fn vm_vk() -> VmVk {
        VmVk::from_u32s(&(1..=25).collect::<Vec<u32>>()).unwrap()
    }

    fn other_identity() -> VkIdentity {
        (
            std::array::from_fn(|i| Kb::from_u32(7 + i as u32)),
            std::array::from_fn(|i| Kb::from_u32(70 + i as u32)),
        )
    }

    /// Public values an honest complete root carries for `vm_vk`, `root` and [`COMMITTED`].
    fn honest_pvs(root: [Kb; 8]) -> Vec<Kb> {
        let at = RECURSION_PV_OFFSETS;
        let mut pvs = vec![Kb::ZERO; RECURSION_NUM_PVS];
        let digest: [u8; 32] = Sha256::digest(COMMITTED).into();
        for (&idx, byte) in at.committed_value_digest.iter().zip(digest) {
            pvs[idx] = Kb::from_u8(byte);
        }
        pvs[at.flag_complete] = Kb::ONE;
        let vk_digest = vm_vk().digest();
        for j in 0..8 {
            pvs[at.riscv_vk_digest[j]] = vk_digest[j];
            pvs[at.vk_root[j]] = root[j];
        }
        let d = sponge_hash(&pvs[..NUM_PV_ELMS_TO_HASH]);
        for (j, &idx) in at.digest.iter().enumerate() {
            pvs[idx] = d[j];
        }
        pvs
    }

    struct Fixture {
        /// A bundle with `vm_vk()`, the whitelist root, and the root key's membership.
        bundle: Vec<u8>,
        envelope: Vec<u8>,
        /// The root key's identity and the whitelist it is leaf 1 of.
        entries: Vec<VkIdentity>,
    }

    fn fixture() -> Fixture {
        let engine: Engine = StarkEngine::new(params());
        let airs: Vec<AirRef<Sc>> = vec![Arc::new(PvAir { sels: sels() })];
        let (pk, vk) = engine.keygen_merged_preprocessed(&airs);
        let entries = vec![other_identity(), vk_identity(&vk)];
        let tree = VkMerkleTree::try_build(&entries).unwrap();

        let trace = generate_trace_rows::<Kb>(0, 1, &sels());
        let ctx = ProvingContext::new(vec![(
            0,
            AirProvingContext::simple(
                ColMajorMatrix::from_row_major(&trace),
                honest_pvs(tree.root()),
            ),
        )]);
        let device = engine.device();
        let proof = engine
            .prover()
            .prove(
                &device.transport_pk_to_device(&pk),
                device.transport_proving_ctx_to_device(&ctx),
            )
            .expect("fixture proof");

        let body = MleRootProofV3::from_root(&(proof, Arc::new(vk))).unwrap();
        Fixture {
            bundle: encode_vk_bundle_v2(&vm_vk(), &tree.root(), &[tree.membership(1, entries[1])])
                .unwrap(),
            envelope: encode_v3(&body).unwrap(),
            entries,
        }
    }

    /// [`verify_with_root`] under the test params, trusting the bundle's own root.
    fn verify_test(bundle: &[u8], envelope: &[u8], committed: &[u8]) -> Result<(), VerifyError> {
        let b = decode_vk_bundle_v2(bundle)?;
        let apex = MleApexVerifier::with_members(params(), b.members, b.vm_vk, b.vk_root)?;
        verify_with(&apex, envelope, committed)
    }

    #[test]
    fn an_honest_root_verifies_and_every_tampering_is_refused() {
        let f = fixture();
        verify_test(&f.bundle, &f.envelope, COMMITTED).expect("the honest root verifies");

        // Committed bytes off by one byte, or dropped.
        let mut committed = COMMITTED.to_vec();
        committed[3] ^= 1;
        let err = verify_test(&f.bundle, &f.envelope, &committed).unwrap_err();
        assert!(matches!(err, VerifyError::CommittedValuesUnbound), "{err}");
        let err = verify_test(&f.bundle, &f.envelope, &[]).unwrap_err();
        assert!(matches!(err, VerifyError::CommittedValuesUnbound), "{err}");

        // Another guest's bundle: a different vm_vk.
        let decoded = decode_vk_bundle_v2(&f.bundle).unwrap();
        let mut other_vm_vk = decoded.vm_vk;
        other_vm_vk.pc_start[0] += Kb::ONE;
        let bundle = encode_vk_bundle_v2(&other_vm_vk, &decoded.vk_root, &decoded.members).unwrap();
        let err = verify_test(&bundle, &f.envelope, COMMITTED).unwrap_err();
        assert!(
            matches!(err, VerifyError::RiscvVkDigestMismatch { .. }),
            "{err}"
        );

        // Another whitelist that also holds the root key: membership passes, vk_root does not.
        let other: Vec<VkIdentity> = vec![f.entries[1], other_identity()];
        let tree = VkMerkleTree::try_build(&other).unwrap();
        let bundle =
            encode_vk_bundle_v2(&vm_vk(), &tree.root(), &[tree.membership(0, other[0])]).unwrap();
        let err = verify_test(&bundle, &f.envelope, COMMITTED).unwrap_err();
        assert!(matches!(err, VerifyError::VkRootMismatch { .. }), "{err}");

        // The right members under a wrong root build no apex.
        let mut root = decoded.vk_root;
        root[0] += Kb::ONE;
        let bundle = encode_vk_bundle_v2(&vm_vk(), &root, &decoded.members).unwrap();
        let err = verify_test(&bundle, &f.envelope, COMMITTED).unwrap_err();
        assert!(matches!(err, VerifyError::MemberOffRoot { .. }), "{err}");

        // A bundle without the root key's membership.
        let tree = VkMerkleTree::try_build(&f.entries).unwrap();
        let bundle =
            encode_vk_bundle_v2(&vm_vk(), &tree.root(), &[tree.membership(0, f.entries[0])])
                .unwrap();
        let err = verify_test(&bundle, &f.envelope, COMMITTED).unwrap_err();
        assert!(matches!(err, VerifyError::NotWhitelisted), "{err}");
    }

    /// A bundle under a self-made whitelist names its own root, and every check against that
    /// root passes; only the root the caller trusts refuses it.
    #[test]
    fn a_self_made_whitelist_is_refused() {
        let f = fixture();
        let decoded = decode_vk_bundle_v2(&f.bundle).unwrap();
        assert_ne!(decoded.vk_root, shipped_vk_root());

        let err = verify(&f.bundle, &f.envelope, COMMITTED).unwrap_err();
        assert!(matches!(err, VerifyError::UntrustedVkRoot), "{err}");
        let err = bundle::apex_from_bundle(&decoded, shipped_vk_root())
            .err()
            .expect("a self-made root");
        assert!(matches!(err, VerifyError::UntrustedVkRoot), "{err}");
        let err =
            verify_with_root(shipped_vk_root(), &f.bundle, &f.envelope, COMMITTED).unwrap_err();
        assert!(matches!(err, VerifyError::UntrustedVkRoot), "{err}");
    }

    #[test]
    fn a_corrupted_envelope_is_refused() {
        let f = fixture();

        let mut magic = f.envelope.clone();
        magic[0] ^= 1;
        let err = verify_test(&f.bundle, &magic, COMMITTED).unwrap_err();
        assert!(matches!(err, VerifyError::Envelope(_)), "{err}");
        let mut version = f.envelope.clone();
        version[8..12].copy_from_slice(&2u32.to_le_bytes());
        let err = verify_test(&f.bundle, &version, COMMITTED).unwrap_err();
        assert!(matches!(err, VerifyError::Envelope(_)), "{err}");

        // One bit flipped anywhere in the proof bytes: a decode failure or a failed verify, never
        // an acceptance.
        let body = envelope::decode_v3(&f.envelope).unwrap();
        let n = body.proof.len();
        for pos in [0, 4, n / 7, n / 3, n / 2, 2 * n / 3, n - 9, n - 1] {
            let mut flipped = body.clone();
            flipped.proof[pos] ^= 0x10;
            let bytes = encode_v3(&flipped).unwrap();
            assert!(
                verify_test(&f.bundle, &bytes, COMMITTED).is_err(),
                "a flipped bit at proof byte {pos} of {n} was accepted"
            );
        }

        // A flipped bit at the vk's middle byte, inside `per_air`, which the pre-hash covers, is
        // refused too. Not every vk byte is guarded: see the malleability note on [`verify`].
        let (_, vk) = body.to_root().unwrap();
        let params = bincode::serialized_size(&vk.inner.params).unwrap() as usize;
        let per_air = bincode::serialized_size(&vk.inner.per_air).unwrap() as usize;
        let mut flipped = body.clone();
        let m = flipped.root_vk.len();
        assert!((params..params + per_air).contains(&(m / 2)));
        flipped.root_vk[m / 2] ^= 0x10;
        let bytes = encode_v3(&flipped).unwrap();
        assert!(verify_test(&f.bundle, &bytes, COMMITTED).is_err());
    }
}
