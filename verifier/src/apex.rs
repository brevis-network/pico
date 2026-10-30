//! Standalone apex verification: accept a root combine proof from nothing but shipped artifacts.
//!
//! The apex is the top of the recursion tree: the final check of a complete root proof.
//!
//! The caller supplies the proof WITH its vk, the trusted whitelist and the trusted exe identity.
//! Trust comes from the whitelist: the supplied vk's identity must be a member, and the STARK
//! verify then runs under that vk. The pre_hash in the identity is recomputed from the vk body
//! first, because the stored field is attacker-settable. There is no whitelist-off mode: without
//! membership, verifying under a caller-supplied vk attests nothing.

use std::sync::Arc;

use pico_mle_core::{keygen::compute_vk_pre_hash, StarkEngine, SystemParams};

use crate::{
    public_values::{check_complete_root_public_values, recursion_public_values},
    whitelist::{vk_identity, VkIdentity, VkMembership, VkWhitelist},
    Engine, Kb, ProofWithVk, VerifyError, VmVk,
};

/// Everything the standalone apex trusts: the whitelist (its root is the per-config constant),
/// the exe identity of the guest being attested, and the recursion system params.
pub struct MleApexVerifier {
    engine: Engine,
    whitelist: Whitelist,
    riscv_vk_digest: [Kb; 8],
    /// Handed in explicitly rather than read off the whitelist, so the trust lives in the
    /// caller's constant; a whitelist with any other root is refused at construction.
    trusted_root: [Kb; 8],
}

/// How the apex authenticates the root's vk against the pinned root.
enum Whitelist {
    /// A full whitelist: what the prover holds.
    Lookup(Arc<dyn VkWhitelist>),
    /// Merkle memberships of the keys a root can carry, each checked against the pinned root at
    /// construction: what a verifier holds when it has no map.
    Members(Vec<VkMembership>),
}

impl MleApexVerifier {
    /// An apex over a full whitelist. Panics if `whitelist` does not build `trusted_root`.
    pub fn new<W: VkWhitelist + 'static>(
        params: SystemParams,
        whitelist: Arc<W>,
        vm_vk: impl Into<VmVk>,
        trusted_root: [Kb; 8],
    ) -> Self {
        assert_eq!(
            whitelist.root(),
            trusted_root,
            "the whitelist handed to the apex does not carry the trusted root"
        );
        Self {
            engine: StarkEngine::new(params),
            whitelist: Whitelist::Lookup(whitelist),
            riscv_vk_digest: vm_vk.into().digest(),
            trusted_root,
        }
    }

    /// [`Self::new`] without the map: the root's vk is authenticated by `members`, Merkle
    /// memberships under `trusted_root`. A member whose path does not reach `trusted_root` is
    /// refused here, so later a match on identity is a proof of membership.
    pub fn with_members(
        params: SystemParams,
        members: Vec<VkMembership>,
        vm_vk: impl Into<VmVk>,
        trusted_root: [Kb; 8],
    ) -> Result<Self, VerifyError> {
        if let Some(bad) = members.iter().find(|m| !m.verifies_against(&trusted_root)) {
            return Err(VerifyError::MemberOffRoot { index: bad.index });
        }
        Ok(Self {
            engine: StarkEngine::new(params),
            whitelist: Whitelist::Members(members),
            riscv_vk_digest: vm_vk.into().digest(),
            trusted_root,
        })
    }

    fn is_whitelisted(&self, id: &VkIdentity) -> bool {
        match &self.whitelist {
            Whitelist::Lookup(w) => w.contains(id),
            Whitelist::Members(members) => members.iter().any(|m| m.identity == *id),
        }
    }

    /// Accept a complete root proof. Checks, in order:
    ///   1. The supplied vk's body hashes to its self-reported pre_hash, and its identity is
    ///      whitelisted: this authenticates the key.
    ///   2. STARK verify under that key.
    ///   3. The complete-root public values (see [`check_complete_root_public_values`]):
    ///      `flag_complete`, `riscv_vk_digest`, `vk_root` against the pinned root, PV digest.
    pub fn verify(&self, root: &ProofWithVk) -> Result<(), VerifyError> {
        let (proof, vk) = root;

        // Fail typed on a non-recursion vk rather than panicking on attacker-shaped input.
        if vk.inner.merged_preprocessed_commit.is_none() {
            return Err(VerifyError::NotRecursionVk);
        }
        // The whitelist indexes the STORED pre_hash and the STARK verify only observes it; without
        // this recompute a weakened body under an honest identity would pass. Merged mode excludes
        // every commitment from the preimage, so no app-prep ids.
        if compute_vk_pre_hash(self.engine.config(), &vk.inner, &[]) != vk.pre_hash {
            return Err(VerifyError::VkBodyMismatch);
        }
        if !self.is_whitelisted(&vk_identity(vk)) {
            return Err(VerifyError::NotWhitelisted);
        }

        self.engine
            .verify(vk, proof)
            .map_err(|e| VerifyError::Stark(format!("{e:?}")))?;

        let pvs = recursion_public_values(&proof.public_values)?;
        check_complete_root_public_values(
            "root",
            pvs,
            &self.riscv_vk_digest,
            Some(&self.trusted_root),
        )
    }
}

#[cfg(test)]
mod tests {
    use std::{borrow::Borrow, sync::Arc};

    use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
    use p3_field::PrimeCharacteristicRing;
    use p3_matrix::dense::RowMajorMatrix;
    use pico_mle_core::{
        air::any_air::BaseAirWithPublicValues,
        builder::LookupBuilder,
        keygen::types::{LinearConstraint, MultiStarkProvingKey, MultiStarkVerifyingKey},
        lookup::SymbolicLookup,
        poly::matrix::ColMajorMatrix,
        proof::Proof,
        prover::{
            AirProvingContext, DeviceDataTransporter, Prover, ProvingContext,
            ReferenceColMajorBackend,
        },
        test_utils::{
            dummy_airs::{
                fib_air::columns::{FibonacciCols, NUM_FIBONACCI_COLS},
                fib_selector_air::{
                    air::FibonacciSelectorAir, columns::FibonacciSelectorCols,
                    trace::generate_trace_rows,
                },
            },
            test_system_params_small,
        },
        AirRef, PartitionedBaseAir, StarkEngine,
    };

    use super::MleApexVerifier;
    use crate::{
        whitelist::{vk_identity, VkIdentity, VkMembership, VkMerkleTree, VkWhitelist},
        Engine, Kb, Sc, VmVk,
    };

    const A: u64 = 0;
    const B: u64 = 1;

    /// A test whitelist: a tree plus its entries.
    struct Map {
        entries: Vec<VkIdentity>,
        tree: VkMerkleTree,
    }

    impl Map {
        fn build(entries: Vec<VkIdentity>) -> Self {
            let tree = VkMerkleTree::try_build(&entries).unwrap();
            Self { entries, tree }
        }
        fn root(&self) -> [Kb; 8] {
            self.tree.root()
        }
        fn membership(&self, i: usize) -> VkMembership {
            self.tree.membership(i, self.entries[i])
        }
    }

    impl VkWhitelist for Map {
        fn root(&self) -> [Kb; 8] {
            self.tree.root()
        }
        fn contains(&self, id: &VkIdentity) -> bool {
            self.entries.contains(id)
        }
    }

    fn params() -> pico_mle_core::SystemParams {
        test_system_params_small(2, 5, 3)
    }

    fn engine() -> Engine {
        StarkEngine::new(params())
    }

    fn sels() -> Vec<bool> {
        vec![true; 1 << 5]
    }

    /// An apex whose whitelist holds exactly `vk`'s identity. The exe identity is a placeholder:
    /// every test here is decided at step (1) or (2), before it is consulted.
    fn apex_trusting(vk: &MultiStarkVerifyingKey<Sc>) -> MleApexVerifier {
        let map = Map::build(vec![vk_identity(vk)]);
        let root = map.root();
        MleApexVerifier::new(params(), Arc::new(map), placeholder_vm_vk(), root)
    }

    fn placeholder_vm_vk() -> VmVk {
        VmVk::from_limbs(&[Kb::ZERO; 25])
    }

    /// A whitelist of `vk` and one other identity, the other first, so `vk` sits at leaf 1.
    fn map_with(vk: &MultiStarkVerifyingKey<Sc>) -> Map {
        let other = (
            std::array::from_fn(|i| Kb::from_u32(7 + i as u32)),
            std::array::from_fn(|i| Kb::from_u32(70 + i as u32)),
        );
        Map::build(vec![other, vk_identity(vk)])
    }

    fn ctx_with_output(x: Kb) -> ProvingContext<ReferenceColMajorBackend<Sc>> {
        let trace = generate_trace_rows::<Kb>(A, B, &sels());
        let pis = vec![Kb::from_u64(A), Kb::from_u64(B), x];
        let air_ctx = AirProvingContext::simple(ColMajorMatrix::from_row_major(&trace), pis);
        ProvingContext::new(vec![(0, air_ctx)])
    }

    fn honest_output() -> Kb {
        let sels = sels();
        let trace = generate_trace_rows::<Kb>(A, B, &sels);
        trace.values[(sels.len() - 1) * NUM_FIBONACCI_COLS + 1]
    }

    fn prove(engine: &Engine, pk: &MultiStarkProvingKey<Sc>, x: Kb) -> Proof<Sc> {
        let device = engine.device();
        let d_pk = device.transport_pk_to_device(pk);
        let d_ctx = device.transport_proving_ctx_to_device(&ctx_with_output(x));
        engine.prover().prove(&d_pk, d_ctx).expect("fixture proof")
    }

    /// `FibonacciSelectorAir` with its last-row output binding removed: the public output `x` is
    /// unconstrained. Its preprocessed trace (the selector column) is unchanged, so its merged
    /// preprocessed commitment equals the honest AIR's; only the lean pre_hash differs.
    struct WeakFibonacciSelectorAir {
        sels: Vec<bool>,
    }

    impl<F: p3_field::Field> PartitionedBaseAir<F> for WeakFibonacciSelectorAir {}
    impl<F: p3_field::Field> BaseAir<F> for WeakFibonacciSelectorAir {
        fn width(&self) -> usize {
            NUM_FIBONACCI_COLS
        }
        fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
            let sels = self.sels.iter().map(|&s| F::from_bool(s)).collect();
            Some(RowMajorMatrix::new_col(sels))
        }
    }
    impl<F: p3_field::Field> BaseAirWithPublicValues<F> for WeakFibonacciSelectorAir {
        fn num_public_values(&self) -> usize {
            3
        }
    }
    impl<AB: AirBuilder + LookupBuilder<SymbolicLookup<AB::Expr>>> Air<AB> for WeakFibonacciSelectorAir
    where
        AB::F: p3_field::Field,
    {
        fn eval(&self, builder: &mut AB) {
            let pis = builder.public_values();
            let (a, b) = (pis[0], pis[1]);
            let preprocessed = builder.preprocessed().clone();
            let preprocessed_local: &FibonacciSelectorCols<AB::Var> =
                (*preprocessed.current_slice()).borrow();
            let main = builder.main();
            let (local, next) = (main.current_slice(), main.next_slice());
            let local: &FibonacciCols<AB::Var> = (*local).borrow();
            let next: &FibonacciCols<AB::Var> = (*next).borrow();

            let mut when_first_row = builder.when_first_row();
            when_first_row.assert_eq(local.left, a);
            when_first_row.assert_eq(local.right, b);

            builder
                .when_transition()
                .when(preprocessed_local.sel)
                .assert_eq(local.right, next.left);
            builder
                .when_transition()
                .when_ne(preprocessed_local.sel, AB::Expr::ONE)
                .assert_eq(local.left, next.left);
            builder
                .when_transition()
                .when(preprocessed_local.sel)
                .assert_eq(local.left + local.right, next.right);
            builder
                .when_transition()
                .when_ne(preprocessed_local.sel, AB::Expr::ONE)
                .assert_eq(local.right, next.right);
            // The honest AIR also has `when_last_row().assert_eq(local.right, x)`; this one does not.
        }
    }

    fn honest_keygen(engine: &Engine) -> (MultiStarkProvingKey<Sc>, MultiStarkVerifyingKey<Sc>) {
        let airs: Vec<AirRef<Sc>> = vec![Arc::new(FibonacciSelectorAir::new(sels(), false))];
        engine.keygen_merged_preprocessed(&airs)
    }

    /// An honest key gets past key authentication and the STARK verify, and is stopped only
    /// later, by the fixture's lack of recursion public values: the recompute rejects nothing it
    /// should accept.
    #[test]
    fn apex_accepts_an_honest_key() {
        let engine = engine();
        let (pk, vk) = honest_keygen(&engine);
        let proof = prove(&engine, &pk, honest_output());
        let err = apex_trusting(&vk)
            .verify(&(proof, Arc::new(vk)))
            .expect_err("the fixture carries no recursion public values");
        assert!(
            err.to_string().contains("no recursion public values"),
            "honest key must clear steps (1)-(2), got: {err}"
        );
    }

    /// Body substitution: honest identity (stored pre_hash and merged commitment), tampered body.
    /// The identity alone is whitelisted, so this is rejected only by the recompute.
    #[test]
    fn apex_rejects_vk_body_substitution() {
        let engine = engine();
        let (pk, honest_vk) = honest_keygen(&engine);
        let proof = prove(&engine, &pk, honest_output());

        let mut inner = honest_vk.inner.clone();
        inner.trace_height_constraints.push(LinearConstraint {
            coefficients: vec![0],
            threshold: 1,
        });
        let forged = MultiStarkVerifyingKey {
            inner,
            pre_hash: honest_vk.pre_hash,
        };
        assert_eq!(vk_identity(&forged), vk_identity(&honest_vk));

        let err = apex_trusting(&honest_vk)
            .verify(&(proof, Arc::new(forged)))
            .expect_err("a tampered body must be rejected");
        assert!(
            err.to_string().contains("self-reported pre_hash"),
            "expected the pre_hash recompute to reject, got: {err}"
        );
    }

    /// The forgery the recompute exists for: a proof of a WRONG output under a weakened AIR, with
    /// the transcript seeded by the honest pre_hash. The forged key carries the honest identity, so
    /// the whitelist admits it, and verifies the proof at the STARK level; the pre_hash recompute
    /// is what rejects it.
    #[test]
    fn apex_rejects_a_forged_proof_under_a_weakened_key() {
        let engine = engine();
        let (_, honest_vk) = honest_keygen(&engine);

        let weak_airs: Vec<AirRef<Sc>> = vec![Arc::new(WeakFibonacciSelectorAir { sels: sels() })];
        let (mut weak_pk, weak_vk) = engine.keygen_merged_preprocessed(&weak_airs);
        assert_eq!(
            weak_vk.inner.merged_preprocessed_commit,
            honest_vk.inner.merged_preprocessed_commit
        );
        weak_pk.vk_pre_hash = honest_vk.pre_hash;
        let proof = prove(&engine, &weak_pk, honest_output() + Kb::ONE);

        let forged = MultiStarkVerifyingKey {
            inner: weak_vk.inner.clone(),
            pre_hash: honest_vk.pre_hash,
        };
        engine
            .verify(&forged, &proof)
            .expect("the forged key accepts the wrong output at the STARK level");
        assert!(engine.verify(&honest_vk, &proof).is_err());

        let err = apex_trusting(&honest_vk)
            .verify(&(proof, Arc::new(forged)))
            .expect_err("the apex must reject the forgery");
        assert!(
            err.to_string().contains("self-reported pre_hash"),
            "expected the pre_hash recompute to reject, got: {err}"
        );
    }

    /// An apex built from memberships clears key authentication as one built from the map does.
    #[test]
    fn apex_from_members_accepts_an_honest_key() {
        let engine = engine();
        let (pk, vk) = honest_keygen(&engine);
        let proof = prove(&engine, &pk, honest_output());
        let map = map_with(&vk);
        let apex = MleApexVerifier::with_members(
            params(),
            vec![map.membership(1)],
            placeholder_vm_vk(),
            map.root(),
        )
        .expect("the member verifies against its root");
        let err = apex
            .verify(&(proof, Arc::new(vk)))
            .expect_err("the fixture carries no recursion public values");
        assert!(
            err.to_string().contains("no recursion public values"),
            "honest key must clear steps (1)-(2), got: {err}"
        );
    }

    /// A key that is in the tree but not among the memberships is refused.
    #[test]
    fn apex_from_members_rejects_a_key_not_among_them() {
        let engine = engine();
        let (pk, vk) = honest_keygen(&engine);
        let proof = prove(&engine, &pk, honest_output());
        let map = map_with(&vk);
        let apex = MleApexVerifier::with_members(
            params(),
            vec![map.membership(0)],
            placeholder_vm_vk(),
            map.root(),
        )
        .expect("the member verifies against its root");
        let err = apex
            .verify(&(proof, Arc::new(vk)))
            .expect_err("a key outside the memberships must be refused");
        assert!(
            err.to_string().contains("not in the whitelist"),
            "got: {err}"
        );
    }

    /// A membership whose path does not reach the trusted root is refused at construction.
    #[test]
    fn with_members_refuses_a_member_off_the_root() {
        let engine = engine();
        let (_, vk) = honest_keygen(&engine);
        let map = map_with(&vk);
        let mut member = map.membership(1);
        member.siblings[0][0] += Kb::ONE;
        assert!(MleApexVerifier::with_members(
            params(),
            vec![member],
            placeholder_vm_vk(),
            map.root()
        )
        .is_err());
        let other_root = Map::build(vec![vk_identity(&vk)]).root();
        assert!(MleApexVerifier::with_members(
            params(),
            vec![map.membership(1)],
            placeholder_vm_vk(),
            other_root
        )
        .is_err());
    }

    /// A whitelist that does not build the pinned root is refused at construction.
    #[test]
    #[should_panic(expected = "does not carry the trusted root")]
    fn new_refuses_a_whitelist_off_the_root() {
        let engine = engine();
        let (_, vk) = honest_keygen(&engine);
        let map = map_with(&vk);
        let other_root = Map::build(vec![vk_identity(&vk)]).root();
        let _ = MleApexVerifier::new(params(), Arc::new(map), placeholder_vm_vk(), other_root);
    }
}
