//! Standalone apex verification (FRI parity): accept a root combine proof from nothing but
//! shipped artifacts — no proving or keygen machine involved.
//!
//! Mirrors the FRI path's outermost `verify(proof, riscv_vk)` surface
//! (`instances/machine/combine.rs` there): the caller supplies the proof WITH its vk, the
//! trusted whitelist artifact, and the trusted VM-layer exe identity. Trust comes from the
//! whitelist — the supplied vk's full identity (lean pre_hash, merged commitment) must be a
//! member, and the STARK verify then runs under that same vk. The pre_hash in that identity is
//! recomputed from the vk body first: the stored field is attacker-settable, and the whitelist
//! only authenticates a body that actually hashes to it. This is exactly FRI's stance
//! (it never verifies under an honestly keygen'd recursion VK either); consequently there is
//! NO whitelist-off mode here — without membership, verifying under a caller-supplied vk
//! attests nothing (dev flows use the machine-bound `CombineMachine::verify` instead, which
//! substitutes its own honestly keygen'd key).

use std::sync::Arc;

use p3_field::PrimeCharacteristicRing;
use pico_mle_core::{keygen::compute_vk_pre_hash, StarkEngine, SystemParams};

use crate::{
    emulator::recursion::public_values::RECURSION_PUBLIC_VALUES_COL_MAP,
    mle::machine::{
        convert::ProofWithVk,
        exe::RiscvVmVk,
        recursion::{digest_to_u32s, Engine, Kb},
        vk_map::{vk_identity, MleVkMap, VkIdentity, VkMembership},
    },
    primitives::consts::RECURSION_NUM_PVS,
};

/// Everything the standalone apex trusts, all loadable from artifacts:
/// the whitelist (its root is the per-config constant), the VM-layer exe identity of the
/// guest being attested, and the recursion system params (engine reconstruction only). The
/// whitelist is shared, not copied: a resident prover builds one verifier and keeps it.
pub struct MleApexVerifier {
    engine: Engine,
    whitelist: Whitelist,
    riscv_vm_vk: RiscvVmVk,
    /// The whitelist root this apex pins. Handed in explicitly rather than read off the map, so
    /// that the trust lives in the caller's constant and the map is only the membership index --
    /// a map with any other root is refused at construction.
    trusted_root: [Kb; 8],
}

/// How the apex authenticates the root's vk against the pinned root.
enum Whitelist {
    /// The whole map: what the prover holds.
    Map(Arc<MleVkMap>),
    /// Merkle memberships of the keys a root can carry, each checked against the pinned root at
    /// construction: what a verifier holds when it has no map (see [`VkMembership`]).
    Members(Vec<VkMembership>),
}

impl MleApexVerifier {
    pub fn new(
        params: SystemParams,
        vk_map: Arc<MleVkMap>,
        riscv_vm_vk: RiscvVmVk,
        trusted_root: [Kb; 8],
    ) -> Self {
        assert_eq!(
            vk_map.root(),
            trusted_root,
            "the whitelist handed to the apex does not carry the trusted root"
        );
        Self {
            engine: StarkEngine::new(params),
            whitelist: Whitelist::Map(vk_map),
            riscv_vm_vk,
            trusted_root,
        }
    }

    /// [`Self::new`] without the map: the root's vk is authenticated by `members`, Merkle
    /// memberships under `trusted_root` of the keys a root can carry (the combine and deferred
    /// node keys). A member whose path does not reach `trusted_root` is refused here, so later a
    /// match on identity is a proof of membership.
    pub fn with_members(
        params: SystemParams,
        members: Vec<VkMembership>,
        riscv_vm_vk: RiscvVmVk,
        trusted_root: [Kb; 8],
    ) -> eyre::Result<Self> {
        if let Some(bad) = members.iter().find(|m| !m.verifies_against(&trusted_root)) {
            eyre::bail!(
                "whitelist member at leaf {} does not verify against the trusted root",
                bad.index
            );
        }
        Ok(Self {
            engine: StarkEngine::new(params),
            whitelist: Whitelist::Members(members),
            riscv_vm_vk,
            trusted_root,
        })
    }

    fn is_whitelisted(&self, id: &VkIdentity) -> bool {
        match &self.whitelist {
            Whitelist::Map(map) => map.find(id).is_some(),
            Whitelist::Members(members) => members.iter().any(|m| m.identity == *id),
        }
    }

    /// Accept a complete root proof. Checks, in order:
    ///   1. The supplied vk's body hashes to its self-reported pre_hash, and its full identity
    ///      is WHITELISTED — this is what authenticates the key (replacing the machine-bound
    ///      verify's honest-keygen substitution).
    ///   2. STARK verify under that (now authenticated) vk.
    ///   3. `flag_complete == 1` (arms the in-circuit universal completeness asserts).
    ///   4. `riscv_vk_digest == RiscvVmVk::digest()` — the exe-identity anchor.
    ///   5. `vk_root` public values == the whitelist root (transitively pinning every
    ///      combine node's whitelist via the in-circuit membership checks).
    ///   6. Recompute the PV digest and compare.
    pub fn verify(&self, root: &ProofWithVk) -> eyre::Result<()> {
        let (proof, vk) = root;

        // (1) Authenticate the supplied key: full identity ∈ whitelist. Fail typed on a
        // non-merged (non-recursion) vk rather than panicking on attacker-shaped input.
        let Some(merged) = vk.inner.merged_preprocessed_commit else {
            eyre::bail!("supplied vk is not a recursion (merged-preprocessed) key");
        };
        let _ = merged;
        // The identity the whitelist indexes is `(pre_hash, merged_commit)` with the STORED
        // pre_hash, and nothing later on this path re-derives it — the STARK verify only observes
        // it. Without this recompute, a vk with an honest identity but a weakened body (a dropped
        // constraint, a removed interaction) passes the whitelist and is then verified under.
        // Merged mode excludes every commitment value from the preimage, so no app-prep ids.
        if compute_vk_pre_hash(self.engine.config(), &vk.inner, &[]) != vk.pre_hash {
            eyre::bail!("supplied vk body does not hash to its self-reported pre_hash");
        }
        if !self.is_whitelisted(&vk_identity(vk)) {
            eyre::bail!("supplied vk is not in the whitelist");
        }

        // (2) STARK verify under the authenticated key.
        self.engine
            .verify(vk, proof)
            .map_err(|e| eyre::eyre!("root proof failed STARK verify: {e:?}"))?;

        let pvs = proof
            .public_values
            .iter()
            .find(|p| p.len() == RECURSION_NUM_PVS)
            .ok_or_else(|| eyre::eyre!("root proof carries no recursion public values"))?;
        let col = RECURSION_PUBLIC_VALUES_COL_MAP;

        // (3) Completeness gate.
        if pvs[col.flag_complete] != Kb::ONE {
            eyre::bail!("root proof is not complete (flag_complete != 1)");
        }
        // (4) Exe-identity anchor.
        let expected = digest_to_u32s(&self.riscv_vm_vk.digest());
        for (j, &idx) in col.riscv_vk_digest.iter().enumerate() {
            if pvs[idx] != Kb::from_u32(expected[j]) {
                eyre::bail!(
                    "root riscv_vk_digest limb {j} does not match the trusted RiscvVmVk digest"
                );
            }
        }
        // (5) Whitelist root: the pinned constant, not whatever the map says.
        for (j, &idx) in col.vk_root.iter().enumerate() {
            if pvs[idx] != self.trusted_root[j] {
                eyre::bail!("root vk_root limb {j} does not match the trusted whitelist root");
            }
        }
        // (6) PV digest recompute (shared padding-free sponge).
        let mut preimage =
            Vec::with_capacity(crate::emulator::recursion::public_values::NUM_PV_ELMS_TO_HASH);
        preimage.extend_from_slice(
            &pvs[..crate::emulator::recursion::public_values::NUM_PV_ELMS_TO_HASH],
        );
        let recomputed = crate::mle::machine::exe::sponge_hash(&preimage);
        for (j, &idx) in col.digest.iter().enumerate() {
            if pvs[idx] != recomputed[j] {
                eyre::bail!("root PV digest limb {j} does not match the recomputed hash");
            }
        }
        Ok(())
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
        machine::septic::SepticDigest,
        mle::machine::{
            exe::RiscvVmVk,
            recursion::{Engine, Kb, Sc},
            vk_map::{vk_identity, MleVkMap},
        },
    };

    const A: u64 = 0;
    const B: u64 = 1;

    fn params() -> pico_mle_core::SystemParams {
        test_system_params_small(2, 5, 3)
    }

    fn engine() -> Engine {
        StarkEngine::new(params())
    }

    fn sels() -> Vec<bool> {
        vec![true; 1 << 5]
    }

    /// An apex whose whitelist holds exactly `vk`'s identity. The VM-layer identity is a
    /// placeholder: every test here is decided at step (1) or (2), before it is consulted.
    fn apex_trusting(vk: &MultiStarkVerifyingKey<Sc>) -> MleApexVerifier {
        let map = MleVkMap::build(vec![vk_identity(vk)]);
        let root = map.root();
        MleApexVerifier::new(params(), Arc::new(map), placeholder_vm_vk(), root)
    }

    fn placeholder_vm_vk() -> RiscvVmVk {
        RiscvVmVk {
            program_commit: Default::default(),
            pc_start: [Kb::ZERO; 3],
            initial_gcs: SepticDigest::<Kb>::zero(),
        }
    }

    /// A whitelist of `vk` and one other identity, the other first, so `vk` sits at leaf 1.
    fn map_with(vk: &MultiStarkVerifyingKey<Sc>) -> MleVkMap {
        let other = (
            std::array::from_fn(|i| Kb::from_u32(7 + i as u32)),
            std::array::from_fn(|i| Kb::from_u32(70 + i as u32)),
        );
        MleVkMap::build(vec![other, vk_identity(vk)])
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
    /// preprocessed commitment equals the honest AIR's — only the lean pre_hash differs.
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
        let other_root = MleVkMap::build(vec![vk_identity(&vk)]).root();
        assert!(MleApexVerifier::with_members(
            params(),
            vec![map.membership(1)],
            placeholder_vm_vk(),
            other_root
        )
        .is_err());
    }
}
