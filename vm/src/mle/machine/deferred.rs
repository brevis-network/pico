//! Deferred prover: one node per sub-proof, each verifying a COMPLETE recursion root of a
//! *sub-program* and advancing the deferred-proof hash chain by one step.
//!
//! The nodes it emits are ordinary recursion proofs, destined for the head of the combine tree —
//! chunk continuity admits them nowhere else (see `build_deferred_program`) — where the digest
//! returned here becomes what the guest's own `deferred_proofs_digest` must match once the chain
//! closes at the root.
//!
//! A tree still only CLOSES when the guest's own digest matches what these nodes built: the root
//! pins the chain's left end to zero and its right end to that digest, so a node spliced in
//! without a guest that called `verify_pico_proof` yields a root that does not verify, rather
//! than one that verifies while attesting less than it claims.
//!
//! Proving keys are keygen'd lazily and deduplicated by child layout: a sub-program's root shape
//! follows its own chunk count, so a batch of sub-proofs can need more than one node shape. Under
//! the whitelist every sub-proof is a combine-tier root, so there is exactly one: the node pads to
//! the combine tier too, and its VK is the one whitelist leaf this machine adds
//! ([`DeferredMachine::preregister`]).

use std::{collections::HashMap, sync::Arc};

use p3_field::PrimeCharacteristicRing;

use crate::{
    compiler::recursion::program::RecursionProgram,
    emulator::recursion::public_values::RECURSION_PUBLIC_VALUES_COL_MAP,
    instances::chiptype::recursion_chiptype::RecursionChipType,
    machine::chip::MetaChip,
    mle::{
        compiler::recursion::{ConvertVerifierCircuit, RecursionVkLayout},
        machine::{
            convert::ProofWithVk,
            exe::RiscvVmVk,
            recursion::{
                build_proving_ctx, extract_recursion_vk_layout, pad_recursion_program,
                recursion_air_refs_with_preprocessed, recursion_public_values,
                recursion_vk_layouts_equal, setup_for_deferred_with_program, CombineChild, Engine,
                Kb, Sc,
            },
            shape::RecursionTier,
            vk_map::{vk_identity, MleVkMap},
        },
    },
    primitives::{consts::DIGEST_SIZE, hash_deferred_proof},
};
use pico_mle_core::{
    config::soundness::{admit_production_vk, UnderBudgetError},
    keygen::types::{MultiStarkProvingKey, MultiStarkVerifyingKey},
    protocol::proof::Proof,
    prover::DeviceDataTransporter,
    StarkEngine, SystemParams,
};

/// One lazily-keygen'd deferred shape: `(child layout, program, pk, vk)`.
pub type DeferredPkEntry = (
    RecursionVkLayout,
    Arc<RecursionProgram<Kb>>,
    MultiStarkProvingKey<Sc>,
    Arc<MultiStarkVerifyingKey<Sc>>,
);

pub struct DeferredMachine {
    pub engine: Engine,
    /// Lazily grown; deduplicated by child layout.
    pks: Vec<DeferredPkEntry>,
    pub chips: Vec<MetaChip<Kb, RecursionChipType<Kb>>>,
    /// The MAIN program's exe identity. Every node publishes its digest and entry pc, and
    /// cross-child continuity forces both to agree with the execution leaves.
    riscv_vm_vk: RiscvVmVk,
    vk_verification: bool,
    /// The whitelist (vk_verification mode): the root each node witnesses and the path proving
    /// its child a member. Supplied via [`Self::set_vk_map`].
    vk_map: Option<Arc<MleVkMap>>,
    /// Test hook: skip the host-side whitelist checks so a bad sub-proof reaches the circuit.
    skip_host_checks: bool,
    /// Test hook: keygen nodes without the requirement that the sub-proof defers nothing.
    admit_nested: bool,
}

impl DeferredMachine {
    /// Deferred nodes prove under the same params as convert and combine (uniform child-verify
    /// cost across the tree).
    pub fn new(params: SystemParams, riscv_vm_vk: RiscvVmVk, vk_verification: bool) -> Self {
        Self {
            engine: StarkEngine::new(params),
            pks: Vec::new(),
            chips: RecursionChipType::<Kb>::mle_recursion_chips(),
            riscv_vm_vk,
            vk_verification,
            vk_map: None,
            skip_host_checks: false,
            admit_nested: false,
        }
    }

    /// Negative tests only: let a sub-proof the host checks would refuse reach the circuit, which
    /// is what has to reject it.
    pub fn skip_host_checks_for_testing(&mut self) {
        self.skip_host_checks = true;
    }

    /// Negative tests only: keygen every node of this machine without the requirement that its
    /// sub-proof's own deferred digest is zero, as the control for a case that must fail on it.
    /// Before the first keygen, so no key of this machine has the requirement.
    pub fn admit_nested_for_testing(&mut self) {
        assert!(
            self.pks.is_empty(),
            "admit_nested_for_testing after a keygen"
        );
        self.admit_nested = true;
    }

    /// Supply the whitelist (vk_verification mode; call before proving).
    pub fn set_vk_map(&mut self, map: Arc<MleVkMap>) {
        assert!(self.vk_verification, "vk_map without vk_verification");
        self.vk_map = Some(map);
    }

    /// Keygen the node over a combine-tier child (`CombineMachine::combine_tier_child_layout`) and
    /// return its VK: under the whitelist, the only deferred shape there is, hence the whitelist
    /// leaf `mle_build_vk_map` adds for it.
    pub fn preregister(
        &mut self,
        combine_tier: &RecursionVkLayout,
    ) -> Result<Arc<MultiStarkVerifyingKey<Sc>>, UnderBudgetError> {
        let idx = self.keygen_for(combine_tier)?;
        Ok(self.pks[idx].3.clone())
    }

    /// Find-or-keygen the proving key for a child shape. Returns the `pks` index.
    fn keygen_for(&mut self, layout: &RecursionVkLayout) -> Result<usize, UnderBudgetError> {
        if let Some(idx) = self
            .pks
            .iter()
            .position(|(l, ..)| recursion_vk_layouts_equal(l, layout))
        {
            return Ok(idx);
        }
        let mut program = if self.admit_nested {
            ConvertVerifierCircuit::build_deferred_program_admitting_nested_for_testing::<Kb>(
                layout,
                self.vk_verification,
            )
        } else {
            ConvertVerifierCircuit::build_deferred_program::<Kb>(layout, self.vk_verification)
        };
        // Whitelist mode pads to the combine tier, as combine does, so the node's lean pre_hash
        // is the combine-tier one: to a parent it is just another B-shaped child, and the
        // standard node shapes already cover every pair it can sit in.
        if self.vk_verification {
            pad_recursion_program("deferred", &mut program, RecursionTier::Combine);
        }
        let program = Arc::new(program);
        let stats = program.stats();
        tracing::info!(
            "deferred keygen: child_W={} instrs: base_alu={} ext_alu={} total={}",
            layout.stacking_widths.iter().sum::<usize>(),
            stats.get("BaseAlu").copied().unwrap_or(0),
            stats.get("ExtAlu").copied().unwrap_or(0),
            stats.values().sum::<usize>(),
        );
        let airs = recursion_air_refs_with_preprocessed(&program);
        let (pk, vk) = self.engine.keygen_merged_preprocessed(&airs);
        admit_production_vk("deferred", "cpu", &vk)?;
        self.pks.push((layout.clone(), program, pk, Arc::new(vk)));
        Ok(self.pks.len() - 1)
    }

    /// Prove one node per sub-proof, chaining the digest from zero.
    ///
    /// Returns the nodes in chain order — which is also the order they must take at the head of
    /// the combine tree — and the final digest.
    pub fn prove_chain(
        &mut self,
        sub_proofs: &[ProofWithVk],
    ) -> eyre::Result<(Vec<ProofWithVk>, [Kb; DIGEST_SIZE])> {
        if self.vk_verification && !self.skip_host_checks {
            self.check_whitelisted(sub_proofs)?;
        }
        let riscv_vk_digest = self.riscv_vm_vk.digest();
        let end_pc = self.riscv_vm_vk.pc_start;
        let mut acc = [Kb::ZERO; DIGEST_SIZE];
        let mut nodes = Vec::with_capacity(sub_proofs.len());
        // Sub-proofs of the same shape share a proving key; transport each one to the device once
        // for the whole chain rather than once per node (combine does the same per layer).
        let mut d_pks = HashMap::new();
        for (proof, vk) in sub_proofs {
            let layout = extract_recursion_vk_layout(vk, Some(proof));
            let idx = self.keygen_for(&layout)?;
            let (_, program, pk, node_vk) = &self.pks[idx];
            let child: CombineChild = (vk.clone(), proof.clone(), layout);
            let (_, record) = setup_for_deferred_with_program(
                &child,
                Arc::clone(program),
                acc,
                riscv_vk_digest,
                end_pc,
                self.vk_map.as_deref(),
            );
            let ctx = build_proving_ctx(&record, &self.chips, "deferred");
            let d_pk = d_pks
                .entry(idx)
                .or_insert_with(|| self.engine.device().transport_pk_to_device(pk));
            let node = self
                .engine
                .prove(d_pk, ctx)
                .map_err(|e| eyre::eyre!("deferred node prove failed: {e:?}"))?;
            nodes.push((node, node_vk.clone()));
            acc = chain_step(&acc, proof)?;
        }
        Ok((nodes, acc))
    }

    /// What the circuit would reject anyway, said up front: under the whitelist each sub-proof
    /// must be a complete root whose VK is a member, proved under this map's root.
    fn check_whitelisted(&self, sub_proofs: &[ProofWithVk]) -> eyre::Result<()> {
        let map = self
            .vk_map
            .as_ref()
            .ok_or_else(|| eyre::eyre!("whitelist mode without a vk map (call set_vk_map)"))?;
        let col = RECURSION_PUBLIC_VALUES_COL_MAP;
        for (i, (proof, vk)) in sub_proofs.iter().enumerate() {
            eyre::ensure!(
                map.find(&vk_identity(vk)).is_some(),
                "sub-proof {i}: its VK is not in the whitelist"
            );
            let pvs = recursion_public_values(&proof.public_values)?;
            eyre::ensure!(
                pvs[col.flag_complete] == Kb::ONE,
                "sub-proof {i}: not a complete root"
            );
            eyre::ensure!(
                col.vk_root
                    .iter()
                    .zip(map.root())
                    .all(|(&idx, r)| pvs[idx] == r),
                "sub-proof {i}: proved under another whitelist root — sub-proofs must be proved \
                 against the same whitelist as the tree that consumes them"
            );
        }
        Ok(())
    }

    /// STARK-verify a node against the honestly keygen'd VK for its shape — substituting the
    /// honest key is what stands in for whitelist membership here, as it does for combine.
    ///
    /// Deliberately only the STARK check: a deferred node's public values carry no standalone
    /// meaning (it attests a chain STEP, not a complete execution), and every relation they must
    /// satisfy is checked by the parent that consumes it — continuity, the merge and
    /// `assert_child_pv_digests`. `CombineMachine::verify`'s further public-value checks have no
    /// counterpart to make here.
    pub fn verify(&self, node: &ProofWithVk) -> eyre::Result<()> {
        let (proof, vk) = node;
        let honest = self
            .pks
            .iter()
            .find(|(_, _, _, v)| {
                v.pre_hash == vk.pre_hash
                    && v.inner.merged_preprocessed_commit == vk.inner.merged_preprocessed_commit
            })
            .ok_or_else(|| eyre::eyre!("no keygen'd deferred shape matches this node's vk"))?;
        self.engine
            .verify(&honest.3, proof)
            .map_err(|e| eyre::eyre!("deferred node failed STARK verify: {e:?}"))
    }

    pub fn num_distinct_shapes(&self) -> usize {
        self.pks.len()
    }
}

/// Host-side mirror of the in-circuit chain step. Same preimage and sponge as the guest's
/// `hash_deferred_proof`, which is what makes the guest's claimed digest and the tree's
/// reconstructed one comparable.
fn chain_step(prev: &[Kb; DIGEST_SIZE], child: &Proof<Sc>) -> eyre::Result<[Kb; DIGEST_SIZE]> {
    let pvs = recursion_public_values(&child.public_values)?;
    let col = RECURSION_PUBLIC_VALUES_COL_MAP;
    let vk_digest: [Kb; DIGEST_SIZE] = std::array::from_fn(|j| pvs[col.riscv_vk_digest[j]]);
    let mut pv_digest = [Kb::ZERO; 32];
    for (slot, &idx) in pv_digest.iter_mut().zip(
        col.committed_value_digest
            .iter()
            .flat_map(|word| word.0.iter()),
    ) {
        *slot = pvs[idx];
    }
    Ok(hash_deferred_proof(prev, &vk_digest, &pv_digest))
}
