//! Combine prover (Phase 3, aggregation): tree-reduces N convert proofs into one complete
//! proof. Per-node dynamic arity-2 with pass-through: each layer pairs consecutive proofs,
//! a leftover proof promotes to the next layer unproven, and the final single node is built
//! with `is_complete = true` (arming the completeness assertions — GCS equals the expected
//! constant point etc.).
//! Proving keys are keygen'd lazily, deduplicated by (ordered child-layout tuple, is_complete).

use std::{collections::HashMap, sync::Arc};

use p3_field::PrimeCharacteristicRing;
use p3_maybe_rayon::prelude::*;

use crate::{
    compiler::recursion::program::RecursionProgram,
    emulator::recursion::public_values::RECURSION_PUBLIC_VALUES_COL_MAP,
    instances::chiptype::recursion_chiptype::RecursionChipType,
    machine::chip::{ChipBehavior, MetaChip},
    mle::{
        compiler::recursion::{ConvertVerifierCircuit, RecursionVkLayout},
        machine::{
            convert::ProofWithVk,
            exe::RiscvVmVk,
            recursion::{
                build_proving_ctx, check_complete_root_public_values, extract_recursion_vk_layout,
                recursion_air_refs_with_preprocessed, recursion_public_values,
                recursion_vk_layouts_equal, setup_for_combine_with_program, CombineChild, Engine,
                Kb, Sc,
            },
            vk_map::{vk_identity, MleVkMap},
        },
    },
    primitives::consts::{DIGEST_SIZE, RECURSION_NUM_PVS},
};
use pico_mle_core::{
    config::soundness::{admit_production_vk, UnderBudgetError},
    keygen::types::{MultiStarkProvingKey, MultiStarkVerifyingKey},
    prover::DeviceDataTransporter,
    StarkEngine, SystemParams,
};

/// One lazily-keygen'd combine shape: `(ordered child layouts, is_complete, program, pk, vk)`.
pub type CombinePkEntry = (
    Vec<RecursionVkLayout>,
    bool,
    Arc<RecursionProgram<Kb>>,
    MultiStarkProvingKey<Sc>,
    Arc<MultiStarkVerifyingKey<Sc>>,
);

/// Proves the combine (aggregation) layer over convert proofs.
pub struct CombineMachine {
    pub engine: Engine,
    /// Lazily grown; deduplicated by (ordered child-layout tuple, is_complete).
    pks: Vec<CombinePkEntry>,
    pub chips: Vec<MetaChip<Kb, RecursionChipType<Kb>>>,
    /// Trusted VM-layer exe identity; the apex pins the root's `riscv_vk_digest` against
    /// `riscv_vm_vk.digest()`.
    riscv_vm_vk: RiscvVmVk,
    /// Whitelist mode (baked into every node program at keygen).
    vk_verification: bool,
    /// The whitelist (vk_verification mode): witness paths at prove time, root + membership
    /// checks at the apex. Supplied via [`Self::set_vk_map`] after the VKs it contains exist.
    vk_map: Option<Arc<MleVkMap>>,
    /// Test hook: skip the host-side node/leaf seam check so a broken seam reaches the circuit.
    skip_seam_check: bool,
}

impl CombineMachine {
    /// Combine nodes prove under the same params as convert (uniform child-verify cost
    /// across the tree); pass `recursion_params_with_100_bits_security()` and the trusted
    /// VM-layer exe identity (`RiscvVmVk::from_program_and_vk`).
    pub fn new(params: SystemParams, riscv_vm_vk: RiscvVmVk, vk_verification: bool) -> Self {
        Self {
            engine: StarkEngine::new(params),
            pks: Vec::new(),
            chips: RecursionChipType::<Kb>::mle_recursion_chips(),
            riscv_vm_vk,
            vk_verification,
            vk_map: None,
            skip_seam_check: false,
        }
    }

    /// Negative tests only: let leaves that do not start the deferred chain where the nodes end
    /// it reach the circuit, whose continuity check is what has to reject them.
    pub fn skip_seam_check_for_testing(&mut self) {
        self.skip_seam_check = true;
    }

    /// Keygen the standard node shapes — every ordered pair of child kinds, non-complete and
    /// complete, plus the single-child complete roots — where a child kind is one convert
    /// ladder row (C_r) or the combine tier (B), so their VKs exist BEFORE proving (the
    /// whitelist must contain them; `child_vk` is any recursion VK of this machine, e.g. a
    /// convert VK). Returns the keygen'd VKs: 2 (R+1)^2 + (R+1) of them for R convert rows.
    ///
    /// Note: whitelisting the complete shapes also admits a COMPLETE proof as a non-root
    /// child of a larger tree. Harmless — the parent overwrites `flag_complete`, continuity
    /// still chains, and the `start_chunk == 1` chain permits only one chunk-1 leaf per tree
    /// (no double GCS injection) — but it does widen the accepted proof-tree grammar.
    pub fn preregister_standard_shapes(
        &mut self,
        child_vk: &MultiStarkVerifyingKey<Sc>,
    ) -> Result<Vec<Arc<MultiStarkVerifyingKey<Sc>>>, UnderBudgetError> {
        let (layouts_c, _) = self.standard_child_layouts(child_vk);
        let layout_b = self.combine_tier_child_layout(child_vk)?;
        // Every ordered child-type combination a tree can produce (pass-through nodes pair
        // convert-tier leftovers with combine-tier proofs in either order), for non-root and
        // root nodes, plus the single-child roots. Row order first, B last, so the leaf order
        // is a function of the tables alone.
        let kinds: Vec<&RecursionVkLayout> = layouts_c.iter().chain([&layout_b]).collect();
        let mut vks = Vec::new();
        for complete in [false, true] {
            for left in &kinds {
                for right in &kinds {
                    let idx = self.keygen_for(&[(*left).clone(), (*right).clone()], complete)?;
                    vks.push(self.pks[idx].4.clone());
                }
            }
        }
        for single in &kinds {
            let idx = self.keygen_for(&[(*single).clone()], true)?;
            vks.push(self.pks[idx].4.clone());
        }
        debug_assert_eq!(vks.len(), Self::standard_node_count());
        Ok(vks)
    }

    /// How many node VKs [`Self::preregister_standard_shapes`] emits: every ordered pair over
    /// the child kinds (one per convert ladder row plus the combine tier), non-root and root,
    /// plus the single-child roots. The whitelist's leaf count is the riscv shape count plus
    /// this.
    pub fn standard_node_count() -> usize {
        let kinds = crate::mle::machine::shape::MLE_RECURSION_CONVERT_LADDER.len() + 1;
        2 * kinds * kinds + kinds
    }

    /// The node [`Self::preregister_standard_shapes`] keygens first: the non-root combine over
    /// two last-row converts, whose vk carries the B pre_hash the combine-tier child layout is
    /// read from. It is one of the standard nodes, so the artifact test can check this binary's
    /// combine keys against the whitelist with a single node keygen.
    pub fn bootstrap_node_vk(
        &mut self,
        child_vk: &MultiStarkVerifyingKey<Sc>,
    ) -> Result<Arc<MultiStarkVerifyingKey<Sc>>, UnderBudgetError> {
        let (layouts_c, _) = self.standard_child_layouts(child_vk);
        let c_last = layouts_c.last().expect("the convert ladder is empty");
        let idx = self.keygen_for(&[c_last.clone(), c_last.clone()], false)?;
        Ok(self.pks[idx].4.clone())
    }

    /// The layout of a combine-tier (B) proof as a child: what every combine node, root included,
    /// emits — and so what a deferred node verifies under the whitelist. Read off the bootstrap
    /// node's VK at the combine tier's heights.
    pub fn combine_tier_child_layout(
        &mut self,
        child_vk: &MultiStarkVerifyingKey<Sc>,
    ) -> Result<RecursionVkLayout, UnderBudgetError> {
        let (_, b_heights) = self.standard_child_layouts(child_vk);
        let combine_vk0 = self.bootstrap_node_vk(child_vk)?;
        Ok(
            crate::mle::machine::recursion::extract_recursion_vk_layout_from_heights(
                &combine_vk0,
                Some(&b_heights),
            ),
        )
    }

    /// The standard child layouts: one convert layout per ladder row (C_r), synthesized from
    /// `child_vk` at the row's heights, and the combine tier's heights the B layout is read at.
    /// Heights are indexed by AIR id (the machine's chip order) -- the tier tables are keyed by
    /// chip NAME, so they map through the machine's chip list.
    fn standard_child_layouts(
        &self,
        child_vk: &MultiStarkVerifyingKey<Sc>,
    ) -> (Vec<RecursionVkLayout>, Vec<Option<usize>>) {
        use crate::mle::machine::shape::{
            MLE_RECURSION_COMBINE_LOG_HEIGHTS, MLE_RECURSION_CONVERT_LADDER,
        };
        let tier_heights = |table: &[(&str, usize)]| -> Vec<Option<usize>> {
            self.chips
                .iter()
                .map(|chip| {
                    let name = chip.name();
                    Some(
                        table
                            .iter()
                            .find(|(n, _)| *n == name)
                            .map(|(_, log)| *log)
                            .unwrap_or_else(|| panic!("chip `{name}` missing from tier table")),
                    )
                })
                .collect()
        };
        // Children come in one SHAPE per convert ladder row (C_r) plus the combine tier (B) --
        // the lean pre_hash depends only on shape, so every convert on row r shares one child
        // layout and every combine node (root included) emits one B-shaped proof, hence one B
        // child-layout, regardless of which node produced it.
        let layouts_c: Vec<RecursionVkLayout> = MLE_RECURSION_CONVERT_LADDER
            .iter()
            .map(|row| {
                crate::mle::machine::recursion::extract_recursion_vk_layout_from_heights(
                    child_vk,
                    Some(&tier_heights(row)),
                )
            })
            .collect();
        (layouts_c, tier_heights(MLE_RECURSION_COMBINE_LOG_HEIGHTS))
    }

    /// Supply the whitelist (vk_verification mode; call before proving).
    pub fn set_vk_map(&mut self, map: Arc<MleVkMap>) {
        assert!(self.vk_verification, "vk_map without vk_verification");
        self.vk_map = Some(map);
    }

    /// Find-or-keygen the proving key for a node shape. Returns the `pks` index.
    fn keygen_for(
        &mut self,
        layouts: &[RecursionVkLayout],
        is_complete: bool,
    ) -> Result<usize, UnderBudgetError> {
        if let Some(idx) = self.pks.iter().position(|(ls, complete, ..)| {
            *complete == is_complete
                && ls.len() == layouts.len()
                && ls
                    .iter()
                    .zip(layouts.iter())
                    .all(|(a, b)| recursion_vk_layouts_equal(a, b))
        }) {
            return Ok(idx);
        }
        let vk_refs: Vec<&RecursionVkLayout> = layouts.iter().collect();
        let mut program = ConvertVerifierCircuit::build_verify_n_program_multi::<Kb>(
            &vk_refs,
            false,
            is_complete,
            self.vk_verification,
        );
        let child_ws: Vec<usize> = layouts
            .iter()
            .map(|l| l.stacking_widths.iter().sum())
            .collect();
        // Recursion shape tier — whitelist mode only (see the note in ConvertMachine::new).
        // Every combine node takes the combine tier, the root included (FRI parity: the root
        // is just the last combine round with `is_complete = true`, not a shape case of its
        // own). Explicit padding (rather than natural heights) keeps the VKs from silently
        // drifting with small circuit changes. `child_Ws` tells the child kinds apart in the
        // check's log (a convert row and the combine tier have different stacked widths); the
        // pair {combine, combine} is the fixpoint the tier tables have to close on.
        if self.vk_verification {
            crate::mle::machine::recursion::pad_recursion_program(
                &format!(
                    "combine n={} complete={is_complete} child_Ws={child_ws:?}",
                    layouts.len()
                ),
                &mut program,
                crate::mle::machine::shape::RecursionTier::Combine,
            );
        }
        let program = Arc::new(program);
        // Per-node observability (level-cascade watch): tallest-chip proxy stats.
        let stats = program.stats();
        tracing::info!(
            "combine keygen: n={} is_complete={} child_Ws={:?} instrs: base_alu={} ext_alu={} total={}",
            layouts.len(),
            is_complete,
            child_ws,
            stats.get("BaseAlu").copied().unwrap_or(0),
            stats.get("ExtAlu").copied().unwrap_or(0),
            stats.values().sum::<usize>(),
        );
        let airs = recursion_air_refs_with_preprocessed(&program);
        // Combine proofs are themselves recursion proofs consumed by higher tree levels:
        // keygen with the merged-preprocessed scheme (the recursion-machine convention, same
        // as convert), so every recursion child — convert or combine — takes the same merged
        // path in verify_one.
        let (pk, vk) = self.engine.keygen_merged_preprocessed(&airs);
        admit_production_vk("combine", "cpu", &vk)?;
        self.pks
            .push((layouts.to_vec(), is_complete, program, pk, Arc::new(vk)));
        Ok(self.pks.len() - 1)
    }

    /// The complete-root entry whose VK identity matches `root_vk`, selected exactly as
    /// [`Self::verify`] selects the honest VK.
    fn complete_entry_for(&self, root_vk: &MultiStarkVerifyingKey<Sc>) -> Option<&CombinePkEntry> {
        self.pks.iter().find(|(_, is_complete, _, _, pk_vk)| {
            *is_complete
                && pk_vk.pre_hash == root_vk.pre_hash
                && pk_vk.inner.merged_preprocessed_commit
                    == root_vk.inner.merged_preprocessed_commit
        })
    }

    /// The child layouts the complete root was keygen'd under, for handing to a verifier that has
    /// no children of its own. `None` when no complete shape matches.
    pub fn root_child_layouts(
        &self,
        root_vk: &MultiStarkVerifyingKey<Sc>,
    ) -> Option<&[RecursionVkLayout]> {
        self.complete_entry_for(root_vk)
            .map(|(layouts, ..)| layouts.as_slice())
    }

    /// The honestly keygen'd VK this machine would verify `root_vk` against.
    ///
    /// Exposed so a caller can assert the supplied VK equals it in full. [`Self::verify`] only
    /// matches on two digests, which is enough to *select* the honest key but does not by itself
    /// witness that the two sides agree on widths, degrees or the constraint set.
    pub fn honest_root_vk(
        &self,
        root_vk: &MultiStarkVerifyingKey<Sc>,
    ) -> Option<&MultiStarkVerifyingKey<Sc>> {
        self.complete_entry_for(root_vk).map(|e| &*e.4)
    }

    /// Keygen the complete-root shape described by `child_layouts`, so [`Self::verify`] has an
    /// honest VK to match against.
    ///
    /// Proving derives the shape from the children it holds; a verifier handed only a proof has
    /// none, so the layouts travel with it.
    ///
    /// ⚠️ **The layouts are trusted.** They are compiled into the verifier circuit, so a caller
    /// that takes them from an untrusted source can be made to keygen a circuit that constrains
    /// nothing and then accept a proof of it. This is sound only where the layouts come from the
    /// same place the proof does and that place is trusted — a cross-build parity check, not an
    /// untrusted-proof entry point. [`Self::verify`]'s contract assumes `prove_tree` established
    /// the shape; this method lets a file establish it instead.
    pub fn preregister_root_shape(
        &mut self,
        child_layouts: &[RecursionVkLayout],
    ) -> Result<(), UnderBudgetError> {
        self.keygen_for(child_layouts, true).map(|_| ())
    }

    /// Deferred nodes are admitted only at the HEAD of the tree.
    ///
    /// That is an in-circuit fact already — chunk continuity rejects a deferred node anywhere else
    /// (the root pins `start_chunk == 1` and continuity numbers the leaves from there, so no leaf
    /// in a tree that can close has `next_chunk == 1`, while a node always does). Checking here
    /// only changes WHERE the reader finds out: a sentence, rather than a root proof that fails
    /// to verify, several minutes later, with nothing naming the cause.
    ///
    /// `start_chunk == next_chunk == 1` is what identifies a deferred node: every convert leaf
    /// sets `next_chunk = chunk + 1`, so no leaf of any kind can have it at 1.
    ///
    /// Under the whitelist (`vk_root` is its root) a node must also carry that root, which the
    /// merge's `vk_root` agreement requires in-circuit: a dev-mode node, or one proved under
    /// another whitelist, is named here rather than failing at witness generation.
    fn check_deferred_prefix(
        children: &[ProofWithVk],
        vk_root: Option<[Kb; 8]>,
        check_seam: bool,
    ) -> eyre::Result<()> {
        let col = RECURSION_PUBLIC_VALUES_COL_MAP;
        let pvs: Vec<Option<&[Kb]>> = children
            .iter()
            .map(|(proof, _)| recursion_public_values(&proof.public_values).ok())
            .collect();
        let flags: Vec<bool> = pvs
            .iter()
            .map(|pv| {
                pv.is_some_and(|pv| pv[col.start_chunk] == Kb::ONE && pv[col.next_chunk] == Kb::ONE)
            })
            .collect();
        check_deferred_prefix_flags(&flags)?;

        // The seam between the last deferred node and the first leaf is where a caller's most
        // likely mistake shows up: leaves are fed their chain value by
        // `ConvertMachine::set_final_deferred_digest`, and forgetting it leaves them at zero while
        // the nodes end somewhere else. Continuity would reject that, minutes later and without
        // naming the cause.
        let count = flags.iter().take_while(|d| **d).count();
        if let Some(root) = vk_root {
            for (i, pv) in pvs[..count].iter().enumerate() {
                let pv = pv.expect("a deferred node was classified from its public values");
                eyre::ensure!(
                    col.vk_root.iter().zip(root).all(|(&idx, r)| pv[idx] == r),
                    "deferred node {i} does not carry this tree's whitelist root — prove it with a \
                     `DeferredMachine` given the same vk map"
                );
            }
        }
        if count > 0 && check_seam {
            if let (Some(Some(last_node)), Some(Some(first_leaf))) =
                (pvs.get(count - 1), pvs.get(count))
            {
                for j in 0..DIGEST_SIZE {
                    let (end, start) = (
                        last_node[col.end_reconstruct_deferred_digest[j]],
                        first_leaf[col.start_reconstruct_deferred_digest[j]],
                    );
                    eyre::ensure!(
                        end == start,
                        "the leaves do not start the deferred chain where the nodes end it \
                         (limb {j}) — call `ConvertMachine::set_final_deferred_digest` with the \
                         digest `DeferredMachine::prove_chain` returned"
                    );
                }
            }
        }
        Ok(())
    }

    /// Tree-reduce the children (convert proofs with their VKs) to one complete root proof.
    pub fn prove_tree(&mut self, children: Vec<ProofWithVk>) -> eyre::Result<ProofWithVk> {
        eyre::ensure!(!children.is_empty(), "prove_tree needs at least one child");
        Self::check_deferred_prefix(
            &children,
            self.vk_map.as_ref().map(|m| m.root()),
            !self.skip_seam_check,
        )?;
        let mut layer: Vec<ProofWithVk> = children;
        let mut level = 0usize;

        loop {
            let n = layer.len();
            // Node grouping: consecutive pairs; a lone input still forms one (n=1) node so the
            // root is always a combine node (a bare convert proof is never complete).
            let num_nodes = if n == 1 { 1 } else { n / 2 };
            let leftover = if n == 1 { 0 } else { n % 2 };
            let is_root_layer = num_nodes == 1 && leftover == 0;

            // Phase 1 (serial, &mut self): extract layouts + find-or-keygen per node.
            let mut node_inputs: Vec<(Vec<CombineChild>, usize)> = Vec::with_capacity(num_nodes);
            let mut layer_iter = layer.into_iter();
            for _ in 0..num_nodes {
                let take = if n == 1 { 1 } else { 2 };
                let node_children: Vec<ProofWithVk> = (&mut layer_iter).take(take).collect();
                let tuples: Vec<_> = node_children
                    .into_iter()
                    .map(|(proof, vk)| {
                        let layout = extract_recursion_vk_layout(&vk, Some(&proof));
                        (vk, proof, layout)
                    })
                    .collect();
                let layouts: Vec<RecursionVkLayout> =
                    tuples.iter().map(|(_, _, l)| l.clone()).collect();
                // Node preflight: dump each child's continuity-relevant PV fields so a
                // violated cross-child relation is visible host-side before proving.
                for (ci, (_, proof, _)) in tuples.iter().enumerate() {
                    if let Some(pvs) = proof
                        .public_values
                        .iter()
                        .find(|p| p.len() == RECURSION_NUM_PVS)
                    {
                        let col = RECURSION_PUBLIC_VALUES_COL_MAP;
                        let g = |idx: usize| pvs[idx];
                        tracing::debug!(
                            "  child[{ci}]: start_pc={:?} next_pc={:?} chunk=({:?},{:?}) exec=({:?},{:?},c={:?}) init=({:?}->{:?}) fin=({:?}->{:?}) flag={:?}",
                            col.start_pc.map(g), col.next_pc.map(g),
                            g(col.start_chunk), g(col.next_chunk),
                            g(col.start_execution_chunk), g(col.next_execution_chunk),
                            g(col.contains_execution_chunk),
                            col.previous_init_addr_limbs.map(g), col.last_init_addr_limbs.map(g),
                            col.previous_finalize_addr_limbs.map(g), col.last_finalize_addr_limbs.map(g),
                            g(col.flag_complete),
                        );
                    }
                }
                let pk_idx = self.keygen_for(&layouts, is_root_layer)?;
                node_inputs.push((tuples, pk_idx));
            }
            let passthrough: Vec<ProofWithVk> = layer_iter.collect();
            debug_assert_eq!(passthrough.len(), leftover);

            tracing::info!(
                "combine layer {level}: {n} in -> {num_nodes} node(s) + {leftover} pass-through{}",
                if is_root_layer { " (ROOT)" } else { "" }
            );

            // Phase 2 (parallel, &self): prove every node in the layer. Transport each
            // distinct proving key to the device once per layer (nodes of the same shape
            // share it) instead of once per node.
            let engine = &self.engine;
            let chips = &self.chips;
            let pks = &self.pks;
            let vk_map = &self.vk_map;
            let mut d_pks = HashMap::new();
            for (_, pk_idx) in &node_inputs {
                d_pks
                    .entry(*pk_idx)
                    .or_insert_with(|| engine.device().transport_pk_to_device(&pks[*pk_idx].3));
            }
            let d_pks = &d_pks;
            let proved: Vec<ProofWithVk> = node_inputs
                .into_par_iter()
                .map(|(tuples, pk_idx)| {
                    let (_, _, program, _, vk) = &pks[pk_idx];
                    let (_, record) = setup_for_combine_with_program(
                        &tuples,
                        Arc::clone(program),
                        is_root_layer,
                        vk_map.as_deref(),
                    );
                    let ctx = build_proving_ctx(
                        &record,
                        chips,
                        if is_root_layer { "root" } else { "combine" },
                    );
                    engine
                        .prove(&d_pks[&pk_idx], ctx)
                        .map(|proof| (proof, vk.clone()))
                        .map_err(|e| eyre::eyre!("{e:?}"))
                })
                .collect::<eyre::Result<Vec<_>>>()?;

            if is_root_layer {
                let mut proved = proved;
                return Ok(proved.pop().expect("root layer proves exactly one node"));
            }
            layer = proved.into_iter().chain(passthrough).collect();
            level += 1;
        }
    }

    /// Host-side acceptance of the root proof. The recursion circuits are app-agnostic (the root
    /// VK depends only on the node shape, not the guest program), so this is where the
    /// program-specific facts are pinned:
    ///   1. Verify the proof against the HONESTLY keygen'd root VK (the `is_complete` shape in
    ///      `self.pks`), not the caller-supplied one — pins the recursion circuit.
    ///   2. `flag_complete == 1` (arms the in-circuit universal completeness asserts).
    ///   3. `riscv_vk_digest == RiscvVmVk::digest()` — the single exe-identity anchor. The
    ///      convert circuit computes `H(DOMAIN ‖ program_commit ‖ pc_start ‖ initial_gcs)`
    ///      in-circuit from the witnessed identity (program_commit Merkle-hard-bound as the
    ///      program table's WHIR stacking root); the chunk-1 gate + GCS injection + in-circuit
    ///      root closure bind the witnessed values to the execution, so this one comparison
    ///      pins the program, its entry pc, and the cross-chunk memory closure.
    ///   4. Recompute the PV digest and compare.
    ///
    /// CONTRACT: these checks are part of the proof's meaning; requires `prove_tree` to have
    /// keygen'd the root shape on this machine (populates the `is_complete` entry). The full
    /// cross-execution VK allowlist (a hardcoded root of approved recursion VKs) is the apex /
    /// on-chain layer's job; pinning the single honest root VK here is the host-side stand-in.
    pub fn verify(&self, root: &ProofWithVk) -> eyre::Result<()> {
        let (proof, vk) = root;
        // (1) Pin the recursion circuit: verify against the honestly keygen'd complete VK whose
        // FULL identity (lean pre_hash AND merged commitment) matches the supplied one, never
        // the supplied struct itself. NOTE: under shape bucketing every recursion VK shares one
        // lean pre_hash (the lean preimage deliberately cannot distinguish same-shape programs),
        // so the pre_hash alone selects nothing — the merged commitment does the work, and there
        // can be several complete shapes (n=2 and the single-chunk n=1 root). The binding
        // soundness lives in `engine.verify(honest_root_vk, …)` below: the verifier observes
        // the HONEST vk's merged commitment, so a proof of any other program diverges.
        let honest_root_vk = self.complete_entry_for(vk).map(|e| &e.4).ok_or_else(|| {
            eyre::eyre!(
                "root proof vk matches no honestly keygen'd complete shape on this machine \
                     (run prove_tree first, and pass the vk prove_tree returned)"
            )
        })?;
        self.engine
            .verify(honest_root_vk, proof)
            .map_err(|e| eyre::eyre!("root combine proof failed STARK verify: {e:?}"))?;

        // (2)-(4) plus the whitelist root: the config-free public-value checks, shared with the
        // embed layer (which re-proves this very root under the outer config and must accept it on
        // exactly the same terms). See `recursion::root_check`.
        //
        // Whitelist mode also pins the ROOT's own VK as a whitelist member — the in-circuit checks
        // cover children only, so the outermost key is pinned here. That runs on `honest_root_vk`,
        // the key the proof actually verified under, never the supplied struct (whose fields are
        // attacker-settable; a stripped merged commitment must yield an error, not a panic — it
        // already failed the identity match in (1)).
        eyre::ensure!(
            !self.vk_verification || self.vk_map.is_some(),
            "vk_verification machine has no vk map at verify time (call set_vk_map)"
        );
        let pvs = recursion_public_values(&proof.public_values)?;
        check_complete_root_public_values(
            "root",
            pvs,
            &self.riscv_vm_vk.digest(),
            self.vk_map.as_ref().map(|m| m.root()).as_ref(),
        )?;
        if let Some(map) = &self.vk_map {
            if map.find(&vk_identity(honest_root_vk)).is_none() {
                eyre::bail!("root proof's VK is not in the whitelist");
            }
        }
        Ok(())
    }

    /// Distinct combine shapes keygen'd so far (observability for the dedup behavior).
    pub fn num_distinct_shapes(&self) -> usize {
        self.pks.len()
    }
}

/// The order half of [`CombineMachine::check_deferred_prefix`], over the classification alone so
/// it can be tested without a proof to hand.
fn check_deferred_prefix_flags(is_deferred: &[bool]) -> eyre::Result<()> {
    let count = is_deferred.iter().take_while(|d| **d).count();
    if let Some(stray) = is_deferred[count..].iter().position(|d| *d) {
        eyre::bail!(
            "deferred node at child {} follows a non-deferred one; they go at the head of the tree",
            count + stray
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::check_deferred_prefix_flags as check;

    #[test]
    fn a_deferred_prefix_is_accepted() {
        for flags in [
            vec![],
            vec![false, false],
            vec![true, false],
            vec![true, true, false, false],
        ] {
            check(&flags).unwrap_or_else(|e| panic!("rejected {flags:?}: {e}"));
        }
    }

    /// The circuit rejects these too (a node's `start_chunk` is 1, and continuity plus the root's
    /// `start_chunk == 1` leave no leaf with `next_chunk == 1`) — but only as a root that fails to
    /// verify, which is why it is worth catching here.
    #[test]
    fn a_deferred_node_after_a_leaf_is_rejected() {
        for (flags, at) in [
            (vec![false, true], 1),
            (vec![true, false, true], 2),
            (vec![false, false, true, true], 2),
        ] {
            let err = check(&flags).unwrap_err().to_string();
            assert!(
                err.contains(&format!("child {at} ")),
                "{flags:?} should name child {at}, got: {err}"
            );
        }
    }
}
