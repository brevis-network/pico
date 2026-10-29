//! Combine prover (Phase 3, aggregation): tree-reduces N convert proofs into one complete
//! proof. Per-node dynamic arity-2 with pass-through: each layer pairs consecutive proofs,
//! a leftover proof promotes to the next layer unproven, and the final single node is built
//! with `is_complete = true` (arming the completeness assertions — GCS equals the expected
//! constant point etc.).
//! Proving keys are keygen'd lazily, deduplicated by (ordered child-layout tuple, is_complete).

use std::{collections::HashMap, sync::Arc};

use p3_field::PrimeCharacteristicRing;
// `Mutex`/`Weak` back the cross-card `PROGRAM_INDEX` and `Instruction` backs `instr_mix`, and all
// three live behind `#[cfg(feature = "cuda")]` — so their imports must carry the same gate.
// `vm/src/lib.rs` sets `#![cfg_attr(feature = "strict", deny(warnings))]`, which turns an unused
// import into a hard error in every build that omits the feature (`pico-aot-codegen` is one).
#[cfg(feature = "cuda")]
use crate::compiler::recursion::instruction::Instruction;
#[cfg(feature = "cuda")]
use std::sync::{Mutex, Weak};

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

    /// Find-or-keygen one node shape, so [`Self::verify`] can accept a root proof of that shape
    /// produced **elsewhere** (i.e. not by this machine's own [`Self::prove_tree`]).
    ///
    /// This exists for the GPU combine path: the GPU machine proves the tree, and its root is
    /// handed back here for the host-side four-step acceptance. `verify` deliberately checks
    /// against an *honestly keygen'd* complete VK rather than the caller-supplied one, which is
    /// why the shape must first exist on this machine — the CONTRACT documented on `verify`.
    /// Pass the SAME ordered `layouts` the root node was proved with (order matters: shapes are
    /// deduplicated by the ordered tuple) and `is_complete = true` for a root. Errs when the
    /// node's key scores below the production soundness budget.
    pub fn register_shape(
        &mut self,
        layouts: &[RecursionVkLayout],
        is_complete: bool,
    ) -> Result<(), UnderBudgetError> {
        self.keygen_for(layouts, is_complete).map(|_| ())
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

// ─── GPU combine prover (per-node) ──────────────────────────────────────────────────────
//
// GPU-only by design: the only consumer is the MLE single-node driver, which proves on the GPU.
// The batch [`CombineMachine`] above remains the CPU reference path (the e2e example drives it),
// and it is also where a GPU-produced root is accepted — see [`CombineMachine::register_shape`]
// and [`CombineMachine::verify`]. The whole section is `cuda`-gated; there is no CPU path.
//
// Mirrors `convert.rs`'s GPU section: one keygen per distinct shape behind a bounded LRU, and a
// CPU stage (`prepare_node`) split from the GPU stage (`prove_prepared_node`) so a driver can
// overlap them. The tree itself is NOT here — the driver drives it (the scheduler's `ProofTree`
// pairs adjacent proofs); this machine only answers "given these children, prove one node".

#[cfg(feature = "cuda")]
use std::time::Instant;

#[cfg(feature = "cuda")]
use crate::mle::machine::recursion::gpu::{self, GpuEngineKb, GpuPbKb};
#[cfg(feature = "cuda")]
use pico_verifier::hash::digest_to_u32s;

/// The prover-side key handle cached per shape: a device-resident proving key.
#[cfg(feature = "cuda")]
type GpuPk = Arc<pico_mle_core::prover::DeviceMultiStarkProvingKey<GpuPbKb>>;

/// One cached keygen per node shape — `(ordered child layouts, is_complete)`.
#[cfg(feature = "cuda")]
struct GpuCombinePkEntry {
    layouts: Vec<RecursionVkLayout>,
    is_complete: bool,
    program: Arc<RecursionProgram<Kb>>,
    vk: Arc<MultiStarkVerifyingKey<Sc>>,
    device_pk: GpuPk,
    /// Monotonic id assigned at keygen. Two identical shapes hit the same cache entry and so
    /// share an id; a shape that was evicted and re-keygen'd gets a NEW id, which is exactly the
    /// signal that a re-keygen happened.
    shape_id: usize,
    /// LRU tick of the last use (larger = more recent).
    last_used: u64,
}

/// Process-wide index of recursion programs already built for a shape, shared across cards.
///
/// WHY. The pk cache is per-card and device-resident (one `GpuCombineMachine` per card), and a
/// node's card is assigned round-robin, so the same shape proved on a different card re-runs
/// `build_verify_n_program_multi` from scratch. Measured on block 24006677 x 4 cards: 30 keygens
/// for 19 distinct shapes, i.e. ~11 rebuild a program another card already holds, and the program
/// build is ~80 ms of the ~100 ms a miss costs — paid on the combine tree's serial critical path,
/// where all four prover lanes are idle waiting for it.
///
/// WHY THIS ADDS NO RESIDENCY. Entries are `Weak`, so the index can only hand back a program some
/// per-card cache entry is still holding alive; it never keeps one alive itself, and a shape
/// evicted from every card's LRU drops out on the next sweep. Host memory only — the device pk
/// stays strictly per-card, which is the invariant `resident-gpu-cache-oom-and-managed-memory`
/// (kb/host-patterns) says not to break. The set of device-resident artefacts is byte-for-byte
/// what it was; only the host-side CPU work of re-deriving an identical program is skipped.
///
/// Lock order is per-card `cache` -> `PROGRAM_INDEX`, never the reverse.
#[cfg(feature = "cuda")]
static PROGRAM_INDEX: Mutex<Vec<SharedProgram>> = Mutex::new(Vec::new());

#[cfg(feature = "cuda")]
struct SharedProgram {
    layouts: Vec<RecursionVkLayout>,
    is_complete: bool,
    program: Weak<RecursionProgram<Kb>>,
}

/// `MLE_COMBINE_OVERLAP_KEYGEN` runs a node's device keygen against its recursion emulation
/// instead of before it. **Default ON**, `=0` puts the keygen back in front of the emulation.
///
/// The cost is one thread per node. The emulation is what runs on it — it opens no spans, so the
/// keygen keeps its own and the span record still accounts for it.
///
/// It needs the program ahead of the key, which is what `MLE_COMB_KEYGEN_FAT` turns off, so the
/// two are mutually exclusive and the fat path wins.
#[cfg(feature = "cuda")]
pub fn combine_overlap_keygen() -> bool {
    crate::mle::env_opt_out("MLE_COMBINE_OVERLAP_KEYGEN")
}

/// The program another card already built for this shape, if one is still alive.
///
/// Dead `Weak`s are dropped as they are passed, so the index self-trims without a sweep of its
/// own; it is bounded by the live per-card caches (cards x `MLE_COMBINE_PK_CACHE`).
#[cfg(feature = "cuda")]
fn shared_program(
    layouts: &[RecursionVkLayout],
    is_complete: bool,
) -> Option<Arc<RecursionProgram<Kb>>> {
    let mut index = PROGRAM_INDEX.lock().expect("program index mutex poisoned");
    let mut found = None;
    index.retain(|e| match e.program.upgrade() {
        None => false,
        Some(p) => {
            if found.is_none()
                && e.is_complete == is_complete
                && e.layouts.len() == layouts.len()
                && e.layouts
                    .iter()
                    .zip(layouts.iter())
                    .all(|(a, b)| recursion_vk_layouts_equal(a, b))
            {
                found = Some(p);
            }
            true
        }
    });
    found
}

/// Publish a freshly built program so the other cards' misses can skip the rebuild.
#[cfg(feature = "cuda")]
fn publish_program(
    layouts: &[RecursionVkLayout],
    is_complete: bool,
    program: &Arc<RecursionProgram<Kb>>,
) {
    PROGRAM_INDEX
        .lock()
        .expect("program index mutex poisoned")
        .push(SharedProgram {
            layouts: layouts.to_vec(),
            is_complete,
            program: Arc::downgrade(program),
        });
}

/// `(base_alu, ext_alu, total)` for the keygen log line, without building a map.
///
/// `RecursionProgram::stats` allocates a `String` PER INSTRUCTION into a `HashMap<String, usize>`.
/// On the ~570 k-instruction recursion program that is ~34 ms — a third of a combine keygen miss,
/// on the tree's serial critical path — and it is paid whether or not the line below is enabled,
/// because the argument is evaluated before the macro decides. These are the same three numbers.
#[cfg(feature = "cuda")]
fn instr_mix(program: &RecursionProgram<Kb>) -> (usize, usize, usize) {
    let mut base_alu = 0usize;
    let mut ext_alu = 0usize;
    for instr in &program.instructions {
        match instr {
            Instruction::BaseAlu(_) => base_alu += 1,
            Instruction::ExtAlu(_) => ext_alu += 1,
            _ => {}
        }
    }
    (base_alu, ext_alu, program.instructions.len())
}

/// One keygen'd shape, for the end-of-run summary ([`GpuCombineMachine::shape_stats`]).
///
/// There is one record per KEYGEN, not per distinct shape: a shape that was evicted and later
/// recurs is keygen'd again and gets a second record. The two coincide exactly when
/// [`ShapeStats::evictions`] is zero.
#[cfg(feature = "cuda")]
#[derive(Clone, Debug)]
pub struct ShapeRecord {
    pub shape_id: usize,
    /// **The shape's identity**: the keygen'd VK's merged-preprocessed commitment, as u32 limbs.
    ///
    /// This is the one exact, cheap discriminator available. The commitment is a Poseidon2 digest
    /// over every AIR's preprocessed trace, which the program alone determines — so equal
    /// fingerprint means the same program (up to a hash collision), and `CombineMachine::verify`
    /// already trusts exactly this field to pick the honestly keygen'd VK. Free: keygen computed
    /// it, and `keygen_recursion_gpu` already asserted host and device agree on it.
    ///
    /// Note it identifies the PROGRAM, while the cache is keyed on the child-layout tuple. Two
    /// records sharing a fingerprint therefore mean one of two things, both worth knowing: an
    /// evicted shape was re-keygen'd, or two distinct layout tuples compiled to the same program
    /// and the second keygen was redundant.
    ///
    /// Do NOT use `pre_hash` for this: the lean preimage deliberately cannot distinguish
    /// same-shape programs (see the note in [`CombineMachine::verify`]).
    pub fingerprint: [u32; 8],
    pub n_children: usize,
    pub is_complete: bool,
    /// Per-child `stacking_widths.iter().sum()` — a coarse, human-readable tier hint
    /// (convert-tier children are wider than combine-tier ones). **Not an identity**: distinct
    /// shapes routinely print the same widths. Use `fingerprint` to tell shapes apart.
    pub child_ws: Vec<usize>,
    pub keygen_ms: u128,
    /// Cache hits on this entry after its keygen, i.e. how many further nodes reused it.
    pub hits: usize,
}

/// The end-of-run shape picture: one accessor, one renderer, so the counts cannot drift apart.
///
/// Invariant: `keygens + hits == nodes proved` (every node either keygens a shape or hits one).
#[cfg(feature = "cuda")]
#[derive(Clone, Debug)]
pub struct ShapeStats {
    /// Keygens performed. Equals the distinct-shape count iff [`Self::distinct_is_exact`].
    pub keygens: usize,
    /// Cache hits across all shapes.
    pub hits: usize,
    /// LRU evictions. Non-zero means a re-keygen of an evicted shape was possible, which is what
    /// turns `keygens` from an exact count into an upper bound.
    pub evictions: usize,
    pub keygen_total_ms: u128,
    pub records: Vec<ShapeRecord>,
}

#[cfg(feature = "cuda")]
impl ShapeStats {
    /// Nodes proved, derived from the two counters rather than counted separately — the driver
    /// asserts this against its own node count.
    pub fn nodes(&self) -> usize {
        self.keygens + self.hits
    }

    /// Whether `keygens` is the exact distinct-shape count (no eviction, so no re-keygen).
    pub fn distinct_is_exact(&self) -> bool {
        self.evictions == 0
    }
}

/// The whole summary line, rendered here so its format lives in one place too.
#[cfg(feature = "cuda")]
impl std::fmt::Display for ShapeStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Keygen is paid in `prepare_node`, not in `prove_prepared_node` where `sum(combine)`
        // accumulates — so it is not a part of that total and routinely exceeds it.
        write!(
            f,
            "keygens={}{} hits={} evictions={} keygen_total={:.3}s (paid in prepare_node, not in sum(combine))",
            self.keygens,
            if self.distinct_is_exact() {
                " (= distinct shapes)"
            } else {
                " (upper bound: evicted shapes may have re-keygen'd)"
            },
            self.hits,
            self.evictions,
            self.keygen_total_ms as f64 / 1000.0,
        )?;
        f.write_str(" [")?;
        for (i, r) in self.records.iter().enumerate() {
            if i > 0 {
                f.write_str(" | ")?;
            }
            write!(
                f,
                "#{} fp={:08x} n={}{} ws={:?} {}ms",
                r.shape_id,
                r.fingerprint[0],
                r.n_children,
                if r.is_complete { "+complete" } else { "" },
                r.child_ws,
                r.keygen_ms,
            )?;
            if r.hits > 0 {
                write!(f, " hits={}", r.hits)?;
            }
        }
        f.write_str("]")
    }
}

/// Per-node GPU combine prover: a pair of children flows in, one node proof flows out. Keygen is
/// per-shape behind a bounded LRU, and recursion trace-gen + proving run on the GPU.
///
/// No `riscv_vm_vk` field: unlike convert, the combine circuit neither witnesses the VM-layer exe
/// identity (it *propagates* the child's `riscv_vk_digest` public value) nor verifies against it —
/// the exe anchor is checked once, at the root, by [`CombineMachine::verify`].
///
/// No `verify` either: the root is handed back to [`CombineMachine`] so the four-step host-side
/// acceptance exists in exactly one place. Per-node `engine.verify` is available to callers as a
/// cheap early-failure net, but it is NOT the security check (it lacks the honest-vk substitution).
#[cfg(feature = "cuda")]
pub struct GpuCombineMachine {
    pub engine: GpuEngineKb,
    /// Whitelist mode: nodes witness their children's membership paths and take the combine
    /// tier shape.
    vk_verification: bool,
    /// The whitelist (whitelist mode): paths at prove time, root as the vk_root public value.
    vk_map: Option<Arc<MleVkMap>>,
    /// Used only for the `ChipBehavior` methods; the FRI parts are dead. See `ConvertMachine::new`.
    chips: Vec<MetaChip<Kb, RecursionChipType<Kb>>>,
    /// `(entries, lru tick, next shape id)`.
    cache: std::sync::Mutex<(Vec<GpuCombinePkEntry>, u64, usize)>,
    /// Cache capacity (`MLE_COMBINE_PK_CACHE`, default 8): the OOM guard — evicted shapes
    /// re-keygen on their next miss (slower, never wrong).
    ///
    /// Convert uses 4; combine deliberately does not inherit it. The cap is neither a speed nor a
    /// memory lever — measured, raising it does NOT reduce the keygen count (a shape is used and
    /// then dead, so the LRU only evicts entries that would not be hit again), and cached device
    /// keys made no measurable difference to the GPU memory-pool high-water mark. What it DOES
    /// buy is the `evictions == 0` certification: without an eviction there can be no re-keygen
    /// of an evicted shape, so the keygen count is exactly the distinct-shape count. A default
    /// that covers a typical tree (8 chunks produce 5-7 shapes) keeps that certification usable;
    /// at 4 it never held.
    cache_cap: usize,
    shapes: std::sync::Mutex<Vec<ShapeRecord>>,
    /// LRU evictions this run. Zero means every keygen was a first-time shape, so the record
    /// count IS the distinct-shape count; non-zero means a re-keygen of an evicted shape is
    /// possible and the record count is an upper bound.
    evictions: std::sync::atomic::AtomicUsize,
}

/// Output of the CPU stage ([`GpuCombineMachine::prepare_node`]), ready for the GPU stage.
#[cfg(feature = "cuda")]
pub struct GpuPreparedCombine {
    vk: Arc<MultiStarkVerifyingKey<Sc>>,
    pk: GpuPk,
    record: crate::emulator::recursion::emulator::RecursionRecord<Kb>,
    child_layouts: Vec<RecursionVkLayout>,
    is_complete: bool,
    keygen_ms: u128,
    setup_ms: u128,
}

/// Device-built combine node (ctx resident), output of [`GpuCombineMachine::build_node_ctx`].
/// Small (recursion-circuit heights), so parking one in a bounded(1) lane is safe — unlike riscv
/// staged ctxs.
#[cfg(feature = "cuda")]
pub struct BuiltCombine {
    vk: Arc<MultiStarkVerifyingKey<Sc>>,
    pk: GpuPk,
    ctx: pico_mle_core::prover::ProvingContext<GpuPbKb>,
    child_layouts: Vec<RecursionVkLayout>,
    is_complete: bool,
    keygen_ms: u128,
    setup_ms: u128,
    tracegen_ms: u128,
}

/// One proved combine node.
#[cfg(feature = "cuda")]
pub struct CombineNode {
    pub proof: ProofWithVk,
    /// The node's ORDERED child layouts. For the root, hand these to
    /// [`CombineMachine::register_shape`] before calling [`CombineMachine::verify`].
    pub child_layouts: Vec<RecursionVkLayout>,
    pub is_complete: bool,
}

#[cfg(feature = "cuda")]
impl GpuCombineMachine {
    /// Combine nodes prove under the same params as convert (uniform child-verify cost across the
    /// tree): pass `recursion_params_with_100_bits_security()`.
    pub fn new(params: SystemParams, vk_verification: bool) -> Self {
        let cache_cap = std::env::var("MLE_COMBINE_PK_CACHE")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(8)
            .max(1);
        Self {
            engine: StarkEngine::new(params),
            vk_verification,
            vk_map: None,
            chips: RecursionChipType::<Kb>::mle_recursion_chips(),
            cache: std::sync::Mutex::new((Vec::new(), 0, 0)),
            cache_cap,
            shapes: std::sync::Mutex::new(Vec::new()),
            evictions: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// Supply the whitelist (whitelist mode; call before proving).
    pub fn set_vk_map(&mut self, map: Arc<MleVkMap>) {
        assert!(self.vk_verification, "vk_map without vk_verification");
        self.vk_map = Some(map);
    }

    /// The node verify program for `layouts` in this machine's mode. In whitelist mode it takes
    /// the combine tier shape and passes the tier check (`pad_recursion_program`), exactly as
    /// `CombineMachine::register_shape` does (the root is the last combine round, not a shape of
    /// its own).
    fn build_node_program(
        &self,
        refs: &[&RecursionVkLayout],
        is_complete: bool,
    ) -> Arc<RecursionProgram<Kb>> {
        let mut program = ConvertVerifierCircuit::build_verify_n_program_multi::<Kb>(
            refs,
            /* is_convert_layer = */ false,
            is_complete,
            self.vk_verification,
        );
        if self.vk_verification {
            let child_ws: Vec<usize> = refs
                .iter()
                .map(|l| l.stacking_widths.iter().sum())
                .collect();
            crate::mle::machine::recursion::pad_recursion_program(
                &format!(
                    "gpu-combine n={} complete={is_complete} child_Ws={child_ws:?}",
                    refs.len()
                ),
                &mut program,
                crate::mle::machine::shape::RecursionTier::Combine,
            );
        }
        Arc::new(program)
    }

    /// CPU stage: extract each child's layout, find-or-keygen the node shape, dump the children's
    /// continuity-relevant public values, and run the recursion emulation producing the record.
    /// Runs off the GPU.
    ///
    /// `is_complete` must be true exactly for the tree's root (it arms the in-circuit completeness
    /// block, and is baked into the program at keygen — so it is part of the shape).
    pub fn prepare_node(&self, children: &[ProofWithVk], is_complete: bool) -> GpuPreparedCombine {
        assert!(!children.is_empty(), "a combine node needs >= 1 child");
        let t0 = Instant::now();
        let tuples: Vec<CombineChild> = children
            .iter()
            .map(|(proof, vk)| {
                let layout = extract_recursion_vk_layout(vk, Some(proof));
                (vk.clone(), proof.clone(), layout)
            })
            .collect();
        let layouts: Vec<RecursionVkLayout> = tuples.iter().map(|(_, _, l)| l.clone()).collect();

        // Node preflight: dump each child's continuity-relevant PV fields so a violated
        // cross-child relation is visible host-side before proving. Mirrors `prove_tree`.
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

        // A cache miss does GPU work (device preprocessed generation) from this CPU preparer;
        // hits never touch the card.
        //
        // The emulation below needs the program but not the key, and on this node's level of the
        // tree both are serial. So build the program first — `get_or_keygen` then finds it
        // published and only generates the key — and run that against the emulation.
        let program_first =
            (combine_overlap_keygen() && !crate::mle::env_flag("MLE_COMB_KEYGEN_FAT")).then(|| {
                shared_program(&layouts, is_complete).unwrap_or_else(|| {
                    let refs: Vec<&RecursionVkLayout> = layouts.iter().collect();
                    let p = self.build_node_program(&refs, is_complete);
                    publish_program(&layouts, is_complete, &p);
                    p
                })
            });

        let (keygen_ms, setup_ms, vk, pk, record) = match program_first {
            // The emulation is what moves to the second thread, not the keygen: it opens no spans,
            // while `get_or_keygen` opens the `Keygen` one, and a span opened on a thread that
            // binds no lane is dropped — which would delete this node's keygen from the record and
            // from every figure derived from it. `keygen_ms` therefore still means what it means in
            // the other arm, and `setup_ms` covers whichever of the two finishes last.
            Some(program) => {
                let t1 = Instant::now();
                let vk_map = self.vk_map.as_deref();
                let ((_, vk, pk), record) = std::thread::scope(|s| {
                    let emulate = s.spawn(|| {
                        setup_for_combine_with_program(
                            &tuples,
                            Arc::clone(&program),
                            is_complete,
                            vk_map,
                        )
                    });
                    let keys = self.get_or_keygen(&layouts, is_complete);
                    let (_, record) = emulate.join().expect("combine emulation thread panicked");
                    (keys, record)
                });
                (
                    t0.elapsed().as_millis(),
                    t1.elapsed().as_millis(),
                    vk,
                    pk,
                    record,
                )
            }
            None => {
                let (program, vk, pk) = self.get_or_keygen(&layouts, is_complete);
                let keygen_ms = t0.elapsed().as_millis();
                let t1 = Instant::now();
                let (_, record) = setup_for_combine_with_program(
                    &tuples,
                    program,
                    is_complete,
                    self.vk_map.as_deref(),
                );
                (keygen_ms, t1.elapsed().as_millis(), vk, pk, record)
            }
        };

        GpuPreparedCombine {
            vk,
            pk,
            record,
            child_layouts: layouts,
            is_complete,
            keygen_ms,
            setup_ms,
        }
    }

    /// GPU stage: device trace-gen + prove.
    pub fn prove_prepared_node(&self, prepared: GpuPreparedCombine) -> eyre::Result<CombineNode> {
        let built = self.build_node_ctx(prepared);
        self.prove_built_node(built)
    }

    /// The BUILD half: device trace-gen. Runs wherever the caller wants it — inline on the
    /// prover, or on a preparer thread so the prover lane never queues behind it.
    pub fn build_node_ctx(&self, prepared: GpuPreparedCombine) -> BuiltCombine {
        let GpuPreparedCombine {
            vk,
            pk,
            record,
            child_layouts,
            is_complete,
            keygen_ms,
            setup_ms,
        } = prepared;
        // The root is not a shape tier of its own — it is the last combine round with
        // `is_complete = true` — but tag the heights line so the two are distinguishable.
        let role = if is_complete {
            "gpu-root"
        } else {
            "gpu-combine"
        };

        let t2 = Instant::now();
        let ctx = {
            // `MLE_BREAKDOWN` times device trace-gen here; commit / rap_constraints / openings
            // record themselves inside `engine.prove`. The driver must `take()` right after this
            // node's prove — the accumulator is thread-local and the same worker thread also
            // proves riscv chunks, so a skipped take leaks into the next chunk's breakdown.
            let _bt = cuda_mle::breakdown::start();
            let ctx = gpu::build_ctx_gpu(
                &record,
                &self.chips,
                crate::mle::machine::riscv::bound_device(),
                role,
            );
            cuda_mle::breakdown::stop_tracegen(_bt);
            if crate::mle::env_flag("MLE_RECURSION_TRACE_COMPARE") {
                gpu::assert_ctx_matches_cpu(&ctx, &record, &self.chips);
            }
            ctx
        };
        BuiltCombine {
            vk,
            pk,
            ctx,
            child_layouts,
            is_complete,
            keygen_ms,
            setup_ms,
            tracegen_ms: t2.elapsed().as_millis(),
        }
    }

    /// The PROVE half: consumes a [`BuiltCombine`] whose ctx is already device-resident.
    pub fn prove_built_node(&self, built: BuiltCombine) -> eyre::Result<CombineNode> {
        // Labels this thread's `[rsprof]`/`[stepprof]` timer lines.
        cuda_mle::set_prove_phase("combine");
        let BuiltCombine {
            vk,
            pk,
            ctx,
            child_layouts,
            is_complete,
            keygen_ms,
            setup_ms,
            tracegen_ms,
        } = built;
        let role = if is_complete {
            "gpu-root"
        } else {
            "gpu-combine"
        };

        let t3 = Instant::now();
        let proof = self
            .engine
            .prove(&pk, ctx)
            .map_err(|e| eyre::eyre!("{e:?}"))?;
        tracing::info!(
            "gpu_combine_timing[{role}]: keygen_ms = {keygen_ms}, setup_ms = {setup_ms}, \
             tracegen_ms = {tracegen_ms}, prove_ms = {}",
            t3.elapsed().as_millis()
        );

        Ok(CombineNode {
            proof: (proof, vk),
            child_layouts,
            is_complete,
        })
    }

    /// Prove one node end to end (CPU stage then GPU stage). Callers that want the two stages on
    /// different pools use [`Self::prepare_node`] / [`Self::prove_prepared_node`] directly.
    pub fn prove_node(
        &self,
        children: &[ProofWithVk],
        is_complete: bool,
    ) -> eyre::Result<CombineNode> {
        let prepared = self.prepare_node(children, is_complete);
        self.prove_prepared_node(prepared)
    }

    /// Verify a node proof against its own vk (host verifier). A cheap early-failure net for the
    /// GPU prover — **not** the security check: it lacks the honest-vk substitution that
    /// [`CombineMachine::verify`] does for the root.
    pub fn verify_node(
        &self,
        vk: &MultiStarkVerifyingKey<Sc>,
        proof: &pico_mle_core::protocol::proof::Proof<Sc>,
    ) -> eyre::Result<()> {
        StarkEngine::verify(&self.engine, vk, proof).map_err(|e| eyre::eyre!("{e:?}"))
    }

    /// Shapes cached on this card right now, and the cap. Same purpose as the convert machine's:
    /// the VRAM census needs to separate "the LRU is still filling" from "something unbounded".
    pub fn cache_len(&self) -> (usize, usize) {
        let guard = self.cache.lock().expect("combine pk cache mutex poisoned");
        (guard.0.len(), self.cache_cap)
    }

    /// The run's shape picture: per-keygen records plus the derived totals, in keygen order.
    ///
    /// The single accessor on purpose — counts derived from the records here rather than at each
    /// call site, so `keygens` / `hits` / `nodes` cannot drift apart.
    pub fn shape_stats(&self) -> ShapeStats {
        let records = self.shapes.lock().expect("shapes mutex poisoned").clone();
        ShapeStats {
            keygens: records.len(),
            hits: records.iter().map(|r| r.hits).sum(),
            evictions: self.evictions.load(std::sync::atomic::Ordering::Relaxed),
            keygen_total_ms: records.iter().map(|r| r.keygen_ms).sum(),
            records,
        }
    }

    /// Cache lookup by `(ordered layouts, is_complete)`; keygen + insert (with LRU eviction) on
    /// miss. Returns clones of the entry's handles: `(program, vk, device pk)`.
    ///
    /// The lock is held across a miss's keygen — same tradeoff `ConvertMachine` makes, and it also
    /// prevents two workers from keygen'ing the same shape concurrently. Note the measured
    /// consequence: recursion keygen is ~1s of mostly-host work, so a contended miss serializes
    /// that long. If that shows up as workers queueing, move the keygen out of the lock (a
    /// per-shape `OnceLock`, or an in-flight table) rather than shrinking the critical section.
    #[allow(clippy::type_complexity)]
    fn get_or_keygen(
        &self,
        layouts: &[RecursionVkLayout],
        is_complete: bool,
    ) -> (
        Arc<RecursionProgram<Kb>>,
        Arc<MultiStarkVerifyingKey<Sc>>,
        GpuPk,
    ) {
        let mut guard = self.cache.lock().expect("combine pk cache mutex poisoned");
        let (entries, tick, next_shape_id) = &mut *guard;
        *tick += 1;
        let now = *tick;
        if let Some(e) = entries.iter_mut().find(|e| {
            e.is_complete == is_complete
                && e.layouts.len() == layouts.len()
                && e.layouts
                    .iter()
                    .zip(layouts.iter())
                    .all(|(a, b)| recursion_vk_layouts_equal(a, b))
        }) {
            e.last_used = now;
            let shape_id = e.shape_id;
            let handles = (e.program.clone(), e.vk.clone(), e.device_pk.clone());
            // Credit the reuse to this shape's record, so the end-of-run summary distinguishes
            // "one shape, two nodes" from "two shapes" (`child_ws` alone cannot — see its docs).
            // Lock order is cache -> shapes, the same as the miss path below; nothing takes them
            // the other way round.
            let mut shapes = self.shapes.lock().expect("shapes mutex poisoned");
            if let Some(rec) = shapes.iter_mut().find(|r| r.shape_id == shape_id) {
                rec.hits += 1;
            }
            drop(shapes);
            return handles;
        }

        // Miss: build the verify program for this node shape and keygen.
        let keygen_span = crate::mle::spans::busy(crate::mle::spans::WorkKind::Keygen, None);
        let t = Instant::now();
        let refs: Vec<&RecursionVkLayout> = layouts.iter().collect();
        // A CPU circuit build that never touches the card, and the bulk of a miss. Within a
        // process it is a pure function of `(layouts, is_complete)`: `is_convert_layer` is fixed
        // false on this path, and the whitelist mode, which decides `vk_verification` and the
        // tier shape, is the same for every combine machine the pipeline builds. So another card
        // that already built this shape has built a program identical to the one we would — see
        // `PROGRAM_INDEX`. Only the device pk below is genuinely per-card.
        let lean = !crate::mle::env_flag("MLE_COMB_KEYGEN_FAT");
        let t_program = Instant::now();
        let shared = if lean {
            shared_program(layouts, is_complete)
        } else {
            None
        };
        let reused_program = shared.is_some();
        let program = shared.unwrap_or_else(|| {
            let p = self.build_node_program(&refs, is_complete);
            if lean {
                publish_program(layouts, is_complete, &p);
            }
            p
        });
        let program_ms = t_program.elapsed().as_millis();
        let (vk, device_pk) = gpu::keygen_recursion_gpu(
            &self.engine,
            &program,
            &self.chips,
            crate::mle::machine::riscv::bound_device(),
        );
        // The CPU keygen's 100-bit gate; the GPU preparers cannot return an error, so it panics.
        admit_production_vk("combine", "gpu", &vk).unwrap_or_else(|e| panic!("{e}"));
        let device_pk: GpuPk = Arc::new(device_pk);
        // Populate the JIT kernels for this key's AIRs. The kernel sources depend only on the AIR
        // constraints (not on heights or the program), and every recursion machine registers the
        // same 21 chips, so these all hit the cubin cache convert's warmup already filled — no
        // mid-pipeline nvrtc compile.
        let t_jit = Instant::now();
        cuda_mle::warmup_jit_kernels::<cuda_mle::hash_scheme::KoalaBearPoseidon2HashScheme>(
            &device_pk,
        );
        let jit_ms = t_jit.elapsed().as_millis();
        let vk = Arc::new(vk);
        let keygen_ms = t.elapsed().as_millis();
        drop(keygen_span);

        let shape_id = *next_shape_id;
        *next_shape_id += 1;
        let child_ws: Vec<usize> = layouts
            .iter()
            .map(|l| l.stacking_widths.iter().sum())
            .collect();
        // The shape's identity — see `ShapeRecord::fingerprint`. All-zero would mean a
        // non-merged keygen, which recursion never does; it would show up as `fp=00000000`.
        let fingerprint = vk
            .inner
            .merged_preprocessed_commit
            .as_ref()
            .map(digest_to_u32s)
            .unwrap_or_default();
        // Per-node observability (level-cascade watch): tallest-chip proxy stats, same fields the
        // CPU `keygen_for` prints so the two paths' keygen lines can be diffed directly.
        let (base_alu, ext_alu, n_instrs) = if lean {
            instr_mix(&program)
        } else {
            let stats = program.stats();
            (
                stats.get("BaseAlu").copied().unwrap_or(0),
                stats.get("ExtAlu").copied().unwrap_or(0),
                stats.values().sum::<usize>(),
            )
        };
        tracing::info!(
            "gpu_combine keygen(miss): shape_id={shape_id} fp={:08x} n={} is_complete={is_complete} \
             child_Ws={child_ws:?} took {keygen_ms} ms (program_ms = {program_ms}{}, jit_ms = {jit_ms}) \
             (cache {}/{}) instrs: base_alu={base_alu} ext_alu={ext_alu} total={n_instrs}",
            fingerprint[0],
            layouts.len(),
            if reused_program { " reused" } else { "" },
            entries.len() + 1,
            self.cache_cap,
        );
        self.shapes
            .lock()
            .expect("shapes mutex poisoned")
            .push(ShapeRecord {
                shape_id,
                fingerprint,
                n_children: layouts.len(),
                is_complete,
                child_ws,
                keygen_ms,
                hits: 0,
            });

        // Bounded LRU: evict the stalest entry beyond capacity (never the one just inserted).
        if entries.len() >= self.cache_cap {
            if let Some(idx) = entries
                .iter()
                .enumerate()
                .min_by_key(|(_, e)| e.last_used)
                .map(|(i, _)| i)
            {
                let evicted = entries.swap_remove(idx);
                // Counted, not just logged: a non-zero total is what makes the keygen count an
                // upper bound rather than the exact distinct-shape count.
                self.evictions
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                tracing::info!(
                    "gpu_combine: evicted shape_id={} (last_used tick {})",
                    evicted.shape_id,
                    evicted.last_used
                );
            }
        }
        entries.push(GpuCombinePkEntry {
            layouts: layouts.to_vec(),
            is_complete,
            program: program.clone(),
            vk: vk.clone(),
            device_pk: device_pk.clone(),
            shape_id,
            last_used: now,
        });
        (program, vk, device_pk)
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
