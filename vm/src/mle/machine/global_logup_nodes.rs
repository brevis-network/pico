//! The prover of the global LogUp's nodes in the recursion tree: the image node and the group
//! nodes, which wrap the second phase of a block's RISC-V proof
//! ([`GlobalLogUpProof`](super::global_logup::GlobalLogUpProof)) into recursion proofs.
//!
//! The nodes lead the tree, in the order [`GlobalLogUpNodeMachine::prove`] returns them: the image node,
//! then the group nodes from the last group to the first. Deferred nodes, if any, follow, and
//! then the chunks' convert leaves.

use std::sync::Arc;

use p3_field::{PrimeCharacteristicRing, PrimeField32};
use pico_mle_core::{
    config::{
        recursion_params_with_128_bits_security,
        soundness::{admit_production_vk, UnderBudgetError},
    },
    global_logup::{self, GroupMachines},
    keygen::types::{MultiStarkProvingKey, MultiStarkVerifyingKey},
    protocol::proof::Proof,
    prover::DeviceDataTransporter,
    StarkEngine, SystemParams,
};

use crate::{
    compiler::recursion::program::RecursionProgram,
    emulator::recursion::public_values::{RecursionPublicValues, RECURSION_PUBLIC_VALUES_COL_MAP},
    instances::chiptype::recursion_chiptype::RecursionChipType,
    machine::chip::MetaChip,
    mle::{
        compiler::recursion::{ConvertVerifierCircuit, RecursionVkLayout},
        machine::{
            convert::ProofWithVk,
            exe::RiscvVmVk,
            global_logup::{chain_values, GlobalLogUpProof},
            recursion::{
                build_proving_ctx, extract_recursion_vk_layout,
                extract_recursion_vk_layout_from_heights, global_sum_and_row_count,
                pad_recursion_program, recursion_air_refs_with_preprocessed,
                recursion_public_values, recursion_vk_layouts_equal,
                setup_for_group_node_with_program, setup_for_image_node_with_program, Engine,
                GroupNodeWitness, ImageNodeWitness, Kb, Sc,
            },
            riscv::RiscvProof,
        },
    },
    primitives::consts::DIGEST_SIZE,
};

type Ef = <Sc as pico_mle_core::StarkProtocolConfig>::EF;

/// The real-row count a node of the tree publishes, in the units of
/// `global_logup::chunk_count`: at the root, the block's. `None` for a proof without recursion
/// public values.
pub fn global_row_count_of(node: &ProofWithVk) -> Option<u64> {
    let pvs = recursion_public_values(&node.0.public_values).ok()?;
    Some(u64::from(
        pvs[RECURSION_PUBLIC_VALUES_COL_MAP.global_row_count].as_canonical_u32(),
    ))
}

/// The global LogUp's sum a node of the tree publishes, as the fraction it is carried as: for
/// the image node or a group node, the sum its group proof states. `None` for a proof without
/// recursion public values.
pub fn global_sum_of(node: &ProofWithVk) -> Option<(Ef, Ef)> {
    let pvs = recursion_public_values(&node.0.public_values).ok()?;
    Some(global_sum_and_row_count(pvs).0)
}

/// Whether the sums the nodes that lead a block's tree publish add up to zero over a non-zero
/// denominator: `global_logup::stated_sums_balance` over the nodes in place of the group
/// proofs, for a prover that holds the nodes of group proofs made on another machine. The
/// prover's early look, as there: nothing is verified.
pub fn published_sums_balance<'a>(nodes: impl IntoIterator<Item = &'a ProofWithVk>) -> bool {
    let sum = nodes
        .into_iter()
        .try_fold((Ef::ZERO, Ef::ONE), |sum, node| {
            Some(global_logup::add_fractions(sum, global_sum_of(node)?))
        });
    sum.is_some_and(|(numerator, denominator)| numerator == Ef::ZERO && denominator != Ef::ZERO)
}

/// Prove the global LogUp's nodes of one block with a machine made for the call, outside the
/// whitelist: what a caller that builds one tree needs. The nodes come back in the order they
/// lead the tree's children; any deferred nodes and the chunks' convert leaves follow them.
///
/// `deferred_digest` is the deferred chain's value the nodes pass through: the chain's start,
/// zero, when the deferred nodes come after them, as they do in the canonical order. A tree
/// with a deferred node ahead of one of these nodes closes too, and that node then passes the
/// value the chain has reached there.
pub fn prove_global_logup_nodes(
    riscv: &RiscvProof,
    vm_vk: &RiscvVmVk,
    deferred_digest: [Kb; DIGEST_SIZE],
) -> eyre::Result<Vec<ProofWithVk>> {
    let mut machine = GlobalLogUpNodeMachine::new(
        recursion_params_with_128_bits_security(),
        &riscv.vk.inner.params,
        false,
    );
    let nodes = machine.prove(vm_vk, &riscv.chunk_proofs, &riscv.global, deferred_digest)?;
    for node in &nodes {
        machine.verify(node)?;
    }
    Ok(nodes)
}

/// One lazily-keygen'd node shape: `(group proof layout, program, pk, vk)`.
type NodePkEntry = (
    RecursionVkLayout,
    Arc<RecursionProgram<Kb>>,
    NodeKey,
    Arc<MultiStarkVerifyingKey<Sc>>,
);

/// A node's proving key, where the machine proves: on the host, or on the GPU it was told to
/// use ([`GlobalLogUpNodeMachine::use_device`]).
#[derive(Clone)]
enum NodeKey {
    Host(Arc<MultiStarkProvingKey<Sc>>),
    #[cfg(feature = "cuda")]
    Device(Arc<DeviceMultiStarkProvingKey<gpu::GpuPbKb>>),
}

#[cfg(feature = "cuda")]
use crate::mle::machine::recursion::gpu;
#[cfg(feature = "cuda")]
use pico_mle_core::prover::DeviceMultiStarkProvingKey;

pub struct GlobalLogUpNodeMachine {
    engine: Engine,
    chips: Vec<MetaChip<Kb, RecursionChipType<Kb>>>,
    /// The RISC-V machine's parameters and the group machines that go with them: the keys the
    /// group proofs verify under, which the node programs bake, and the parameter digest the
    /// image node derives the challenges over.
    riscv: SystemParams,
    group: GroupMachines,
    /// Lazily grown; each list deduplicated by the group proof's layout. Which node a proof
    /// goes to is the caller's to say, not the layout's: an image table of the top tier has the
    /// layout of one chunk table, and the image node and the group node of one table are
    /// different programs.
    ///
    /// Each entry with the [`super::PK_CACHE_RUN`] that added it, for a caller that drops the
    /// keys of a run it drained ([`Self::drop_keys_added_in`]).
    group_pks: Vec<(u64, NodePkEntry)>,
    image_pks: Vec<(u64, NodePkEntry)>,
    vk_verification: bool,
    vk_root: Option<[Kb; DIGEST_SIZE]>,
    /// The GPU engine the nodes are keygen'd and proved with, once [`Self::use_device`] was
    /// called. Verifying stays on the host.
    #[cfg(feature = "cuda")]
    device: Option<gpu::GpuEngineKb>,
}

impl GlobalLogUpNodeMachine {
    /// `params` are the recursion machines' (the nodes prove under the same ones as convert and
    /// combine), `riscv` the RISC-V machine's.
    pub fn new(params: SystemParams, riscv: &SystemParams, vk_verification: bool) -> Self {
        Self {
            engine: StarkEngine::new(params),
            chips: RecursionChipType::<Kb>::mle_recursion_chips(),
            riscv: riscv.clone(),
            group: GroupMachines::new(riscv),
            group_pks: Vec::new(),
            image_pks: Vec::new(),
            vk_verification,
            vk_root: None,
            #[cfg(feature = "cuda")]
            device: None,
        }
    }

    /// Keygen and prove the nodes on a GPU from here on: the card the calling thread is bound
    /// to when it keygens or proves. Before the first keygen, so no key of this machine is a
    /// host one.
    #[cfg(feature = "cuda")]
    pub fn use_device(&mut self) {
        assert!(
            self.group_pks.is_empty() && self.image_pks.is_empty(),
            "use_device after a keygen"
        );
        self.device = Some(StarkEngine::new(self.engine.params().clone()));
    }

    /// Supply the whitelist root every node publishes (vk_verification mode; call before
    /// proving).
    pub fn set_vk_root(&mut self, root: [Kb; DIGEST_SIZE]) {
        assert!(self.vk_verification, "vk_root without vk_verification");
        self.vk_root = Some(root);
    }

    /// Keygen every node of the operating point and return the keys: the group nodes for 1 to
    /// `MAX_GROUP_LEN` tables, in that order, then the image nodes, one per image tier from the
    /// lowest. Under the whitelist these are the leaves the nodes take, and they have to be in
    /// the map before any proof witnesses its root.
    ///
    /// The group machines' keys, which the node programs bake, pass the production gate here,
    /// with the round the group proofs share: this is the path the whitelist's builder takes,
    /// and it does not go through the riscv machine's keygen, which gates them for a prover.
    pub fn preregister(
        &mut self,
    ) -> Result<Vec<Arc<MultiStarkVerifyingKey<Sc>>>, UnderBudgetError> {
        self.group.admit_production("host")?;
        let log_height = global_logup::global_log_height(&self.riscv);
        let mut keys = Vec::new();
        for tables in 1..=global_logup::MAX_GROUP_LEN {
            let layout = self.layout_at(tables, log_height);
            keys.push(self.keygen_for(&layout, false)?.3);
        }
        for tier in global_logup::image_log_heights(&self.riscv) {
            let layout = self.layout_at(1, tier);
            keys.push(self.keygen_for(&layout, true)?.3);
        }
        Ok(keys)
    }

    /// The layout of a group proof over `tables` tables of `2^log_height` rows: what
    /// [`Self::group_layout`] gives for such a proof, without one.
    fn layout_at(&self, tables: usize, log_height: usize) -> RecursionVkLayout {
        let vk = self
            .group
            .vk(tables)
            .expect("a group machine for every size up to MAX_GROUP_LEN");
        extract_recursion_vk_layout_from_heights(vk, Some(&vec![Some(log_height); tables]))
    }

    /// The layout of a group proof, held to this machine's own key for its size: the node
    /// program bakes the key's pre-hash, and the key is what says the tables' rows are summed.
    fn group_layout(&self, proof: &Proof<Sc>) -> eyre::Result<RecursionVkLayout> {
        let vk = self.group_vk(proof)?;
        Ok(extract_recursion_vk_layout(vk, Some(proof)))
    }

    fn group_vk(&self, proof: &Proof<Sc>) -> eyre::Result<&MultiStarkVerifyingKey<Sc>> {
        let tables = proof.trace_vdata.len();
        self.group
            .vk(tables)
            .ok_or_else(|| eyre::eyre!("a group proof over {tables} tables has no group machine"))
    }

    /// Find-or-keygen the proving key of the node for a group proof's layout.
    fn keygen_for(
        &mut self,
        layout: &RecursionVkLayout,
        image: bool,
    ) -> Result<NodePkEntry, UnderBudgetError> {
        let pks = if image {
            &self.image_pks
        } else {
            &self.group_pks
        };
        if let Some((_, entry)) = pks
            .iter()
            .find(|(_, (l, ..))| recursion_vk_layouts_equal(l, layout))
        {
            return Ok(entry.clone());
        }
        let label = if image { "image_node" } else { "group_node" };
        let mut program = if image {
            ConvertVerifierCircuit::build_image_node_program::<Kb>(
                layout,
                self.group.params_digest().map(|x| x.as_canonical_u32()),
                self.vk_verification,
            )
        } else {
            ConvertVerifierCircuit::build_group_node_program::<Kb>(
                layout,
                self.riscv.log_stacked_height(),
                self.vk_verification,
            )
        };
        // Whitelist mode: the image node pads to the first convert row, so that to its parent
        // it is the child kind a small convert leaf is; a group node pads to the group nodes'
        // own row, one child kind whatever the group's size.
        if self.vk_verification {
            let tier = if image {
                crate::mle::machine::shape::RecursionTier::Convert(0)
            } else {
                crate::mle::machine::shape::RecursionTier::GroupNode
            };
            pad_recursion_program(label, &mut program, tier);
        }
        let program = Arc::new(program);
        #[cfg(feature = "cuda")]
        let on_device = self.device.as_ref().map(|engine| {
            let (vk, d_pk) = gpu::keygen_recursion_gpu(
                engine,
                &program,
                &self.chips,
                crate::mle::machine::riscv::bound_device(),
            );
            // The recursion AIRs' kernels: compiled once per process, as for a convert key.
            let d_pk = Arc::new(d_pk);
            cuda_mle::warmup_jit_kernels::<cuda_mle::hash_scheme::KoalaBearPoseidon2HashScheme>(
                &d_pk,
            );
            (NodeKey::Device(d_pk), vk, "gpu")
        });
        #[cfg(feature = "cuda")]
        let keyed = on_device.unwrap_or_else(|| self.keygen_on_host(&program));
        #[cfg(not(feature = "cuda"))]
        let keyed = self.keygen_on_host(&program);
        let (key, vk, backend) = keyed;
        admit_production_vk(label, backend, &vk)?;
        let entry: NodePkEntry = (layout.clone(), program, key, Arc::new(vk));
        let run = super::PK_CACHE_RUN.load(std::sync::atomic::Ordering::Relaxed);
        if image {
            self.image_pks.push((run, entry.clone()));
        } else {
            self.group_pks.push((run, entry.clone()));
        }
        Ok(entry)
    }

    /// Drops the keys this machine added during `run` (a [`super::PK_CACHE_RUN`]); returns how
    /// many. A run that was drained after running out of device memory gives back what it
    /// keygen'd, as the convert and combine caches do.
    pub fn drop_keys_added_in(&mut self, run: u64) -> usize {
        let before = self.group_pks.len() + self.image_pks.len();
        self.group_pks.retain(|(added, _)| *added != run);
        self.image_pks.retain(|(added, _)| *added != run);
        before - self.group_pks.len() - self.image_pks.len()
    }

    /// A node program's key for the host prover, with the backend's name for the soundness log.
    fn keygen_on_host(
        &self,
        program: &Arc<RecursionProgram<Kb>>,
    ) -> (NodeKey, MultiStarkVerifyingKey<Sc>, &'static str) {
        let airs = recursion_air_refs_with_preprocessed(program);
        let (pk, vk) = self.engine.keygen_merged_preprocessed(&airs);
        (NodeKey::Host(Arc::new(pk)), vk, "cpu")
    }

    /// Prove the nodes that lead a block's tree: the image node, then one node per group proof,
    /// from the last group to the first.
    ///
    /// `chunk_proofs` and `global` are the block's RISC-V proof, already verified; `vm_vk` the
    /// program's identity, whose digest the challenges were derived over. `deferred_digest` is
    /// the deferred chain's value the nodes pass through: zero, the chain's start, in the
    /// canonical order, where any deferred node comes after them.
    pub fn prove(
        &mut self,
        vm_vk: &RiscvVmVk,
        chunk_proofs: &[Proof<Sc>],
        global: &GlobalLogUpProof,
        deferred_digest: [Kb; DIGEST_SIZE],
    ) -> eyre::Result<Vec<ProofWithVk>> {
        let chain = chain_values(&self.riscv, chunk_proofs)?;
        self.prove_with_chain(vm_vk, &chain, global, deferred_digest)
    }

    /// [`Self::prove`] for a caller that holds the chain over the chunks' table commitments
    /// rather than the chunk proofs: `chain[i]` is the value before chunk `i + 1`, and the last
    /// one the root (`chain_values`).
    pub fn prove_with_chain(
        &mut self,
        vm_vk: &RiscvVmVk,
        chain: &[[Kb; DIGEST_SIZE]],
        global: &GlobalLogUpProof,
        deferred_digest: [Kb; DIGEST_SIZE],
    ) -> eyre::Result<Vec<ProofWithVk>> {
        let (image, groups) = self.witnesses(vm_vk, chain, global, deferred_digest)?;
        let mut nodes = Vec::with_capacity(1 + groups.len());
        nodes.push(self.prove_image_node(&global.image_proof, &image)?);
        for (group, witness) in &groups {
            nodes.push(self.prove_group_node(&global.group_proofs[*group], witness)?);
        }
        Ok(nodes)
    }

    /// What the nodes over `global` are told, in the order they lead the tree: the image node's
    /// witness, then each group node's with the index of its group proof, from the last group
    /// to the first. [`Self::prove_with_chain`] proves them one after another on this machine;
    /// a caller with several machines hands them out ([`Self::prove_image_node`],
    /// [`Self::prove_group_node`]).
    pub fn witnesses(
        &self,
        vm_vk: &RiscvVmVk,
        chain: &[[Kb; DIGEST_SIZE]],
        global: &GlobalLogUpProof,
        deferred_digest: [Kb; DIGEST_SIZE],
    ) -> eyre::Result<(ImageNodeWitness, Vec<(usize, GroupNodeWitness)>)> {
        let image = self.image_witness(vm_vk, chain, global.pow_witness, deferred_digest)?;

        // Each group covers the chunks after the previous group's, as many as it has tables.
        let mut first_chunks = Vec::with_capacity(global.group_proofs.len());
        let mut covered = 0usize;
        for group_proof in &global.group_proofs {
            first_chunks.push(covered + 1);
            covered += group_proof.trace_vdata.len();
        }
        eyre::ensure!(
            covered + 1 == chain.len(),
            "the group proofs cover {covered} chunks of {}",
            chain.len() - 1
        );
        let groups = first_chunks
            .into_iter()
            .enumerate()
            .rev()
            .map(|(group, first_chunk)| {
                let witness = self.group_witness(
                    vm_vk,
                    chain,
                    global.pow_witness,
                    first_chunk,
                    deferred_digest,
                )?;
                Ok((group, witness))
            })
            .collect::<eyre::Result<Vec<_>>>()?;
        Ok((image, groups))
    }

    /// The block's challenges behind `pow_witness`, from the root of `chain`.
    fn challenges(
        &self,
        vm_vk: &RiscvVmVk,
        chain: &[[Kb; DIGEST_SIZE]],
        pow_witness: Kb,
    ) -> eyre::Result<(Ef, Ef)> {
        if self.vk_verification && self.vk_root.is_none() {
            eyre::bail!("vk_verification mode: call set_vk_root before proving");
        }
        global_logup::check_challenges(
            &self.group.params_digest(),
            &vm_vk.digest(),
            chain.last().expect("the chain has its initial value"),
            self.riscv.logup.pow_bits,
            pow_witness,
        )
        .ok_or_else(|| eyre::eyre!("the global LogUp's proof-of-work witness is invalid"))
    }

    /// What the image node is told, for a block with the chain `chain` (as in
    /// [`Self::prove_with_chain`]) and the proof-of-work witness `pow_witness` behind its
    /// challenges. With [`Self::group_witness`], [`Self::witnesses`] one node at a time: for a
    /// caller that proves only some of a block's group proofs, another machine the rest.
    pub fn image_witness(
        &self,
        vm_vk: &RiscvVmVk,
        chain: &[[Kb; DIGEST_SIZE]],
        pow_witness: Kb,
        deferred_digest: [Kb; DIGEST_SIZE],
    ) -> eyre::Result<ImageNodeWitness> {
        let chain_root = *chain.last().expect("the chain has its initial value");
        Ok(ImageNodeWitness {
            challenges: self.challenges(vm_vk, chain, pow_witness)?,
            pow_witness,
            chain_root,
            chain_value: chain_root,
            riscv_vk_digest: vm_vk.digest(),
            program_commit: vm_vk.program_commit,
            pc: vm_vk.pc_start,
            deferred_digest,
            vk_root: self.vk_root,
        })
    }

    /// What the node over the group proof whose first table is chunk `first_chunk`'s (counted
    /// from one) is told: see [`Self::image_witness`].
    pub fn group_witness(
        &self,
        vm_vk: &RiscvVmVk,
        chain: &[[Kb; DIGEST_SIZE]],
        pow_witness: Kb,
        first_chunk: usize,
        deferred_digest: [Kb; DIGEST_SIZE],
    ) -> eyre::Result<GroupNodeWitness> {
        eyre::ensure!(
            (1..chain.len()).contains(&first_chunk),
            "a group starts at chunk {first_chunk} of {}",
            chain.len() - 1
        );
        Ok(GroupNodeWitness {
            challenges: self.challenges(vm_vk, chain, pow_witness)?,
            first_chunk: u32::try_from(first_chunk)?,
            chain_before: chain[first_chunk - 1],
            riscv_vk_digest: vm_vk.digest(),
            pc: vm_vk.pc_start,
            deferred_digest,
            vk_root: self.vk_root,
        })
    }

    /// Prove the image node over `image_proof` with the witness as given. [`Self::prove`] is
    /// the honest caller; a negative test hands in a witness of its own.
    pub fn prove_image_node(
        &mut self,
        image_proof: &Proof<Sc>,
        witness: &ImageNodeWitness,
    ) -> eyre::Result<ProofWithVk> {
        let layout = self.group_layout(image_proof)?;
        let (_, program, pk, node_vk) = self.keygen_for(&layout, true)?;
        let (_, record) = setup_for_image_node_with_program(
            self.group_vk(image_proof)?,
            image_proof,
            &layout,
            program,
            witness,
        );
        Ok((self.prove_record(&record, &pk, "image_node")?, node_vk))
    }

    /// Prove a group node over `group_proof` with the witness as given. [`Self::prove`] is the
    /// honest caller; a negative test hands in a witness of its own.
    pub fn prove_group_node(
        &mut self,
        group_proof: &Proof<Sc>,
        witness: &GroupNodeWitness,
    ) -> eyre::Result<ProofWithVk> {
        self.prove_group_node_publishing_for_testing(group_proof, witness, |_| {})
    }

    /// Negative tests only: [`Self::prove_group_node`], with `publish` applied to the public
    /// values the proof carries once the node's circuit has run. A proof's own constraints hold
    /// its public values to nothing but their digest, which the circuit computed over the values
    /// it has: the node still verifies. Its parent recomputes the digest over the published
    /// values, and has to refuse it.
    pub fn prove_group_node_publishing_for_testing(
        &mut self,
        group_proof: &Proof<Sc>,
        witness: &GroupNodeWitness,
        publish: impl FnOnce(&mut RecursionPublicValues<Kb>),
    ) -> eyre::Result<ProofWithVk> {
        let layout = self.group_layout(group_proof)?;
        let (_, program, pk, node_vk) = self.keygen_for(&layout, false)?;
        let (_, mut record) = setup_for_group_node_with_program(
            self.group_vk(group_proof)?,
            group_proof,
            &layout,
            program,
            witness,
        );
        publish(&mut record.public_values);
        Ok((self.prove_record(&record, &pk, "group_node")?, node_vk))
    }

    fn prove_record(
        &self,
        record: &crate::emulator::recursion::emulator::RecursionRecord<Kb>,
        key: &NodeKey,
        label: &'static str,
    ) -> eyre::Result<Proof<Sc>> {
        match key {
            NodeKey::Host(pk) => {
                let ctx = build_proving_ctx(record, &self.chips, label);
                let d_pk = self.engine.device().transport_pk_to_device(pk);
                self.engine.prove(&d_pk, ctx)
            }
            #[cfg(feature = "cuda")]
            NodeKey::Device(d_pk) => {
                let engine = self.device.as_ref().expect("a device key has its engine");
                let ctx = gpu::build_ctx_gpu(
                    record,
                    &self.chips,
                    crate::mle::machine::riscv::bound_device(),
                    label,
                );
                cuda_mle::set_prove_phase(label);
                return engine
                    .prove(d_pk, ctx)
                    .map_err(|e| eyre::eyre!("{label} node prove failed: {e:?}"));
            }
        }
        .map_err(|e| eyre::eyre!("{label} node prove failed: {e:?}"))
    }

    /// STARK-verify a node against this machine's own key for its shape. As for a deferred
    /// node, its public values have no standalone meaning: every relation they must satisfy is
    /// checked by the parent that consumes it.
    pub fn verify(&self, node: &ProofWithVk) -> eyre::Result<()> {
        let (proof, vk) = node;
        let honest = self
            .image_pks
            .iter()
            .chain(&self.group_pks)
            .map(|(_, entry)| entry)
            .find(|(_, _, _, v)| {
                v.pre_hash == vk.pre_hash
                    && v.inner.merged_preprocessed_commit == vk.inner.merged_preprocessed_commit
            })
            .ok_or_else(|| eyre::eyre!("the node's key is none this machine made"))?;
        self.engine
            .verify(&honest.3, proof)
            .map_err(|e| eyre::eyre!("node verify failed: {e:?}"))
    }
}

#[cfg(test)]
mod tests {
    use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};
    use pico_mle_core::config::{koala_bear_poseidon2::EF, riscv_params_with_128_bits_security};

    use super::*;
    use crate::mle::machine::recursion::{
        setup_for_global_logup_closure_with_program, setup_for_program_without_hints,
    };

    const LOG_STACKED_HEIGHT: usize = 20;

    /// The layout of a group proof over `tables` tables of `2^log_height` rows, under the group
    /// machines of a riscv machine at [`LOG_STACKED_HEIGHT`].
    fn group_layout(tables: usize, log_height: usize) -> RecursionVkLayout {
        let riscv = riscv_params_with_128_bits_security(LOG_STACKED_HEIGHT);
        let group = GroupMachines::new(&riscv);
        extract_recursion_vk_layout_from_heights(
            group.vk(tables).unwrap(),
            Some(&vec![Some(log_height); tables]),
        )
    }

    /// The node programs build for the layouts a group proof and an image proof have.
    #[test]
    fn the_node_programs_build() {
        let log_height = global_logup::global_log_height_at(LOG_STACKED_HEIGHT);
        ConvertVerifierCircuit::build_group_node_program::<Kb>(
            &group_layout(2, log_height),
            LOG_STACKED_HEIGHT,
            false,
        );
        ConvertVerifierCircuit::build_image_node_program::<Kb>(
            &group_layout(1, global_logup::MIN_IMAGE_LOG_HEIGHT),
            [0; DIGEST_SIZE],
            false,
        );
    }

    /// A group node reads every table at the operating point's one height: for a group proof at
    /// another height there is no program.
    #[test]
    #[should_panic(expected = "table per AIR at 2^19 rows")]
    fn a_group_proof_at_another_height_has_no_group_node() {
        ConvertVerifierCircuit::build_group_node_program::<Kb>(
            &group_layout(2, 18),
            LOG_STACKED_HEIGHT,
            false,
        );
    }

    /// A group proof under other parameters than the riscv machine's own (here one more bit of
    /// the LogUp proof of work) has another key at every group size. A group node bakes its
    /// child's key, and the whitelist's node leaves are the nodes over the production point's
    /// group machines: such a proof has no node on the whitelist to go through.
    #[test]
    fn a_group_proof_under_other_params_has_another_key() {
        let riscv = riscv_params_with_128_bits_security(LOG_STACKED_HEIGHT);
        let mut other = riscv.clone();
        other.logup.pow_bits += 1;
        let (ours, theirs) = (GroupMachines::new(&riscv), GroupMachines::new(&other));
        for tables in 1..=global_logup::MAX_GROUP_LEN {
            assert_ne!(
                ours.vk(tables).unwrap().pre_hash,
                theirs.vk(tables).unwrap().pre_hash,
                "group size {tables}"
            );
        }
    }

    /// An image node exists per image tier, and for no other height.
    #[test]
    #[should_panic(expected = "no tier of the image table")]
    fn an_image_table_off_the_tiers_has_no_image_node() {
        ConvertVerifierCircuit::build_image_node_program::<Kb>(
            &group_layout(1, global_logup::MIN_IMAGE_LOG_HEIGHT - 1),
            [0; DIGEST_SIZE],
            false,
        );
    }

    /// Whether a root holding these global LogUp fields passes the root's assertions about
    /// them: a program of nothing else, proved and verified, with the honest prover's hints.
    fn closure_accepted(
        chain_start: [Kb; DIGEST_SIZE],
        chain_end: [Kb; DIGEST_SIZE],
        (p, q): (EF, EF),
        count: u64,
        max_count: u64,
    ) -> bool {
        let limbs = |digest: [Kb; DIGEST_SIZE]| digest.map(|x| x.as_canonical_u32());
        let coeffs = |x: &EF| -> Vec<u32> {
            <EF as BasedVectorSpace<Kb>>::as_basis_coefficients_slice(x)
                .iter()
                .map(|c| c.as_canonical_u32())
                .collect()
        };
        let frac: [u32; 10] = [coeffs(&p), coeffs(&q)].concat().try_into().unwrap();
        let count = u32::try_from(count).unwrap();
        let program = Arc::new(
            ConvertVerifierCircuit::build_global_logup_closure_program_for_testing::<Kb>(
                limbs(chain_start),
                limbs(chain_end),
                frac,
                count,
                max_count,
            ),
        );
        let record = setup_for_global_logup_closure_with_program(
            Arc::clone(&program),
            q,
            Kb::from_u32(count),
            max_count,
        );
        proved_and_verified(&program, record)
    }

    /// Whether `program`, executed into `record`, proves and verifies. `None` is an execution
    /// the runtime itself stopped.
    fn proved_and_verified(
        program: &Arc<RecursionProgram<Kb>>,
        record: Option<crate::emulator::recursion::emulator::RecursionRecord<Kb>>,
    ) -> bool {
        let Some(record) = record else {
            return false;
        };
        let engine: Engine = StarkEngine::new(recursion_params_with_128_bits_security());
        let airs = recursion_air_refs_with_preprocessed(program);
        let (pk, vk) = engine.keygen_merged_preprocessed(&airs);
        let chips = RecursionChipType::<Kb>::mle_recursion_chips();
        let ctx = build_proving_ctx(&record, &chips, "global_logup_test_program");
        let d_pk = engine.device().transport_pk_to_device(&pk);
        match engine.prove(&d_pk, ctx) {
            Ok(proof) => engine.verify(&vk, &proof).is_ok(),
            Err(_) => false,
        }
    }

    /// Whether the circuits' wrap of `x` with `(alpha, beta)` is `expected`.
    fn wrap_accepted(
        alpha: EF,
        beta: EF,
        x: [Kb; DIGEST_SIZE],
        expected: [Kb; DIGEST_SIZE],
    ) -> bool {
        let limbs = |digest: [Kb; DIGEST_SIZE]| digest.map(|x| x.as_canonical_u32());
        let coeffs = |x: &EF| -> [u32; 5] {
            let coeffs = <EF as BasedVectorSpace<Kb>>::as_basis_coefficients_slice(x);
            std::array::from_fn(|i| coeffs[i].as_canonical_u32())
        };
        let program = Arc::new(
            ConvertVerifierCircuit::build_chain_wrap_program_for_testing::<Kb>(
                coeffs(&alpha),
                coeffs(&beta),
                limbs(x),
                limbs(expected),
            ),
        );
        let record = setup_for_program_without_hints(Arc::clone(&program));
        proved_and_verified(&program, record)
    }

    /// A small recursion program, for the tests that need some recursion key.
    fn some_recursion_program() -> RecursionProgram<Kb> {
        ConvertVerifierCircuit::build_chain_wrap_program_for_testing::<Kb>(
            [1; 5],
            [2; 5],
            [3; DIGEST_SIZE],
            [4; DIGEST_SIZE],
        )
    }

    /// The layout of some recursion key: only programs are built over it.
    fn some_recursion_layout() -> RecursionVkLayout {
        let program = Arc::new(some_recursion_program());
        let engine: Engine = StarkEngine::new(recursion_params_with_128_bits_security());
        let (_, vk) =
            engine.keygen_merged_preprocessed(&recursion_air_refs_with_preprocessed(&program));
        extract_recursion_vk_layout_from_heights(&vk, None)
    }

    /// In whitelist mode a parent bakes each recursion child's vk pre-hash: a child layout with
    /// another pre-hash gives another node program, another deferred program, and another
    /// program over one complete child (the compress and embed programs). Outside that mode the
    /// pre-hash is a witness, and the programs do not depend on it.
    #[test]
    fn a_whitelist_parent_bakes_its_childs_pre_hash() {
        let child = some_recursion_layout();
        let mut other = child.clone();
        other.vk_pre_hash[0] ^= 1;

        let instructions =
            |program: RecursionProgram<Kb>| bincode::serialize(&program.instructions).unwrap();
        let node = |child: &RecursionVkLayout, whitelist: bool| {
            instructions(ConvertVerifierCircuit::build_verify_n_program_multi::<Kb>(
                &[child, child],
                false,
                false,
                whitelist,
            ))
        };
        let deferred = |child: &RecursionVkLayout, whitelist: bool| {
            instructions(ConvertVerifierCircuit::build_deferred_program::<Kb>(
                child, whitelist,
            ))
        };
        let over_a_root = |child: &RecursionVkLayout, whitelist: bool| {
            instructions(ConvertVerifierCircuit::build_verify_n_program_multi::<Kb>(
                &[child],
                false,
                true,
                whitelist,
            ))
        };
        assert!(node(&child, false) == node(&other, false));
        assert!(deferred(&child, false) == deferred(&other, false));
        assert!(over_a_root(&child, false) == over_a_root(&other, false));
        assert!(node(&child, true) != node(&other, true));
        assert!(deferred(&child, true) != deferred(&other, true));
        assert!(over_a_root(&child, true) != over_a_root(&other, true));
    }

    /// The pre-hash a whitelist parent bakes is not read as well. Against the same program
    /// outside the whitelist it takes the whitelist's root (8 hints) and a Merkle path per child
    /// (an index bit and a sibling digest per level), and eight hints fewer per child: the
    /// pre-hash. A leaf hashed over a second, witnessed copy of the pre-hash would show here.
    #[test]
    fn a_whitelist_parent_reads_no_pre_hash() {
        use crate::{
            compiler::recursion::instruction::Instruction,
            mle::machine::vk_map::MLE_VK_MERKLE_DEPTH,
        };
        let child = some_recursion_layout();
        let hints = |program: RecursionProgram<Kb>| -> usize {
            program
                .instructions
                .iter()
                .map(|i| match i {
                    Instruction::Hint(h) => h.output_addrs_mults.len(),
                    _ => 0,
                })
                .sum()
        };
        let whitelist_takes = |children: usize| {
            DIGEST_SIZE + children * MLE_VK_MERKLE_DEPTH * (1 + DIGEST_SIZE)
                - children * DIGEST_SIZE
        };
        let node = |whitelist: bool| {
            hints(ConvertVerifierCircuit::build_verify_n_program_multi::<Kb>(
                &[&child, &child],
                false,
                false,
                whitelist,
            ))
        };
        let over_a_root = |whitelist: bool| {
            hints(ConvertVerifierCircuit::build_verify_n_program_multi::<Kb>(
                &[&child],
                false,
                true,
                whitelist,
            ))
        };
        let deferred = |whitelist: bool| {
            hints(ConvertVerifierCircuit::build_deferred_program::<Kb>(
                &child, whitelist,
            ))
        };
        assert_eq!(node(true), node(false) + whitelist_takes(2));
        assert_eq!(over_a_root(true), over_a_root(false) + whitelist_takes(1));
        assert_eq!(deferred(true), deferred(false) + whitelist_takes(1));
    }

    /// The pre-hash computed for a key at another row's heights is the one a key keygen'd at
    /// those heights has: two keys of one program, padded to two rows, each give the other's.
    /// (The artifact test holds the same against the shipped rows; this needs no artifact.)
    #[test]
    fn the_pre_hash_at_a_rows_heights_is_that_of_a_key_of_the_row() {
        use crate::mle::machine::{recursion::recursion_tier_log_heights, shape::RecursionTier};
        let engine: Engine = StarkEngine::new(recursion_params_with_128_bits_security());
        let key_at = |tier: RecursionTier| {
            let mut program = some_recursion_program();
            pad_recursion_program("test", &mut program, tier);
            let (_, vk) = engine.keygen_merged_preprocessed(&recursion_air_refs_with_preprocessed(
                &Arc::new(program),
            ));
            vk
        };
        let rows = [RecursionTier::Combine, RecursionTier::GroupNode];
        let keys = rows.map(key_at);
        assert_ne!(keys[0].pre_hash, keys[1].pre_hash);
        for from in 0..2 {
            for to in 0..2 {
                let at_row = extract_recursion_vk_layout_from_heights(
                    &keys[from],
                    Some(&recursion_tier_log_heights(rows[to])),
                );
                assert_eq!(
                    at_row.vk_pre_hash,
                    keys[to].pre_hash.map(|limb| limb.as_canonical_u32()),
                    "from a key of {:?} to the heights of {:?}",
                    rows[from],
                    rows[to]
                );
            }
        }
    }

    /// The wrap the node programs make of a chain value is the one `global_logup::wrap` defines: the
    /// programs compute it themselves and no host value is ever compared with it, so this is
    /// what holds the two definitions together. (The other wrap, `global_logup::wrap_top`, is held by
    /// the root's closure below.)
    #[test]
    fn the_circuits_wrap_is_the_native_one() {
        let ef = |seed: u32| EF::from_basis_coefficients_fn(|i| Kb::from_u32(seed + 3 * i as u32));
        let (alpha, beta) = (ef(700_001), ef(900_007));
        let x: [Kb; DIGEST_SIZE] = std::array::from_fn(|i| Kb::from_u32(2000 + i as u32));
        assert!(wrap_accepted(
            alpha,
            beta,
            x,
            global_logup::wrap(alpha, beta, &x)
        ));
        // The challenges in the other order, and the other wrap's value.
        assert!(!wrap_accepted(
            alpha,
            beta,
            x,
            global_logup::wrap(beta, alpha, &x)
        ));
        assert!(!wrap_accepted(
            alpha,
            beta,
            x,
            global_logup::wrap_top(&x, &x)
        ));
    }

    /// The root's three assertions about the global LogUp, each on a program that makes nothing
    /// but them: the chain closes on `H(TAG_TOP ‖ end ‖ end)`; the sum is zero over a non-zero
    /// denominator; the count is within the limit, up to it and not past it.
    #[test]
    fn the_root_assertions_hold_one_by_one() {
        let end: [Kb; DIGEST_SIZE] = std::array::from_fn(|i| Kb::from_u32(1000 + i as u32));
        let closed = global_logup::wrap_top(&end, &end);
        let zero_sum = (EF::ZERO, EF::from_u32(12_345));
        let max = global_logup::MAX_COUNT;
        assert!(closure_accepted(closed, end, zero_sum, 0, max));
        assert!(closure_accepted(closed, end, zero_sum, max, max));

        // The chain: the end itself as the start, and a wrap of another value.
        assert!(!closure_accepted(end, end, zero_sum, 0, max));
        let other = global_logup::wrap_top(&closed, &end);
        assert!(!closure_accepted(other, end, zero_sum, 0, max));
        // The sum: a numerator off zero; a zero denominator, under either numerator.
        assert!(!closure_accepted(
            closed,
            end,
            (EF::ONE, zero_sum.1),
            0,
            max
        ));
        assert!(!closure_accepted(closed, end, (EF::ZERO, EF::ZERO), 0, max));
        assert!(!closure_accepted(closed, end, (EF::ONE, EF::ZERO), 0, max));
        // The count: one past the limit, and near 2^28, the most a tree's count reaches.
        assert!(!closure_accepted(closed, end, zero_sum, max + 1, max));
        assert!(!closure_accepted(closed, end, zero_sum, (1 << 28) - 1, max));
        // A lower limit: at it, and one past it.
        assert!(closure_accepted(closed, end, zero_sum, 7, 7));
        assert!(!closure_accepted(closed, end, zero_sum, 8, 7));
    }

    /// A group proof is in the external LogUp challenge mode; the programs that verify
    /// internal-mode children (convert, combine, compress, embed) do not take one.
    #[test]
    #[should_panic(expected = "LogUp challenge mode")]
    fn an_internal_mode_verifier_refuses_a_group_proof() {
        let layout = group_layout(1, global_logup::global_log_height_at(LOG_STACKED_HEIGHT));
        ConvertVerifierCircuit::build_verify_n_program_multi::<Kb>(&[&layout], false, false, false);
    }
}
