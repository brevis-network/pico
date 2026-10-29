//! Embed prover: re-proves the complete combine root 1:1 under the **outer** (BN254-Poseidon2)
//! config, so the on-chain gnark circuit can verify the resulting proof with native BN254 `Permute`
//! opcodes instead of emulated Poseidon2-KoalaBear.
//!
//! Structurally this is a combine node with `n = 1` and `is_complete = true` — the same
//! `build_verify_n_program_multi` program family, the same chip set, the same merged-preprocessed
//! keygen. The *only* thing that differs is the engine: PCS commitments and the Fiat–Shamir
//! transcript run over BN254 Poseidon2 ([`KoalaBearBn254Poseidon2CpuEngine`]) while the recursion VM
//! program and all field arithmetic stay KoalaBear.
//!
//! That one substitution is the whole point. A native width-3 BN254 permutation is ~240 R1CS
//! constraints in gnark; an emulated width-16 Poseidon2-KoalaBear is ~53,000. Verifying a
//! KoalaBear-hashed proof on-chain would need a QAP past Groth16's BN254 limit, so the proof has to
//! be re-committed under a BN254-native hash first.
//!
//! # Why it is safe to re-prove rather than re-verify
//!
//! The embed proof asserts "there exists a valid combine root proof with these public values". Its
//! public values are the child's, propagated unchanged, so the host acceptance checks are literally
//! the combine root's checks — [`check_complete_root_public_values`], shared, not copied.
//!
//! # Merged-preprocessed keygen is mandatory, not an optimization
//!
//! Per-air keygen is *legal* here (the embed proof is verified only by the host and by gnark, never
//! by a brevis recursion circuit), but it would commit each of the 21 AIRs separately: ~646 KiB of
//! Merkle paths in the proof and ~20,680 in-circuit node compressions. [`keygen_merged_preprocessed`] folds
//! them into two commitments, which is what makes the wrap circuit affordable.
//!
//! [`keygen_merged_preprocessed`]: pico_mle_core::StarkEngine::keygen_merged_preprocessed

use std::sync::Arc;

use crate::{
    compiler::recursion::program::RecursionProgram,
    instances::chiptype::recursion_chiptype::RecursionChipType,
    machine::chip::MetaChip,
    mle::{
        compiler::recursion::{ConvertVerifierCircuit, RecursionVkLayout},
        config::koala_bear_bn254_poseidon2::KoalaBearBn254Poseidon2CpuEngine,
        machine::{
            convert::ProofWithVk,
            exe::RiscvVmVk,
            recursion::{
                build_proving_ctx, check_complete_root_public_values, extract_recursion_vk_layout,
                recursion_air_refs_with_preprocessed, recursion_public_values,
                recursion_vk_layouts_equal, setup_for_combine_with_program, Kb,
            },
            shape::RecursionTier,
            vk_map::MleVkMap,
        },
    },
};
use pico_mle_core::{
    config::soundness::{admit_production_vk, UnderBudgetError},
    keygen::types::{MultiStarkProvingKey, MultiStarkVerifyingKey},
    proof::Proof,
    prover::DeviceDataTransporter,
    StarkEngine, SystemParams,
};

/// The outer (embed) engine and its config.
pub type EmbedEngine = KoalaBearBn254Poseidon2CpuEngine;
pub type EmbedSc = <EmbedEngine as StarkEngine>::SC;

/// An embed proof plus the verifying key it verifies under.
pub type EmbedProofWithVk = (Proof<EmbedSc>, Arc<MultiStarkVerifyingKey<EmbedSc>>);

/// One lazily-keygen'd embed shape: `(child layout, program, pk, vk)`.
type EmbedPkEntry = (
    RecursionVkLayout,
    Arc<RecursionProgram<Kb>>,
    MultiStarkProvingKey<EmbedSc>,
    Arc<MultiStarkVerifyingKey<EmbedSc>>,
);

/// Proves the embed layer over a complete combine-root proof.
pub struct EmbedMachine {
    pub engine: EmbedEngine,
    /// Lazily grown; deduplicated by child layout (embed is always a complete `n = 1` node).
    pks: Vec<EmbedPkEntry>,
    chips: Vec<MetaChip<Kb, RecursionChipType<Kb>>>,
    /// Trusted VM-layer exe identity, as at the apex: the embed proof's `riscv_vk_digest` is pinned
    /// against `riscv_vm_vk.digest()`.
    riscv_vm_vk: RiscvVmVk,
    /// Whitelist mode, baked into the program at keygen. Must match the combine root's mode: with
    /// it on, the embed circuit re-runs the child's whitelist membership check in-circuit and
    /// propagates `vk_root`, which is the only way the whitelist chain survives the KoalaBear →
    /// BN254 boundary (the embed VK itself can never be a whitelist member — the whitelist is keyed
    /// on KoalaBear digests).
    vk_verification: bool,
    /// The whitelist (vk_verification mode): witnessed at prove time, root-checked at verify time.
    vk_map: Option<Arc<MleVkMap>>,
}

impl EmbedMachine {
    /// Pass `embed_params_with_100_bits_security()` and the same trusted exe identity /
    /// whitelist mode the combine machine ran with.
    pub fn new(params: SystemParams, riscv_vm_vk: RiscvVmVk, vk_verification: bool) -> Self {
        Self {
            engine: StarkEngine::new(params),
            pks: Vec::new(),
            chips: RecursionChipType::<Kb>::mle_recursion_chips(),
            riscv_vm_vk,
            vk_verification,
            vk_map: None,
        }
    }

    /// Supply the whitelist (vk_verification mode; call before proving).
    pub fn set_vk_map(&mut self, map: Arc<MleVkMap>) {
        assert!(self.vk_verification, "vk_map without vk_verification");
        self.vk_map = Some(map);
    }

    /// Keygen the embed node over a complete combine root of `layout` and return its VK, without
    /// proving. [`Self::prove`] keygens the same key for a root whose layout this is, the layout
    /// being `extract_recursion_vk_layout(&root_vk, Some(&root_proof))`.
    pub fn preregister(
        &mut self,
        layout: &RecursionVkLayout,
    ) -> Result<Arc<MultiStarkVerifyingKey<EmbedSc>>, UnderBudgetError> {
        let idx = self.keygen_for(layout)?;
        Ok(self.pks[idx].3.clone())
    }

    /// Find-or-keygen the proving key for a child layout. Returns the `pks` index.
    fn keygen_for(&mut self, layout: &RecursionVkLayout) -> Result<usize, UnderBudgetError> {
        if let Some(idx) = self
            .pks
            .iter()
            .position(|(l, ..)| recursion_vk_layouts_equal(l, layout))
        {
            return Ok(idx);
        }
        let mut program = ConvertVerifierCircuit::build_verify_n_program_multi::<Kb>(
            &[layout],
            false, // is_convert_layer: the child is a recursion proof, not a RISCV one
            true,  // is_complete: embed only ever wraps a complete root
            self.vk_verification,
        );
        // Same explicit tier padding as a combine node. Beyond keeping heights from drifting with
        // small circuit changes, it is what makes the embed VK independent of the child's exact
        // heights — and the Groth16 setup bakes that VK in as circuit constants, so a VK that moved
        // with the child would invalidate the proving key.
        if self.vk_verification {
            crate::mle::machine::recursion::pad_recursion_program(
                "embed",
                &mut program,
                RecursionTier::Embed,
            );
        }
        let program = Arc::new(program);
        let stats = program.stats();
        tracing::info!(
            "embed keygen: child_W={} instrs: base_alu={} ext_alu={} total={}",
            layout.stacking_widths.iter().sum::<usize>(),
            stats.get("BaseAlu").copied().unwrap_or(0),
            stats.get("ExtAlu").copied().unwrap_or(0),
            stats.values().sum::<usize>(),
        );
        let airs = recursion_air_refs_with_preprocessed::<EmbedSc>(&program);
        let (pk, vk) = self.engine.keygen_merged_preprocessed(&airs);
        admit_production_vk("embed", "cpu", &vk)?;
        self.pks.push((layout.clone(), program, pk, Arc::new(vk)));
        Ok(self.pks.len() - 1)
    }

    /// Re-prove the complete combine root as a single embed proof (BN254-hashed).
    pub fn prove(&mut self, root: ProofWithVk) -> eyre::Result<EmbedProofWithVk> {
        eyre::ensure!(
            !self.vk_verification || self.vk_map.is_some(),
            "vk_verification machine has no vk map at prove time (call set_vk_map)"
        );
        let (proof, vk) = root;
        let layout = extract_recursion_vk_layout(&vk, Some(&proof));
        let pk_idx = self.keygen_for(&layout)?;
        let (_, program, pk, embed_vk) = &self.pks[pk_idx];

        let children = vec![(vk, proof, layout)];
        let (_, record) = setup_for_combine_with_program(
            &children,
            Arc::clone(program),
            true,
            self.vk_map.as_deref(),
        );
        let ctx = build_proving_ctx::<EmbedSc>(&record, &self.chips, "embed");
        let d_pk = self.engine.device().transport_pk_to_device(pk);
        self.engine
            .prove(&d_pk, ctx)
            .map(|p| (p, embed_vk.clone()))
            .map_err(|e| eyre::eyre!("embed prove failed: {e:?}"))
    }

    /// Host acceptance of the embed proof, on the same terms as the combine root it re-proves:
    ///   1. verify against the HONESTLY keygen'd embed VK on this machine, never a supplied one;
    ///   2. the shared complete-root public-value checks.
    ///
    /// The one combine check with no analogue here is whitelist membership of the outermost VK: the
    /// whitelist is keyed on KoalaBear digests, so a BN254-digest embed key is not a candidate. What
    /// carries the whitelist across the boundary instead is the `vk_root` public value, checked in
    /// (2) — and, in whitelist mode, the child's in-circuit membership proof.
    pub fn verify(&self, proof: &EmbedProofWithVk) -> eyre::Result<()> {
        eyre::ensure!(
            !self.vk_verification || self.vk_map.is_some(),
            "vk_verification machine has no vk map at verify time (call set_vk_map)"
        );
        let (embed_proof, vk) = proof;
        let honest_vk = self
            .pks
            .iter()
            .find(|(_, _, _, pk_vk)| {
                pk_vk.pre_hash == vk.pre_hash
                    && pk_vk.inner.merged_preprocessed_commit == vk.inner.merged_preprocessed_commit
            })
            .map(|e| &e.3)
            .ok_or_else(|| {
                eyre::eyre!(
                    "embed proof vk matches no honestly keygen'd shape on this machine \
                     (run prove first, and pass the vk prove returned)"
                )
            })?;
        self.engine
            .verify(honest_vk, embed_proof)
            .map_err(|e| eyre::eyre!("embed proof failed STARK verify: {e:?}"))?;

        let pvs = recursion_public_values(&embed_proof.public_values)?;
        check_complete_root_public_values(
            "embed",
            pvs,
            &self.riscv_vm_vk.digest(),
            self.vk_map.as_ref().map(|m| m.root()).as_ref(),
        )?;
        Ok(())
    }

    /// Distinct embed shapes keygen'd so far (observability for the dedup behavior).
    pub fn num_distinct_shapes(&self) -> usize {
        self.pks.len()
    }
}
