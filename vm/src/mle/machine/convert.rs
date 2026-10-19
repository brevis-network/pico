//! Convert prover (Phase 2, leaf recursion): wraps each RISCV proof in a recursion
//! circuit that verifies it. Proofs are grouped by [`RecursionVkLayout`] so each
//! distinct shape is keygen'd once; all proofs of a shape then prove in parallel.

use std::sync::Arc;

use p3_field::PrimeCharacteristicRing;
use p3_maybe_rayon::prelude::*;

use crate::{
    compiler::recursion::program::RecursionProgram,
    instances::chiptype::recursion_chiptype::RecursionChipType,
    machine::chip::MetaChip,
    mle::{
        compiler::recursion::{ConvertProgramInput, ConvertVerifierCircuit, RecursionVkLayout},
        machine::{
            exe::RiscvVmVk,
            recursion::{
                build_proving_ctx, extract_recursion_vk_layout,
                recursion_air_refs_with_preprocessed, recursion_vk_layouts_equal,
                setup_for_convert_with_program, Engine, Kb, Sc,
            },
        },
    },
    primitives::consts::DIGEST_SIZE,
};
use pico_mle_core::{
    config::soundness::{admit_production_vk, UnderBudgetError},
    keygen::types::{MultiStarkProvingKey, MultiStarkVerifyingKey},
    protocol::proof::Proof,
    prover::DeviceDataTransporter,
    StarkEngine, SystemParams,
};

/// One keygen result per distinct [`RecursionVkLayout`]:
/// `(layout, verify_program, proving_key, verifying_key)`.
pub type ConvertPkEntry = (
    RecursionVkLayout,
    Arc<RecursionProgram<Kb>>,
    MultiStarkProvingKey<Sc>,
    Arc<MultiStarkVerifyingKey<Sc>>,
);

/// A convert proof paired with the convert VK it verifies under.
pub type ProofWithVk = (Proof<Sc>, Arc<MultiStarkVerifyingKey<Sc>>);

/// Why a [`ConvertMachine`] could not be built, configured or queried.
#[derive(Debug, thiserror::Error)]
pub enum ConvertError {
    /// No RISCV proofs to wrap. Every later lookup would fail, so it is refused up front.
    #[error("ConvertMachine::new requires a non-empty RISCV proof bundle; got zero proofs")]
    EmptyBundle,
    /// The proof's layout was not among those registered at [`ConvertMachine::new`], so no proving
    /// key verifies it. Reachable from a proof that did not come from the bundle `new` saw.
    #[error(
        "no proving key matches this proof's recursion layout; every proof proved here must have \
         been in the bundle passed to ConvertMachine::new"
    )]
    NoPkForLayout,
    /// A whitelist root was supplied to a machine that was not built in whitelist mode, or proving
    /// was attempted in whitelist mode before one was supplied.
    #[error("whitelist misconfiguration: {0}")]
    Whitelist(&'static str),
    /// No proving keys registered — only reachable on a machine built outside [`Self::new`].
    #[error("no proving keys registered")]
    NoPks,
    /// A convert key scored below the production soundness budget.
    #[error(transparent)]
    UnderBudget(#[from] UnderBudgetError),
}

/// Proves the convert (leaf recursion) layer for a set of RISCV proofs sharing one RISCV VK.
pub struct ConvertMachine {
    pub engine: Engine,
    /// One entry per distinct [`RecursionVkLayout`].
    pub pks: Vec<ConvertPkEntry>,
    // Used only for the `ChipBehavior` methods; the FRI parts are dead. See `ConvertMachine::new`.
    pub chips: Vec<MetaChip<Kb, RecursionChipType<Kb>>>,
    pub riscv_vk: Arc<MultiStarkVerifyingKey<Sc>>,
    /// VM-layer exe identity (program_commit, pc_start, initial_gcs). Witnessed into every
    /// convert proof; the circuit folds it into the `riscv_vk_digest` public value.
    pub riscv_vm_vk: RiscvVmVk,
    /// Whitelist mode (baked into the programs at `new`): proofs witness `vk_root` into their
    /// public values. The root VALUE is supplied later via [`Self::set_vk_root`] (the map is
    /// built from these very VKs, so it cannot exist at construction).
    vk_verification: bool,
    /// The whitelist root pushed into every convert witness (vk_verification mode).
    vk_root: Option<[Kb; 8]>,
    /// The digest the tree's deferred nodes end on; zero when the tree has none.
    final_deferred_digest: [Kb; DIGEST_SIZE],
}

/// Keygen one convert proving key: build the verify program for `layout`, then key it.
fn keygen_layout(
    engine: &Engine,
    layout: RecursionVkLayout,
    vk_verification: bool,
) -> Result<ConvertPkEntry, UnderBudgetError> {
    let input = ConvertProgramInput {
        vk: layout.clone(),
        vk_verification,
    };
    let t_prog = std::time::Instant::now();
    let mut program = ConvertVerifierCircuit::build_verify_program(&input);
    // Recursion shape tier — whitelist mode only (mirrors the FRI linkage:
    // shape normalization exists to make VKs finite/enumerable; without vk
    // verification, natural shapes keep proofs small and keygen stays dynamic).
    if vk_verification {
        crate::mle::machine::recursion::pad_convert_program("convert", &mut program);
    }
    let program = Arc::new(program);
    let program_ms = t_prog.elapsed().as_millis();
    let t_refs = std::time::Instant::now();
    let airs = recursion_air_refs_with_preprocessed(&program);
    let air_refs_ms = t_refs.elapsed().as_millis();
    let t_kg = std::time::Instant::now();
    let (pk, vk) = engine.keygen_merged_preprocessed(&airs);
    admit_production_vk("convert", "cpu", &vk)?;
    tracing::info!(
        "convert_timing keygen_detail: program_ms = {program_ms}, \
         air_refs_ms = {air_refs_ms}, engine_keygen_ms = {}",
        t_kg.elapsed().as_millis()
    );
    Ok((layout, program, pk, Arc::new(vk)))
}

impl ConvertMachine {
    /// Build a convert prover for a RISCV VK and all proofs: group proofs by
    /// [`RecursionVkLayout`] and keygen one proving key per distinct layout.
    pub fn new(
        riscv_vk: Arc<MultiStarkVerifyingKey<Sc>>,
        riscv_vm_vk: RiscvVmVk,
        proofs: &[Proof<Sc>],
        params: SystemParams,
        vk_verification: bool,
    ) -> Result<Self, ConvertError> {
        // An empty bundle builds zero PKs and would surface only later, in `get_vk`/`find_pk`.
        if proofs.is_empty() {
            return Err(ConvertError::EmptyBundle);
        }

        let engine: Engine = StarkEngine::new(params);
        // As in `RiscvMachine::new`: the recursion trace generation uses these chips only for their
        // `ChipBehavior` methods, while `MetaChip::new` builds FRI parts that are discarded and
        // re-derived in `engine.keygen_merged_preprocessed`.
        //
        // TODO(fri-removal): carry bare `RecursionChipType<Kb>` enums instead of `MetaChip`. Until
        // then the FRI-only `VirtualPairLookup` / `symbolic_to_virtual_pair` can't be deleted.
        let chips = RecursionChipType::<Kb>::mle_recursion_chips();

        let t_layouts = std::time::Instant::now();
        // Extract each proof's layout once (in parallel — it builds a per-AIR EvalDag and is
        // not cheap), then reuse for dedup + the reorder-by-count scan below.
        let all_layouts: Vec<RecursionVkLayout> = proofs
            .par_iter()
            .map(|proof| extract_recursion_vk_layout(&riscv_vk, Some(proof)))
            .collect();
        let layouts_ms = t_layouts.elapsed().as_millis();

        // Distinct layouts (serial linear-scan dedup), then keygen one PK per distinct layout in
        // parallel (`engine.keygen` is `&self` and pure, so concurrent calls are safe).
        let mut distinct: Vec<RecursionVkLayout> = Vec::new();
        for layout in &all_layouts {
            if !distinct
                .iter()
                .any(|existing| recursion_vk_layouts_equal(existing, layout))
            {
                distinct.push(layout.clone());
            }
        }

        let t_keygen = std::time::Instant::now();
        let mut pks: Vec<ConvertPkEntry> = distinct
            .into_par_iter()
            .map(|layout| keygen_layout(&engine, layout, vk_verification))
            .collect::<Result<_, _>>()?;
        tracing::info!(
            "convert_timing new: layouts_ms = {layouts_ms}, keygen_ms = {} (n_distinct = {})",
            t_keygen.elapsed().as_millis(),
            pks.len()
        );

        // Reorder so the most-matched layout is pks[0] (get_vk/prove_primary target pks[0]).
        if pks.len() > 1 {
            let mut counts = vec![0usize; pks.len()];
            for layout in &all_layouts {
                if let Some(idx) = pks
                    .iter()
                    .position(|(s, _, _, _)| recursion_vk_layouts_equal(s, layout))
                {
                    counts[idx] += 1;
                }
            }
            let best = counts
                .iter()
                .enumerate()
                .max_by_key(|&(_, &c)| c)
                .map(|(i, _)| i)
                .unwrap_or(0);
            pks.swap(0, best);
        }

        Ok(Self {
            engine,
            pks,
            chips,
            riscv_vk,
            riscv_vm_vk,
            vk_verification,
            vk_root: None,
            final_deferred_digest: [Kb::ZERO; DIGEST_SIZE],
        })
    }

    /// Keygen a proving key for every layout in `proofs` that has none yet, and report how many
    /// were added.
    ///
    /// What lets one machine serve a later bundle of the same program: a layout already keyed is
    /// not keyed again. Bucketed layouts are few and repeat; natural-height layouts follow each
    /// chunk's per-AIR heights, so a new input usually brings new ones and the machine grows with
    /// every distinct input unless its owner bounds it. New entries go on the end, leaving `pks[0]`
    /// — the most-matched layout of the bundle the machine was built for, and what
    /// [`Self::get_vk`] reports — where it was, unless the owner reorders or trims `pks` (the SDK
    /// keeps them in order of last use and drops the least recently used).
    pub fn register_layouts(&mut self, proofs: &[Proof<Sc>]) -> Result<usize, ConvertError> {
        if proofs.is_empty() {
            return Err(ConvertError::EmptyBundle);
        }
        let layouts: Vec<RecursionVkLayout> = proofs
            .par_iter()
            .map(|proof| extract_recursion_vk_layout(&self.riscv_vk, Some(proof)))
            .collect();

        let mut missing: Vec<RecursionVkLayout> = Vec::new();
        for layout in layouts {
            let known = self
                .pks
                .iter()
                .any(|(existing, ..)| recursion_vk_layouts_equal(existing, &layout))
                || missing
                    .iter()
                    .any(|existing| recursion_vk_layouts_equal(existing, &layout));
            if !known {
                missing.push(layout);
            }
        }
        if missing.is_empty() {
            return Ok(0);
        }

        let added = missing.len();
        let t_keygen = std::time::Instant::now();
        let vk_verification = self.vk_verification;
        let fresh: Vec<ConvertPkEntry> = missing
            .into_par_iter()
            .map(|layout| keygen_layout(&self.engine, layout, vk_verification))
            .collect::<Result<_, _>>()?;
        self.pks.extend(fresh);
        tracing::info!(
            "convert_timing register_layouts: keygen_ms = {} (n_new = {added}, n_total = {})",
            t_keygen.elapsed().as_millis(),
            self.pks.len()
        );
        Ok(added)
    }

    /// Supply the whitelist root (vk_verification mode; call before proving).
    pub fn set_vk_root(&mut self, root: [Kb; 8]) -> Result<(), ConvertError> {
        if !self.vk_verification {
            return Err(ConvertError::Whitelist(
                "a vk_root was supplied to a machine built without vk_verification",
            ));
        }
        self.vk_root = Some(root);
        Ok(())
    }

    /// Supply the digest the tree's deferred nodes end on; call before proving when the tree has
    /// any. Every leaf passes this same value through the reconstruct chain, and the root asserts
    /// the guest's own `deferred_proofs_digest` equals it — so a value that does not match what
    /// the deferred nodes actually built yields a root that does not verify, rather than one
    /// that verifies while attesting less than it claims.
    ///
    /// It is machine state, so it persists across `prove` calls: a machine reused for the next
    /// tree must be given that tree's digest, or zero, before proving it.
    pub fn set_final_deferred_digest(&mut self, digest: [Kb; DIGEST_SIZE]) {
        self.final_deferred_digest = digest;
    }

    /// Find the PK/program matching a proof's layout via linear scan.
    fn find_pk(&self, proof: &Proof<Sc>) -> Result<&ConvertPkEntry, ConvertError> {
        let layout = extract_recursion_vk_layout(&self.riscv_vk, Some(proof));
        self.pks
            .iter()
            .find(|(existing, _, _, _)| recursion_vk_layouts_equal(existing, &layout))
            .ok_or(ConvertError::NoPkForLayout)
    }

    /// Prove all RISCV proofs, returning one convert proof each.
    pub fn prove(&self, riscv_proofs: &[Proof<Sc>]) -> eyre::Result<Vec<Proof<Sc>>> {
        self.prove_with_vks(riscv_proofs)
            .map(|pairs| pairs.into_iter().map(|(p, _)| p).collect())
    }

    /// Prove all RISCV proofs and pair each convert proof with its convert VK (dynamic-VK safe).
    pub fn prove_with_vks(&self, riscv_proofs: &[Proof<Sc>]) -> eyre::Result<Vec<ProofWithVk>> {
        riscv_proofs
            .par_iter()
            .map(|proof| {
                let t0 = std::time::Instant::now();
                let (_, keygen_program, pk, vk) = self.find_pk(proof)?;
                let d_pk = self.engine.device().transport_pk_to_device(pk);
                let transport_ms = t0.elapsed().as_millis();
                let t1 = std::time::Instant::now();
                if self.vk_verification && self.vk_root.is_none() {
                    return Err(ConvertError::Whitelist(
                        "vk_verification mode: call set_vk_root before proving",
                    )
                    .into());
                }
                let (_, record) = setup_for_convert_with_program(
                    &self.riscv_vk,
                    &self.riscv_vm_vk,
                    proof,
                    Arc::clone(keygen_program),
                    self.final_deferred_digest,
                    self.vk_root,
                );
                let setup_ms = t1.elapsed().as_millis();
                let t2 = std::time::Instant::now();
                let ctx = build_proving_ctx(&record, &self.chips, "convert");
                let tracegen_ms = t2.elapsed().as_millis();
                let t3 = std::time::Instant::now();
                let result = self
                    .engine
                    .prove(&d_pk, ctx)
                    .map(|convert_proof| (convert_proof, vk.clone()))
                    .map_err(|e| eyre::eyre!("{e:?}"));
                tracing::info!(
                    "convert_timing proof: transport_ms = {transport_ms}, setup_ms = {setup_ms}, \
                     tracegen_ms = {tracegen_ms}, prove_ms = {}",
                    t3.elapsed().as_millis()
                );
                result
            })
            .collect()
    }

    /// VK from the first registered PK.
    pub fn get_vk(&self) -> Result<Arc<MultiStarkVerifyingKey<Sc>>, ConvertError> {
        self.pks
            .first()
            .map(|entry| entry.3.clone())
            .ok_or(ConvertError::NoPks)
    }

    /// VK for the PK matching the given RISCV proof's layout.
    pub fn get_vk_for_proof(
        &self,
        proof: &Proof<Sc>,
    ) -> Result<Arc<MultiStarkVerifyingKey<Sc>>, ConvertError> {
        self.find_pk(proof).map(|entry| entry.3.clone())
    }

    /// All registered convert VKs (one per distinct layout).
    pub fn all_vks(&self) -> Vec<Arc<MultiStarkVerifyingKey<Sc>>> {
        self.pks.iter().map(|(_, _, _, vk)| vk.clone()).collect()
    }
}
