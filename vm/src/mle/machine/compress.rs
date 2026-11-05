//! Compress prover: re-proves the complete combine root 1:1 under the **inner** (KoalaBear-Poseidon2)
//! config at the compress preset's parameters, into the proof that is handed out — the final
//! compression layer, the ≤ 300 KiB basis. The chain goes on from here: `EmbedMachine`
//! (`super::embed`, behind `multi-field-transcript`) re-proves the compress proof under the outer
//! BN254-hashed config for the on-chain path.
//!
//! Structurally this is a combine node with `n = 1` and `is_complete = true`: the same
//! `build_verify_n_program_multi` program family, the same chip set, the same merged-preprocessed
//! keygen as `EmbedMachine`. The two differ in the engine, the preset's name and the child — a
//! combine root here, a compress proof there — so their programs and the tier rows that pad them
//! differ too; the compress preset carries the embed preset's values (see its doc for why they are
//! two presets).
//! What the layer buys is size: the combine root is proved at the recursion preset
//! (`log_blowup = 2`, 383 WHIR queries, height 2^21) and weighs 646–716 KiB (fib-10 and reth
//! 18884864, dev and whitelist mode); re-proved at `log_blowup = 4` with list decoding (123
//! queries, height 2^20) the same statement weighs 292.17 KiB in whitelist mode and at most that in
//! dev mode [whitelist mode: fib-10 and reth 18884864; dev mode: 292.17 KiB over reth 18884864
//! (and 24600825 when the layer was introduced), 271.76 KiB on fib-10].
//!
//! This file and `embed.rs` are two machines rather than one generic over the engine, by design:
//! with the `cuda` feature compress has its own engine and device path, which embed does not.
//!
//! # Why it is safe to re-prove rather than re-verify
//!
//! The compress proof asserts "there exists a valid combine root proof with these public values".
//! Its public values are the child's, propagated unchanged, so the host acceptance checks are
//! literally the combine root's checks — [`check_complete_root_public_values`], shared, not copied.
//!
//! # The proof type is the root's
//!
//! A compress proof and a combine root proof are both [`ProofWithVk`] over the inner config. They
//! are told apart by the verifying key (the compress preset gives a different `pre_hash`) and by
//! the caller's phase label; a root handed to [`CompressMachine::verify`] matches no honest compress
//! key and is refused, never accepted.

use std::sync::Arc;

use crate::{
    compiler::recursion::program::RecursionProgram,
    instances::chiptype::recursion_chiptype::RecursionChipType,
    machine::chip::MetaChip,
    mle::{
        compiler::recursion::{ConvertVerifierCircuit, RecursionVkLayout},
        machine::{
            convert::ProofWithVk,
            exe::RiscvVmVk,
            recursion::{
                build_proving_ctx, check_complete_root_public_values, extract_recursion_vk_layout,
                recursion_air_refs_with_preprocessed, recursion_public_values,
                recursion_vk_layouts_equal, setup_for_combine_with_program, Kb,
            },
            riscv::{Engine, Sc},
            shape::RecursionTier,
            vk_map::MleVkMap,
        },
    },
};
use pico_mle_core::{
    config::soundness::{admit_production_vk, UnderBudgetError},
    keygen::types::{MultiStarkProvingKey, MultiStarkVerifyingKey},
    prover::DeviceDataTransporter,
    StarkEngine, SystemParams,
};

/// The compress engine and its config: the inner KoalaBear-Poseidon2 engine the recursion
/// machines prove with.
pub type CompressEngine = Engine;
pub type CompressSc = Sc;

/// A compress proof plus the verifying key it verifies under — the same type as a combine root's.
pub type CompressProofWithVk = ProofWithVk;

/// One lazily-keygen'd compress shape: `(child layout, program, pk, vk)`.
type CompressPkEntry = (
    RecursionVkLayout,
    Arc<RecursionProgram<Kb>>,
    MultiStarkProvingKey<CompressSc>,
    Arc<MultiStarkVerifyingKey<CompressSc>>,
);

/// Proves the compress layer over a complete combine-root proof.
pub struct CompressMachine {
    pub engine: CompressEngine,
    /// Lazily grown; deduplicated by child layout (compress is always a complete `n = 1` node).
    /// In whitelist mode the root has one layout (the combine-tier child), so one key.
    pks: Vec<CompressPkEntry>,
    chips: Vec<MetaChip<Kb, RecursionChipType<Kb>>>,
    /// Trusted VM-layer exe identity, as at the apex: the compress proof's `riscv_vk_digest` is
    /// pinned against `riscv_vm_vk.digest()`.
    riscv_vm_vk: RiscvVmVk,
    /// Whitelist mode, baked into the program at keygen. Must match the combine root's mode: with
    /// it on, the compress circuit re-runs the child's whitelist membership check in-circuit and
    /// propagates `vk_root`. The compress key itself is a KoalaBear-digest key, so it can be a
    /// whitelist member, and is one: the whitelist carries its leaf.
    vk_verification: bool,
    /// The whitelist (vk_verification mode): witnessed at prove time, root-checked at verify time.
    vk_map: Option<Arc<MleVkMap>>,
}

/// The compress program over a complete root of `layout`. One function for the CPU machine and
/// [`GpuCompressMachine`], so the two cannot keygen different programs for the same root.
fn compress_program(
    layout: &RecursionVkLayout,
    vk_verification: bool,
) -> Arc<RecursionProgram<Kb>> {
    let mut program = ConvertVerifierCircuit::build_verify_n_program_multi::<Kb>(
        &[layout],
        false, // is_convert_layer: the child is a recursion proof, not a RISCV one
        true,  // is_complete: compress only ever wraps a complete root
        vk_verification,
    );
    // Same explicit tier padding as a combine node, in whitelist mode only: it is what makes
    // the compress VK independent of the child's exact heights. The compress tier row is the
    // program's natural heights in whitelist mode, which is what decides the
    // whitelist-mode proof size (the dev-mode size is the natural shape's).
    if vk_verification {
        crate::mle::machine::recursion::pad_recursion_program(
            "compress",
            &mut program,
            RecursionTier::Compress,
        );
    }
    Arc::new(program)
}

impl CompressMachine {
    /// Pass `compress_params_with_128_bits_security()` and the same trusted exe identity /
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

    /// Keygen the compress node over a complete combine root of `layout` and return its VK, without
    /// proving. [`Self::prove`] keygens the same key for a root whose layout this is, the layout
    /// being `extract_recursion_vk_layout(&root_vk, Some(&root_proof))`.
    pub fn preregister(
        &mut self,
        layout: &RecursionVkLayout,
    ) -> Result<Arc<MultiStarkVerifyingKey<CompressSc>>, UnderBudgetError> {
        let idx = self.keygen_for(layout)?;
        Ok(self.pks[idx].3.clone())
    }

    /// The honestly keygen'd VK this machine would verify `vk` against, selected on the two digests
    /// [`Self::verify`] matches on. Exposed so a cross-build check can assert full equality, which
    /// the two digests do not by themselves witness.
    pub fn honest_compress_vk(
        &self,
        vk: &MultiStarkVerifyingKey<CompressSc>,
    ) -> Option<&MultiStarkVerifyingKey<CompressSc>> {
        self.pks
            .iter()
            .find(|(_, _, _, pk_vk)| {
                pk_vk.pre_hash == vk.pre_hash
                    && pk_vk.inner.merged_preprocessed_commit == vk.inner.merged_preprocessed_commit
            })
            .map(|e| &*e.3)
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
        let program = compress_program(layout, self.vk_verification);
        let stats = program.stats();
        tracing::info!(
            "compress keygen: child_W={} instrs: base_alu={} ext_alu={} total={}",
            layout.stacking_widths.iter().sum::<usize>(),
            stats.get("BaseAlu").copied().unwrap_or(0),
            stats.get("ExtAlu").copied().unwrap_or(0),
            stats.values().sum::<usize>(),
        );
        let airs = recursion_air_refs_with_preprocessed::<CompressSc>(&program);
        let (pk, vk) = self.engine.keygen_merged_preprocessed(&airs);
        admit_production_vk("compress", "cpu", &vk)?;
        self.pks.push((layout.clone(), program, pk, Arc::new(vk)));
        Ok(self.pks.len() - 1)
    }

    /// Re-prove the complete combine root as a single compress proof.
    pub fn prove(&mut self, root: ProofWithVk) -> eyre::Result<CompressProofWithVk> {
        eyre::ensure!(
            !self.vk_verification || self.vk_map.is_some(),
            "vk_verification machine has no vk map at prove time (call set_vk_map)"
        );
        let (proof, vk) = root;
        let layout = extract_recursion_vk_layout(&vk, Some(&proof));
        let pk_idx = self.keygen_for(&layout)?;
        let (_, program, pk, compress_vk) = &self.pks[pk_idx];

        let children = vec![(vk, proof, layout)];
        let (_, record) = setup_for_combine_with_program(
            &children,
            Arc::clone(program),
            true,
            self.vk_map.as_deref(),
        );
        let ctx = build_proving_ctx::<CompressSc>(&record, &self.chips, "compress");
        // `CompressEngine` is `riscv::Engine`, the GPU engine under `cuda`, whose prover takes
        // device traces: move the host-built context over (transposed on the device).
        #[cfg(feature = "cuda")]
        let ctx = cuda_mle::transport_row_major_ctx_to_device(ctx)
            .map_err(|e| eyre::eyre!("compress context to device failed: {e:?}"))?;
        let d_pk = self.engine.device().transport_pk_to_device(pk);
        let _span = tracing::info_span!("compress_prove").entered();
        self.engine
            .prove(&d_pk, ctx)
            .map(|p| (p, compress_vk.clone()))
            .map_err(|e| eyre::eyre!("compress prove failed: {e:?}"))
    }

    /// Host acceptance of the compress proof, on the same terms as the combine root it re-proves:
    ///   1. verify against the HONESTLY keygen'd compress VK on this machine, never a supplied one;
    ///   2. the shared complete-root public-value checks.
    ///
    /// Membership of the compress VK in the whitelist is checked by the SDK apex
    /// (`MleApexVerifier::verify_compress`), not here.
    pub fn verify(&self, proof: &CompressProofWithVk) -> eyre::Result<()> {
        eyre::ensure!(
            !self.vk_verification || self.vk_map.is_some(),
            "vk_verification machine has no vk map at verify time (call set_vk_map)"
        );
        let (compress_proof, vk) = proof;
        let honest_vk = self.honest_compress_vk(vk).ok_or_else(|| {
            eyre::eyre!(
                "compress proof vk matches no honestly keygen'd shape on this machine \
                 (run prove first, and pass the vk prove returned)"
            )
        })?;
        self.engine
            .verify(honest_vk, compress_proof)
            .map_err(|e| eyre::eyre!("compress proof failed STARK verify: {e:?}"))?;

        let pvs = recursion_public_values(&compress_proof.public_values)?;
        check_complete_root_public_values(
            "compress",
            pvs,
            &self.riscv_vm_vk.digest(),
            self.vk_map.as_ref().map(|m| m.root()).as_ref(),
        )?;
        Ok(())
    }

    /// Distinct compress shapes keygen'd so far (observability for the dedup behavior).
    pub fn num_distinct_shapes(&self) -> usize {
        self.pks.len()
    }
}

// ── GPU compress ────────────────────────────────────────────────────────────────────────────────
//
// The production prover for the compress layer, on the pattern of `GpuCombineMachine`: device
// keygen (`keygen_recursion_gpu`), device trace-gen (`build_ctx_gpu`) and the GPU prove, on the
// card the calling thread is bound to. Acceptance stays on the CPU [`CompressMachine`]
// (`preregister` the root's layout, then `verify`), so the host-side checks exist in one place, as
// combine's do.

#[cfg(feature = "cuda")]
use crate::mle::machine::recursion::{
    gpu::{self, GpuEngineKb, GpuPbKb},
    setup_for_combine_with_program as setup_compress,
};

/// One device-keygen'd compress shape: `(child layout, program, vk, device pk)`.
#[cfg(feature = "cuda")]
type GpuCompressPkEntry = (
    RecursionVkLayout,
    Arc<RecursionProgram<Kb>>,
    Arc<MultiStarkVerifyingKey<CompressSc>>,
    Arc<pico_mle_core::prover::DeviceMultiStarkProvingKey<GpuPbKb>>,
);

/// A compress proof from [`GpuCompressMachine::prove`], with the root layout its key was built
/// for (what the CPU machine must `preregister` to verify it) and where the time went.
#[cfg(feature = "cuda")]
pub struct GpuCompressProof {
    pub proof: CompressProofWithVk,
    pub root_layout: RecursionVkLayout,
    /// Zero on a cache hit.
    pub keygen_ms: u128,
    pub setup_ms: u128,
    pub tracegen_ms: u128,
    pub prove_ms: u128,
}

/// Proves the compress layer on the GPU. One per process is enough: compress runs once per
/// block, after the tree has collapsed, so it never competes with another lane for a card.
#[cfg(feature = "cuda")]
pub struct GpuCompressMachine {
    pub engine: GpuEngineKb,
    vk_verification: bool,
    vk_map: Option<Arc<MleVkMap>>,
    /// Used only for the `ChipBehavior` methods. See `ConvertMachine::new`.
    chips: Vec<MetaChip<Kb, RecursionChipType<Kb>>>,
    /// Keyed by root layout and never evicted: at most one shape per root layout, and in
    /// whitelist mode at most 20 (see [`CompressMachine::pks`]).
    pks: std::sync::Mutex<Vec<GpuCompressPkEntry>>,
}

#[cfg(feature = "cuda")]
impl GpuCompressMachine {
    /// Pass `compress_params_with_128_bits_security()`, and the whitelist mode the combine
    /// machines ran with.
    pub fn new(params: SystemParams, vk_verification: bool) -> Self {
        Self {
            engine: StarkEngine::new(params),
            vk_verification,
            vk_map: None,
            chips: RecursionChipType::<Kb>::mle_recursion_chips(),
            pks: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// Supply the whitelist (vk_verification mode; call before proving).
    pub fn set_vk_map(&mut self, map: Arc<MleVkMap>) {
        assert!(self.vk_verification, "vk_map without vk_verification");
        self.vk_map = Some(map);
    }

    /// Find-or-keygen on the bound card. Returns the entry's handles and the keygen time (zero on
    /// a hit).
    #[allow(clippy::type_complexity)]
    fn get_or_keygen(
        &self,
        layout: &RecursionVkLayout,
    ) -> eyre::Result<(
        Arc<RecursionProgram<Kb>>,
        Arc<MultiStarkVerifyingKey<CompressSc>>,
        Arc<pico_mle_core::prover::DeviceMultiStarkProvingKey<GpuPbKb>>,
        u128,
    )> {
        let mut pks = self.pks.lock().expect("compress pk cache mutex poisoned");
        if let Some((_, program, vk, pk)) = pks
            .iter()
            .find(|(l, ..)| recursion_vk_layouts_equal(l, layout))
        {
            return Ok((program.clone(), vk.clone(), pk.clone(), 0));
        }
        let keygen_span = crate::mle::spans::busy(crate::mle::spans::WorkKind::Keygen, None);
        let t = std::time::Instant::now();
        let program = compress_program(layout, self.vk_verification);
        let (vk, device_pk) = gpu::keygen_recursion_gpu(
            &self.engine,
            &program,
            &self.chips,
            crate::mle::machine::riscv::bound_device(),
        );
        admit_production_vk("compress", "gpu", &vk)?;
        let device_pk = Arc::new(device_pk);
        // Same 21 chips as convert and combine, so these hit the cubin cache convert's warmup
        // filled.
        cuda_mle::warmup_jit_kernels::<cuda_mle::hash_scheme::KoalaBearPoseidon2HashScheme>(
            &device_pk,
        );
        let vk = Arc::new(vk);
        let keygen_ms = t.elapsed().as_millis();
        drop(keygen_span);
        tracing::info!(
            "gpu_compress keygen: child_W={} instrs={} took {keygen_ms} ms",
            layout.stacking_widths.iter().sum::<usize>(),
            program.instructions.len(),
        );
        pks.push((
            layout.clone(),
            program.clone(),
            vk.clone(),
            device_pk.clone(),
        ));
        Ok((program, vk, device_pk, keygen_ms))
    }

    /// Re-prove the complete combine root as a single compress proof, on the bound card. Verify
    /// the result with [`CompressMachine::verify`] after `preregister(&proof.root_layout)`.
    pub fn prove(&self, root: &ProofWithVk) -> eyre::Result<GpuCompressProof> {
        eyre::ensure!(
            !self.vk_verification || self.vk_map.is_some(),
            "vk_verification machine has no vk map at prove time (call set_vk_map)"
        );
        let (proof, vk) = root;
        let root_layout = extract_recursion_vk_layout(vk, Some(proof));
        let (program, compress_vk, pk, keygen_ms) = self.get_or_keygen(&root_layout)?;

        let t_setup = std::time::Instant::now();
        let children = vec![(vk.clone(), proof.clone(), root_layout.clone())];
        let (_, record) = setup_compress(&children, program, true, self.vk_map.as_deref());
        let setup_ms = t_setup.elapsed().as_millis();

        let t_trace = std::time::Instant::now();
        let ctx = gpu::build_ctx_gpu(
            &record,
            &self.chips,
            crate::mle::machine::riscv::bound_device(),
            "gpu-compress",
        );
        if crate::mle::env_flag("MLE_RECURSION_TRACE_COMPARE") {
            gpu::assert_ctx_matches_cpu(&ctx, &record, &self.chips);
        }
        let tracegen_ms = t_trace.elapsed().as_millis();

        // Labels this thread's `[rsprof]`/`[stepprof]` timer lines.
        cuda_mle::set_prove_phase("compress");
        let t_prove = std::time::Instant::now();
        let proof = self
            .engine
            .prove(&pk, ctx)
            .map_err(|e| eyre::eyre!("compress prove failed: {e:?}"))?;
        let prove_ms = t_prove.elapsed().as_millis();
        tracing::info!(
            "gpu_compress_timing: keygen_ms = {keygen_ms}, setup_ms = {setup_ms}, \
             tracegen_ms = {tracegen_ms}, prove_ms = {prove_ms}"
        );
        Ok(GpuCompressProof {
            proof: (proof, compress_vk),
            root_layout,
            keygen_ms,
            setup_ms,
            tracegen_ms,
            prove_ms,
        })
    }
}
