//! Convert prover (Phase 2, leaf recursion): wraps each RISCV proof in a recursion
//! circuit that verifies it. Proofs are grouped by [`RecursionVkLayout`] so each
//! distinct shape is keygen'd once; all proofs of a shape then prove in parallel.

use std::sync::Arc;
// The process-global program cache is `cuda`-only, and so are these. `pico-vm` builds without
// that feature (pico-aot-codegen pulls it in that shape) under `deny(warnings)`, where an
// unconditional import of them is a hard error.
#[cfg(feature = "cuda")]
use std::sync::{Condvar, Mutex, OnceLock};

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

// ─── GPU convert prover (per-chunk) ─────────────────────────────────────────────────────
//
// GPU-only by design: the only consumer is the MLE single-node driver, which proves on the GPU.
// The batch [`ConvertMachine`] above remains the CPU reference path (the e2e example drives it).
// The whole section is `cuda`-gated — there is no CPU path.

#[cfg(feature = "cuda")]
use crate::mle::machine::recursion::gpu::{GpuEngineKb, GpuPbKb};

/// Process-global cache of built verify programs, keyed by layout.
///
/// **Why global rather than per-machine.** `ConvertVerifierCircuit::build_verify_program` is a pure
/// function of `ConvertProgramInput { vk: layout, vk_verification }` (the mode is process-wide) —
/// no engine, no device, no card. Each card owns its own `GpuConvertMachine`, and the pipeline
/// picks a chunk's card **round-robin** (`convert_card_for` in `distributed-vm/src/mle/mod.rs`), so
/// a per-machine cache rebuilds the same program once per card. Sharing the program is also what
/// lets [`GpuConvertMachine::prebuild_program`] pre-build off the critical path without knowing
/// which card will pick the chunk up.
///
/// Layouts recur across cards and blocks within a run, which is what this cache exploits.
///
/// Only the program is shared. The vk and the device pk stay per-machine: the pk is device memory
/// and is not transferable between cards.
///
/// The program itself is shared by `Arc` and carries interior-mutable bucket caches, so two cards
/// can be inside a keygen pass over one program at once — see `RecursionProgram::bucket_for_pass`,
/// which refcounts those passes for exactly this reason.
#[cfg(feature = "cuda")]
struct ProgramCache {
    /// Built and available. `(layout, program, insert tick)`, bounded LRU by tick.
    ///
    /// The key is an `Arc` so that claiming a build and publishing it move a refcount rather than
    /// a `RecursionVkLayout` — which is deep (`per_air` carries a full `EvalDag` per RISC-V AIR)
    /// and would otherwise be cloned with this process-wide lock held.
    ready: Vec<(Arc<RecursionVkLayout>, Arc<RecursionProgram<Kb>>, u64)>,
    /// A build is in progress for these layouts. A second requester WAITS on the condvar rather
    /// than duplicating the build — which is the whole point at four cards, where the
    /// pre-build and the preparer race for the same layout by construction.
    in_flight: Vec<Arc<RecursionVkLayout>>,
    tick: u64,
}

#[cfg(feature = "cuda")]
static PROGRAM_CACHE: OnceLock<(Mutex<ProgramCache>, Condvar)> = OnceLock::new();

/// Clears a layout's `in_flight` mark and wakes its waiters **even if the build panics**.
///
/// Without this, a panicking `build_verify_program` would leave the layout marked in flight for
/// the life of the process and every later requester would wait on the condvar forever — turning
/// a crash into a hang. That is not hypothetical here: the pre-build runs on its own worker
/// thread, where a panic kills only that thread and would otherwise go unnoticed. On unwind the
/// next requester finds the layout neither ready nor in flight, becomes the builder, and panics on
/// the real path — which is the correct outcome: fail loudly, never hang.
#[cfg(feature = "cuda")]
struct InFlightGuard<'a> {
    lock: &'a Mutex<ProgramCache>,
    cv: &'a Condvar,
    layout: &'a RecursionVkLayout,
    /// Cleared by the success path, which removes the mark itself under the lock it already holds.
    armed: bool,
}

#[cfg(feature = "cuda")]
impl Drop for InFlightGuard<'_> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        if let Ok(mut g) = self.lock.lock() {
            g.in_flight
                .retain(|l| !recursion_vk_layouts_equal(l.as_ref(), self.layout));
        }
        self.cv.notify_all();
    }
}

/// `MLE_CONVERT_PROGRAM_CACHE` (default 256): entries kept.
///
/// Sized to hold every convert program a resident run keeps meeting, so that each is built once
/// and later blocks reuse it: in whitelist mode the 80 p99 blocks use 184 distinct layouts. The
/// program is card-independent, so the reuse holds whichever card a chunk goes to. A retained
/// entry pins a `RecursionProgram` in host RAM, about 50 MiB resident: the whitelist-mode set adds
/// about 9.5 GB to the run's resident memory. With the whitelist off, layouts follow each chunk's
/// natural heights and repeat far less (about 1,180 distinct over the same blocks), so the cache
/// fills and wraps, at about 16 GB. An LRU wrap is visible rather than silent: eviction logs.
#[cfg(feature = "cuda")]
fn program_cache_cap() -> usize {
    std::env::var("MLE_CONVERT_PROGRAM_CACHE")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(256)
        .max(1)
}

/// The program for `layout`, built at most once process-wide. Returns
/// `(program, built_here, layout_clone_us)`; `built_here == false` means it came from the cache or
/// from another thread's in-flight build.
///
/// `speculative` marks a pre-build: one that nobody is waiting on. A speculative result is
/// published only if the cache has room, never by evicting — an entry a preparer is about to ask
/// for must not be displaced by a build for a chunk that has already gone by.
///
/// The expensive build runs with **no lock held**, so distinct layouts build concurrently. Callers
/// racing on the SAME layout serialise on the condvar and share one build.
#[cfg(feature = "cuda")]
fn program_for_layout(
    layout: &RecursionVkLayout,
    speculative: bool,
) -> (Arc<RecursionProgram<Kb>>, bool, u128) {
    let (lock, cv) = PROGRAM_CACHE.get_or_init(|| {
        (
            Mutex::new(ProgramCache {
                ready: Vec::new(),
                in_flight: Vec::new(),
                tick: 0,
            }),
            Condvar::new(),
        )
    });
    let mut guard = lock.lock().expect("convert program cache mutex poisoned");
    let mut layout_clone_us = 0u128;
    let key: Arc<RecursionVkLayout> = loop {
        guard.tick += 1;
        let now = guard.tick;
        if let Some(e) = guard
            .ready
            .iter_mut()
            .find(|(l, _, _)| recursion_vk_layouts_equal(l.as_ref(), layout))
        {
            e.2 = now;
            return (e.1.clone(), false, layout_clone_us);
        }
        if guard
            .in_flight
            .iter()
            .any(|l| recursion_vk_layouts_equal(l.as_ref(), layout))
        {
            guard = cv
                .wait(guard)
                .expect("convert program cache mutex poisoned");
            continue;
        }
        // Claiming the build needs an owned key, and `RecursionVkLayout` is deep. Clone it with
        // the lock RELEASED — every other card's lookup would otherwise queue behind this clone —
        // then re-check, because the gap is long enough for another thread to claim the same
        // layout. On a hit the clone is never paid at all.
        drop(guard);
        let t_clone = std::time::Instant::now();
        let key = Arc::new(layout.clone());
        layout_clone_us += t_clone.elapsed().as_micros();
        guard = lock.lock().expect("convert program cache mutex poisoned");
        if guard
            .ready
            .iter()
            .any(|(l, _, _)| recursion_vk_layouts_equal(l.as_ref(), layout))
            || guard
                .in_flight
                .iter()
                .any(|l| recursion_vk_layouts_equal(l.as_ref(), layout))
        {
            continue;
        }
        guard.in_flight.push(Arc::clone(&key));
        break key;
    };
    drop(guard);

    // Unlocked: the CPU circuit build. The guard makes a panic here a loud failure
    // rather than a permanent hang for every later requester of this layout.
    let mut in_flight = InFlightGuard {
        lock,
        cv,
        layout,
        armed: true,
    };
    let t = std::time::Instant::now();
    let program = build_convert_program(layout);
    let program_ms = t.elapsed().as_millis();

    let mut guard = lock.lock().expect("convert program cache mutex poisoned");
    in_flight.armed = false;
    guard
        .in_flight
        .retain(|l| !recursion_vk_layouts_equal(l.as_ref(), layout));
    guard.tick += 1;
    let now = guard.tick;
    let cap = program_cache_cap();
    // A SPECULATIVE build has no waiter: the chunk it was built for may already have been proved.
    // Evicting for it would hand the critical path a rebuild of whatever it displaced, so a full
    // cache simply drops it. A real miss, whose caller is holding the result either way, evicts.
    let mut dropped = false;
    if guard.ready.len() >= cap {
        if speculative {
            dropped = true;
        } else if let Some(idx) = guard
            .ready
            .iter()
            .enumerate()
            .min_by_key(|(_, e)| e.2)
            .map(|(i, _)| i)
        {
            let evicted = guard.ready.swap_remove(idx);
            tracing::info!(
                target: "bench",
                "gpu_convert_program evict: tick {} (cache {}/{cap})",
                evicted.2,
                guard.ready.len()
            );
        }
    }
    if !dropped {
        guard.ready.push((key, program.clone(), now));
    }
    let n_ready = guard.ready.len();
    drop(guard);
    cv.notify_all();
    tracing::info!(
        target: "bench",
        "gpu_convert_program build: program_ms = {program_ms} (cache {n_ready}/{cap}, \
         speculative = {speculative}, published = {})",
        !dropped
    );
    (program, true, layout_clone_us)
}

/// The prover-side key handle cached per layout: a device-resident proving key.
#[cfg(feature = "cuda")]
type GpuPk = Arc<pico_mle_core::prover::DeviceMultiStarkProvingKey<GpuPbKb>>;

/// One cached keygen per [`RecursionVkLayout`]: the verify program, the convert vk, and the
/// device-resident proving key.
#[cfg(feature = "cuda")]
struct GpuPkEntry {
    layout: RecursionVkLayout,
    program: Arc<RecursionProgram<Kb>>,
    vk: Arc<MultiStarkVerifyingKey<Sc>>,
    device_pk: GpuPk,
    /// LRU tick of the last use (larger = more recent).
    last_used: u64,
}

/// Microsecond partition of one keygen-cache miss. Collected in one place rather than threaded out
/// of the keygen block as a tuple, so adding or dropping a term does not reshape that block.
#[cfg(feature = "cuda")]
#[derive(Default)]
struct MissTiming {
    /// `RecursionVkLayout::per_air` carries a full `EvalDag` per RISC-V AIR, so the clones this
    /// miss pays inside `program_for_layout` — the cache key and `ConvertProgramInput` — are deep.
    /// Reported by that function and recorded here; 0 on a cache hit, which pays neither.
    layout_clone_us: u128,
    program_ms: u128,
    /// The program came from the process-global cache (a pre-build, or another card's earlier
    /// miss) rather than being built here. This is the field that proves the hoist is live.
    program_hit: bool,
    keygen_call_us: u128,
    jit_ms: u128,
}

#[cfg(feature = "cuda")]
impl MissTiming {
    /// Logged on its own line so the harness-parsed `gpu_convert_timing keygen(miss):` line stays
    /// byte-identical. `miss_us` closes the partition: whatever it exceeds
    /// `program + keygen_call + jit` by is still unattributed.
    ///
    /// `layout_clone_us` is NOT a term of that partition — it is a breakdown *of* `program_ms`,
    /// measured inside `program_for_layout`. Adding it to the others double-counts.
    fn log(&self, miss_us: u128) {
        tracing::info!(
            "mle_keygen_miss_detail: miss_us = {miss_us}, layout_clone_us = {}, \
             keygen_call_us = {}",
            self.layout_clone_us,
            self.keygen_call_us
        );
    }
}

/// Per-chunk GPU convert prover: riscv proofs flow in one at a time, keygen happens
/// per-layout with a bounded LRU cache, and recursion trace-gen + proving run on the GPU. The batch
/// [`ConvertMachine`] stays as-is (the CPU reference path the e2e example drives).
/// Whitelist mode of the GPU convert programs, process-wide: the program cache below is keyed
/// by layout alone, so one process builds convert programs in one mode. Set by the first
/// `GpuConvertMachine::new`; a later machine asking for the other mode is a caller bug.
#[cfg(feature = "cuda")]
static CONVERT_WHITELIST_MODE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();

/// The core ladder row the whitelist-mode warmup keygens: row 13 holds 406 of the 3,275 corpus
/// core chunks (`MLE_CORE_LADDER`, the 80-block p99 corpus). Any row serves the warmup's
/// purpose; this one is the likeliest cache hit.
#[cfg(feature = "cuda")]
const WARMUP_CORE_CLASS: usize = 13;

#[cfg(feature = "cuda")]
fn convert_whitelist_mode() -> bool {
    CONVERT_WHITELIST_MODE.get().copied().unwrap_or(false)
}

/// The convert verify program for `layout` in the process's mode. In whitelist mode the program
/// takes the convert tier shape and passes the tier check (`pad_convert_program`), exactly as
/// `ConvertMachine::new` does.
#[cfg(feature = "cuda")]
fn build_convert_program(layout: &RecursionVkLayout) -> Arc<RecursionProgram<Kb>> {
    let vk_verification = convert_whitelist_mode();
    let input = ConvertProgramInput {
        vk: layout.clone(),
        vk_verification,
    };
    let mut program = ConvertVerifierCircuit::build_verify_program(&input);
    if vk_verification {
        crate::mle::machine::recursion::pad_convert_program("convert", &mut program);
    }
    Arc::new(program)
}

#[cfg(feature = "cuda")]
pub struct GpuConvertMachine {
    pub engine: GpuEngineKb,
    /// Whitelist mode: proofs witness `vk_root` into their public values and the programs are
    /// tier-shaped. Fixed per process (see `CONVERT_WHITELIST_MODE`).
    vk_verification: bool,
    /// The whitelist root pushed into every convert witness (whitelist mode).
    vk_root: Option<[Kb; 8]>,
    /// The digest the tree's deferred nodes end on; zero when the tree has none.
    final_deferred_digest: [Kb; DIGEST_SIZE],
    // Used only for the `ChipBehavior` methods; the FRI parts are dead. See `ConvertMachine::new`.
    chips: Vec<MetaChip<Kb, RecursionChipType<Kb>>>,
    riscv_vk: Arc<MultiStarkVerifyingKey<Sc>>,
    riscv_vm_vk: RiscvVmVk,
    cache: std::sync::Mutex<(Vec<GpuPkEntry>, u64)>,
    /// Cache capacity (`MLE_CONVERT_PK_CACHE`, default 4): the OOM guard — evicted layouts
    /// re-keygen on their next miss (slower, never wrong).
    cache_cap: usize,
}

#[cfg(feature = "cuda")]
impl GpuConvertMachine {
    /// Light constructor: no proofs, no upfront keygen. Call [`Self::pre_keygen_warmup`] once
    /// from a quiescent thread before the proving pipeline spins up (JIT warmup — see there).
    pub fn new(
        riscv_vk: Arc<MultiStarkVerifyingKey<Sc>>,
        riscv_vm_vk: RiscvVmVk,
        params: SystemParams,
        vk_verification: bool,
    ) -> Self {
        if CONVERT_WHITELIST_MODE.set(vk_verification).is_err() {
            assert_eq!(
                convert_whitelist_mode(),
                vk_verification,
                "GPU convert machines of both whitelist modes in one process: the program cache is \
                 keyed by layout alone"
            );
        }
        let cache_cap = std::env::var("MLE_CONVERT_PK_CACHE")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(4)
            .max(1);
        Self {
            engine: StarkEngine::new(params),
            vk_verification,
            vk_root: None,
            final_deferred_digest: [Kb::ZERO; DIGEST_SIZE],
            chips: RecursionChipType::<Kb>::mle_recursion_chips(),
            riscv_vk,
            riscv_vm_vk,
            cache: std::sync::Mutex::new((Vec::new(), 0)),
            cache_cap,
        }
    }

    /// Supply the whitelist root (whitelist mode; call before proving).
    pub fn set_vk_root(&mut self, root: [Kb; 8]) {
        assert!(self.vk_verification, "vk_root without vk_verification");
        self.vk_root = Some(root);
    }

    /// As [`ConvertMachine::set_final_deferred_digest`].
    pub fn set_final_deferred_digest(&mut self, digest: [Kb; DIGEST_SIZE]) {
        self.final_deferred_digest = digest;
    }

    /// Layouts cached on this card right now, and the cap. Device proving keys are the entries,
    /// so this is the card's LRU residency — read by the VRAM census, which needs to say whether a
    /// resting-live climb is the cache filling up (bounded, ends at the cap) or something else.
    pub fn cache_len(&self) -> (usize, usize) {
        let guard = self.cache.lock().expect("convert pk cache mutex poisoned");
        (guard.0.len(), self.cache_cap)
    }

    /// Warm the recursion JIT kernels with one cheap keygen on the CALLING thread. Run this while
    /// the process is quiescent: the first keygen nvrtc-compiles the recursion kernels, and
    /// libnvrtc deadlocks in a heavily-threaded process.
    ///
    /// In whitelist mode the dominant layout is synthesizable: the ladder's most populated core
    /// class (`WARMUP_CORE_CLASS`), a shape whose convert program passes the tier check.
    ///
    /// In natural-shape mode (vk_verification off) there is no synthesizable dominant layout — the
    /// all-present worst-case (`heights = None`) substitutes the maximum height per air and trips
    /// the LogUp height bound. So this warms up with an all-present MINIMAL-height layout instead:
    /// kernel sources depend only on the AIR constraints (not on heights), so the cubins compiled
    /// here serve every real layout; the keygen itself is small, and the cache entry is
    /// warmup-only (it will not match real proofs and eventually evicts).
    pub fn pre_keygen_warmup(&self) {
        let num_airs = self.riscv_vk.inner.per_air.len();
        let heights = if self.vk_verification {
            // Whitelist mode checks every convert program against its tier, and the all-present
            // minimal layout below is no whitelist shape: its MemoryConst table alone overflows
            // the Convert tier. The ladder's most populated core class is a real shape, so the
            // check passes and the same cubins get compiled, and the proving key it leaves in
            // the cache is one the first chunk of that class reuses.
            let class = crate::mle::machine::shape::MLE_CORE_LADDER[WARMUP_CORE_CLASS];
            crate::mle::machine::riscv::per_air_log_heights_of(class, num_airs)
        } else {
            // l_skip + 1 keeps every air's hypercube_dim positive while staying tiny.
            let l_skip = self.riscv_vk.inner.params.l_skip;
            vec![Some(l_skip + 1); num_airs]
        };
        let layout = crate::mle::machine::recursion::extract_recursion_vk_layout_from_heights(
            &self.riscv_vk,
            Some(heights.as_slice()),
        );
        let _ = self.get_or_keygen(layout);
    }

    /// Build this chunk's verify program AHEAD of its convert stage, from the committed trace
    /// heights its riscv prove has already fixed.
    ///
    /// **The hoist.** The program build dominates a convert keygen miss and is pure CPU work that
    /// never touches the card. A chunk's layout is fully determined by its per-AIR committed
    /// log-heights (`extract_recursion_vk_layout` takes *only* that vector from the proof —
    /// `mle/machine/recursion/layout.rs:157-173`), and those heights are final the moment riscv
    /// **trace-gen** returns, early in the prove. So calling this from the riscv lane after
    /// trace-gen puts the build inside the slack of the chunk's own prove, and the preparer that
    /// picks the chunk up afterwards finds it in the process-global cache.
    ///
    /// Off the critical path in both directions: it takes **no** pk-cache lock and touches **no**
    /// device, so it cannot block a prove or a keygen on any card.
    ///
    /// Fails safe by construction. If `per_air_log_heights` were ever wrong the layout would
    /// differ, `recursion_vk_layouts_equal` would miss, and the real path would build its own
    /// program exactly as it does today — a wasted build, never a wrong proof. Nothing here can
    /// change what is proved: the program is a pure function of the layout, and the layout the
    /// prover actually uses is still derived from the finished proof.
    pub fn prebuild_program(&self, per_air_log_heights: &[Option<usize>]) {
        let t = std::time::Instant::now();
        let Some(layout) = self.prebuild_layout(per_air_log_heights) else {
            return;
        };
        let (_program, built_here, _clone_us) = program_for_layout(&layout, true);
        tracing::info!(
            target: "bench",
            "gpu_convert_prebuild: total_ms = {}, built = {built_here}",
            t.elapsed().as_millis()
        );
    }

    /// The layout these heights describe, or `None` when they fail a guard below — every
    /// caller must go through this, because an out-of-bounds height panics inside the extraction
    /// and this binary's panic hook takes the whole run down with it.
    fn prebuild_layout(&self, per_air_log_heights: &[Option<usize>]) -> Option<RecursionVkLayout> {
        let t = std::time::Instant::now();
        // NEGATIVE CONTROLS, off by default and never set on a timing cell. Both make every
        // pre-built layout wrong; they differ in HOW, and each tests a different guarantee.
        //   =1  decrement a height -> in-bounds but wrong. Tests the FAIL-SAFE path: the layout
        //       builds fine, the consumer's equality check misses, the normal build runs.
        //   =2  increment a height -> OUT OF BOUNDS. Tests the precondition below. This is the
        //       mode that found the defect: an out-of-bounds height panics inside
        //       `extract_recursion_vk_layout_from_heights`, and this binary's panic hook
        //       (`distributed-vm/bin/mle_single_node.rs:13-16`) calls `process::exit(101)` on ANY
        //       thread's panic, so a pre-build panic killed the whole run.
        let poison = std::env::var("MLE_CONVERT_PREBUILD_POISON")
            .ok()
            .and_then(|v| v.parse::<u8>().ok())
            .unwrap_or(0);
        let mut poisoned = per_air_log_heights.to_vec();
        if poison > 0 {
            if let Some(h) = poisoned.iter_mut().flatten().next() {
                if poison == 1 {
                    *h = h.saturating_sub(1);
                } else {
                    *h += 1;
                }
            }
        }
        let heights: &[Option<usize>] = if poison > 0 {
            &poisoned
        } else {
            per_air_log_heights
        };

        // PRECONDITION, and it is load-bearing rather than defensive. `prebuild_program` runs on a
        // background worker, and **this binary makes a worker panic fatal**: its panic hook exits
        // the process with 101 (`mle_single_node.rs:13-16`, so that a dead worker cannot hang the
        // run silently). The hook fires BEFORE unwinding, so `catch_unwind` here would not help —
        // the panic has to be prevented, not caught.
        //
        // `extract_recursion_vk_layout_from_heights` has TWO unconditional panics on a bad height
        // and both have to be prevented here, not caught:
        //   1. the stacking bound (`recursion/layout.rs:41`, `LayoutHeightExceeded`);
        //   2. the host LogUp overflow assert (`recursion/layout.rs:457`), which a height that is
        //      still within the stacking bound can trip on its own — the common case for a height
        //      off by one, since real heights sit well below the bound.
        // Real heights always satisfy both — a proof was produced under them — so neither fires in
        // normal running. They fire only on a height this function had no business being handed,
        // which is exactly the case the hoist's "a wrong pre-build is harmless" claim has to
        // survive.
        let params = &self.riscv_vk.inner.params;
        let max_log_height = params.l_skip + params.n_stack;
        let l_skip = params.l_skip;
        let n_airs = self.riscv_vk.inner.per_air.len();
        if heights.len() != n_airs {
            tracing::warn!(
                target: "bench",
                "gpu_convert_prebuild: skipped — {} heights for {n_airs} airs",
                heights.len()
            );
            return None;
        }
        if let Some(bad) = heights.iter().flatten().find(|&&h| h > max_log_height) {
            tracing::warn!(
                target: "bench",
                "gpu_convert_prebuild: skipped — log_height {bad} exceeds l_skip + n_stack = \
                 {max_log_height} (poison = {poison})"
            );
            return None;
        }
        // Mirrors the assert at `recursion/layout.rs:457` as a predicate. The shift is bounded by
        // the check above, so it cannot itself overflow.
        let logup_ok = self
            .riscv_vk
            .inner
            .trace_height_constraints
            .iter()
            .all(|constraint| {
                let sum: u64 = (0..n_airs)
                    .filter_map(|air_id| {
                        let log_height = heights[air_id]?;
                        Some(
                            (1u64
                                << pico_mle_core::protocol::stacking::lifted_log_height(
                                    log_height, l_skip,
                                ))
                                * constraint.coefficients[air_id] as u64,
                        )
                    })
                    .sum();
                sum < constraint.threshold as u64
            });
        if !logup_ok {
            tracing::warn!(
                target: "bench",
                "gpu_convert_prebuild: skipped — these heights violate the host LogUp overflow \
                 bound (poison = {poison})"
            );
            return None;
        }
        let layout = crate::mle::machine::recursion::extract_recursion_vk_layout_from_heights(
            &self.riscv_vk,
            Some(heights),
        );
        tracing::debug!(
            target: "bench",
            "gpu_convert_prebuild: extract_ms = {}, poison = {poison}",
            t.elapsed().as_millis()
        );
        Some(layout)
    }

    /// Pre-build for the caller's card: the program as above, and then the device proving key, so
    /// the preparer finds a warm cache instead of paying a keygen on the tree's critical chain.
    ///
    /// The caller must already be bound to the card this machine belongs to, and must have taken
    /// the same card the node will be proven on — a key cached on the wrong card is dead weight.
    /// Wrong heights stay fail-safe: the layout simply misses the preparer's lookup, which then
    /// keygens as it does today.
    pub fn prebuild_pk(&self, per_air_log_heights: &[Option<usize>]) {
        let t = std::time::Instant::now();
        let Some(layout) = self.prebuild_layout(per_air_log_heights) else {
            return;
        };
        // Speculatively, so the program cache will not evict a live entry for a guess; the keygen
        // below then finds it published rather than building its own.
        let (_program, _built_here, _clone_us) = program_for_layout(&layout, true);
        // Populates this machine's cache; the handles themselves are the preparer's to fetch.
        let _ = self.get_or_keygen(layout);
        tracing::info!(
            target: "bench",
            "gpu_convert_prebuild_pk: total_ms = {}",
            t.elapsed().as_millis()
        );
    }

    /// Prove ONE riscv proof into a convert proof (FRI-model, per-chunk), paired with the
    /// convert vk it verifies under.
    pub fn prove_one(&self, proof: &Proof<Sc>) -> eyre::Result<ProofWithVk> {
        let prepared = self.prepare_one(proof);
        self.prove_prepared(prepared)
    }

    /// CPU stage of the per-chunk pipeline (the FRI convert-preparer role): layout extraction,
    /// keygen-cache lookup, and the recursion emulation producing the record. Runs off the GPU.
    pub fn prepare_one(&self, proof: &Proof<Sc>) -> GpuPreparedConvert {
        let t_extract = std::time::Instant::now();
        let layout = extract_recursion_vk_layout(&self.riscv_vk, Some(proof));
        let extract_us = t_extract.elapsed().as_micros();
        // Extraction rebuilds every AIR's `EvalDag` and is paid on a cache HIT too, so leaving it
        // inside `keygen_ms` would give that field a floor that hides how much of keygen the cache
        // avoids. `t_keygen` starts after it, and the two are reported as separate fields.
        let extract_ms = extract_us / 1000;
        // A cache miss does GPU work inside `get_or_keygen`; hits never touch the card. A layout
        // carries the chunk's trace heights: natural ones with the whitelist off, padded to a fixed
        // set of shapes in whitelist mode, where far more chunks share a key.
        let t_keygen = std::time::Instant::now();
        let entry = self.get_or_keygen(layout);
        let keygen_ms = t_keygen.elapsed().as_millis();
        // The identical extraction runs a second time inside `setup_for_convert_with_program` below;
        // both sides stay measured while threading the caller's layout through is still an open
        // question. Microseconds because this one is a comparison against that site, not a phase cost.
        tracing::debug!("mle_keygen_extract: keygen_side_us = {extract_us}");

        let t1 = std::time::Instant::now();
        if self.vk_verification {
            assert!(
                self.vk_root.is_some(),
                "vk_verification mode: call set_vk_root before proving"
            );
        }
        let (_, record) = setup_for_convert_with_program(
            &self.riscv_vk,
            &self.riscv_vm_vk,
            proof,
            Arc::clone(&entry.0),
            self.final_deferred_digest,
            self.vk_root,
        );
        let setup_ms = t1.elapsed().as_millis();
        GpuPreparedConvert {
            vk: entry.1,
            pk: entry.2,
            record,
            extract_ms,
            keygen_ms,
            setup_ms,
        }
    }

    /// GPU stage of the per-chunk pipeline (the FRI convert-prover role): trace-gen + prove.
    /// Prove from a prepared convert: build the ctx then prove, back to back. Callers that need
    /// the halves separately use [`Self::build_convert_ctx`] + [`Self::prove_built`] directly.
    pub fn prove_prepared(&self, prepared: GpuPreparedConvert) -> eyre::Result<ProofWithVk> {
        let built = self.build_convert_ctx(prepared);
        self.prove_built(built)
    }

    /// Trace-gen on device (`build_ctx_gpu`), optionally cross-checked against the CPU path.
    pub fn build_convert_ctx(&self, prepared: GpuPreparedConvert) -> BuiltConvert {
        let GpuPreparedConvert {
            vk,
            pk,
            record,
            extract_ms,
            keygen_ms,
            setup_ms,
        } = prepared;
        let t2 = std::time::Instant::now();
        let ctx = {
            use crate::mle::machine::recursion::gpu;
            // Times device trace-gen; the rest self-records inside `engine.prove`. The driver must
            // `take()` right after this chunk's prove, or the accumulator leaks into the next arm.
            let _bt = cuda_mle::breakdown::start();
            let ctx = gpu::build_ctx_gpu(
                &record,
                &self.chips,
                crate::mle::machine::riscv::bound_device(),
                "gpu-convert",
            );
            cuda_mle::breakdown::stop_tracegen(_bt);
            if crate::mle::env_flag("MLE_RECURSION_TRACE_COMPARE") {
                gpu::assert_ctx_matches_cpu(&ctx, &record, &self.chips);
            }
            ctx
        };
        BuiltConvert {
            vk,
            pk,
            ctx,
            extract_ms,
            keygen_ms,
            setup_ms,
            tracegen_ms: t2.elapsed().as_millis(),
        }
    }

    /// The prove half: consumes a [`BuiltConvert`] whose ctx is already device-resident.
    pub fn prove_built(&self, built: BuiltConvert) -> eyre::Result<ProofWithVk> {
        // Labels this thread's `[rsprof]`/`[stepprof]` timer lines.
        cuda_mle::set_prove_phase("convert");
        let BuiltConvert {
            vk,
            pk,
            ctx,
            extract_ms,
            keygen_ms,
            setup_ms,
            tracegen_ms,
        } = built;
        let t3 = std::time::Instant::now();
        let result = self
            .engine
            .prove(&pk, ctx)
            .map(|p| (p, vk))
            .map_err(|e| eyre::eyre!("{e:?}"));
        // On `bench`: the shipped filter drops this module's target, and this is the only line
        // carrying the per-chunk cost split.
        //
        // `extract_ms` was INSERTED at the front of this line, not appended. The previous shape was
        // `gpu_convert_timing: keygen_ms = …`, so anything anchored on that prefix reads nothing
        // now. This line has an out-of-tree consumer, so changing its shape means changing that
        // consumer in the same change.
        // `keygen_ms` CHANGED MEANING here: it no longer includes the layout extraction, which now has its
        // own field. A two-arm comparison whose base predates this commit is therefore comparing
        // keygen-with-extraction against keygen-without, under one field name, and nothing in the two
        // numbers says so.
        tracing::info!(
            target: "bench",
            "gpu_convert_timing: extract_ms = {extract_ms}, keygen_ms = {keygen_ms}, \
             setup_ms = {setup_ms}, tracegen_ms = {tracegen_ms}, prove_ms = {}",
            t3.elapsed().as_millis()
        );
        result
    }

    /// Verify a convert proof against its vk (host verifier). Thin wrapper so drivers don't need
    /// the `StarkEngine` trait in scope.
    pub fn verify(&self, vk: &MultiStarkVerifyingKey<Sc>, proof: &Proof<Sc>) -> eyre::Result<()> {
        StarkEngine::verify(&self.engine, vk, proof).map_err(|e| eyre::eyre!("{e:?}"))
    }

    /// Cache lookup by layout; keygen + insert (with LRU eviction) on miss. Returns clones of the
    /// entry's handles: (program, vk, prover key).
    ///
    /// The lock is held across a miss's KEYGEN — serializing a card's keygens is simpler and also
    /// prevents duplicate keygen of the same layout racing in — but deliberately NOT across the
    /// program build. That build is card-independent and shared process-wide, so a waiter on it
    /// is waiting for another thread; holding this card's pk cache meanwhile would block every
    /// other preparer on this card, including ones whose own layout is already cached. The lock is
    /// dropped and the entry re-checked on re-acquire, since another preparer on this card can
    /// insert in the gap.
    #[allow(clippy::type_complexity)]
    fn get_or_keygen(
        &self,
        layout: RecursionVkLayout,
    ) -> (
        Arc<RecursionProgram<Kb>>,
        Arc<MultiStarkVerifyingKey<Sc>>,
        GpuPk,
    ) {
        {
            let mut guard = self.cache.lock().unwrap();
            let (entries, tick) = &mut *guard;
            *tick += 1;
            let now = *tick;
            if let Some(e) = entries
                .iter_mut()
                .find(|e| recursion_vk_layouts_equal(&e.layout, &layout))
            {
                e.last_used = now;
                return (e.program.clone(), e.vk.clone(), e.device_pk.clone());
            }
        }

        // Miss: take the verify program for this layout (built in the process's whitelist mode,
        // see `build_convert_program`) and keygen.
        let keygen_span = crate::mle::spans::busy(crate::mle::spans::WorkKind::Keygen, None);
        let t = std::time::Instant::now();
        let mut timing = MissTiming::default();
        // The program comes from the PROCESS-GLOBAL cache (see [`program_for_layout`]): it is a
        // pure function of the layout and the dominant term of a miss, so a pre-build off the
        // critical path (`prebuild_program`) or another card's earlier miss serves this call.
        // `program_ms` reads ~0 on a hit and the full build on a miss; `program_hit` says which.
        // Runs with NO pk lock held — see this function's doc.
        let t_program = std::time::Instant::now();
        let (program, built_here, layout_clone_us) = program_for_layout(&layout, false);
        timing.program_ms = t_program.elapsed().as_millis();
        timing.program_hit = !built_here;
        timing.layout_clone_us = layout_clone_us;

        let mut guard = self.cache.lock().unwrap();
        let (entries, tick) = &mut *guard;
        *tick += 1;
        let now = *tick;
        // Re-check: the program build ran unlocked, and another preparer on this card can have
        // keygen'd the same layout in that window. Taking theirs keeps one device pk per layout.
        if let Some(e) = entries
            .iter_mut()
            .find(|e| recursion_vk_layouts_equal(&e.layout, &layout))
        {
            e.last_used = now;
            return (e.program.clone(), e.vk.clone(), e.device_pk.clone());
        }

        let (vk, pk) = {
            use crate::mle::machine::recursion::gpu;
            let t_keygen_call = std::time::Instant::now();
            let (vk, device_pk) = gpu::keygen_recursion_gpu(
                &self.engine,
                &program,
                &self.chips,
                crate::mle::machine::riscv::bound_device(),
            );
            // The CPU keygen's 100-bit gate; the GPU preparers cannot return an error, so it panics.
            admit_production_vk("convert", "gpu", &vk).unwrap_or_else(|e| panic!("{e}"));
            timing.keygen_call_us = t_keygen_call.elapsed().as_micros();
            // Populate the JIT kernels for this key's AIRs. The first shape nvrtc-compiles; later
            // layouts hit the disk cubin cache (sources depend only on the AIR constraints), so no
            // mid-pipeline nvrtc compile happens. Concurrent keygens are serialised inside
            // `compile_kernel`.
            let device_pk = Arc::new(device_pk);
            let t_jit = std::time::Instant::now();
            cuda_mle::warmup_jit_kernels::<cuda_mle::hash_scheme::KoalaBearPoseidon2HashScheme>(
                &device_pk,
            );
            timing.jit_ms = t_jit.elapsed().as_millis();
            (Arc::new(vk), device_pk)
        };
        drop(keygen_span);
        // Append new fields, never insert — the sibling `gpu_convert_timing:` line's prefix is what
        // tells the two apart. On `bench` for the same reason as that sibling.
        //
        // `program_ms` is reported by TWO line families and they mean opposite things: this one is
        // a build (or a hit) on the critical path, `gpu_convert_program build:` is an
        // off-critical-path pre-build. Summing them double-counts convert keygen cost — filter by
        // prefix.
        tracing::info!(
            target: "bench",
            "gpu_convert_timing keygen(miss): {} ms (cache {}/{}), program_ms = {}, jit_ms = {}, \
             program_hit = {}",
            t.elapsed().as_millis(),
            entries.len() + 1,
            self.cache_cap,
            timing.program_ms,
            timing.jit_ms,
            timing.program_hit
        );
        timing.log(t.elapsed().as_micros());

        // Bounded LRU: evict the stalest entry beyond capacity (never the one just inserted).
        if entries.len() >= self.cache_cap {
            if let Some(idx) = entries
                .iter()
                .enumerate()
                .min_by_key(|(_, e)| e.last_used)
                .map(|(i, _)| i)
            {
                let evicted = entries.swap_remove(idx);
                tracing::info!(
                    "gpu_convert: evicted a cached layout (last_used tick {})",
                    evicted.last_used
                );
            }
        }
        let entry = GpuPkEntry {
            layout,
            program: program.clone(),
            vk: vk.clone(),
            device_pk: pk.clone(),
            last_used: now,
        };
        entries.push(entry);
        (program, vk, pk)
    }
}

/// A convert with its proving context already built (device-resident). Consumed by
/// [`GpuConvertMachine::prove_built`] on the same thread that built it — a built ctx must not park
/// between build and prove, or its residency lands inside some other prove's VRAM high-water.
#[cfg(feature = "cuda")]
pub struct BuiltConvert {
    vk: Arc<MultiStarkVerifyingKey<Sc>>,
    pk: GpuPk,
    ctx: pico_mle_core::prover::ProvingContext<GpuPbKb>,
    /// Carried through only so `prove_built` can report the whole per-chunk stage split on one
    /// line; the build itself has no use for it.
    extract_ms: u128,
    keygen_ms: u128,
    setup_ms: u128,
    tracegen_ms: u128,
}

/// Output of the CPU preparation stage ([`GpuConvertMachine::prepare_one`]), ready for the
/// GPU stage ([`GpuConvertMachine::prove_prepared`]). Flows through the pipeline channel.
#[cfg(feature = "cuda")]
pub struct GpuPreparedConvert {
    vk: Arc<MultiStarkVerifyingKey<Sc>>,
    pk: GpuPk,
    record: crate::emulator::recursion::emulator::RecursionRecord<Kb>,
    /// Layout extraction, measured apart from `keygen_ms` because it is paid on a cache hit too.
    extract_ms: u128,
    keygen_ms: u128,
    setup_ms: u128,
}
