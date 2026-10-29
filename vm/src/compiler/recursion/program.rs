#[cfg(feature = "cuda")]
use super::mle_instruction_buckets::{Candidates, MleVariant};
use super::{
    instruction::Instruction, instruction_buckets::InstructionBuckets,
    mle_instruction_buckets::MleInstructionBuckets, prep_rows::PrepRowCounts,
};
use crate::{
    compiler::program::ProgramBehavior,
    instances::compiler::shapes::recursion_shape::RecursionPadShape, machine::septic::SepticDigest,
};
use backtrace::Backtrace;
use hashbrown::HashMap;
use p3_field::Field;
use serde::{Deserialize, Serialize};
use tracing::debug;

#[derive(Debug, Serialize, Deserialize)]
pub struct RecursionProgram<F> {
    pub instructions: Vec<Instruction<F>>,
    pub total_memory: usize,
    #[serde(skip)]
    pub traces: Vec<Option<Backtrace>>,
    pub shape: Option<RecursionPadShape>,
    /// Pre-computed instruction buckets.
    /// Serialized into `program_cache.bin` for maximal performance.
    pub instruction_buckets: std::sync::RwLock<Option<InstructionBuckets<F>>>,
    /// Lazy [`PrepRowCounts`] over `instructions`; read through [`Self::prep_row_counts`].
    /// Not serialized — deriving it on demand leaves no way for the two to disagree.
    #[serde(skip)]
    pub(crate) prep_row_counts_cache: std::sync::OnceLock<PrepRowCounts>,

    /// Half-open instruction range of each child's `verify_one`, in child order.
    ///
    /// A combine program is prologue | child 0 | child 1 | merge, and `Runtime::run_split`
    /// interprets the two children at once. This is how it knows where to cut.
    ///
    /// Recorded by [`ConvertVerifierCircuit::build_verify_n_program_multi`], which is the only
    /// place that knows; empty on a program built any other way, and the emulator then runs
    /// serially. Not serialized: it is a property of how the program was built, and a program
    /// that arrives without it must fall back rather than trust a stale range.
    #[serde(skip)]
    pub child_spans: Vec<(usize, usize)>,

    /// Backing store for [`Self::const_write_positions`]. A pure derivation of `instructions`,
    /// like `prep_row_counts_cache`, and not serialized for the same reason.
    #[serde(skip)]
    pub(crate) const_writes_cache: std::sync::OnceLock<Vec<u32>>,
    /// Positions of the MLE-only instruction variants, built and dropped by
    /// [`Self::bucket_for_pass`] and read through [`Self::mle_candidates`]. The MLE sibling of
    /// `instruction_buckets`, and deliberately NOT serialized: it is a pure derivation of
    /// `instructions`, and unlike `instruction_buckets` no cache file has ever contained it.
    ///
    /// Held behind an `Arc` so a reader takes a handle and releases the lock immediately, rather
    /// than holding a guard across its whole generation pass. That is what makes clearing safe at
    /// any point: a chip still working keeps its own handle alive.
    #[serde(skip)]
    pub(crate) mle_instruction_buckets:
        std::sync::RwLock<Option<std::sync::Arc<MleInstructionBuckets>>>,
    /// Live [`BucketScope`] count, and what the buckets looked like before the first of them.
    ///
    /// One `RecursionProgram` is shared process-wide across cards (`mle/machine/convert.rs`), so
    /// two keygens run passes over it concurrently. Per-scope restore flags would let the first to
    /// finish clear buckets the second is still reading — correct, but it drops that pass onto the
    /// raw whole-program scan the buckets exist to avoid. Only the LAST scope out restores.
    ///
    /// Gated with its only reader: without `cuda` there is no `BucketScope`, so an ungated
    /// field here would be written by `Default`/`Clone` and never read — dead code in the
    /// no-CUDA build of this crate, which is compiled under `deny(warnings)`.
    #[cfg(feature = "cuda")]
    #[serde(skip)]
    pub(crate) bucket_passes: std::sync::Mutex<BucketPasses>,
}

/// Nesting state for [`RecursionProgram::bucket_for_pass`].
#[cfg(feature = "cuda")]
#[derive(Debug, Default)]
pub(crate) struct BucketPasses {
    /// Live scopes over this program.
    active: usize,
    /// Whether each bucket set was absent when `active` last rose from 0 — i.e. whether these
    /// passes own it. Buckets that arrived from `program_cache.bin` are never ours to drop.
    restore_fri: bool,
    restore_mle: bool,
}

// Hand-written (not derived) so `Default` does not require `F: Default`, which the generic
// construction sites (`..Default::default()`) do not have.
impl<F> Default for RecursionProgram<F> {
    fn default() -> Self {
        Self {
            instructions: Vec::new(),
            total_memory: 0,
            traces: Vec::new(),
            shape: None,
            child_spans: Vec::new(),
            const_writes_cache: std::sync::OnceLock::new(),
            instruction_buckets: std::sync::RwLock::new(None),
            prep_row_counts_cache: std::sync::OnceLock::new(),
            mle_instruction_buckets: std::sync::RwLock::new(None),
            #[cfg(feature = "cuda")]
            bucket_passes: std::sync::Mutex::new(BucketPasses::default()),
        }
    }
}

impl<F: Clone> Clone for RecursionProgram<F> {
    fn clone(&self) -> Self {
        Self {
            instructions: self.instructions.clone(),
            total_memory: self.total_memory,
            traces: self.traces.clone(),
            shape: self.shape.clone(),
            // Same `instructions`, so the same ranges and the same constant positions.
            child_spans: self.child_spans.clone(),
            const_writes_cache: match self.const_writes_cache.get() {
                Some(c) => std::sync::OnceLock::from(c.clone()),
                None => std::sync::OnceLock::new(),
            },
            instruction_buckets: std::sync::RwLock::new(
                self.instruction_buckets.read().unwrap().clone(),
            ),
            // Same `instructions`, same counts — carry them rather than recompute.
            prep_row_counts_cache: match self.prep_row_counts_cache.get() {
                Some(c) => std::sync::OnceLock::from(c.clone()),
                None => std::sync::OnceLock::new(),
            },
            // Same `instructions`, same positions. Carrying is an `Arc` bump, not a copy.
            mle_instruction_buckets: std::sync::RwLock::new(
                self.mle_instruction_buckets.read().unwrap().clone(),
            ),
            // Scope nesting is per instance, never inherited: a clone has no live scopes.
            #[cfg(feature = "cuda")]
            bucket_passes: std::sync::Mutex::new(BucketPasses::default()),
        }
    }
}

impl<F: Field> ProgramBehavior<F> for RecursionProgram<F> {
    fn pc_start(&self) -> [F; 3] {
        [F::ZERO; 3]
    }

    fn clone(&self) -> Self {
        Clone::clone(self)
    }

    fn initial_global_cumulative_sum(&self) -> SepticDigest<F> {
        SepticDigest::<F>::zero()
    }
}

impl<F> RecursionProgram<F> {
    /// Positions of the `Instruction::Mem(Write)` constants, found on first call and cached.
    ///
    /// `Runtime::run_split` evaluates them ahead of the fork and would otherwise rescan a
    /// quarter-million instructions per node to find them. One program serves many nodes, so
    /// the scan is paid once.
    ///
    /// Cached, and `instructions` is public: editing a program after this has been called
    /// leaves the cache describing the old one. Build the program, then read it.
    pub fn const_write_positions(&self) -> &[u32] {
        self.const_writes_cache.get_or_init(|| {
            self.instructions
                .iter()
                .enumerate()
                .filter(|(_, i)| crate::emulator::recursion::emulator::is_const_write(i))
                .map(|(i, _)| i as u32)
                .collect()
        })
    }

    /// Unpadded preprocessed row counts for every MLE recursion chip, tallied on first call in a
    /// single pass over `instructions` and cached.
    pub(crate) fn prep_row_counts(&self) -> &PrepRowCounts {
        self.prep_row_counts_cache
            .get_or_init(|| PrepRowCounts::from_instructions(&self.instructions))
    }

    /// A guard over the FRI-set buckets. Returns a lock guard rather than an owned handle (the
    /// shape [`Self::mle_candidates`] uses) because `InstructionBuckets` owns instruction *copies*
    /// and is far too large to hand out by value.
    pub fn get_buckets(
        &self,
    ) -> Option<std::sync::RwLockReadGuard<'_, Option<InstructionBuckets<F>>>> {
        let lock = self.instruction_buckets.read().unwrap();
        if lock.is_some() {
            Some(lock)
        } else {
            None
        }
    }

    /// The instructions a chip has to consider for `variant`: its pre-classified positions when
    /// [`Self::bucket_for_pass`] has built the MLE buckets, else the whole program.
    ///
    /// Answering with the whole program is always correct — the caller's own `filter_map` is what
    /// selects payloads — so this needs no fallback logic at the call site. Only the GPU
    /// preprocessed generators call it.
    #[cfg(feature = "cuda")]
    pub(crate) fn mle_candidates(&self, variant: MleVariant) -> Candidates<'_, F> {
        Candidates::new(
            &self.instructions,
            self.mle_instruction_buckets.read().unwrap().clone(),
            variant,
        )
    }
}

impl<F: Field> RecursionProgram<F> {
    pub fn ensure_bucketed(&self) {
        // Double-checked locking pattern for speed and correctness
        if self.instruction_buckets.read().unwrap().is_none() {
            let mut lock = self.instruction_buckets.write().unwrap();
            if lock.is_none() {
                *lock = Some(InstructionBuckets::from_instructions(&self.instructions));
            }
        }
    }

    /// Classify the MLE-only instruction variants by position, once. Idempotent, with the same
    /// double-checked locking as [`Self::ensure_bucketed`], so concurrent callers build it once.
    #[cfg(feature = "cuda")]
    fn ensure_mle_bucketed(&self) {
        if self.mle_instruction_buckets.read().unwrap().is_none() {
            let mut lock = self.mle_instruction_buckets.write().unwrap();
            if lock.is_none() {
                *lock = Some(std::sync::Arc::new(
                    MleInstructionBuckets::from_instructions(&self.instructions),
                ));
            }
        }
    }

    /// Build both bucket sets for one pass over the program, and drop again whatever *this* call
    /// built when the returned guard falls.
    ///
    /// Buckets are worth building per pass but not worth keeping: `InstructionBuckets` holds owned
    /// copies of every FRI-set variant, so on a program a key cache keeps alive they cost that
    /// much host RAM per cached entry. The MLE recursion keygen wants them only for the duration of
    /// its preprocessed-generation loop.
    ///
    /// Restoring, not clearing, is the point of the guard: `instruction_buckets` is `pub`, is
    /// `Serialize`d into `program_cache.bin`, and can therefore arrive already populated from a
    /// cache this pass does not own. A guard that cleared unconditionally would throw that away.
    ///
    /// Gated on `cuda` because `mle::machine::recursion::gpu` is the sole caller and is itself
    /// gated, so without the feature this would be dead code rather than merely unused. The reader
    /// side, [`Self::mle_candidates`], is deliberately NOT gated: the chips call it unconditionally
    /// (`ChipBehavior::gpu_generate_preprocessed` is not feature-gated), and without this builder
    /// it simply always answers with the whole program, leaving every chip on its raw scan.
    /// `#[must_use]` because discarding the guard drops the buckets immediately: the pass would
    /// then silently take the raw-scan path it was calling this to avoid.
    #[cfg(feature = "cuda")]
    #[must_use]
    pub(crate) fn bucket_for_pass(&self) -> BucketScope<'_, F> {
        {
            let mut passes = self.bucket_passes.lock().unwrap_or_else(|e| e.into_inner());
            // Only the outermost scope decides ownership. A later scope entering while the first
            // still runs would see the buckets present and wrongly conclude it must not restore
            // them -- harmless -- but the first would still clear them out from under it, which is
            // not. The count is what makes the decision the LAST scope's.
            if passes.active == 0 {
                passes.restore_fri = self.instruction_buckets.read().unwrap().is_none();
                passes.restore_mle = self.mle_instruction_buckets.read().unwrap().is_none();
            }
            passes.active += 1;
        }
        self.ensure_bucketed();
        self.ensure_mle_bucketed();
        BucketScope { program: self }
    }
}

/// Drops the buckets [`RecursionProgram::bucket_for_pass`] built, leaving any that were already
/// there alone -- and only once the LAST live scope over this program falls.
///
/// A holder of a [`RecursionProgram::get_buckets`] guard must release it before this falls, since
/// restoring takes the write lock. MLE readers cannot deadlock against it at all: they hold their
/// own `Arc`.
#[cfg(feature = "cuda")]
pub(crate) struct BucketScope<'a, F> {
    program: &'a RecursionProgram<F>,
}

#[cfg(feature = "cuda")]
impl<F> Drop for BucketScope<'_, F> {
    fn drop(&mut self) {
        // `unwrap_or_else(into_inner)`, not `unwrap`: a poisoned lock here would mean panicking
        // during a drop. The state behind it is two bools and a count -- nothing a panicking
        // builder can leave torn.
        let (restore_fri, restore_mle) = {
            let mut passes = self
                .program
                .bucket_passes
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            passes.active = passes.active.saturating_sub(1);
            if passes.active > 0 {
                // Another pass is still reading these buckets. Clearing now would drop it onto
                // the raw whole-program scan for every chip it has left.
                return;
            }
            (passes.restore_fri, passes.restore_mle)
        };
        if restore_fri {
            if let Ok(mut lock) = self.program.instruction_buckets.write() {
                *lock = None;
            }
        }
        if restore_mle {
            if let Ok(mut lock) = self.program.mle_instruction_buckets.write() {
                *lock = None;
            }
        }
    }
}

impl<F: Field> RecursionProgram<F> {
    #[inline]
    pub fn fixed_log2_rows(&self, chip_name: &String) -> Option<usize> {
        self.shape
            .as_ref()
            .map(|shape| {
                shape
                    .inner
                    .get(chip_name)
                    .unwrap_or_else(|| panic!("Chip {} not found in specified shape", chip_name))
            })
            .copied()
    }

    /// Padded preprocessed height for `chip_name` given its unpadded row count: the declared
    /// shape's height if the program carries a shape, else the next power of two above a 16-row
    /// floor. Agrees with both host padding families (`chips::utils::next_power_of_two` and
    /// `machine::utils::pad_to_power_of_two`), which differ only in rejecting an undersized shape.
    ///
    /// **An undersized shape must be rejected here, not rounded up.** Every
    /// `gpu_generate_preprocessed` sizes its device allocation from this and then launches a
    /// kernel bounded only by the instruction count, so `1 << log2_rows` below the real row count
    /// is an out-of-bounds device write. Keeping the assert in one place is why this is a method
    /// rather than a match repeated per chip.
    #[inline]
    pub(crate) fn padded_prep_rows(&self, chip_name: &String, nb_rows: usize) -> usize {
        let nb_rows = nb_rows.max(16);
        match self.fixed_log2_rows(chip_name) {
            Some(log2_rows) => {
                let padded = 1usize << log2_rows;
                assert!(
                    padded >= nb_rows,
                    "fixed_log2_rows too small for {chip_name}: 2^{log2_rows}={padded} < \
                     {nb_rows} real rows"
                );
                padded
            }
            None => nb_rows.next_power_of_two(),
        }
    }

    // compute number of each type of instructions in the program
    pub fn stats(&self) -> HashMap<String, usize> {
        let mut stats = HashMap::new();
        for instr in &self.instructions {
            let key = match instr {
                Instruction::BaseAlu(_) => "BaseAlu",
                Instruction::ExtAlu(_) => "ExtAlu",
                Instruction::Mem(_) => "Mem",
                Instruction::Poseidon2(_) => "Poseidon2",
                Instruction::Select(_) => "Select",
                Instruction::ExpReverseBitsLen(_) => "ExpReverseBitsLen",
                Instruction::BatchFRI(_) => "BatchFRI",
                Instruction::HintBits(_) => "HintBits",
                Instruction::Print(_) => "Print",
                Instruction::HintExt2Felts(_) => "HintExt2Felts",
                Instruction::CommitPublicValues(_) => "CommitPublicValues",
                Instruction::HintAddCurve(_) => "HintAddCurve",
                Instruction::Hint(_) => "Hint",
                Instruction::AssertZeroExt(_) => "AssertZeroExt",
                Instruction::FracFold(_) => "FracFold",
                Instruction::UnivariateFold(_) => "UnivariateFold",
                Instruction::MleOpen(_) => "MleOpen",
                Instruction::LagrangeEvalD2(_) => "LagrangeEvalD2",
                Instruction::GkrSumcheckRound(_) => "GkrSumcheckRound",
                Instruction::ExtDotProduct(_) => "ExtDotProduct",
                Instruction::HornerEval(_) => "HornerEval",
                Instruction::DigestSelect(_) => "DigestSelect",
                Instruction::BinaryFoldStep(_) => "BinaryFoldStep",
                Instruction::PackBlock(_) => "PackBlock",
                Instruction::UnpackBlock(_) => "UnpackBlock",
                Instruction::Poseidon2Packed(_) => "Poseidon2Packed",
                Instruction::ExpBitsLen(_) => "ExpBitsLen",
            };
            *stats.entry(key.to_string()).or_insert(0) += 1;
        }
        stats
    }

    // print stats of the program
    pub fn print_stats(&self) {
        let stats = self.stats();
        debug!("Program stats:");
        for (key, value) in stats {
            debug!("   |- {:<26}: {}", key, value);
        }
    }
}
