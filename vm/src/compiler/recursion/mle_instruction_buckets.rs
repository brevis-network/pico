//! Positions of each MLE-only instruction variant within `instructions`, classified in one pass
//! and cached on the program (see `RecursionProgram::bucket_for_pass`), so a chip's
//! `gpu_generate_preprocessed` narrows to its own candidates instead of scanning the whole program.
//!
//! Separate from [`super::instruction_buckets::InstructionBuckets`], which covers only the 9-chip
//! FRI set and is deliberately not extended: it is `Serialize`d into `program_cache.bin` for the
//! FRI distributed workers over a codec that is not self-describing, so new fields there would
//! break every existing cache file. This type is never serialized.
//!
//! **Positions, not copies.** Two reasons, both about not introducing defects:
//!
//! * The MLE variants that carry `Vec` fields (`UnivariateFold`, `ExtDotProduct`, `HornerEval`,
//!   `ExpBitsLen`) would each have to be *cloned* into an owned bucket, duplicating those vectors
//!   for the lifetime of the bucket. A `u32` position duplicates nothing, so the whole structure
//!   costs 4 bytes per matching instruction rather than a copy of the program's payloads.
//! * A consumer keeps its existing `filter_map` over `Instruction` verbatim and only changes *what
//!   it iterates*. So a position list that is wrong can only ever cause a chip to see fewer
//!   candidates — never one instruction's payload read as another's. [`MleVariant::of`] is used
//!   only to *build* the buckets; the unbucketed arm of [`Candidates`] yields the whole program
//!   exactly as the pre-bucketing scan did, so it cannot narrow anything either.
//!
//! **What catches a wrong position list, precisely.** Fewer candidates means fewer rows, and how
//! loudly that fails depends on where it is read:
//!
//! * `assemble_pk_with_device_merged_prep` compares each device matrix against the host keygen's
//!   *declared* geometry (`ChipBehavior::preprocessed_rows`, which reads the independent
//!   [`super::prep_rows::PrepRowCounts`] tally) on every call, cross-check or not. The production
//!   recursion keygen builds its program with no shape, so `padded_prep_rows` is
//!   `next_power_of_two(max(rows, 16))` and a short bucket usually shrinks that height — but it is
//!   a *padded-height* comparison, so an under-report staying inside the same power of two, or
//!   anything under the 16-row floor, passes it.
//! * The exact, row-for-row oracle is the host↔device digest equality inside
//!   `keygen_recursion_gpu_with`, which runs under `MLE_KEYGEN_CROSSCHECK=1` and by default in
//!   `cfg(test)`. So `test_keygen_recursion_gpu_all_instruction_variants_match_host` witnesses all
//!   14 variants, but nothing witnesses them in a production run, and CI never runs the GPU tests.
//!
//! Treat that parity test as the gate on any change to how instructions are located here, and do
//! not expect a production run to catch an off-by-a-few.

use std::sync::Arc;

use super::instruction::Instruction;

/// An MLE-only instruction variant — one whose chip is absent from
/// [`super::instruction_buckets::InstructionBuckets`]. The discriminant is the bucket index.
///
/// The 7 chips the MLE recursion set shares with the FRI set (MemoryConst, MemoryVar, BaseAlu,
/// ExtAlu, Select, Poseidon2, PublicValues) are absent: they already read `InstructionBuckets`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MleVariant {
    AssertZeroExt,
    FracFold,
    MleOpen,
    UnivariateFold,
    LagrangeEvalD2,
    GkrSumcheckRound,
    ExtDotProduct,
    HornerEval,
    DigestSelect,
    BinaryFoldStep,
    PackBlock,
    UnpackBlock,
    Poseidon2Packed,
    ExpBitsLen,
}

impl MleVariant {
    /// Every variant, in discriminant order — the one list this module is sized by. A variant left
    /// out is an out-of-bounds bucket index on first use, not a silent miscount, and
    /// `variants_are_indexed_by_discriminant` pins the pairing.
    pub const ALL: [Self; 14] = [
        Self::AssertZeroExt,
        Self::FracFold,
        Self::MleOpen,
        Self::UnivariateFold,
        Self::LagrangeEvalD2,
        Self::GkrSumcheckRound,
        Self::ExtDotProduct,
        Self::HornerEval,
        Self::DigestSelect,
        Self::BinaryFoldStep,
        Self::PackBlock,
        Self::UnpackBlock,
        Self::Poseidon2Packed,
        Self::ExpBitsLen,
    ];

    pub const COUNT: usize = Self::ALL.len();

    /// The variant `instruction` belongs to, or `None` for a FRI-set variant (which has its own
    /// bucket) or one carrying no preprocessed trace.
    ///
    /// Matched exhaustively rather than with a `_` arm so a new MLE instruction variant fails to
    /// compile here instead of silently never being bucketed.
    pub fn of<F>(instruction: &Instruction<F>) -> Option<Self> {
        match instruction {
            Instruction::AssertZeroExt(_) => Some(Self::AssertZeroExt),
            Instruction::FracFold(_) => Some(Self::FracFold),
            Instruction::MleOpen(_) => Some(Self::MleOpen),
            Instruction::UnivariateFold(_) => Some(Self::UnivariateFold),
            Instruction::LagrangeEvalD2(_) => Some(Self::LagrangeEvalD2),
            Instruction::GkrSumcheckRound(_) => Some(Self::GkrSumcheckRound),
            Instruction::ExtDotProduct(_) => Some(Self::ExtDotProduct),
            Instruction::HornerEval(_) => Some(Self::HornerEval),
            Instruction::DigestSelect(_) => Some(Self::DigestSelect),
            Instruction::BinaryFoldStep(_) => Some(Self::BinaryFoldStep),
            Instruction::PackBlock(_) => Some(Self::PackBlock),
            Instruction::UnpackBlock(_) => Some(Self::UnpackBlock),
            Instruction::Poseidon2Packed(_) => Some(Self::Poseidon2Packed),
            Instruction::ExpBitsLen(_) => Some(Self::ExpBitsLen),
            Instruction::BaseAlu(_)
            | Instruction::ExtAlu(_)
            | Instruction::Mem(_)
            | Instruction::Poseidon2(_)
            | Instruction::Select(_)
            | Instruction::ExpReverseBitsLen(_)
            | Instruction::BatchFRI(_)
            | Instruction::CommitPublicValues(_)
            | Instruction::Hint(_)
            | Instruction::HintBits(_)
            | Instruction::HintExt2Felts(_)
            | Instruction::HintAddCurve(_)
            | Instruction::Print(_) => None,
        }
    }
}

/// Positions in `instructions` of every MLE-only variant, in ascending order — so a consumer that
/// gathers by these indices sees its instructions in original program order, exactly as its raw
/// scan did.
#[derive(Debug)]
pub struct MleInstructionBuckets {
    /// Indexed by `variant as usize` and read only through [`Self::positions`], so no consumer
    /// ever names a bucket by anything but its variant.
    positions: [Box<[u32]>; MleVariant::COUNT],
    /// The program length these positions were classified from; checked by [`Candidates::new`].
    #[cfg_attr(not(feature = "cuda"), allow(dead_code))]
    n_instructions: usize,
}

impl MleInstructionBuckets {
    /// One pass over `instructions`, pushing each MLE variant's position onto its own list.
    ///
    /// Unlike `InstructionBuckets::from_instructions` this does not pre-count to size exactly:
    /// there is nothing to size but `Vec<u32>`s, so amortized growth is cheaper than a second
    /// full pass over a 1–2 M instruction program.
    ///
    /// # Panics
    /// If `instructions.len()` exceeds `u32::MAX`. Recursion programs are ~1–2 M instructions;
    /// the assert is here so the narrowing can never wrap silently.
    pub fn from_instructions<F>(instructions: &[Instruction<F>]) -> Self {
        assert!(
            u32::try_from(instructions.len()).is_ok(),
            "recursion program has {} instructions, which does not fit the u32 positions this \
             bucket stores",
            instructions.len()
        );
        let mut lists: [Vec<u32>; MleVariant::COUNT] = std::array::from_fn(|_| Vec::new());
        for (i, instruction) in instructions.iter().enumerate() {
            if let Some(variant) = MleVariant::of(instruction) {
                lists[variant as usize].push(i as u32);
            }
        }
        Self {
            positions: lists.map(Vec::into_boxed_slice),
            n_instructions: instructions.len(),
        }
    }

    fn positions(&self, variant: MleVariant) -> &[u32] {
        &self.positions[variant as usize]
    }
}

/// The instructions a chip has to consider: one variant's pre-classified candidates when the
/// buckets have been built, else the whole program.
///
/// Consumers keep their own `filter_map` over `Instruction` unchanged and only swap what it
/// iterates, which is what bounds the blast radius — see the module docs. Both arms yield in
/// ascending position order, so a chip sees its instructions in program order either way.
///
/// Holds an owned `Arc` rather than a lock guard, so a generation pass can neither deadlock
/// against a concurrent clear nor have its positions freed underneath it.
pub struct Candidates<'a, F> {
    instructions: &'a [Instruction<F>],
    buckets: Option<Arc<MleInstructionBuckets>>,
    variant: MleVariant,
    next: usize,
}

impl<'a, F> Candidates<'a, F> {
    /// # Panics
    /// In debug, if `buckets` was classified from a program of a different length than
    /// `instructions` — the one stale-bucket case that would otherwise quietly yield fewer rows.
    /// A position out of range panics on indexing in either profile, rather than reading a
    /// neighbouring instruction.
    #[cfg_attr(not(feature = "cuda"), allow(dead_code))]
    pub(crate) fn new(
        instructions: &'a [Instruction<F>],
        buckets: Option<Arc<MleInstructionBuckets>>,
        variant: MleVariant,
    ) -> Self {
        debug_assert!(
            buckets
                .as_ref()
                .is_none_or(|b| b.n_instructions == instructions.len()),
            "MLE instruction buckets are stale: classified from {:?} instructions, asked about {}",
            buckets.as_ref().map(|b| b.n_instructions),
            instructions.len()
        );
        Self {
            instructions,
            buckets,
            variant,
            next: 0,
        }
    }
}

impl<'a, F> Iterator for Candidates<'a, F> {
    type Item = &'a Instruction<F>;

    fn next(&mut self) -> Option<Self::Item> {
        let instructions = self.instructions;
        let (variant, next) = (self.variant, self.next);
        // Either `?`/`return` ends the iterator: an exhausted bucket, or the end of the program.
        let index = match self.buckets.as_deref() {
            Some(buckets) => *buckets.positions(variant).get(next)? as usize,
            // Deliberately the whole program rather than an `MleVariant::of` filter: this arm has
            // to stay byte-identical to the scan every consumer did before bucketing existed.
            None if next < instructions.len() => next,
            None => return None,
        };
        self.next = next + 1;
        // Indexed rather than `get`: a position out of range means these buckets were built from a
        // different program, which has to be loud and not a quietly shorter trace.
        Some(&instructions[index])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `positions` is indexed by `variant as usize`, so `ALL` has to be complete and in
    /// discriminant order — a variant listed twice or out of order aliases two chips' buckets.
    #[test]
    fn variants_are_indexed_by_discriminant() {
        for (i, variant) in MleVariant::ALL.iter().enumerate() {
            assert_eq!(*variant as usize, i, "ALL[{i}] is {variant:?}");
        }
    }
}
