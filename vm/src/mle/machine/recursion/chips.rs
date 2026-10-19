//! Recursion chip set, keygen AIR refs, and proving-context construction.
//!
//! The recursion Poseidon2 chips run the field's one Poseidon2 instance (`FieldSpecificPoseidon2Config`,
//! Plonky3's `default_koalabear_poseidon2_16`), which is also the engine transcript's permutation, so the
//! circuit re-derives the RISCV proof's Fiat-Shamir transcript; [`RecursionPrepAir`] forwards each
//! chip's program-dependent preprocessed trace into keygen, and [`build_proving_ctx`] assembles the
//! per-chip main traces for proving.

use std::{marker::PhantomData, sync::Arc};

use p3_air::BaseAir;
use p3_field::Field;
use p3_matrix::{dense::RowMajorMatrix, Dimensions, Matrix};
use p3_maybe_rayon::prelude::*;

use crate::{
    chips::chips::{
        alu_base::BaseAluChip,
        alu_ext::ExtAluChip,
        assert_zero_ext::AssertZeroExtChip,
        binary_fold_step::BinaryFoldStepChip,
        digest_select::DigestSelectChip,
        exp_bits_len::ExpBitsLenChip,
        ext_dot_product::ExtDotProductChip,
        frac_fold::FracFoldChip,
        gkr_sumcheck_round::GkrSumcheckRoundChip,
        horner_eval::HornerEvalChip,
        lagrange_eval_d2::LagrangeEvalD2Chip,
        mle_open::MleOpenChip,
        pack_block::PackBlockChip,
        poseidon2::FieldSpecificPoseidon2Chip,
        poseidon2_packed::FieldSpecificPoseidon2PackedChip,
        public_values::PublicValuesChip,
        recursion_memory::{constant::MemoryConstChip, variable::MemoryVarChip},
        select::SelectChip,
        univariate_fold::UnivariateFoldChip,
        unpack_block::UnpackBlockChip,
    },
    compiler::recursion::program::RecursionProgram,
    emulator::recursion::emulator::RecursionRecord,
    instances::chiptype::recursion_chiptype::RecursionChipType,
    machine::chip::{ChipBehavior, MetaChip, PreprocessedRows},
    primitives::consts::RECURSION_NUM_PVS,
};
use pico_mle_core::{
    air::any_air::BaseAirWithPublicValues,
    prover::{AirProvingContext, ProvingContext},
    AirRef, PartitionedBaseAir, StarkProtocolConfig,
};
use pico_mle_cpu::CpuBackend;

use super::Kb;

/// The Poseidon2 chip for the recursion layer: the field's Poseidon2 instance
/// (`FieldSpecificPoseidon2Config::round_constants`), which is also the engine transcript's
/// permutation, so the circuit re-derives the RISCV proof's Fiat-Shamir transcript with the chip's
/// own constants. Both the keygen AIR (air refs) and the trace-gen chip set
/// (`mle_recursion_chips`) must use this.
pub fn recursion_poseidon2_chip() -> FieldSpecificPoseidon2Chip<Kb> {
    FieldSpecificPoseidon2Chip::<Kb>::default()
}

/// The packed-I/O Poseidon2 chip for the recursion layer, on the same instance as
/// [`recursion_poseidon2_chip`].
pub fn recursion_poseidon2_packed_chip() -> FieldSpecificPoseidon2PackedChip<Kb> {
    FieldSpecificPoseidon2PackedChip::<Kb>::default()
}

// ─── Program-dependent preprocessed wrapper ─────────────────────────────────────
//
// Keygen only calls `BaseAir::preprocessed_trace()` (no program argument), but every
// recursion chip's preprocessed trace is derived from the recursion *program*. This
// wrapper holds the program and forwards `generate_preprocessed` into the keygen path
// — the recursion analogue of [`crate::mle::machine::air::PrepAir`], which serves the
// RISCV program.

/// Wraps a recursion chip with the recursion program so keygen can read its
/// program-dependent preprocessed trace. `num_public_values` is reported to keygen
/// (the chips themselves don't declare it here, since they reuse `constraints.rs`
/// without the per-chip `BaseAirWithPublicValues` impl that a dedicated AIR module
/// would otherwise provide).
pub struct RecursionPrepAir<F, C> {
    pub inner: C,
    pub program: Arc<RecursionProgram<F>>,
    pub num_public_values: usize,
    _phantom: PhantomData<F>,
}

impl<F, C> RecursionPrepAir<F, C> {
    pub fn new(inner: C, program: Arc<RecursionProgram<F>>, num_public_values: usize) -> Self {
        Self {
            inner,
            program,
            num_public_values,
            _phantom: PhantomData,
        }
    }
}

impl<F, C> BaseAir<F> for RecursionPrepAir<F, C>
where
    F: Field,
    C: ChipBehavior<F, Program = RecursionProgram<F>>,
{
    fn width(&self) -> usize {
        BaseAir::<F>::width(&self.inner)
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        self.inner.generate_preprocessed(&self.program)
    }
}

impl<F, C> PartitionedBaseAir<F> for RecursionPrepAir<F, C>
where
    F: Field,
    C: ChipBehavior<F, Program = RecursionProgram<F>>,
{
    /// Declared geometry, so merged deferred-commit keygen can skip building the trace whose only
    /// surviving output is these two numbers. A chip that declares nothing falls through to the
    /// trait default, i.e. to generating the trace.
    fn preprocessed_dims(&self) -> Option<Dimensions> {
        let Some(rows) = self.inner.preprocessed_rows(&self.program) else {
            return BaseAir::<F>::preprocessed_trace(self).map(|t| t.dimensions());
        };
        let height = match rows {
            PreprocessedRows::FixedLog2(log2_rows) => 1 << log2_rows,
            // Same rule, same assert, one home: the five generators that read a declared
            // count pad with `padded_prep_rows` too, so a declaration cannot drift from the
            // generator it mirrors, and an undersized shape is rejected on both paths.
            PreprocessedRows::Unpadded(rows) => self
                .program
                .padded_prep_rows(&ChipBehavior::<F>::name(&self.inner), rows),
        };
        Some(Dimensions {
            height,
            width: ChipBehavior::<F>::preprocessed_width(&self.inner),
        })
    }
}

impl<F, C> BaseAirWithPublicValues<F> for RecursionPrepAir<F, C>
where
    F: Field,
    C: ChipBehavior<F, Program = RecursionProgram<F>>,
{
    fn num_public_values(&self) -> usize {
        self.num_public_values
    }
}

impl<F, C, CB> p3_air::Air<CB> for RecursionPrepAir<F, C>
where
    F: Field,
    C: ChipBehavior<F, Program = RecursionProgram<F>> + p3_air::Air<CB>,
    CB: p3_air::AirBuilder<F = F>,
{
    fn eval(&self, builder: &mut CB) {
        self.inner.eval(builder);
    }
}

// ─── Recursion AIR list + proving context (mirrors RISCV machine's build_ctx) ────

/// Build the ordered `AirRef<SC>` list for the recursion verifier circuit, with each
/// chip's program-dependent preprocessed trace attached via [`RecursionPrepAir`].
///
/// The order matches `RecursionChipType::mle_recursion_chips()`.
/// Takes an `&Arc` rather than an `&RecursionProgram` because the `Arc` is all the
/// [`RecursionPrepAir`]s need: each one holds a handle purely to satisfy the argument-free
/// `BaseAir::preprocessed_trace()`. Cloning the program instead would deep-copy 1-2M instructions
/// per keygen, and every production caller already owns an `Arc`.
///
/// Generic over the protocol config so the same chip set can be keygen'd under the inner
/// (Poseidon2-KoalaBear) config and under the outer BN254-hashed embed config. Only the hash and
/// transcript differ between those; the AIRs are pure KoalaBear, which is what `F = Kb` pins.
pub fn recursion_air_refs_with_preprocessed<SC: StarkProtocolConfig<F = Kb>>(
    program: &Arc<RecursionProgram<Kb>>,
) -> Vec<AirRef<SC>> {
    let p = Arc::clone(program);
    vec![
        Arc::new(RecursionPrepAir::new(
            MemoryConstChip::<Kb>::default(),
            p.clone(),
            0,
        )) as AirRef<SC>,
        Arc::new(RecursionPrepAir::new(
            MemoryVarChip::<Kb>::default(),
            p.clone(),
            0,
        )) as AirRef<SC>,
        Arc::new(RecursionPrepAir::new(
            BaseAluChip::<Kb>::default(),
            p.clone(),
            0,
        )) as AirRef<SC>,
        Arc::new(RecursionPrepAir::new(
            ExtAluChip::<Kb>::default(),
            p.clone(),
            0,
        )) as AirRef<SC>,
        Arc::new(RecursionPrepAir::new(
            SelectChip::<Kb>::default(),
            p.clone(),
            0,
        )) as AirRef<SC>,
        Arc::new(RecursionPrepAir::new(
            recursion_poseidon2_chip(),
            p.clone(),
            0,
        )) as AirRef<SC>,
        Arc::new(RecursionPrepAir::new(
            PublicValuesChip::<Kb>::default(),
            p.clone(),
            RECURSION_NUM_PVS,
        )) as AirRef<SC>,
        Arc::new(RecursionPrepAir::new(
            AssertZeroExtChip::<Kb>::default(),
            p.clone(),
            0,
        )) as AirRef<SC>,
        Arc::new(RecursionPrepAir::new(
            FracFoldChip::<Kb>::default(),
            p.clone(),
            0,
        )) as AirRef<SC>,
        Arc::new(RecursionPrepAir::new(
            MleOpenChip::<Kb>::default(),
            p.clone(),
            0,
        )) as AirRef<SC>,
        Arc::new(RecursionPrepAir::new(
            UnivariateFoldChip::<Kb>::default(),
            p.clone(),
            0,
        )) as AirRef<SC>,
        Arc::new(RecursionPrepAir::new(
            LagrangeEvalD2Chip::<Kb>::default(),
            p.clone(),
            0,
        )) as AirRef<SC>,
        Arc::new(RecursionPrepAir::new(
            GkrSumcheckRoundChip::<Kb>::default(),
            p.clone(),
            0,
        )) as AirRef<SC>,
        Arc::new(RecursionPrepAir::new(
            ExtDotProductChip::<Kb>::default(),
            p.clone(),
            0,
        )) as AirRef<SC>,
        Arc::new(RecursionPrepAir::new(
            HornerEvalChip::<Kb>::default(),
            p.clone(),
            0,
        )) as AirRef<SC>,
        Arc::new(RecursionPrepAir::new(
            DigestSelectChip::<Kb>::default(),
            p.clone(),
            0,
        )) as AirRef<SC>,
        Arc::new(RecursionPrepAir::new(
            BinaryFoldStepChip::<Kb>::default(),
            p.clone(),
            0,
        )) as AirRef<SC>,
        Arc::new(RecursionPrepAir::new(
            PackBlockChip::<Kb>::default(),
            p.clone(),
            0,
        )) as AirRef<SC>,
        Arc::new(RecursionPrepAir::new(
            UnpackBlockChip::<Kb>::default(),
            p.clone(),
            0,
        )) as AirRef<SC>,
        Arc::new(RecursionPrepAir::new(
            recursion_poseidon2_packed_chip(),
            p.clone(),
            0,
        )) as AirRef<SC>,
        Arc::new(RecursionPrepAir::new(ExpBitsLenChip::<Kb>::default(), p, 0)) as AirRef<SC>,
    ]
}

/// Build a [`ProvingContext`] from a recursion record: one main trace per chip (in
/// `mle_recursion_chips()` order). Preprocessed traces come from the proving key
/// (keygen reads them via [`RecursionPrepAir::preprocessed_trace`]); `cached_mains`
/// is empty. Only the `PublicValues` chip receives public values.
///
/// Generic over the protocol config for the same reason as
/// [`recursion_air_refs_with_preprocessed`]: with `SC::F = Kb`, `CpuBackend<SC>`'s `Val` and
/// `Matrix` are the same types for every such `SC`, so the traces built here are valid proving
/// input under both the inner and the outer config.
pub fn build_proving_ctx<SC: StarkProtocolConfig<F = Kb>>(
    record: &RecursionRecord<Kb>,
    // Used only for the `ChipBehavior` methods; the FRI parts are dead. See `ConvertMachine::new`.
    chips: &[MetaChip<Kb, RecursionChipType<Kb>>],
    role: &str,
) -> ProvingContext<CpuBackend<SC>> {
    let pvs: Vec<Kb> = record.public_values.as_array().to_vec();
    let per_trace: Vec<(usize, AirProvingContext<CpuBackend<SC>>)> = chips
        .par_iter()
        .enumerate()
        .map(|(air_id, chip)| {
            let trace = chip.generate_main(record, &mut RecursionRecord::<Kb>::default());
            let ctx = if chip.name() == "PublicValues" {
                AirProvingContext::simple(trace, pvs.clone())
            } else {
                AirProvingContext::simple_no_pis(trace)
            };
            (air_id, ctx)
        })
        .collect();
    // Height observability (one line per proof): what the recursion tier tables
    // (`shape::MLE_RECURSION_*_LOG_HEIGHTS`) were measured from, and what flags drift from them.
    tracing::info!(
        "recursion_heights[{role}]: {}",
        chips
            .iter()
            .zip(per_trace.iter())
            .map(|(chip, (_, ctx))| format!(
                "{}={}",
                chip.name(),
                p3_matrix::Matrix::height(&ctx.common_main)
            ))
            .collect::<Vec<_>>()
            .join(" ")
    );
    ProvingContext::new(per_trace)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pico_mle_core::config::koala_bear_poseidon2::KoalaBearPoseidon2Config;

    /// The AIR list length is the recursion chip-set size — the two must stay in lockstep, since
    /// `build_proving_ctx` pairs them positionally (slice index == AIR id).
    #[test]
    fn air_refs_match_the_chip_set_length() {
        let program = Arc::new(RecursionProgram::<Kb>::default());
        let airs = recursion_air_refs_with_preprocessed::<KoalaBearPoseidon2Config>(&program);
        assert_eq!(
            airs.len(),
            RecursionChipType::<Kb>::mle_recursion_chips().len()
        );
    }

    /// The generic-ization is real, not vacuous: both helpers must also instantiate at a config
    /// whose hash and transcript are BN254 rather than Poseidon2-KoalaBear. This is what the embed
    /// layer needs; a missing bound shows up here instead of 3,000 lines downstream.
    #[cfg(feature = "multi-field-transcript")]
    #[test]
    fn helpers_instantiate_at_the_outer_config() {
        use crate::mle::config::koala_bear_bn254_poseidon2::KoalaBearBn254Poseidon2Config as Outer;

        let program = Arc::new(RecursionProgram::<Kb>::default());
        let inner = recursion_air_refs_with_preprocessed::<KoalaBearPoseidon2Config>(&program);
        let outer: Vec<AirRef<Outer>> = recursion_air_refs_with_preprocessed(&program);
        // Same AIRs in the same order — the config only changes how they are committed to.
        assert_eq!(
            outer.iter().map(|a| a.name()).collect::<Vec<_>>(),
            inner.iter().map(|a| a.name()).collect::<Vec<_>>(),
        );

        // Compile-only for `build_proving_ctx`: it needs a real recursion record, which only the
        // embed prover can produce. Instantiating the type is what this guards.
        #[allow(dead_code)]
        fn outer_ctx_typechecks(
            record: &RecursionRecord<Kb>,
            chips: &[MetaChip<Kb, RecursionChipType<Kb>>],
        ) -> ProvingContext<CpuBackend<Outer>> {
            build_proving_ctx(record, chips, "embed")
        }
    }
}

/// Recursion programs used as fixtures by the preprocessed-geometry tests below.
#[cfg(test)]
pub(crate) mod test_programs {
    use super::*;
    use crate::{
        compiler::recursion::{
            instruction::{
                base_alu, commit_public_values, ext_alu, mem, poseidon2, HintAddCurveInstr,
                HintBitsInstr, HintExt2FeltsInstr, HintInstr, Instruction,
            },
            types::{
                Address, AssertZeroExtInstr, BinaryFoldStepInstr, DigestSelectInstr,
                ExpBitsLenInstr, ExtDotProductInstr, FracFoldInstr, GkrSumcheckRoundInstr,
                HornerEvalInstr, LagrangeEvalD2Instr, MemAccessKind, MleOpenInstr, PackBlockInstr,
                Poseidon2PackedInstr, SelectInstr, SelectIo, UnivariateFoldInstr, UnpackBlockInstr,
            },
        },
        emulator::recursion::{
            emulator::{BaseAluOpcode, ExtAluOpcode},
            public_values::RecursionPublicValues,
        },
        primitives::consts::EXTENSION_DEGREE,
    };
    use p3_field::PrimeCharacteristicRing;

    /// `n` of each declared chip's own instruction, plus the single `CommitPublicValues` every
    /// recursion program carries (the PublicValues chip requires exactly one).
    pub(crate) fn mixed_program(n: u32) -> RecursionProgram<Kb> {
        let mut instructions: Vec<Instruction<Kb>> = Vec::new();
        for i in 0..n {
            instructions.push(base_alu(BaseAluOpcode::AddF, 1, i, i, i));
            instructions.push(ext_alu(ExtAluOpcode::AddE, 1, i, i, i));
            instructions.push(mem(MemAccessKind::Write, 1, i, i));
            instructions.push(Instruction::AssertZeroExt(AssertZeroExtInstr {
                addr: Address(Kb::from_u32(i)),
            }));
            instructions.push(poseidon2([1; 16], [i; 16], [i; 16]));
            let a = Address(Kb::from_u32(i));
            instructions.push(Instruction::Select(SelectInstr {
                addrs: SelectIo {
                    bit: a,
                    out1: a,
                    out2: a,
                    in1: a,
                    in2: a,
                },
                mult1: Kb::ONE,
                mult2: Kb::ONE,
            }));
            // The three chips whose height is a SUM of per-instruction vector lengths, not an
            // instruction count — the counts most likely to be got wrong, so they need real
            // instructions here. Lengths satisfy each generator's own `debug_assert`: MemoryVar
            // takes every Hint variant's output list and the tally has one arm per variant, so
            // all four are emitted (4 accesses each = one whole `div_ceil(VAR_MEM_DATAPAR)` row);
            // ExtDotProduct needs `val_addrs` a multiple of `EXT_DOT_PRODUCT_GROUPS`(2) and
            // `mu_addrs` exactly 4x its group count; HornerEval needs `coeff_addrs` a multiple
            // of `HORNER_EVAL_DATAPAR`(4).
            instructions.push(Instruction::Hint(HintInstr {
                output_addrs_mults: vec![(a, Kb::ONE); 4],
            }));
            // Deliberately not a multiple of `VAR_MEM_DATAPAR`: the tally divides once, at the
            // end, over the sum across variants. Were it to divide per instruction the totals
            // would differ, and every length being a whole row would hide that.
            instructions.push(Instruction::HintBits(HintBitsInstr {
                output_addrs_mults: vec![(a, Kb::ONE); 6],
                input_addr: a,
            }));
            instructions.push(Instruction::HintExt2Felts(HintExt2FeltsInstr {
                output_addrs_mults: [(a, Kb::ONE); EXTENSION_DEGREE],
                input_addr: a,
            }));
            instructions.push(Instruction::HintAddCurve(Box::new(HintAddCurveInstr {
                output_x_addrs_mults: vec![(a, Kb::ONE); 2],
                output_y_addrs_mults: vec![(a, Kb::ONE); 2],
                input1_x_addrs: vec![a; 2],
                input1_y_addrs: vec![a; 2],
                input2_x_addrs: vec![a; 2],
                input2_y_addrs: vec![a; 2],
            })));
            instructions.push(Instruction::ExtDotProduct(Box::new(ExtDotProductInstr {
                mu_addrs: vec![a; 8],
                val_addrs: vec![a; 2],
                acc_addr: a,
                mult: Kb::ONE,
            })));
            instructions.push(Instruction::HornerEval(Box::new(HornerEvalInstr {
                coeff_addrs: vec![a; 4],
                x_addr: a,
                out_addr: a,
                mult: Kb::ONE,
            })));
            // The remaining declared chips. Values are irrelevant — the program is never emulated
            // or proven here, only measured — but every chip must appear at a NONZERO row count,
            // or its declaration is compared only against an empty trace and a wrong divisor (or a
            // count read off the wrong field) passes.
            instructions.push(Instruction::FracFold(FracFoldInstr {
                in_p1_addr: a,
                in_q1_addr: a,
                in_p2_addr: a,
                in_q2_addr: a,
                out_p_addr: a,
                out_q_addr: a,
                mult: Kb::ONE,
            }));
            instructions.push(Instruction::MleOpen(MleOpenInstr {
                col_ref: 0,
                opening_value_addr: a,
            }));
            instructions.push(Instruction::UnivariateFold(Box::new(UnivariateFoldInstr {
                coeffs_addrs: vec![a; 4],
                claimed_sum_addr: a,
                r_addr: a,
                next_sum_addr: a,
                mult: Kb::ONE,
            })));
            instructions.push(Instruction::LagrangeEvalD2(LagrangeEvalD2Instr {
                claim_addr: a,
                s1_addr: a,
                s2_addr: a,
                r_addr: a,
                next_claim_addr: a,
                mult: Kb::ONE,
            }));
            instructions.push(Instruction::GkrSumcheckRound(Box::new(
                GkrSumcheckRoundInstr {
                    claim_addr: a,
                    s1_addr: a,
                    s2_addr: a,
                    s3_addr: a,
                    r_addr: a,
                    xi_addr: a,
                    eq_in_addr: a,
                    next_claim_addr: a,
                    eq_out_addr: a,
                    mult_next: Kb::ONE,
                    mult_eq: Kb::ONE,
                },
            )));
            instructions.push(Instruction::DigestSelect(Box::new(DigestSelectInstr {
                bit_addr: a,
                in1_addrs: [a; 2],
                in2_addrs: [a; 2],
                out_addrs: [a; 2],
                mults: [Kb::ONE; 2],
            })));
            instructions.push(Instruction::BinaryFoldStep(Box::new(BinaryFoldStepInstr {
                tw_addr: a,
                xi_addr: a,
                inv_tw_addr: a,
                xi_inv_addr: a,
                alpha_addr: a,
                v_lo_addr: a,
                v_hi_addr: a,
                out_addr: a,
                mult: Kb::ONE,
            })));
            instructions.push(Instruction::PackBlock(Box::new(PackBlockInstr {
                in_addrs: [a; 4],
                out_addr: a,
                mult: Kb::ONE,
            })));
            instructions.push(Instruction::UnpackBlock(Box::new(UnpackBlockInstr {
                in_addr: a,
                out_addrs: [a; 4],
                mults: [Kb::ONE; 4],
            })));
            instructions.push(Instruction::Poseidon2Packed(Box::new(
                Poseidon2PackedInstr {
                    input_addrs: [a; 4],
                    output_addrs: [a; 4],
                    mults: [Kb::ONE; 4],
                },
            )));
            // `num_bits < 32` per the instruction's contract; the chip emits a fixed
            // `NUM_BITS_MAX_PLUS_ONE` block per instruction regardless.
            instructions.push(Instruction::ExpBitsLen(Box::new(ExpBitsLenInstr {
                base: Kb::ONE,
                num_bits: 31,
                bit_src_in_addr: a,
                result_out_addr: a,
                result_mult: Kb::ONE,
                bit_outs_addrs_mults: vec![(a, Kb::ONE); 31],
            })));
        }
        instructions.push(commit_public_values(
            &RecursionPublicValues::<u32>::default(),
        ));
        RecursionProgram {
            instructions,
            ..Default::default()
        }
    }
}

/// The declared preprocessed geometry must equal the generated trace's, for every recursion AIR.
///
/// This is the guard that makes [`ChipBehavior::preprocessed_rows`] safe to hand-write: each
/// override replicates one generator's row count, and a generator that changes without its
/// override fails here. It needs no device, so it runs wherever `cargo test -p pico-vm` runs.
#[cfg(test)]
mod dims_tests {
    use super::{test_programs::mixed_program, *};
    use pico_mle_core::config::koala_bear_poseidon2::KoalaBearPoseidon2Config;

    /// Every AIR's `preprocessed_dims()` against its own `preprocessed_trace()`. An AIR that
    /// declares nothing falls back to generating, so its row is a tautology — which is the point:
    /// the set can be converted chip by chip and this test never needs updating.
    fn assert_declared_matches_generated(label: &str, program: &Arc<RecursionProgram<Kb>>) {
        // `AnyAir::name()` is the blanket `type_name` impl, so every recursion AIR reports the
        // identical `RecursionPrepAir<KoalaBearParameters>, ...` — useless for locating a failure.
        // The AIR list is built in `mle_recursion_chips()` order, so take the names from there.
        let chips = RecursionChipType::<Kb>::mle_recursion_chips();
        let airs = recursion_air_refs_with_preprocessed::<KoalaBearPoseidon2Config>(program);
        assert_eq!(
            airs.len(),
            chips.len(),
            "AIR list and chip set have diverged in length, so the names below would mislabel"
        );
        for (air, chip) in airs.iter().zip(&chips) {
            let declared = air.preprocessed_dims();
            let generated = BaseAir::<Kb>::preprocessed_trace(air.as_ref()).map(|t| t.dimensions());
            assert_eq!(
                declared,
                generated,
                "[{label}] chip {} declares preprocessed dims that do not match its generated trace",
                ChipBehavior::<Kb>::name(chip)
            );
        }
    }

    #[test]
    fn declared_preprocessed_dims_match_generated() {
        // A wrong row count is observable only through the padded height, so the counts must land
        // a chip exactly ON a power-of-two boundary for an off-by-one to cross it (at n=9 a +1
        // error still pads to 16). Pairs straddle 16/32/64 for each divisor in the set: (16,17)
        // for the one-row-per-instruction and summed chips, (32,33) for `div_ceil(2)`, (64,65)
        // for `div_ceil(4)`; 0 covers the empty program and the 16-row floor. Mutation-checked:
        // +1 on the ExtDotProduct, HornerEval or MemoryVar counts fails this test, and n=33
        // is what catches an ExpBitsLen multiplier of 31 (33*32 = 1056 pads to 2048, 33*31 =
        // 1023 pads to 1024) — for a power-of-two n the two round to the same height.
        for n in [0, 1, 2, 3, 5, 8, 9, 16, 17, 32, 33, 64, 65] {
            assert_declared_matches_generated(
                &format!("mixed_program({n})"),
                &Arc::new(mixed_program(n)),
            );
        }
    }

    /// Under a shape, declaration and generator both return `1 << log2_rows`, so this case has no
    /// teeth for row COUNTS. What it does cover: that the shaped branch of `preprocessed_dims` is
    /// taken at all, that widths still agree, and — the reason it earns its keep — that
    /// `PublicValues` keeps ignoring the shape. A uniform log2 far from `PUB_VALUES_LOG_HEIGHT`
    /// means re-declaring that chip as `Unpadded` would read `1 << 12` against a 16-row trace.
    #[test]
    fn declared_preprocessed_dims_match_generated_under_a_shape() {
        for n in [0, 16, 65] {
            let mut program = mixed_program(n);
            // Every chip in the set must be present or `fixed_log2_rows` panics. 2^12 clears the
            // largest count these programs produce (ExpBitsLen at n=65 is 2080 rows).
            program.shape = Some(
                crate::instances::compiler::shapes::recursion_shape::RecursionPadShape {
                    inner: RecursionChipType::<Kb>::mle_recursion_chips()
                        .iter()
                        .map(|chip| (ChipBehavior::<Kb>::name(chip), 12))
                        .collect(),
                },
            );
            assert_declared_matches_generated(
                &format!("shaped mixed_program({n})"),
                &Arc::new(program),
            );
        }
    }

    /// The tables are sized with no slack, so they are only safe while the check that guards them
    /// actually rejects. An undersized tier must panic and name the chip and the gap — a check
    /// that quietly returns is worse than none, because the zero slack was chosen on the
    /// assumption it fires.
    #[test]
    #[should_panic(expected = "the recursion shapes do not close")]
    fn a_program_past_its_tier_is_rejected() {
        // The comparison is against the tier TABLE, not against anything carried on the program,
        // so an oversized program is what trips it: this instruction stream needs far more rows
        // than any real convert node, and the Convert tier has no slack to absorb it.
        let last = crate::mle::machine::shape::MLE_RECURSION_CONVERT_LADDER.len() - 1;
        super::check_recursion_tier(
            "oversized",
            &super::recursion_natural_rows(&mixed_program(1 << 20)),
            crate::mle::machine::shape::RecursionTier::Convert(last),
        );
    }

    /// The tier report has to cover the whole machine. A chip that declares no row count is
    /// unmeasurable, and one skipped silently is how a tier check comes back green over a chip
    /// nobody looked at — which is exactly what `RecursionChipType::chip_heights` does, covering
    /// six of the twenty-one. `recursion_tier_fit` panics on either; this holds it to that.
    #[test]
    fn the_tier_report_covers_every_chip() {
        let fit = super::recursion_tier_fit(
            &super::recursion_natural_rows(&mixed_program(17)),
            crate::mle::machine::shape::RecursionTier::Convert(0),
        );
        let chips = RecursionChipType::<Kb>::mle_recursion_chips();
        assert_eq!(fit.len(), chips.len());
        for (chip, (name, ..)) in chips.iter().zip(&fit) {
            assert_eq!(&ChipBehavior::<Kb>::name(chip), name, "chip order drifted");
        }
    }

    /// The tripwire the shared padding rule exists for: an undersized shape must be REJECTED, not
    /// rounded up. Were it rounded, the declaration and the generator would both report
    /// `1 << log2_rows` and agree with each other while both being smaller than the program, so
    /// the disagreement this test exists to catch would read as agreement.
    #[test]
    #[should_panic(expected = "fixed_log2_rows too small")]
    fn an_undersized_shape_is_rejected_not_rounded_up() {
        let mut program = mixed_program(65);
        // 2^4 = 16 rows declared against 65 real rows for every one-row-per-instruction chip.
        program.shape = Some(
            crate::instances::compiler::shapes::recursion_shape::RecursionPadShape {
                inner: RecursionChipType::<Kb>::mle_recursion_chips()
                    .iter()
                    .map(|chip| (ChipBehavior::<Kb>::name(chip), 4))
                    .collect(),
            },
        );
        for air in
            &recursion_air_refs_with_preprocessed::<KoalaBearPoseidon2Config>(&Arc::new(program))
        {
            let _ = air.preprocessed_dims();
        }
    }

    /// Every chip in the set must DECLARE its geometry. The parity test above stays green for a
    /// chip that declares nothing (it falls back to generating), so without this the whole point
    /// of the change — not building 21 traces per keygen — can regress silently as chips are
    /// added.
    #[test]
    fn every_recursion_chip_declares_preprocessed_rows() {
        let program = mixed_program(1);
        for chip in &RecursionChipType::<Kb>::mle_recursion_chips() {
            assert!(
                ChipBehavior::<Kb>::preprocessed_rows(chip, &program).is_some(),
                "chip {} does not declare preprocessed_rows, so merged deferred-commit keygen \
                 falls back to generating its trace",
                ChipBehavior::<Kb>::name(chip)
            );
        }
    }
}

/// Each recursion chip's natural (pre-padding) row count, as `(chip name, natural rows)`, in the
/// machine's chip order.
///
/// The counts come from each chip's own [`ChipBehavior::preprocessed_rows`], which is
/// instruction-stream arithmetic — no trace is built — and which
/// `declared_preprocessed_dims_match_generated` holds to the generator's own count. A chip that
/// declares nothing panics rather than being skipped: a silently skipped chip is how a tier
/// check comes back green over a chip nobody looked at.
///
/// Under a shape the declaration reports the padded height instead, so the program must not
/// carry one yet: the natural counts are what select the shape.
pub fn recursion_natural_rows(program: &RecursionProgram<Kb>) -> Vec<(String, usize)> {
    assert!(
        program.shape.is_none(),
        "natural row counts are read before the program takes a shape"
    );
    let chips = RecursionChipType::<Kb>::mle_recursion_chips();
    let rows: Vec<(String, usize)> = chips
        .iter()
        .map(|chip| {
            let name = ChipBehavior::<Kb>::name(chip);
            // A chip that declares no row count cannot be measured, and skipping it silently is
            // how a tier check comes back green over a chip nobody looked at — the failure
            // `RecursionChipType::chip_heights` has, covering six of the twenty-one. Every
            // recursion chip declares today; one that stops has to say so loudly.
            let declared = chip.preprocessed_rows(program).unwrap_or_else(|| {
                panic!("chip `{name}` declares no preprocessed row count, so its tier is unchecked")
            });
            let natural = match declared {
                // The 16-row floor the generators pad to, applied here too.
                PreprocessedRows::Unpadded(rows) => rows.max(16),
                // The chip ignores the shape, so it is its own tier.
                PreprocessedRows::FixedLog2(log2) => 1usize << log2,
            };
            (name, natural)
        })
        .collect();
    assert_eq!(
        rows.len(),
        chips.len(),
        "the tier report covers fewer chips than the machine has"
    );
    rows
}

/// The convert ladder row a program pads to: the first row of
/// [`crate::mle::machine::shape::MLE_RECURSION_CONVERT_LADDER`] that holds every chip's natural
/// height. The last row holds every shape the whitelist admits, so a program past it is not a
/// whitelist shape at all and the panic names the chip.
///
/// `natural` is [`recursion_natural_rows`] of the program, read before it takes its shape; the
/// builder and the prover both derive the row from the program alone, so they agree on it.
pub fn select_convert_row(natural: &[(String, usize)]) -> usize {
    let ladder = crate::mle::machine::shape::MLE_RECURSION_CONVERT_LADDER;
    for (row, table) in ladder.iter().enumerate() {
        let holds = natural.iter().all(|(name, rows)| {
            let log = rows.next_power_of_two().trailing_zeros() as usize;
            let cap = table
                .iter()
                .find(|(n, _)| *n == name)
                .map(|(_, h)| *h)
                .unwrap_or_else(|| panic!("chip `{name}` has no entry in convert row {row}"));
            log <= cap
        });
        if holds {
            return row;
        }
    }
    let last = ladder.len() - 1;
    let over: Vec<String> = natural
        .iter()
        .filter_map(|(name, rows)| {
            let log = rows.next_power_of_two().trailing_zeros() as usize;
            let cap = ladder[last]
                .iter()
                .find(|(n, _)| *n == name)
                .map(|(_, h)| *h)?;
            (log > cap)
                .then(|| format!("{name} needs 2^{log} ({rows} rows), last row holds 2^{cap}"))
        })
        .collect();
    panic!(
        "no convert row holds this program: {}; the recursion shapes do not close, widen the \
         last row",
        over.join(", ")
    );
}

/// How each recursion chip's natural (pre-padding) row count compares with the tier height it
/// will pad to, as `(chip name, natural rows, tier log height)`: `natural`, the program's
/// [`recursion_natural_rows`] read before it took its shape, against the tier's table. A chip with
/// no tier entry panics rather than being skipped.
///
/// This is the preprocessed side. A main trace taller than its tier cannot slip through either:
/// `machine::utils::padded_row_count` panics when the declared size is below the real row count.
pub fn recursion_tier_fit(
    natural: &[(String, usize)],
    tier: crate::mle::machine::shape::RecursionTier,
) -> Vec<(String, usize, usize)> {
    let pad = crate::mle::machine::shape::mle_recursion_pad_shape_for(tier);
    natural
        .iter()
        .map(|(name, natural)| {
            let tier_log = *pad
                .inner
                .get(name)
                .unwrap_or_else(|| panic!("chip `{name}` has no entry in the {tier:?} tier table"));
            (name.clone(), *natural, tier_log)
        })
        .collect()
}

/// Reject a recursion program that does not fit its tier, and report the slack it leaves.
///
/// This is the self-consistency check of the tier tables: every node shape the whitelist admits
/// has to fit the tier its role selects, or the recursion shapes do not close. Running it at
/// keygen means a breach is found while the shapes are being built rather than part-way through
/// a proving run.
///
/// `natural` is the program's [`recursion_natural_rows`], read before it took its shape. Callers
/// read it once; on the convert path the same counts also select the ladder row.
///
/// The per-chip slack is the input for tightening (or widening) the tables, so it is logged
/// under `MLE_SHAPE_MARGIN=1` rather than always: one line per chip per node shape is far too
/// much for a normal run.
pub fn check_recursion_tier(
    label: &str,
    natural: &[(String, usize)],
    tier: crate::mle::machine::shape::RecursionTier,
) {
    let report =
        std::env::var("MLE_SHAPE_MARGIN").is_ok_and(|v| v == "1" || v.eq_ignore_ascii_case("true"));
    let mut worst: Option<(String, usize)> = None;
    for (name, natural, tier_log) in recursion_tier_fit(natural, tier) {
        let natural_log = natural.next_power_of_two().trailing_zeros() as usize;
        assert!(
            natural_log <= tier_log,
            "[{label}] {name} needs 2^{natural_log} ({natural} rows) but its {tier:?} tier is \
             2^{tier_log}: the recursion shapes do not close, widen the tier table"
        );
        let slack = tier_log - natural_log;
        if report {
            tracing::info!(
                target: "mle_shape_margin",
                "[{label}] {name}: 2^{natural_log} -> 2^{tier_log} (slack {slack})"
            );
        }
        if worst.as_ref().is_none_or(|(_, s)| slack < *s) {
            worst = Some((name, slack));
        }
    }
    if report {
        if let Some((name, slack)) = worst {
            tracing::info!(
                target: "mle_shape_margin",
                "[{label}] tightest chip: {name}, slack {slack}"
            );
        }
    }
}

/// Whitelist mode: pad a convert program to the first convert ladder row that holds it, and
/// check it against that row. The natural row counts are read once, before the program takes the
/// shape, and serve both the row selection and the check. Returns the tier the program took.
pub fn pad_convert_program(
    label: &str,
    program: &mut RecursionProgram<Kb>,
) -> crate::mle::machine::shape::RecursionTier {
    let natural = recursion_natural_rows(program);
    let tier = crate::mle::machine::shape::RecursionTier::Convert(select_convert_row(&natural));
    program.shape = Some(crate::mle::machine::shape::mle_recursion_pad_shape_for(
        tier,
    ));
    check_recursion_tier(label, &natural, tier);
    tier
}

/// Whitelist mode: pad a recursion program to a fixed tier (combine, embed) and check it against
/// that tier's table, from the natural row counts read before the program takes the shape.
pub fn pad_recursion_program(
    label: &str,
    program: &mut RecursionProgram<Kb>,
    tier: crate::mle::machine::shape::RecursionTier,
) {
    let natural = recursion_natural_rows(program);
    program.shape = Some(crate::mle::machine::shape::mle_recursion_pad_shape_for(
        tier,
    ));
    check_recursion_tier(label, &natural, tier);
}
