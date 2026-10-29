//! Tests for the GPU prover.
//!
//! `kb_arithmetic_test.rs` holds the KoalaBear extension-field arithmetic and the fold-parity
//! tests; the harness those tests use is `pub(crate)` here.
//!
//! Nearly every test drives a device path, most of them differentially against the matching
//! `mle-core` CPU routine or reference engine.

use std::sync::Arc;

use itertools::Itertools;
use mle_core::{
    poly::matrix::MatrixDimensions,
    prover::{DeviceDataTransporter, MultiRapProver},
    test_utils::{FibFixture, InteractionsFixture11, TestFixture},
    FiatShamirTranscript, StarkEngine, StarkProtocolConfig,
};
use p3_field::{PrimeCharacteristicRing, TwoAdicField};
use test_case::test_case;
use tracing::{debug, Level};

use crate::base::DeviceMatrix;

/// No-op shim; mle-core doesn't expose `setup_tracing_with_log_level`.
fn setup_tracing_with_log_level(_level: Level) {}

// ===========================================================================
// Prover paths: interactions / zerocheck, WHIR
// ===========================================================================

/// CPU KB interaction roundtrip test (reference). If this PASSES, the bug is GPU-specific.
#[test]
fn test_kb_cpu_interactions_roundtrip_reference() {
    use mle_core::{
        config::koala_bear_poseidon2::DuplexSponge as KbDuplexSponge,
        engine::koala_bear_poseidon2::KoalaBearPoseidon2RefEngine,
        test_utils::test_system_params_small,
    };

    setup_tracing_with_log_level(Level::DEBUG);

    let engine =
        KoalaBearPoseidon2RefEngine::<KbDuplexSponge>::new(test_system_params_small(0, 8, 3));
    let fixture = InteractionsFixture11;
    let (vk, proof) = fixture.keygen_and_prove(&engine);
    engine
        .verify(&vk, &proof)
        .expect("KB CPU l_skip=0 interactions roundtrip should verify (CPU reference)");
    println!("PASS: KB CPU interactions roundtrip (CPU prover is correct)");
}

/// Compare CPU vs GPU numerator_term_per_air for the small fixture.
/// This pinpoints whether the bug is in the batch MLE evaluation.
#[test]
fn test_kb_compare_cpu_gpu_numerator_terms() {
    use mle_core::{
        config::koala_bear_poseidon2::DuplexSponge as KbDuplexSponge,
        engine::koala_bear_poseidon2::KoalaBearPoseidon2RefEngine,
        test_utils::test_system_params_small,
    };

    use crate::KoalaBearPoseidon2GpuEngine;

    setup_tracing_with_log_level(Level::WARN);

    let fixture = InteractionsFixture11;

    // CPU proof
    let cpu_engine =
        KoalaBearPoseidon2RefEngine::<KbDuplexSponge>::new(test_system_params_small(0, 8, 3));
    let (_, proof_cpu) = fixture.keygen_and_prove(&cpu_engine);
    let cpu_numer = &proof_cpu.batch_constraint_proof.numerator_term_per_air;
    let cpu_denom = &proof_cpu.batch_constraint_proof.denominator_term_per_air;
    println!("CPU numerator_terms ({} AIRs):", cpu_numer.len());
    for (i, (n, d)) in cpu_numer.iter().zip(cpu_denom.iter()).enumerate() {
        println!("  air[{i}]: numer={n:?} denom={d:?}");
    }

    // GPU proof
    let gpu_engine = KoalaBearPoseidon2GpuEngine::new(test_system_params_small(0, 8, 3));
    let (_, proof_gpu) = fixture.keygen_and_prove(&gpu_engine);
    let gpu_numer = &proof_gpu.batch_constraint_proof.numerator_term_per_air;
    let gpu_denom = &proof_gpu.batch_constraint_proof.denominator_term_per_air;
    println!("GPU numerator_terms ({} AIRs):", gpu_numer.len());
    for (i, (n, d)) in gpu_numer.iter().zip(gpu_denom.iter()).enumerate() {
        println!("  air[{i}]: numer={n:?} denom={d:?}");
    }

    // Compare
    let mut mismatch = false;
    for (i, (cn, gn)) in cpu_numer.iter().zip(gpu_numer.iter()).enumerate() {
        if cn != gn {
            println!("MISMATCH numer air[{i}]: cpu={cn:?} gpu={gn:?}");
            mismatch = true;
        }
    }
    if !mismatch {
        println!("PASS: numerator_terms match between CPU and GPU!");
    }
    // Also print p_xi_claim values by running verify in debug mode
}

/// KB GPU interaction roundtrip test on KoalaBearPoseidon2GpuEngine. If GkrNumeratorMismatch
/// occurs here, the bug is in the GPU KB batch MLE for small inputs. If it passes here but fails for reth188, the bug is size-dependent.
#[test]
fn test_kb_interactions_roundtrip_with_l_skip_zero() {
    use mle_core::test_utils::test_system_params_small;

    use crate::KoalaBearPoseidon2GpuEngine;

    setup_tracing_with_log_level(Level::DEBUG);

    let engine = KoalaBearPoseidon2GpuEngine::new(test_system_params_small(0, 8, 3));
    let fixture = InteractionsFixture11;
    let (vk, proof) = fixture.keygen_and_prove(&engine);
    engine
        .verify(&vk, &proof)
        .expect("KB l_skip=0 interactions roundtrip should verify");
}

#[test_case(2; "l_skip_2")]
#[test_case(2; "l_skip_2_n10")]
#[test_case(4; "l_skip_4")]
fn test_kb_interactions_roundtrip_l_skip(l_skip: usize) {
    use mle_core::test_utils::test_system_params_small;

    use crate::KoalaBearPoseidon2GpuEngine;

    setup_tracing_with_log_level(Level::DEBUG);

    let n = 8; // n_stack=8 for both l_skip cases for now
    let engine = KoalaBearPoseidon2GpuEngine::new(test_system_params_small(l_skip, n, 3));
    let fixture = InteractionsFixture11;
    let (vk, proof) = fixture.keygen_and_prove(&engine);
    engine
        .verify(&vk, &proof)
        .unwrap_or_else(|e| panic!("KB l_skip={l_skip} interactions roundtrip failed: {e:?}"));
}

/// KB GPU fib roundtrip — fib has AIR constraints (zerocheck) so this exercises the
/// zerocheck sumcheck path (unlike InteractionsFixture11 which has no constraints).
/// Small trace (256 rows) so it runs in seconds.
#[test_case(0; "l_skip_0")]
#[test_case(2; "l_skip_2")]
fn test_kb_fib_roundtrip(l_skip: usize) {
    use mle_core::test_utils::{test_system_params_small, FibFixture, TestFixture};

    use crate::KoalaBearPoseidon2GpuEngine;

    setup_tracing_with_log_level(Level::DEBUG);

    let engine = KoalaBearPoseidon2GpuEngine::new(test_system_params_small(l_skip, 8, 3));
    let fib = FibFixture::new(0, 1, 1 << (l_skip + 8));
    let (pk, vk) = fib.keygen(&engine);
    let proof = fib.prove(&engine, &pk);
    engine
        .verify(&vk, &proof)
        .unwrap_or_else(|e| panic!("KB l_skip={l_skip} fib roundtrip failed: {e:?}"));
}

/// Zero every proof-of-work bit count in `params`.
///
/// A grind returns *a* witness whose hash meets the `bits` target, not a canonical one, and the
/// GPU searches its window in parallel while the CPU walks it sequentially -- so on identical
/// transcript state the two legitimately land on different witnesses (measured on this fixture:
/// `mu_pow_witness` 3 on GPU vs 565968897 on CPU). Each witness is observed into the transcript,
/// so from the first grind onward every later challenge, and therefore every later proof value,
/// diverges even though both proofs verify under either engine. A 0-bit grind has a unique
/// trivial witness, which is what lets a CPU/GPU comparison *assert* equality rather than merely
/// print it.
///
/// `query_phase_pow_bits` is zeroed after `WhirConfig::new` has already sized `rounds`, so the
/// proof shape (round count, queries per round) is untouched -- only the grind becomes trivial.
fn zero_pow(mut params: mle_core::SystemParams) -> mle_core::SystemParams {
    params.logup.pow_bits = 0;
    params.whir.mu_pow_bits = 0;
    params.whir.folding_pow_bits = 0;
    params.whir.query_phase_pow_bits = 0;
    params
}

/// Asserts two [`mle_core::proof::WhirProof`]s agree field by field.
///
/// One `assert_eq!` on the whole struct would report "left != right" over megabytes of nested
/// vectors; per-field assertions name the field, and the length checks fire before the content
/// checks so a shape divergence is reported as a shape divergence. The WHIR prover owns four
/// kernels -- `whir_algebraic_batch_traces`, `whir_sumcheck_coeff_moments_round`,
/// `whir_fold_coeffs_and_moments` and `w_moments_accumulate` -- and none had direct coverage
/// before this test; each one's output reaches at least one field compared here.
fn assert_whir_proof_eq<SCfg: StarkProtocolConfig>(
    case: &str,
    cpu: &mle_core::proof::WhirProof<SCfg>,
    gpu: &mle_core::proof::WhirProof<SCfg>,
) {
    // Grinding: must be the trivial witness on both sides, or `zero_pow` was not applied and
    // every later comparison below is meaningless rather than merely failing.
    assert_eq!(
        cpu.mu_pow_witness, gpu.mu_pow_witness,
        "{case}: mu_pow_witness -- a non-trivial grind means zero_pow was not applied"
    );
    assert_eq!(
        cpu.folding_pow_witnesses, gpu.folding_pow_witnesses,
        "{case}: folding_pow_witnesses"
    );
    assert_eq!(
        cpu.query_phase_pow_witnesses, gpu.query_phase_pow_witnesses,
        "{case}: query_phase_pow_witnesses"
    );

    // Sumcheck: `whir_sumcheck_coeff_moments_round` on the GPU (coefficient/moment basis) against
    // the CPU's evaluation-basis loop. s(1) and s(2) are basis-independent scalars, so these must
    // agree element for element.
    assert_eq!(
        cpu.whir_sumcheck_polys.len(),
        gpu.whir_sumcheck_polys.len(),
        "{case}: whir_sumcheck_polys length"
    );
    for (i, (c, g)) in cpu
        .whir_sumcheck_polys
        .iter()
        .zip(&gpu.whir_sumcheck_polys)
        .enumerate()
    {
        assert_eq!(c, g, "{case}: whir_sumcheck_polys[{i}]");
    }

    // Per-round commit phase: reached through `whir_fold_coeffs_and_moments` (the folded `f`
    // becomes the committed codeword) and `w_moments_accumulate` (whose moments steer the next
    // round's sumcheck, hence every later commit).
    assert_eq!(
        cpu.codeword_commits, gpu.codeword_commits,
        "{case}: codeword_commits"
    );
    assert_eq!(cpu.ood_values, gpu.ood_values, "{case}: ood_values");
    assert_eq!(cpu.final_poly, gpu.final_poly, "{case}: final_poly");

    // Query phase, round 0: `initial_round_opened_rows` is the only field carrying the stacked
    // matrix the GPU builds via `whir_algebraic_batch_traces`.
    assert_eq!(
        cpu.initial_round_opened_rows.len(),
        gpu.initial_round_opened_rows.len(),
        "{case}: initial_round_opened_rows commit count"
    );
    for (commit, (c_rows, g_rows)) in cpu
        .initial_round_opened_rows
        .iter()
        .zip(&gpu.initial_round_opened_rows)
        .enumerate()
    {
        assert_eq!(
            c_rows.len(),
            g_rows.len(),
            "{case}: initial_round_opened_rows[{commit}] query count"
        );
        for (q, (c_q, g_q)) in c_rows.iter().zip(g_rows).enumerate() {
            assert_eq!(
                c_q, g_q,
                "{case}: initial_round_opened_rows[{commit}][query {q}]"
            );
        }
    }
    assert_eq!(
        cpu.initial_round_merkle_proofs, gpu.initial_round_merkle_proofs,
        "{case}: initial_round_merkle_proofs"
    );

    // Query phase, later rounds.
    assert_eq!(
        cpu.codeword_opened_values.len(),
        gpu.codeword_opened_values.len(),
        "{case}: codeword_opened_values round count"
    );
    for (r, (c_r, g_r)) in cpu
        .codeword_opened_values
        .iter()
        .zip(&gpu.codeword_opened_values)
        .enumerate()
    {
        assert_eq!(c_r, g_r, "{case}: codeword_opened_values[round {r}]");
    }
    assert_eq!(
        cpu.codeword_merkle_proofs, gpu.codeword_merkle_proofs,
        "{case}: codeword_merkle_proofs"
    );
}

/// Asserts two [`mle_core::proof::StackingProof`]s agree field by field.
///
/// The stacked-reduction phase (`prove_stacked_opening_reduction_gpu`) runs before WHIR and
/// its output was otherwise only pinned by the whole-proof `assert_eq!` in the parity test, which
/// reports a divergence as a generic "earlier phase differs". Naming the three fields turns a
/// stacked-reduction regression into a precise diagnostic: the round-0 univariate coefficients, the
/// per-round quadratic sumcheck messages (evals at X=1,2), and the per-commit/per-column opening
/// claims. Length checks fire before content so a shape divergence reads as one.
fn assert_stacking_proof_eq<SCfg: StarkProtocolConfig>(
    case: &str,
    cpu: &mle_core::proof::StackingProof<SCfg>,
    gpu: &mle_core::proof::StackingProof<SCfg>,
) {
    assert_eq!(
        cpu.univariate_round_coeffs.len(),
        gpu.univariate_round_coeffs.len(),
        "{case}: stacking univariate_round_coeffs length"
    );
    for (i, (c, g)) in cpu
        .univariate_round_coeffs
        .iter()
        .zip(&gpu.univariate_round_coeffs)
        .enumerate()
    {
        assert_eq!(c, g, "{case}: stacking univariate_round_coeffs[{i}]");
    }

    assert_eq!(
        cpu.sumcheck_round_polys.len(),
        gpu.sumcheck_round_polys.len(),
        "{case}: stacking sumcheck_round_polys round count"
    );
    for (i, (c, g)) in cpu
        .sumcheck_round_polys
        .iter()
        .zip(&gpu.sumcheck_round_polys)
        .enumerate()
    {
        assert_eq!(c, g, "{case}: stacking sumcheck_round_polys[round {i}]");
    }

    assert_eq!(
        cpu.stacking_openings.len(),
        gpu.stacking_openings.len(),
        "{case}: stacking_openings per-commit count"
    );
    for (i, (c, g)) in cpu
        .stacking_openings
        .iter()
        .zip(&gpu.stacking_openings)
        .enumerate()
    {
        assert_eq!(c, g, "{case}: stacking_openings[commit {i}] (per-column)");
    }
}

/// Element-wise CPU<->GPU parity for the whole KoalaBear WHIR prover.
///
/// Supersedes a version of this test that computed both proofs and only `println!`d whether the
/// sumcheck polys matched: it asserted nothing, reported `MISMATCH` on every run, and still passed
/// -- so it stood in the green list while covering nothing. The mismatch it saw was grind search
/// order, not arithmetic (see [`zero_pow`]); with the grinds made trivial the two proofs are
/// bit-identical, so this asserts that and compares every `WhirProof` field, not just one.
///
/// Both fixtures are exercised because they drive different WHIR inputs: `FibFixture` has real
/// constraints (a non-trivial zerocheck feeding the stacked opening), `InteractionsFixture11` has
/// interactions but no constraints. `l_skip` is varied because it selects the within-chunk zeta
/// path in `prove_whir_opening_gpu` (`l_skip == 0` skips it entirely).
///
/// `interactions` at `l_skip = 4` is the only case with a *strided* trace. The batch kernel indexes
/// a trace shorter than the skip domain with `stride = skip_domain / height`, carried as
/// `BatchingTracePacket::stride_shift`; every other case here has traces taller than the skip
/// domain, i.e. `stride == 1` and `stride_shift == 0`, which cannot tell a correct shift from a
/// zeroed one. `InteractionsFixture11`'s two traces are 4 and 8 rows against a 16-row skip domain,
/// so this case drives `stride_shift` 2 and 1 within one proof.
#[test_case(0, "fib" ; "fib_l_skip_0")]
#[test_case(2, "fib" ; "fib_l_skip_2")]
#[test_case(2, "interactions" ; "interactions_l_skip_2")]
#[test_case(4, "interactions" ; "interactions_l_skip_4_strided")]
fn test_kb_whir_proof_matches_cpu(l_skip: usize, fixture: &str) {
    use mle_core::{
        config::koala_bear_poseidon2::DuplexSponge as KbDuplexSponge,
        engine::koala_bear_poseidon2::KoalaBearPoseidon2RefEngine,
        test_utils::test_system_params_small,
    };

    use crate::KoalaBearPoseidon2GpuEngine;

    setup_tracing_with_log_level(Level::WARN);

    let params = zero_pow(test_system_params_small(l_skip, 8, 3));
    let cpu_engine = KoalaBearPoseidon2RefEngine::<KbDuplexSponge>::new(params.clone());
    let gpu_engine = KoalaBearPoseidon2GpuEngine::new(params);

    let case = format!("{fixture} l_skip={l_skip}");
    let (cpu_vk, cpu_proof, gpu_vk, gpu_proof) = match fixture {
        "fib" => {
            let fib = FibFixture::new(0, 1, 1 << (l_skip + 8));
            let (cpu_vk, cpu_proof) = fib.keygen_and_prove(&cpu_engine);
            let (gpu_vk, gpu_proof) = fib.keygen_and_prove(&gpu_engine);
            (cpu_vk, cpu_proof, gpu_vk, gpu_proof)
        }
        "interactions" => {
            let (cpu_vk, cpu_proof) = InteractionsFixture11.keygen_and_prove(&cpu_engine);
            let (gpu_vk, gpu_proof) = InteractionsFixture11.keygen_and_prove(&gpu_engine);
            (cpu_vk, cpu_proof, gpu_vk, gpu_proof)
        }
        other => panic!("unknown fixture {other}"),
    };

    // Keygen is field-for-field deterministic, so a vk divergence would mean the two proofs were
    // never comparable in the first place -- check it before blaming the prover.
    assert_eq!(cpu_vk.pre_hash, gpu_vk.pre_hash, "{case}: vk pre_hash");

    // Stacked-reduction phase runs before WHIR; pin its StackingProof explicitly so a
    // reduction regression is named here rather than surfacing as an opaque whole-proof diff below.
    assert_stacking_proof_eq(&case, &cpu_proof.stacking_proof, &gpu_proof.stacking_proof);

    assert_whir_proof_eq(&case, &cpu_proof.whir_proof, &gpu_proof.whir_proof);

    // The WHIR proof is the last phase, so an earlier divergence would surface above as a WHIR
    // difference with a confusing field name. Assert the whole proof too, which also pins the
    // phases WHIR consumes (stacked reduction, batch constraints, GKR).
    assert_eq!(
        cpu_proof, gpu_proof,
        "{case}: WHIR fields agree but some earlier proof phase differs"
    );

    // Both must stand on their own, and cross-verify: verification recomputes every challenge, so
    // this pins that the two transcripts emit the same challenge stream.
    gpu_engine
        .verify(&gpu_vk, &gpu_proof)
        .unwrap_or_else(|e| panic!("{case}: GPU proof under GPU engine: {e:?}"));
    cpu_engine
        .verify(&gpu_vk, &gpu_proof)
        .unwrap_or_else(|e| panic!("{case}: GPU proof under CPU engine: {e:?}"));
}

// ===========================================================================
// Fold-family CPU<->GPU parity harness, shared with the KoalaBear tests
// ===========================================================================

/// Element-wise CPU<->GPU parity harness for the three sumcheck fold kernels (`fold_mle`,
/// `batch_fold_mle`, `triangular_fold_mle`), generic over [`FieldKernels`]; the KoalaBear tests in
/// `kb_arithmetic_test.rs` drive it.
///
/// Every oracle is an independent `mle-core` CPU routine -- `fold_mle_evals`,
/// `batch_fold_mle_evals`, `evals_eq_hypercube_serial`, `eval_eq_mle` -- never a re-derivation of
/// the fold formula. The GPU buffers are column-major, which is why the oracles are the
/// `prover::sumcheck::*` ones and not the row-major `poly::row_major::*_rm` twins.
pub(crate) mod fold_parity {
    use itertools::Itertools;
    use mle_core::{
        poly::{
            eq::{eval_eq_mle, evals_eq_hypercube_serial},
            matrix::{ColMajorMatrix, MatrixDimensions},
        },
        prover::sumcheck::{batch_fold_mle_evals, fold_mle_evals},
    };
    use p3_field::{BasedVectorSpace, PrimeCharacteristicRing, PrimeField32};
    use rand::{rngs::StdRng, Rng, RngExt};

    use crate::{
        cuda::field_kernels::FieldKernels,
        poly::EqEvalSegments,
        runtime::{
            copy::{MemCopyD2H, MemCopyH2D},
            d_buffer::DeviceBuffer,
            stream::device_synchronize,
        },
    };

    /// Slack appended past the end of the shared grid's span, so that even the matrix owning
    /// every one of `max_output_cells` cells still carries a canary tail.
    const CANARY_PAD: usize = 8;

    /// Length of every output buffer these harnesses allocate, whatever the individual matrix's
    /// shape: the full span of the shared grid, plus [`CANARY_PAD`].
    ///
    /// Both fold kernels index one grid sized for the *largest* matrix and every thread writes at
    /// its own `tidx`, so a matrix with fewer output cells is only correct because of the kernel's
    /// `tidx >= output_height * width` guard. Spanning the whole grid keeps a regressed guard's
    /// writes *inside* the allocation, where the [`canary`] pre-fill turns them into an assertion
    /// failure instead of heap corruption; conversely a cell the grid never covered reads back as
    /// the canary instead of the folded value.
    fn canary_buffer_len(max_output_cells: usize) -> usize {
        max_output_cells + CANARY_PAD
    }

    /// Panics unless the launch about to be made is a single block, which is what makes
    /// [`canary_buffer_len`]'s "the tail spans the whole grid" exact: `fold_mle_launch_params`
    /// gives a grid whose x-extent is exactly `max_output_cells` up to `MAX_THREADS` and ragged
    /// above it, where a surplus thread could write past the tail. Only the two parity harnesses
    /// call this -- the reject harnesses expect no launch at all, so it must not gate theirs.
    fn assert_single_block_grid(case: &str, max_output_cells: usize) {
        assert!(
            max_output_cells <= 1024,
            "{case}: the canary tail is sized for a single-block grid; \
             max_output_cells = {max_output_cells}"
        );
    }

    /// A value no random input can collide with, small enough to be canonical in KoalaBear
    /// (order `0x7f000001`).
    fn canary<FK: FieldKernels>() -> FK::ValExt {
        FK::ValExt::from_basis_coefficients_fn(|i| FK::Val::from_u32(0x0bad_f00d + i as u32))
    }

    /// `cudaErrorInvalidValue` -- what the fold launchers return when they refuse a degenerate
    /// argument instead of launching. Spelled out rather than imported because nothing in this
    /// crate binds the `cudaError_t` enum.
    const CUDA_ERROR_INVALID_VALUE: i32 = 1;

    /// One pseudo-random extension element, base coordinate by base coordinate.
    pub(crate) fn random_ext<FK: FieldKernels>(rng: &mut StdRng) -> FK::ValExt {
        FK::ValExt::from_basis_coefficients_fn(|_| {
            FK::Val::from_u32(rng.random::<u32>() % FK::Val::ORDER_U32)
        })
    }

    /// A pseudo-random column-major matrix. `height` must be a power of two
    /// (`ColMajorMatrix::new` asserts it).
    pub(crate) fn random_col_major<FK: FieldKernels>(
        rng: &mut StdRng,
        height: usize,
        width: usize,
    ) -> ColMajorMatrix<FK::ValExt> {
        let values = (0..height * width)
            .map(|_| random_ext::<FK>(rng))
            .collect_vec();
        ColMajorMatrix::new(values, width)
    }

    /// A pseudo-random column-major matrix over the *base* field `FK::Val` (the trace field for the
    /// PLE fold). `height` must be a power of two (`ColMajorMatrix::new` asserts it).
    pub(crate) fn random_col_major_base<FK: FieldKernels>(
        rng: &mut StdRng,
        height: usize,
        width: usize,
    ) -> ColMajorMatrix<FK::Val> {
        let values = (0..height * width)
            .map(|_| FK::Val::from_u32(rng.random::<u32>() % FK::Val::ORDER_U32))
            .collect_vec();
        ColMajorMatrix::new(values, width)
    }

    /// Element-wise CPU<->GPU parity for the prismalinear round-0 fold kernel `fold_ple_from_evals`,
    /// driven through [`fold_ple_evals_rotate`](crate::logup_zerocheck::fold_ple::fold_ple_evals_rotate).
    ///
    /// The oracle is mle-core's `prover::sumcheck::fold_ple_evals`, never a re-derivation of the
    /// fold. `fold_ple_evals_rotate` packs the base fold (`is_rot = false`) into the first `width`
    /// columns and the rotated fold (`is_rot = true`) into the next `width`; both halves are checked.
    /// `mat` is the *unlifted* trace (`height` a power of two, `height >= 2^l_skip`); the fold
    /// collapses the `l_skip` skip-domain, giving `num_x = height >> l_skip` output rows.
    pub(crate) fn assert_fold_ple_matches_cpu<FK: FieldKernels>(
        case: &str,
        mat: &ColMajorMatrix<FK::Val>,
        l_skip: usize,
        r: FK::ValExt,
    ) where
        FK::Val: p3_field::TwoAdicField,
        FK::ValExt: p3_field::ExtensionField<FK::Val> + p3_field::TwoAdicField,
    {
        use std::sync::Arc;

        use mle_core::prover::sumcheck::fold_ple_evals;
        use p3_field::TwoAdicField;

        use crate::{
            base::DeviceMatrix, logup_zerocheck::fold_ple::fold_ple_evals_rotate,
            utils::compute_barycentric_inv_lagrange_denoms,
        };

        let height = mat.height();
        let width = mat.width();
        let skip = 1usize << l_skip;
        assert!(height >= skip, "{case}: fold_ple needs height >= 2^l_skip");
        let num_x = height >> l_skip;

        // Upload the trace column-major; build the coset domain and barycentric denoms at r.
        let d_mat = DeviceMatrix::new(
            Arc::new(mat.values.as_slice().to_device().unwrap()),
            height,
            width,
        );
        let omega = FK::Val::two_adic_generator(l_skip);
        let omega_pows: Vec<FK::Val> = omega.powers().take(skip).collect_vec();
        let d_omega_pows = omega_pows.as_slice().to_device().unwrap();
        let inv_denoms =
            compute_barycentric_inv_lagrange_denoms::<FK::Val, FK::ValExt>(l_skip, &omega_pows, r);
        let d_inv_denoms = inv_denoms.as_slice().to_device().unwrap();

        // GPU: base + rotated folds packed side by side.
        let folded =
            fold_ple_evals_rotate::<FK>(l_skip, &d_omega_pows, &d_mat, &d_inv_denoms, true)
                .unwrap();
        device_synchronize().unwrap();
        let got: Vec<FK::ValExt> = folded.buffer().to_host().unwrap();
        assert_eq!(got.len(), num_x * width * 2, "{case}: folded buffer len");

        // CPU oracle for each half.
        let base = fold_ple_evals(l_skip, mat.as_view().into(), false, r);
        let rot = fold_ple_evals(l_skip, mat.as_view().into(), true, r);
        assert_eq!(
            (base.height(), base.width()),
            (num_x, width),
            "{case}: base oracle shape"
        );

        for (i, &exp) in base.values.iter().enumerate() {
            assert_eq!(got[i], exp, "{case}: base cell {i}");
        }
        for (i, &exp) in rot.values.iter().enumerate() {
            assert_eq!(got[num_x * width + i], exp, "{case}: rot cell {i}");
        }
    }

    /// Allocates `num_matrices` canary-filled output buffers, each [`canary_buffer_len`] long.
    ///
    /// Returns the buffers alongside the host vectors that seeded them: `copy_to` is an *async*
    /// H2D copy, so those vectors must outlive the stream synchronization and cannot be dropped
    /// here.
    #[allow(clippy::type_complexity)]
    fn alloc_canary_outputs<FK: FieldKernels>(
        num_matrices: usize,
        max_output_cells: usize,
    ) -> (Vec<DeviceBuffer<FK::ValExt>>, Vec<Vec<FK::ValExt>>) {
        let fills = (0..num_matrices)
            .map(|_| vec![canary::<FK>(); canary_buffer_len(max_output_cells)])
            .collect_vec();
        let buffers = fills
            .iter()
            .map(|fill| {
                let mut buffer = DeviceBuffer::<FK::ValExt>::with_capacity(fill.len());
                fill.copy_to(&mut buffer).unwrap();
                buffer
            })
            .collect_vec();
        (buffers, fills)
    }

    /// Asserts the folded cells match `expected` and that the canary tail is untouched.
    fn assert_output_matches<FK: FieldKernels>(
        case: &str,
        mat_idx: usize,
        output_height: usize,
        width: usize,
        max_output_cells: usize,
        got: &[FK::ValExt],
        expected: &ColMajorMatrix<FK::ValExt>,
    ) {
        let cells = output_height * width;
        assert_eq!(expected.height(), output_height, "{case}: oracle height");
        assert_eq!(expected.width(), width, "{case}: oracle width");
        assert_eq!(
            got.len(),
            canary_buffer_len(max_output_cells),
            "{case}: output buffer len"
        );
        for col in 0..width {
            for row in 0..output_height {
                // Column-major: (row, col) lives at `col * output_height + row` on both sides.
                let idx = col * output_height + row;
                assert_eq!(
                    got[idx], expected.values[idx],
                    "{case}: matrix {mat_idx} row {row} col {col}"
                );
            }
        }
        for (i, tail) in got[cells..].iter().enumerate() {
            assert_eq!(
                *tail,
                canary::<FK>(),
                "{case}: matrix {mat_idx} canary cell {i} was overwritten -- the kernel's \
                 out-of-range thread guard did not mask the shared grid"
            );
        }
    }

    /// Uploads `mats` column-major, runs `FK::fold_mle` (one shared `output_height`), and asserts
    /// every output cell against `mle_core::prover::sumcheck::fold_mle_evals`.
    ///
    /// Returns the downloaded GPU outputs (folded cells only) so callers can layer extra
    /// closed-form self-checks on top of the oracle.
    pub(crate) fn assert_fold_mle_matches_cpu<FK: FieldKernels>(
        case: &str,
        mats: &[ColMajorMatrix<FK::ValExt>],
        r: FK::ValExt,
    ) -> Vec<Vec<FK::ValExt>> {
        let input_height = mats[0].height();
        assert!(input_height >= 2, "{case}: fold_mle needs >= 2 input rows");
        assert!(
            mats.iter().all(|mat| mat.height() == input_height),
            "{case}: fold_mle folds every matrix at one shared height"
        );
        let output_height = input_height >> 1;
        let cells = mats
            .iter()
            .map(|mat| output_height * mat.width())
            .collect_vec();
        let max_output_cells = *cells.iter().max().unwrap();
        assert_single_block_grid(case, max_output_cells);

        let d_inputs = mats
            .iter()
            .map(|mat| mat.values.as_slice().to_device().unwrap())
            .collect_vec();
        let (d_outputs, _fills) = alloc_canary_outputs::<FK>(mats.len(), max_output_cells);

        let input_ptrs = d_inputs.iter().map(|buf| buf.as_ptr()).collect_vec();
        let output_ptrs = d_outputs.iter().map(|buf| buf.as_mut_ptr()).collect_vec();
        let widths = mats.iter().map(|mat| mat.width() as u32).collect_vec();
        let d_input_ptrs = input_ptrs.to_device().unwrap();
        let d_output_ptrs = output_ptrs.to_device().unwrap();
        let d_widths = widths.to_device().unwrap();

        // SAFETY: every pointer array points into a buffer that outlives the launch and the
        // download below, and input buffer `i` holds `2 * output_height * widths[i]` elements.
        // Only the *outputs* are padded to the shared grid's span; the inputs stay at the
        // matrices' true size, since padding them would feed the oracle a matrix the test did not
        // build. So a regressed range guard may fault the launch on its input read
        // (`cudaErrorIllegalAddress` out of `device_synchronize`) rather than trip the canary.
        unsafe {
            FK::fold_mle(
                &d_input_ptrs,
                &d_output_ptrs,
                &d_widths,
                mats.len().try_into().unwrap(),
                output_height as u32,
                max_output_cells as u32,
                r,
            )
            .unwrap_or_else(|e| panic!("{case}: fold_mle launch failed: {e:?}"));
        }
        device_synchronize().unwrap();

        let mut folded = Vec::with_capacity(mats.len());
        for (i, (mat, d_out)) in mats.iter().zip(d_outputs.iter()).enumerate() {
            let got = d_out.to_host().unwrap();
            let expected = fold_mle_evals(mat.clone(), r);
            assert_output_matches::<FK>(
                case,
                i,
                output_height,
                mat.width(),
                max_output_cells,
                &got,
                &expected,
            );
            folded.push(got[..output_height * mat.width()].to_vec());
        }
        folded
    }

    /// Uploads `mats` column-major, runs `FK::batch_fold_mle` (per-matrix `log_output_heights`),
    /// and asserts every output cell against
    /// `mle_core::prover::sumcheck::batch_fold_mle_evals`.
    ///
    /// Every matrix must have at least two rows: `batch_fold_mle` is only called on matrices the
    /// caller has not already folded to height 1. Covering `log_output_height == 0` -- the
    /// shortest matrix the production caller keeps -- therefore forces input height exactly 2,
    /// where every column folds to a single row, so such a matrix exercises the per-matrix
    /// `log_output_heights` lookup rather than the column-major stride; the taller matrices
    /// alongside it are what cover the stride.
    // Only `kb_arithmetic_test` drives this one, and that module is KB-gated, so without the
    // feature the helper has no caller and trips `dead_code`.
    pub(crate) fn assert_batch_fold_mle_matches_cpu<FK: FieldKernels>(
        case: &str,
        mats: &[ColMajorMatrix<FK::ValExt>],
        r: FK::ValExt,
    ) {
        assert!(
            mats.iter().all(|mat| mat.height() >= 2),
            "{case}: batch_fold_mle is only called on matrices the caller has not yet folded to \
             height 1"
        );
        let output_heights = mats.iter().map(|mat| mat.height() >> 1).collect_vec();
        let log_output_heights = output_heights
            .iter()
            .map(|&h| h.ilog2() as u8)
            .collect_vec();
        let cells = output_heights
            .iter()
            .zip(mats)
            .map(|(&h, mat)| h * mat.width())
            .collect_vec();
        let max_output_cells = *cells.iter().max().unwrap();
        assert_single_block_grid(case, max_output_cells);

        let d_inputs = mats
            .iter()
            .map(|mat| mat.values.as_slice().to_device().unwrap())
            .collect_vec();
        let (d_outputs, _fills) = alloc_canary_outputs::<FK>(mats.len(), max_output_cells);

        let input_ptrs = d_inputs.iter().map(|buf| buf.as_ptr()).collect_vec();
        let output_ptrs = d_outputs.iter().map(|buf| buf.as_mut_ptr()).collect_vec();
        let widths = mats.iter().map(|mat| mat.width() as u32).collect_vec();
        let d_input_ptrs = input_ptrs.to_device().unwrap();
        let d_output_ptrs = output_ptrs.to_device().unwrap();
        let d_widths = widths.to_device().unwrap();
        let d_log_output_heights = log_output_heights.to_device().unwrap();

        // SAFETY: as `assert_fold_mle_matches_cpu`, including its output-only padding, except that
        // matrix `i` folds against its own `log_output_heights[i]`, so input buffer `i` holds
        // `2 * output_heights[i] * widths[i]` elements.
        unsafe {
            FK::batch_fold_mle(
                &d_input_ptrs,
                &d_output_ptrs,
                &d_widths,
                mats.len().try_into().unwrap(),
                &d_log_output_heights,
                max_output_cells as u32,
                r,
            )
            .unwrap_or_else(|e| panic!("{case}: batch_fold_mle launch failed: {e:?}"));
        }
        device_synchronize().unwrap();

        let expected = batch_fold_mle_evals(mats.to_vec(), r);
        for (i, ((mat, d_out), want)) in
            mats.iter().zip(d_outputs.iter()).zip(&expected).enumerate()
        {
            let got = d_out.to_host().unwrap();
            assert_output_matches::<FK>(
                case,
                i,
                output_heights[i],
                mat.width(),
                max_output_cells,
                &got,
                want,
            );
        }
    }

    /// Uploads `mats` exactly as the parity harness does, then calls `FK::fold_mle` with a
    /// deliberately degenerate `output_height` / `max_output_cells` and asserts the launcher
    /// *refuses*: `cudaErrorInvalidValue` back through the wrapper, and the output buffers still
    /// holding nothing but [`canary`], which is what says no kernel ran. Every buffer handed in is
    /// valid and self-consistent -- only the scalar under test lies -- so a failure here is a
    /// missing guard, not a broken harness.
    pub(crate) fn assert_fold_mle_rejects<FK: FieldKernels>(
        case: &str,
        mats: &[ColMajorMatrix<FK::ValExt>],
        r: FK::ValExt,
        output_height: u32,
        max_output_cells: u32,
    ) {
        let valid_output_height = mats[0].height() >> 1;
        // Sized for whichever is larger: the matrices' true output cells, or the grid the
        // degenerate `max_output_cells` would have built -- so a launch that should not have
        // happened still writes inside the allocation.
        let alloc_cells = mats
            .iter()
            .map(|mat| valid_output_height * mat.width())
            .max()
            .unwrap()
            .max(max_output_cells as usize);

        let d_inputs = mats
            .iter()
            .map(|mat| mat.values.as_slice().to_device().unwrap())
            .collect_vec();
        let (d_outputs, _fills) = alloc_canary_outputs::<FK>(mats.len(), alloc_cells);

        let input_ptrs = d_inputs.iter().map(|buf| buf.as_ptr()).collect_vec();
        let output_ptrs = d_outputs.iter().map(|buf| buf.as_mut_ptr()).collect_vec();
        let widths = mats.iter().map(|mat| mat.width() as u32).collect_vec();
        let d_input_ptrs = input_ptrs.to_device().unwrap();
        let d_output_ptrs = output_ptrs.to_device().unwrap();
        let d_widths = widths.to_device().unwrap();

        // SAFETY: every buffer is sized for the matrices' true shapes and outlives the call; the
        // launcher is expected to return before dereferencing any of them.
        let err = unsafe {
            FK::fold_mle(
                &d_input_ptrs,
                &d_output_ptrs,
                &d_widths,
                mats.len().try_into().unwrap(),
                output_height,
                max_output_cells,
                r,
            )
        }
        .expect_err(&format!(
            "{case}: the launcher accepted output_height={output_height}, \
             max_output_cells={max_output_cells}"
        ));
        assert_eq!(
            err.code, CUDA_ERROR_INVALID_VALUE,
            "{case}: expected cudaErrorInvalidValue, got {err:?}"
        );

        device_synchronize().unwrap();
        for (i, d_out) in d_outputs.iter().enumerate() {
            for (j, cell) in d_out.to_host().unwrap().iter().enumerate() {
                assert_eq!(
                    *cell,
                    canary::<FK>(),
                    "{case}: matrix {i} cell {j} was written -- the launcher rejected the \
                     arguments but still launched"
                );
            }
        }
    }

    /// [`assert_fold_mle_rejects`] for `FK::batch_fold_mle`, which shares the launch-parameter
    /// helper and therefore the same `max_output_cells == 0` division by zero, but takes its
    /// heights as logs and so has no height check of its own.
    pub(crate) fn assert_batch_fold_mle_rejects<FK: FieldKernels>(
        case: &str,
        mats: &[ColMajorMatrix<FK::ValExt>],
        r: FK::ValExt,
        max_output_cells: u32,
    ) {
        let output_heights = mats.iter().map(|mat| mat.height() >> 1).collect_vec();
        let log_output_heights = output_heights
            .iter()
            .map(|&h| h.ilog2() as u8)
            .collect_vec();
        // As in `assert_fold_mle_rejects`: cover both the true output cells and the grid the
        // degenerate `max_output_cells` would have produced.
        let alloc_cells = output_heights
            .iter()
            .zip(mats)
            .map(|(&h, mat)| h * mat.width())
            .max()
            .unwrap()
            .max(max_output_cells as usize);

        let d_inputs = mats
            .iter()
            .map(|mat| mat.values.as_slice().to_device().unwrap())
            .collect_vec();
        let (d_outputs, _fills) = alloc_canary_outputs::<FK>(mats.len(), alloc_cells);

        let input_ptrs = d_inputs.iter().map(|buf| buf.as_ptr()).collect_vec();
        let output_ptrs = d_outputs.iter().map(|buf| buf.as_mut_ptr()).collect_vec();
        let widths = mats.iter().map(|mat| mat.width() as u32).collect_vec();
        let d_input_ptrs = input_ptrs.to_device().unwrap();
        let d_output_ptrs = output_ptrs.to_device().unwrap();
        let d_widths = widths.to_device().unwrap();
        let d_log_output_heights = log_output_heights.to_device().unwrap();

        // SAFETY: as `assert_batch_fold_mle_matches_cpu` -- every buffer is sized for its own
        // matrix's true shape and outlives the call; only `max_output_cells` is degenerate.
        let err = unsafe {
            FK::batch_fold_mle(
                &d_input_ptrs,
                &d_output_ptrs,
                &d_widths,
                mats.len().try_into().unwrap(),
                &d_log_output_heights,
                max_output_cells,
                r,
            )
        }
        .expect_err(&format!(
            "{case}: the launcher accepted max_output_cells={max_output_cells}"
        ));
        assert_eq!(
            err.code, CUDA_ERROR_INVALID_VALUE,
            "{case}: expected cudaErrorInvalidValue, got {err:?}"
        );

        device_synchronize().unwrap();
        for (i, d_out) in d_outputs.iter().enumerate() {
            for (j, cell) in d_out.to_host().unwrap().iter().enumerate() {
                assert_eq!(
                    *cell,
                    canary::<FK>(),
                    "{case}: matrix {i} cell {j} was written -- the launcher rejected the \
                     arguments but still launched"
                );
            }
        }
    }

    /// Builds an `EqEvalSegments` over `x`, folds it with `FK::triangular_fold_mle`, and checks
    /// first the *input* segment tree's convention -- layer `n` is
    /// `evals_eq_hypercube_serial(&x[..n])`, with `eval_eq_mle` as the pointwise arbiter pinning
    /// the little-endian index convention -- and then the fold identity
    /// `out_n[y] = eq(x[0], r) * eq(x[1..=n], y)`, which holds because adjacent indices `2y` /
    /// `2y + 1` of input layer `n + 1` differ only in bit 0 (the variable `x[0]`), so folding them
    /// at `r` factors out their common `eq(x[1..=n], y)`.
    ///
    /// `x` must be non-empty; `output_max_n = x.len() - 1`, the shape `triangular_fold_mle`
    /// requires (input segment tree twice the output's size).
    // KB-gated for the same reason as `assert_batch_fold_mle_matches_cpu` above.
    pub(crate) fn assert_triangular_fold_matches_cpu<FK: FieldKernels>(
        case: &str,
        x: &[FK::ValExt],
        r: FK::ValExt,
    ) {
        let output_max_n = x.len().checked_sub(1).expect("x must be non-empty");
        let input = EqEvalSegments::<FK::ValExt>::new_with_kernels::<FK>(x).unwrap();
        device_synchronize().unwrap();

        // ── Step 1: the input segment tree's bit-order convention ──────────────────
        let input_host = input.buffer().to_host().unwrap();
        assert_eq!(
            input_host.len(),
            2 << x.len(),
            "{case}: EqEvalSegments buffer holds 2^(max_n + 1) cells"
        );
        for n in 0..=x.len() {
            let cpu = evals_eq_hypercube_serial(&x[..n]);
            for (i, want) in cpu.iter().enumerate() {
                let point = (0..n)
                    .map(|j| {
                        if (i >> j) & 1 == 1 {
                            FK::ValExt::ONE
                        } else {
                            FK::ValExt::ZERO
                        }
                    })
                    .collect_vec();
                assert_eq!(
                    *want,
                    eval_eq_mle(&x[..n], &point),
                    "{case}: oracle bit-order self-check, layer {n} index {i}"
                );
            }
            let gpu = &input_host[(1 << n)..(2 << n)];
            for (i, (g, c)) in gpu.iter().zip(cpu.iter()).enumerate() {
                assert_eq!(g, c, "{case}: input eq layer {n} index {i}");
            }
        }

        // ── Step 2: the fold identity ─────────────────────────────────────────────
        let seed = [FK::ValExt::ZERO];
        let mut buffer = DeviceBuffer::<FK::ValExt>::with_capacity(2 << output_max_n);
        seed.copy_to(&mut buffer).unwrap();
        // SAFETY: `buffer` has exactly the `2 << output_max_n` elements `EqEvalSegments` documents
        // for `max_n = output_max_n`, and the copy above zeroed its never-read index-0 slot.
        let mut output = unsafe { EqEvalSegments::from_raw_parts(buffer, output_max_n) };
        // SAFETY: `input` holds the `4 << output_max_n` elements `triangular_fold_mle` reads and
        // `output` the `2 << output_max_n` it writes; the per-thread default stream orders the
        // fills above before this launch, and `seed` outlives the synchronization below.
        unsafe {
            FK::triangular_fold_mle(&mut output, &input, r, output_max_n)
                .unwrap_or_else(|e| panic!("{case}: triangular_fold_mle launch failed: {e:?}"));
        }
        device_synchronize().unwrap();

        let eq_x0_r: FK::ValExt = eval_eq_mle(&x[..1], &[r]);
        let output_host = output.buffer().to_host().unwrap();
        for n in 0..=output_max_n {
            let tail = evals_eq_hypercube_serial(&x[1..n + 1]);
            let gpu = &output_host[(1 << n)..(2 << n)];
            assert_eq!(gpu.len(), tail.len(), "{case}: output layer {n} len");
            for (y, (g, t)) in gpu.iter().zip(tail.iter()).enumerate() {
                assert_eq!(*g, eq_x0_r * *t, "{case}: output eq layer {n} index {y}");
            }
        }
    }
}
