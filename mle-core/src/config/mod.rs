use p3_field::TwoAdicField;
use p3_koala_bear::KoalaBear;

use crate::{
    config::{
        log_up_params::log_up_security_params_koala_bear_100_bits, soundness::SoundnessCalculator,
    },
    interaction::LogUpSecurityParameters,
};

/// STARK protocol configuration trait (`StarkProtocolConfig`, `SystemParams`, ...).
#[allow(clippy::module_inception)]
mod config;
pub use config::*;

/// Protocol hasher trait definition.
pub mod hasher;
/// Multi-field packing helpers used by the multi-field transcript.
#[cfg(feature = "multi-field-transcript")]
pub mod multi_field_packing;
/// Round-by-round soundness calculator (`SoundnessCalculator`) for the MLE proof system.
pub mod soundness;

/// STARK config where the base field is KoalaBear, extension field is KoalaBear^4, and the hasher
/// is `Poseidon2<KoalaBear>`.
pub mod koala_bear_poseidon2;
pub mod log_up_params;

// ==========================================================================
// Production configurations
// ==========================================================================
// These configurations target 100-bits of proven round-by-round (RBR) security with KoalaBear as
// the base field and KoalaBear^4 as the extension field.

const WHIR_MAX_LOG_FINAL_POLY_LEN: usize = 10;
const SECURITY_BITS_TARGET: usize = 100;

/// LogUp grinding sufficient for 100-bit security, accounting for the PCS list-size union bound of
/// the initial WHIR proximity regime (`log2_pcs_list_size` is 0 for unique decoding).
///
/// The list size depends only on the *initial* WHIR round's proximity regime, rate, and degree, so
/// it can be derived up front from the same inputs `SystemParams::new` uses to build the WHIR
/// config and passed straight in. `w_stack` is there because the calculator takes a batch size, not
/// because it moves the grinding.
fn log_up_params_for_whir(
    proximity: WhirProximityStrategy,
    log_stacked_height: usize,
    log_blowup: usize,
    w_stack: usize,
) -> LogUpSecurityParameters {
    let log2_pcs_list_size = SoundnessCalculator::whir_proximity_gap_security(
        proximity.initial_round(),
        soundness::challenge_field_bits::<koala_bear_poseidon2::KoalaBearPoseidon2Config>(),
        log_stacked_height,
        log_blowup,
        w_stack,
    )
    .log2_list_size;
    log_up_security_params_koala_bear_100_bits(log2_pcs_list_size)
}

pub const DEFAULT_RISCV_L_SKIP: usize = 4;
pub const DEFAULT_RISCV_LOG_BLOWUP: usize = 1;
pub const DEFAULT_RECURSION_LOG_BLOWUP: usize = 2;
pub const DEFAULT_ROOT_LOG_BLOWUP: usize = 4;

/// The tallest riscv stacked height KoalaBear can encode: the RS domain is
/// `2^(log_stacked_height + DEFAULT_RISCV_LOG_BLOWUP)`, and its exponent cannot pass the field's
/// two-adicity.
pub const MAX_RISCV_LOG_STACKED_HEIGHT: usize =
    <KoalaBear as TwoAdicField>::TWO_ADICITY - DEFAULT_RISCV_LOG_BLOWUP;

/// Global constraint-degree bound of the riscv machine. Every riscv AIR is at most cubic (the
/// Cpu and MemoryInitialize/Finalize hand-off constraints were the last degree-4 ones); keygen
/// rejects any AIR above this bound, so a regression cannot slip through silently. Lowering it
/// from 4 cuts the zerocheck batch-sumcheck round polynomials from 5 to 4 evaluations and the
/// univariate-skip round polynomial from degree 75 to 60 (76 to 61 coefficients), and it only
/// raises the soundness bound.
pub const RISCV_MAX_CONSTRAINT_DEGREE: usize = 3;
/// Global constraint-degree bound of the recursion machines: `GkrSumcheckRoundChip` and
/// `BinaryFoldStepChip` carry degree-4 constraints.
pub const RECURSION_MAX_CONSTRAINT_DEGREE: usize = 4;

/// Returns `SystemParams` targeting 100 bits of proven RBR security for the riscv machine.
///
/// # Assumptions for 100-bit security
/// - **Max trace height**: `log_stacked_height` ≤ [`MAX_RISCV_LOG_STACKED_HEIGHT`] (23): with
///   `log_blowup = 1` the RS domain is `2^(log_stacked_height + 1)`, and KoalaBear's two-adicity
///   is 24.
/// - **Max constraints per AIR**: ≤ 5,000
/// - **Num AIRs**: ≤ 100
/// - **Max interactions per AIR**: ≤ 2,000
/// - **Num trace columns** (unstacked, total across all AIRs): ≤ 40,000
/// - **`w_stack`** = 2,048, bounding total stacked cells to `w_stack × 2^(n_stack + l_skip)`
/// - **Max constraint degree**: [`RISCV_MAX_CONSTRAINT_DEGREE`] (3), enforced at keygen
///
/// Checked by `tests/soundness.rs` at every height this preset admits, at these bounds and at the
/// measured shape of the riscv machine.
///
/// Panics with the [`ParamsError`] that [`try_riscv_params_with_100_bits_security`] returns.
pub fn riscv_params_with_100_bits_security(log_stacked_height: usize) -> SystemParams {
    try_riscv_params_with_100_bits_security(log_stacked_height)
        .unwrap_or_else(|err| panic!("{err}"))
}

/// [`riscv_params_with_100_bits_security`], refusing a height above
/// [`MAX_RISCV_LOG_STACKED_HEIGHT`], or one at or below `WHIR_MAX_LOG_FINAL_POLY_LEN` (10), which
/// leaves no WHIR round. The way to vet a riscv height: it makes every check the preset makes.
pub fn try_riscv_params_with_100_bits_security(
    log_stacked_height: usize,
) -> Result<SystemParams, ParamsError> {
    check_rs_domain::<KoalaBear>(log_stacked_height, DEFAULT_RISCV_LOG_BLOWUP)?;
    check_whir_round(log_stacked_height)?;
    const W_STACK: usize = 2048;
    let n_stack = log_stacked_height - DEFAULT_RISCV_L_SKIP;
    admit_koala_bear(SystemParams::try_new(
        DEFAULT_RISCV_LOG_BLOWUP,
        DEFAULT_RISCV_L_SKIP,
        n_stack,
        W_STACK,
        WHIR_MAX_LOG_FINAL_POLY_LEN,
        5,  // folding pow
        15, // mu pow
        WhirProximityStrategy::UniqueDecoding,
        SECURITY_BITS_TARGET,
        log_up_params_for_whir(
            WhirProximityStrategy::UniqueDecoding,
            DEFAULT_RISCV_L_SKIP + n_stack,
            DEFAULT_RISCV_LOG_BLOWUP,
            W_STACK,
        ),
        RISCV_MAX_CONSTRAINT_DEGREE,
    )?)
}

/// Refuses a preset height at or below the final polynomial length, which leaves no WHIR round,
/// before the height is split into `l_skip + n_stack` and could no longer be reported as asked.
fn check_whir_round(log_stacked_height: usize) -> Result<(), ParamsError> {
    if log_stacked_height <= WHIR_MAX_LOG_FINAL_POLY_LEN {
        return Err(ParamsError::NoWhirRound {
            log_stacked_height,
            log_final_poly_len: WHIR_MAX_LOG_FINAL_POLY_LEN,
        });
    }
    Ok(())
}

/// Default `log_blowup` for the compress layer (higher than app to reduce WHIR query count).
pub const DEFAULT_COMPRESS_LOG_BLOWUP: usize = 2;

/// Returns `SystemParams` for the compress layer targeting 100 bits of proven RBR security.
///
/// Uses `log_blowup=2` (vs `riscv_params` which uses 1) to reduce WHIR query count while
/// maintaining the same security level. Re-proves a single combine proof into a smaller proof.
/// The RS domain is `2^(log_stacked_height + 2)`, so KoalaBear holds heights up to 22.
///
/// Panics with the [`ParamsError`] that [`try_compress_params_with_100_bits_security`] returns.
pub fn compress_params_with_100_bits_security(log_stacked_height: usize) -> SystemParams {
    try_compress_params_with_100_bits_security(log_stacked_height)
        .unwrap_or_else(|err| panic!("{err}"))
}

/// [`compress_params_with_100_bits_security`], refusing a height whose RS domain KoalaBear cannot
/// hold, or one that leaves no WHIR round.
pub fn try_compress_params_with_100_bits_security(
    log_stacked_height: usize,
) -> Result<SystemParams, ParamsError> {
    check_rs_domain::<KoalaBear>(log_stacked_height, DEFAULT_COMPRESS_LOG_BLOWUP)?;
    check_whir_round(log_stacked_height)?;
    admit_koala_bear(SystemParams::try_new(
        DEFAULT_COMPRESS_LOG_BLOWUP,
        DEFAULT_RISCV_L_SKIP,
        log_stacked_height - DEFAULT_RISCV_L_SKIP,
        2048,
        WHIR_MAX_LOG_FINAL_POLY_LEN,
        5,  // folding pow
        15, // mu pow
        WhirProximityStrategy::UniqueDecoding,
        SECURITY_BITS_TARGET,
        log_up_params_for_whir(
            WhirProximityStrategy::UniqueDecoding,
            log_stacked_height,
            DEFAULT_COMPRESS_LOG_BLOWUP,
            2048,
        ),
        RECURSION_MAX_CONSTRAINT_DEGREE,
    )?)
}

/// Returns `SystemParams` for the embed layer targeting 100 bits of proven RBR security.
///
/// The embed layer re-proves a complete recursion root under the outer (BN254-hashed) config so an
/// on-chain gnark circuit can verify it with native BN254 permutations. Only the hash and the
/// transcript change there, so these are ordinary KoalaBear STARK parameters; what makes them their
/// own preset is that the *verifier* is a Groth16 circuit, and every WHIR query it checks costs
/// R1CS constraints.
///
/// # Assumptions for 100-bit security
/// - **Max trace height**: ≤ 2^20 (= `l_skip + n_stack`)
/// - **Max constraints per AIR**: ≤ 1,000
/// - **Num AIRs**: ≤ 21 (the recursion chip set)
/// - **Max interactions per AIR**: ≤ 100
/// - **Num trace columns** (unstacked, total across all AIRs): ≤ 2,000
/// - **`w_stack`** = 64, bounding total stacked cells to `w_stack × 2^(n_stack + l_skip)`
///
/// Config: `l_skip=4, n_stack=16, log_blowup=4` — the RS domain is `4+16+4 = 24`, exactly
/// KoalaBear's two-adicity, so this is the largest blowup (hence the fewest WHIR queries) the field
/// allows at this stacked height. Measured over a real combine root: tallest chip 2^16 (16×
/// headroom) and stacked `Σw = 17` against `w_stack = 64` (3.8×).
///
/// # Why ListDecoding { m: 1 }
///
/// The list-decoding regime cuts the WHIR query count from 250 (UniqueDecoding) to 104, and the
/// wrap circuit's permutation count with it. The [`soundness`] calculator charges the list size in
/// the fold error, uses the *next* round's list size for the OOD/shift terms and charges `L_PCS` as
/// a penalty rather than a bonus, so its verdict is a soundness claim in this regime too.
///
/// Measured with this calculator at the assumptions above: `log2(L_PCS) = 2.585`,
/// LogUp grinding derived to 18 bits, total **100.38 bits**, binding term LogUp (WHIR is at
/// 100.66: query/shift 100.66, OOD 100.78, fold 101.61). `m = 2` at this shape reaches only 97.93
/// and is therefore not usable. See `embed_preset_meets_100_bits_at_assumed_bounds` in
/// `tests/soundness.rs`.
///
/// Reducing `n_stack` to buy a shorter WHIR schedule is a false economy and was measured: it raises
/// the stacked width, and the initial WHIR round opens `2^k` rows of `Σw` felts per query, so the
/// leaf hashing grows faster than the query count falls (`n=16/blowup=4` → ~5.7k circuit
/// permutations; `n=14/blowup=6/w=128` → ~8.3k despite 163 queries instead of 250).
pub fn embed_params_with_100_bits_security() -> SystemParams {
    const EMBED_PROXIMITY: WhirProximityStrategy = WhirProximityStrategy::ListDecoding { m: 1 };
    admit_koala_bear(SystemParams::new(
        DEFAULT_ROOT_LOG_BLOWUP,
        DEFAULT_RISCV_L_SKIP,
        16, // n_stack → log_stacked_height 20
        64, // w_stack (measured embed Σw = 17)
        WHIR_MAX_LOG_FINAL_POLY_LEN,
        16, // folding pow (LD{m:1} retune)
        18, // mu pow (LD{m:1} retune)
        EMBED_PROXIMITY,
        SECURITY_BITS_TARGET,
        log_up_params_for_whir(
            EMBED_PROXIMITY,
            DEFAULT_RISCV_L_SKIP + 16,
            DEFAULT_ROOT_LOG_BLOWUP,
            64,
        ),
        RECURSION_MAX_CONSTRAINT_DEGREE,
    ))
    .unwrap_or_else(|err| panic!("{err}"))
}

/// Returns `SystemParams` targeting 100 bits of proven RBR security for the recursion machines
/// (convert and combine, and the CPU-side root verification).
///
/// # Assumptions for 100-bit security
/// - **Max trace height**: ≤ 2^21
/// - **Max constraints per AIR**: ≤ 1,000
/// - **Num AIRs**: ≤ 50
/// - **Max interactions per AIR**: ≤ 100 (maximum number of interactions in a single AIR for a
///   single row)
/// - **Num trace columns** (unstacked, total across all AIRs): ≤ 2,000
/// - **`w_stack`** = 2,048, bounding total stacked cells to `w_stack × 2^(n_stack + l_skip)`
/// - **Max constraint degree**: [`RECURSION_MAX_CONSTRAINT_DEGREE`] (4), enforced at keygen
///
/// Config: `l_skip=4, n_stack=17, log_blowup=2`.
///
/// Checked by `tests/soundness.rs` at these bounds and at the measured shape of the convert and
/// combine machines.
pub fn recursion_params_with_100_bits_security() -> SystemParams {
    const L_SKIP: usize = 4;
    const N_STACK: usize = 17;
    const W_STACK: usize = 2048;
    admit_koala_bear(SystemParams::new(
        DEFAULT_RECURSION_LOG_BLOWUP,
        L_SKIP,
        N_STACK,
        W_STACK,
        WHIR_MAX_LOG_FINAL_POLY_LEN,
        4,  // folding pow
        13, // mu pow
        WhirProximityStrategy::UniqueDecoding,
        SECURITY_BITS_TARGET,
        log_up_params_for_whir(
            WhirProximityStrategy::UniqueDecoding,
            L_SKIP + N_STACK,
            DEFAULT_RECURSION_LOG_BLOWUP,
            W_STACK,
        ),
        RECURSION_MAX_CONSTRAINT_DEGREE,
    ))
    .unwrap_or_else(|err| panic!("{err}"))
}

/// `params`, once [`check_field_admissible`] accepts it over KoalaBear, the field every preset
/// proves over.
fn admit_koala_bear(params: SystemParams) -> Result<SystemParams, ParamsError> {
    check_field_admissible::<KoalaBear>(&params)?;
    Ok(params)
}

// ==========================================================================
// Field constants for the soundness calculator (production KoalaBear config)
// ==========================================================================

/// Order `p` of the base field for the production [`koala_bear_poseidon2::KoalaBearPoseidon2Config`]
/// (`2^31 - 2^24 + 1`), as an `f64` for the soundness calculator.
pub fn base_field_order() -> f64 {
    soundness::base_field_order::<koala_bear_poseidon2::KoalaBearPoseidon2Config>()
}

/// Number of bits in the challenge field `KoalaBear^4` for the production config (`4 · log2 p`,
/// about 123.95).
pub fn challenge_field_bits() -> f64 {
    soundness::challenge_field_bits::<koala_bear_poseidon2::KoalaBearPoseidon2Config>()
}

#[cfg(test)]
mod poseidon2_kat;

#[cfg(test)]
mod tests {
    use p3_koala_bear::KoalaBear;

    use super::*;
    use crate::p3_field::PrimeField32;

    /// Deriving the LogUp grinding from the soundness calculator must not move the wired presets:
    /// both run WHIR in unique decoding, where the PCS list size is 1 and the derivation lands on
    /// the historical floor of 18 grinding bits.
    #[test]
    fn wired_presets_keep_their_log_up_parameters() {
        fn expect(logup: &LogUpSecurityParameters, label: &str) {
            assert_eq!(logup.max_interaction_count, KoalaBear::ORDER_U32, "{label}");
            assert_eq!(logup.log_max_message_length, 7, "{label}");
            assert_eq!(logup.pow_bits, 18, "{label}");
        }
        for log_stacked_height in WHIR_MAX_LOG_FINAL_POLY_LEN + 1..=MAX_RISCV_LOG_STACKED_HEIGHT {
            expect(
                &riscv_params_with_100_bits_security(log_stacked_height).logup,
                &format!("riscv @ log_stacked_height {log_stacked_height}"),
            );
        }
        expect(
            &recursion_params_with_100_bits_security().logup,
            "recursion",
        );
    }

    /// The helper has to charge the initial round's list size, which the wired presets cannot
    /// show: they are all unique decoding, where it is zero. Under list decoding the derivation
    /// rises above the floor, and this shape lands on the same value under both BCHKS25 degree
    /// bounds.
    #[test]
    fn log_up_params_for_whir_charges_the_initial_round_list_size() {
        let params =
            log_up_params_for_whir(WhirProximityStrategy::ListDecoding { m: 4 }, 20, 4, 64);
        assert_eq!(params.pow_bits, 20);
    }
}
