use p3_field::TwoAdicField;
use p3_koala_bear::KoalaBear;

use crate::{
    config::{
        log_up_params::log_up_security_params_koala_bear_128_bits, soundness::SoundnessCalculator,
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

/// STARK config where the base field is KoalaBear, extension field is KoalaBear^5, and the hasher
/// is `Poseidon2<KoalaBear>`.
pub mod koala_bear_poseidon2;
pub mod log_up_params;

// ==========================================================================
// Production configurations
// ==========================================================================
// These configurations target 128 bits of proven round-by-round (RBR) security with KoalaBear as
// the base field and KoalaBear^5 as the extension field.

const WHIR_MAX_LOG_FINAL_POLY_LEN: usize = 10;
const SECURITY_BITS_TARGET: usize = 128;

/// LogUp grinding sufficient for 128-bit security, accounting for the PCS list-size union bound of
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
    log_up_security_params_koala_bear_128_bits(initial_round_log2_list_size(
        proximity,
        log_stacked_height,
        log_blowup,
        w_stack,
    ))
}

/// `log2(L_PCS)` of the initial WHIR round: the list-size charge `log_up_params_for_whir` passes
/// on; zero under unique decoding.
fn initial_round_log2_list_size(
    proximity: WhirProximityStrategy,
    log_stacked_height: usize,
    log_blowup: usize,
    w_stack: usize,
) -> f64 {
    SoundnessCalculator::whir_proximity_gap_security(
        proximity.initial_round(),
        soundness::challenge_field_bits::<koala_bear_poseidon2::KoalaBearPoseidon2Config>(),
        log_stacked_height,
        log_blowup,
        w_stack,
    )
    .log2_list_size
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

/// Returns `SystemParams` targeting 128 bits of proven RBR security for the riscv machine.
///
/// # Assumptions for 128-bit security
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
/// Panics with the [`ParamsError`] that [`try_riscv_params_with_128_bits_security`] returns.
pub fn riscv_params_with_128_bits_security(log_stacked_height: usize) -> SystemParams {
    try_riscv_params_with_128_bits_security(log_stacked_height)
        .unwrap_or_else(|err| panic!("{err}"))
}

/// [`riscv_params_with_128_bits_security`], refusing a height above
/// [`MAX_RISCV_LOG_STACKED_HEIGHT`], or one at or below `WHIR_MAX_LOG_FINAL_POLY_LEN` (10), which
/// leaves no WHIR round. The way to vet a riscv height: it makes every check the preset makes.
pub fn try_riscv_params_with_128_bits_security(
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

/// Returns `SystemParams` for the compress layer targeting 128 bits of proven RBR security.
///
/// The compress layer is the final compression layer: a complete combine root re-proved 1:1 by the
/// recursion chip set under the inner KoalaBear-Poseidon2 config, into the one proof that is
/// handed out (the ≤ 300 KiB basis), which embed re-proves for the on-chain path. Its parameters
/// are the embed preset's, value for value, and the two are separate functions, since they are
/// tuned for different costs — compress for proof size, embed for the Groth16 circuit's cost per
/// WHIR query. Keeping embed's values equal to these is a choice (the wrap circuit over them is
/// 7,243,820 R1CS, 13.6% under 2^23), not a necessity: `compress_and_embed_params_agree_today` in
/// `tests/soundness.rs` pins it while it holds.
///
/// # Assumptions for 128-bit security
/// Those of [`embed_params_with_128_bits_security`]: height ≤ 2^20, ≤ 1,000 constraints and ≤ 100
/// interactions per AIR, ≤ 21 AIRs, ≤ 2,000 columns, `w_stack` 64. Measured: 21 AIRs / 170
/// constraints / 34 interactions / 1409 columns, 128.05 bits. In dev mode (whitelist off) the
/// heights are the program's natural heights over the root it is given, so the size follows the
/// input: stacked width 20 + 5 (main + preprocessed) = 25 and 299,179 bytes = 292.17 KiB with
/// `--step compress` on reth 18884864 (and on reth 24600825 when the layer was introduced);
/// fib-10's smaller root gives 15 + 5 = 20 and 278,279 bytes. In whitelist mode the heights are the
/// compress tier row's (`MLE_RECURSION_COMPRESS_LOG_HEIGHTS`), the program's natural heights over
/// the one combine-tier root layout, the largest a root takes, so every proof has the largest
/// dev-mode shape: stacked width 20 + 5 = 25 against `w_stack` 64, 299,179 bytes, 128.05 bits,
/// measured under a self-built whitelist on fib-10 and reth 18884864 / 24600825 and under the
/// shipped artifact. (Before compress had its own row, it padded to the embed row of the time:
/// stacked width 52, 403.85 KiB. The row decides the whitelist-mode size.)
///
/// Config: `l_skip=4, n_stack=16, log_blowup=4`, `ListDecoding { m: 2 }`, fold PoW 16, μ PoW 18,
/// queries [65, 34, 24]; the reasoning behind each value is in the embed preset's doc.
pub fn compress_params_with_128_bits_security() -> SystemParams {
    const COMPRESS_PROXIMITY: WhirProximityStrategy = WhirProximityStrategy::ListDecoding { m: 2 };
    admit_koala_bear(SystemParams::new(
        DEFAULT_ROOT_LOG_BLOWUP,
        DEFAULT_RISCV_L_SKIP,
        16, // n_stack → log_stacked_height 20
        64, // w_stack (measured compress stacked width 25: whitelist mode, the dev-mode maximum)
        WHIR_MAX_LOG_FINAL_POLY_LEN,
        16, // folding pow
        18, // mu pow
        COMPRESS_PROXIMITY,
        SECURITY_BITS_TARGET,
        log_up_params_for_whir(
            COMPRESS_PROXIMITY,
            DEFAULT_RISCV_L_SKIP + 16,
            DEFAULT_ROOT_LOG_BLOWUP,
            64,
        ),
        RECURSION_MAX_CONSTRAINT_DEGREE,
    ))
    .unwrap_or_else(|err| panic!("{err}"))
}

/// Returns `SystemParams` for the embed layer targeting 128 bits of proven RBR security.
///
/// The embed layer re-proves the compress proof under the outer (BN254-hashed) config so an
/// on-chain gnark circuit can verify it with native BN254 permutations. Only the hash and the
/// transcript change there, so these are ordinary KoalaBear STARK parameters; what makes them their
/// own preset is that the *verifier* is a Groth16 circuit, and every WHIR query it checks costs
/// R1CS constraints.
///
/// # Assumptions for 128-bit security
/// - **Max trace height**: ≤ 2^20 (= `l_skip + n_stack`)
/// - **Max constraints per AIR**: ≤ 1,000
/// - **Num AIRs**: ≤ 21 (the recursion chip set)
/// - **Max interactions per AIR**: ≤ 100
/// - **Num trace columns** (unstacked, total across all AIRs): ≤ 2,000
/// - **`w_stack`** = 64, bounding total stacked cells to `w_stack × 2^(n_stack + l_skip)`
///
/// Config: `l_skip=4, n_stack=16, log_blowup=4` — the RS domain is `4+16+4 = 24`, exactly
/// KoalaBear's two-adicity, so this is the largest blowup (hence the fewest WHIR queries) the field
/// allows at this stacked height. Measured in dev mode over the compress proof of fib-10:
/// tallest chip 2^16 (16× headroom) and stacked width 8 + 3 (main + preprocessed) = 11 against
/// `w_stack = 64`, proof 239,319 bytes = 233.71 KiB; in whitelist mode the heights are the embed
/// tier row's (`MLE_RECURSION_EMBED_LOG_HEIGHTS`), the natural heights of the embed program over
/// the compress proof's layout, measured by the tier probe: tallest chip 2^16 (ExtAlu);
/// `--step wrap` (through embed) under the shipped artifact measured the same on fib-10 and reth
/// 18884864: stacked width 11, 239,319 bytes. (When embed re-proved the combine root, it had the
/// compress proof's shape: stacked width 25 and 299,179 bytes in whitelist mode.)
///
/// # Why ListDecoding { m: 2 }
///
/// List decoding cuts the WHIR query count against unique decoding, and the wrap circuit's
/// permutation count with it. At the 128-bit target over KoalaBear^5 `m = 2`
/// solves to [65, 34, 24] queries at `l_skip=4, n_stack=16, log_blowup=4`, fold PoW 16, μ PoW 18;
/// `m = 1` needs more queries ([77, 38, 25]); `m ≥ 3` would need fewer still, but its fold term
/// falls below the target at fold PoW 16 (`m = 3`: 126.49 bits), so `m = 2` is the largest list
/// size this shape admits. The [`soundness`] calculator charges the list size in the fold
/// error, uses the *next* round's list size for the OOD/shift terms and charges `L_PCS` as a
/// penalty rather than a bonus, so its verdict is a soundness claim in this regime too.
///
/// Scored with this calculator at the assumptions above: LogUp grinding at the wired 18-bit floor
/// (the derivation needs 16 bits at this list size, see `log_up_params.rs`), LogUp 130.63 bits,
/// total **128.05 bits**, binding term WHIR query / shift (128.05; proximity gaps and fold 128.92,
/// OOD 130.30, μ batching 130.94). See
/// `embed_preset_meets_128_bits_at_assumed_bounds` and `embed_components_are_pinned` in
/// `tests/soundness.rs`.
///
/// Reducing `n_stack` to buy a shorter WHIR schedule was measured to be a false economy, on the
/// program over a combine root (when embed re-proved the root; worth measuring again over the
/// smaller program): it
/// raises the stacked width, and the initial WHIR round opens `2^k` rows of `Σw` felts per query,
/// so the leaf hashing grows faster than the query count falls (100-bit unique-decoding figures:
/// `n=16/blowup=4` → ~5.7k circuit permutations, `n=14/blowup=6/w=128` → ~8.3k despite 163 queries
/// instead of 250).
pub fn embed_params_with_128_bits_security() -> SystemParams {
    const EMBED_PROXIMITY: WhirProximityStrategy = WhirProximityStrategy::ListDecoding { m: 2 };
    admit_koala_bear(SystemParams::new(
        DEFAULT_ROOT_LOG_BLOWUP,
        DEFAULT_RISCV_L_SKIP,
        16, // n_stack → log_stacked_height 20
        64, // w_stack (measured embed stacked width 11 over the compress proof)
        WHIR_MAX_LOG_FINAL_POLY_LEN,
        16, // folding pow
        18, // mu pow
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

/// Returns `SystemParams` targeting 128 bits of proven RBR security for the recursion machines
/// (convert, combine and deferred, and the CPU-side root verification).
///
/// # Assumptions for 128-bit security
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
/// Checked by `tests/soundness.rs` at these bounds and at the measured shape of the convert,
/// combine and deferred machines.
pub fn recursion_params_with_128_bits_security() -> SystemParams {
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

/// Number of bits in the challenge field `KoalaBear^5` for the production config (`5 · log2 p`,
/// about 154.94).
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
                &riscv_params_with_128_bits_security(log_stacked_height).logup,
                &format!("riscv @ log_stacked_height {log_stacked_height}"),
            );
        }
        expect(
            &recursion_params_with_128_bits_security().logup,
            "recursion",
        );
    }

    /// The helper has to charge the initial round's list size, which
    /// `wired_presets_keep_their_log_up_parameters` cannot show: riscv and recursion are unique
    /// decoding, where it is zero, and at the 128-bit target over KoalaBear^5 the floor
    /// (`MIN_KOALA_BEAR_LOGUP_POW_BITS`) covers every wired preset. So the charge is read off the
    /// pre-floor requirement: list decoding at this shape needs more grinding than unique
    /// decoding, and the wired value is that requirement floored.
    #[test]
    fn log_up_params_for_whir_charges_the_initial_round_list_size() {
        use log_up_params::{required_log_up_pow_bits, MIN_KOALA_BEAR_LOGUP_POW_BITS};
        let (h, blowup, w) = (20, 4, 64);
        let ud_list =
            initial_round_log2_list_size(WhirProximityStrategy::UniqueDecoding, h, blowup, w);
        let ld_list = initial_round_log2_list_size(
            WhirProximityStrategy::ListDecoding { m: 4 },
            h,
            blowup,
            w,
        );
        assert_eq!(ud_list, 0.0);
        assert!(ld_list > 0.0);
        let (ud_needed, ld_needed) = (
            required_log_up_pow_bits(ud_list),
            required_log_up_pow_bits(ld_list),
        );
        assert_eq!(ud_needed, 13);
        assert!(ld_needed > ud_needed, "list size {ld_list} is not charged");
        if cfg!(not(feature = "soundness-bchks25-optimized")) {
            assert!((ld_list - 4.17).abs() < 0.01, "{ld_list}");
            assert_eq!(ld_needed, 17);
        }
        let ud = log_up_params_for_whir(WhirProximityStrategy::UniqueDecoding, h, blowup, w);
        let ld = log_up_params_for_whir(WhirProximityStrategy::ListDecoding { m: 4 }, h, blowup, w);
        assert_eq!(ud.pow_bits, ud_needed.max(MIN_KOALA_BEAR_LOGUP_POW_BITS));
        assert_eq!(ld.pow_bits, ld_needed.max(MIN_KOALA_BEAR_LOGUP_POW_BITS));
    }
}
