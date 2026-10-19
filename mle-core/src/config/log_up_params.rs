use p3_koala_bear::KoalaBear;

use crate::{
    config::{
        koala_bear_poseidon2::KoalaBearPoseidon2Config,
        soundness::{challenge_field_bits, SoundnessCalculator},
    },
    interaction::LogUpSecurityParameters,
    p3_field::PrimeField32,
};

const TARGET_LOGUP_SECURITY_BITS: f64 = 100.0;
const MIN_KOALA_BEAR_LOGUP_POW_BITS: usize = 18;

/// Returns KoalaBear LogUp parameters with at least 100 bits after the PCS list-size union bound.
///
/// `log2_pcs_list_size` is `log2(L_PCS)` for the initial WHIR proximity regime. It is zero for
/// unique decoding.
pub fn log_up_security_params_koala_bear_100_bits(
    log2_pcs_list_size: f64,
) -> LogUpSecurityParameters {
    assert!(
        log2_pcs_list_size.is_finite() && log2_pcs_list_size >= 0.0,
        "log2_pcs_list_size must be finite and nonnegative"
    );

    let challenge_field_bits = challenge_field_bits::<KoalaBearPoseidon2Config>();
    let max_interaction_count = KoalaBear::ORDER_U32;
    let log_max_message_length = 7;

    // Pre-grinding LogUp security via the soundness calculator (the single source of truth).
    // Security is linear in `pow_bits` with unit slope, so the grinding needed to reach the target
    // is exactly the remaining gap. Floor at `MIN_KOALA_BEAR_LOGUP_POW_BITS` to keep the historical
    // baseline margin for the unique-decoding configs. The authoritative check that the resulting
    // params clear the target is the `*_preset_meets_100_bits_at_assumed_bounds` tests in
    // `tests/soundness.rs`, which run the full calculator (including the `sample_bits` grinding
    // bias).
    let security_without_pow = SoundnessCalculator::logup_soundness(
        max_interaction_count,
        log_max_message_length,
        challenge_field_bits,
        log2_pcs_list_size,
    );
    let pow_bits = ((TARGET_LOGUP_SECURITY_BITS - security_without_pow)
        .ceil()
        .max(0.0) as usize)
        .max(MIN_KOALA_BEAR_LOGUP_POW_BITS);

    LogUpSecurityParameters {
        max_interaction_count,
        log_max_message_length,
        pow_bits,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Nominal (unbiased) LogUp security must clear the target for every list size; the calculator
    /// tests in `tests/soundness.rs` re-check it with the `sample_bits` grinding bias applied.
    #[test]
    fn koala_bear_log_up_params_meet_100_bits() {
        for log2_pcs_list_size in [0.0, 1.0, 2.58497, 3.5] {
            let params = log_up_security_params_koala_bear_100_bits(log2_pcs_list_size);
            let bits = SoundnessCalculator::logup_soundness(
                params.max_interaction_count,
                params.log_max_message_length,
                challenge_field_bits::<KoalaBearPoseidon2Config>(),
                log2_pcs_list_size,
            ) + params.pow_bits as f64;
            assert!(
                bits >= TARGET_LOGUP_SECURITY_BITS,
                "log2(L_PCS) = {log2_pcs_list_size} only reached {bits:.4} bits with pow_bits {}",
                params.pow_bits
            );
        }
    }

    /// Unique decoding lands on the historical floor.
    #[test]
    fn koala_bear_unique_decoding_pow_bits_is_the_floor() {
        let params = log_up_security_params_koala_bear_100_bits(0.0);
        assert_eq!(params.pow_bits, MIN_KOALA_BEAR_LOGUP_POW_BITS);
    }
}
