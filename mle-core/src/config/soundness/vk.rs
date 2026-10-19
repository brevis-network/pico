//! Soundness inputs read off a verifying key.
//!
//! A `MultiStarkVerifyingKey` fixes the protocol parameters and, per AIR, the constraint DAG, the
//! interactions and the trace widths. That is every input of the soundness calculator except two
//! that vary per proof and are taken at their worst case: the trace heights (the verifier-enforced
//! stacked height) and the LogUp-GKR depth ([`WORST_CASE_N_LOGUP`]). [`VkShape`] collects the
//! key's inputs, [`SoundnessCalculator::calculate_from_vk`] scores a key, [`log_vk_soundness`]
//! reports both in one log line after a keygen, and [`admit_production_vk`] does the same and
//! refuses a key that scores below [`PRODUCTION_SECURITY_BITS`].

use thiserror::Error;

use super::{base_field_order, challenge_field_bits, SoundnessCalculator, WhirSoundnessCalculator};
use crate::{
    config::{StarkProtocolConfig, SystemParams, SECURITY_BITS_TARGET},
    keygen::types::MultiStarkVerifyingKey,
};

/// Circuit-shape bounds read off a verifying key, valid for every proof the key can verify.
///
/// Optional AIRs count whether or not a given proof uses them, every trace is taken at the stacked
/// height (the verifier rejects anything taller), and column counts include preprocessed,
/// cached-main and common-main columns. All fields but `max_interactions_per_air` enter the
/// calculator; that one is reported so the preset's documented bound on it can be checked (the
/// LogUp term depends on interactions only through the verifier-enforced total count).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VkShape {
    pub num_airs: usize,
    pub max_constraints_per_air: usize,
    pub max_interactions_per_air: usize,
    /// Total unstacked trace columns across all AIRs (preprocessed + cached mains + common main).
    pub num_trace_columns: usize,
    /// `l_skip + n_stack`: the verifier-enforced bound on every trace's log-height.
    pub log_stacked_height: usize,
}

impl VkShape {
    pub fn from_vk<SC: StarkProtocolConfig>(vk: &MultiStarkVerifyingKey<SC>) -> Self {
        let mut shape = Self {
            num_airs: vk.inner.per_air.len(),
            max_constraints_per_air: 0,
            max_interactions_per_air: 0,
            num_trace_columns: 0,
            log_stacked_height: vk.inner.params.log_stacked_height(),
        };
        for air_vk in &vk.inner.per_air {
            shape.max_constraints_per_air = shape
                .max_constraints_per_air
                .max(air_vk.symbolic_constraints.constraints.constraint_idx.len());
            shape.max_interactions_per_air = shape
                .max_interactions_per_air
                .max(air_vk.symbolic_constraints.interactions.len());
            let width = &air_vk.params.width;
            shape.num_trace_columns += width.preprocessed.unwrap_or(0) + width.main_width();
        }
        shape
    }
}

impl WhirSoundnessCalculator {
    /// Every WHIR error source by name, in the order the soundness manifest records them.
    pub fn components(&self) -> [(&'static str, f64); 8] {
        [
            ("mu_batching_bits", self.mu_batching_bits),
            ("fold_rbr_bits", self.fold_rbr_bits),
            ("proximity_gaps_bits", self.proximity_gaps_bits),
            ("sumcheck_bits", self.sumcheck_bits),
            ("ood_rbr_bits", self.ood_rbr_bits),
            ("shift_rbr_bits", self.shift_rbr_bits),
            ("query_bits", self.query_bits),
            ("gamma_batching_bits", self.gamma_batching_bits),
        ]
    }
}

/// The LogUp-GKR depth at which the calculator is evaluated.
///
/// The verifier derives `n_logup` from each proof's lifted interaction count, so a key admits every
/// depth from 0 (a proof without interactions) up to the field bound. Round-by-round accounting
/// charges every GKR round the same error regardless of how many rounds there are, and the only
/// other place the depth enters is the constraint-batching round, which samples the
/// `n_trace − n_logup` coordinates the GKR output does not provide together with the batching
/// challenge: fewer GKR layers mean a higher-degree batching polynomial. The smallest depth is
/// therefore the worst case over all proofs (the unit test `worst_case_depth_is_zero` below checks
/// this for every component on the production presets).
pub const WORST_CASE_N_LOGUP: usize = 0;

impl SoundnessCalculator {
    /// Every component by name, the total last, in the order the soundness manifest records them.
    pub fn components(&self) -> [(&'static str, f64); 8] {
        [
            ("logup_bits", self.logup_bits),
            ("gkr_sumcheck_bits", self.gkr_sumcheck_bits),
            ("gkr_batching_bits", self.gkr_batching_bits),
            ("zerocheck_sumcheck_bits", self.zerocheck_sumcheck_bits),
            ("constraint_batching_bits", self.constraint_batching_bits),
            ("stacked_reduction_bits", self.stacked_reduction_bits),
            ("whir_bits", self.whir_bits),
            ("total_bits", self.total_bits),
        ]
    }

    /// Provable bits of the verifier defined by `vk`, at the shape bounds [`VkShape::from_vk`]
    /// reads off the key.
    pub fn calculate_from_vk<SC: StarkProtocolConfig>(vk: &MultiStarkVerifyingKey<SC>) -> Self {
        Self::calculate_for_shape::<SC>(&vk.inner.params, &VkShape::from_vk(vk))
    }

    /// Runs the calculator for `params` at the given shape bounds, with the field constants of
    /// `SC` and the worst-case GKR depth [`WORST_CASE_N_LOGUP`]. This is the single entry point
    /// behind both [`Self::calculate_from_vk`] and the production tests, so a shape copied out of a
    /// keygen log scores exactly as the key did.
    pub fn calculate_for_shape<SC: StarkProtocolConfig>(
        params: &SystemParams,
        shape: &VkShape,
    ) -> Self {
        // The calculator charges at least one GKR round (`l_skip + n_logup >= 1`); a preset with
        // `l_skip = 0` is scored at depth 1 instead, the shallowest it can express.
        #[allow(clippy::unnecessary_min_or_max)] // `WORST_CASE_N_LOGUP` is 0 today
        let n_logup = WORST_CASE_N_LOGUP.max(1usize.saturating_sub(params.l_skip));
        Self::calculate(
            params,
            base_field_order::<SC>(),
            challenge_field_bits::<SC>(),
            shape.max_constraints_per_air,
            shape.num_airs,
            params.max_constraint_degree,
            shape.log_stacked_height,
            shape.num_trace_columns,
            params.w_stack,
            n_logup,
        )
    }
}

/// Logs one `info` line (target `mle_soundness`, message `keygen soundness`) with the shape bounds
/// read off `vk` and the provable bits they give. `machine` and `backend` are free-form labels for
/// the line (the riscv machine reports the compiled backend, convert and combine the machine
/// variant). Meant to run once per keygen; it costs a pass over the key's per-AIR metadata. Enable
/// with `RUST_LOG=...,mle_soundness=info`.
pub fn log_vk_soundness<SC: StarkProtocolConfig>(
    machine: &str,
    backend: &str,
    vk: &MultiStarkVerifyingKey<SC>,
) {
    score_and_log(machine, backend, vk);
}

fn score_and_log<SC: StarkProtocolConfig>(
    machine: &str,
    backend: &str,
    vk: &MultiStarkVerifyingKey<SC>,
) -> (VkShape, SoundnessCalculator) {
    let shape = VkShape::from_vk(vk);
    let soundness = SoundnessCalculator::calculate_for_shape::<SC>(&vk.inner.params, &shape);
    tracing::info!(
        target: "mle_soundness",
        machine,
        backend,
        num_airs = shape.num_airs,
        max_constraints_per_air = shape.max_constraints_per_air,
        max_interactions_per_air = shape.max_interactions_per_air,
        num_trace_columns = shape.num_trace_columns,
        log_stacked_height = shape.log_stacked_height,
        vk_pre_hash = ?vk.pre_hash,
        bits = %format_args!("{:.2}", soundness.total_bits),
        "keygen soundness"
    );
    (shape, soundness)
}

/// The provable bits every production verifying key must reach: the target the presets are
/// derived for.
pub const PRODUCTION_SECURITY_BITS: f64 = SECURITY_BITS_TARGET as f64;

/// A verifying key whose verifier scores below [`PRODUCTION_SECURITY_BITS`].
#[derive(Clone, Debug, PartialEq, Error)]
#[error(
    "{machine} verifying key scores {bits:.2} bits, below the {PRODUCTION_SECURITY_BITS}-bit \
     production budget (vk_pre_hash {pre_hash}, {shape:?})"
)]
pub struct UnderBudgetError {
    pub machine: String,
    pub bits: f64,
    pub pre_hash: String,
    pub shape: VkShape,
}

/// The one gate a production keygen passes its key through: logs it as [`log_vk_soundness`] does,
/// then refuses it below [`PRODUCTION_SECURITY_BITS`], returning the score otherwise. `machine`
/// names the key in the log line and the error.
///
/// The score is the worst case over every proof the key verifies, so it is a function of the key
/// alone. The weak parameters of the test utilities score far below the budget and are keygen'd
/// without this gate.
pub fn admit_production_vk<SC: StarkProtocolConfig>(
    machine: &str,
    backend: &str,
    vk: &MultiStarkVerifyingKey<SC>,
) -> Result<SoundnessCalculator, UnderBudgetError> {
    let (shape, soundness) = score_and_log(machine, backend, vk);
    if soundness.total_bits >= PRODUCTION_SECURITY_BITS {
        Ok(soundness)
    } else {
        Err(UnderBudgetError {
            machine: machine.to_string(),
            bits: soundness.total_bits,
            pre_hash: format!("{:?}", vk.pre_hash),
            shape,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::{
            koala_bear_poseidon2::{DuplexSponge, KoalaBearPoseidon2Config},
            recursion_params_with_100_bits_security, riscv_params_with_100_bits_security,
            soundness::{base_field_order, challenge_field_bits},
        },
        engine::koala_bear_poseidon2::KoalaBearPoseidon2RefEngine,
        test_utils::{test_system_params_small, MixtureFixture, TestFixture},
        StarkEngine,
    };

    /// `calculate_from_vk` must equal `calculate` fed with the bounds read off the same key.
    /// The mixture fixture carries AIRs with constraints as well as AIRs with interactions, so every
    /// term of the calculator is exercised.
    #[test]
    fn vk_soundness_matches_manual_bounds() {
        let params = test_system_params_small(2, 5, 3);
        let engine = KoalaBearPoseidon2RefEngine::<DuplexSponge>::new(params.clone());
        let fixture = MixtureFixture::standard(
            4,
            KoalaBearPoseidon2Config::default_from_params(params.clone()),
        );
        let (_pk, vk) = fixture.keygen(&engine);

        let num_airs = vk.inner.per_air.len();
        let max_c = vk
            .inner
            .per_air
            .iter()
            .map(|a| a.symbolic_constraints.constraints.constraint_idx.len())
            .max()
            .unwrap();
        let max_i = vk
            .inner
            .per_air
            .iter()
            .map(|a| a.symbolic_constraints.interactions.len())
            .max()
            .unwrap();
        let cols: usize = vk
            .inner
            .per_air
            .iter()
            .map(|a| a.params.width.preprocessed.unwrap_or(0) + a.params.width.main_width())
            .sum();
        assert!(
            num_airs > 0 && max_c > 0 && max_i > 0,
            "fixture must carry constraints and interactions"
        );
        assert_eq!(
            VkShape::from_vk(&vk),
            VkShape {
                num_airs,
                max_constraints_per_air: max_c,
                max_interactions_per_air: max_i,
                num_trace_columns: cols,
                log_stacked_height: params.log_stacked_height(),
            }
        );

        let from_vk = SoundnessCalculator::calculate_from_vk(&vk);
        let manual = SoundnessCalculator::calculate(
            &params,
            base_field_order::<KoalaBearPoseidon2Config>(),
            challenge_field_bits::<KoalaBearPoseidon2Config>(),
            max_c,
            num_airs,
            params.max_constraint_degree,
            params.log_stacked_height(),
            cols,
            params.w_stack,
            WORST_CASE_N_LOGUP,
        );
        assert_eq!(from_vk.total_bits, manual.total_bits);
        assert_eq!(
            from_vk.constraint_batching_bits,
            manual.constraint_batching_bits
        );
        assert_eq!(
            from_vk.stacked_reduction_bits,
            manual.stacked_reduction_bits
        );
        assert_eq!(from_vk.logup_bits, manual.logup_bits);
        assert_eq!(from_vk.whir_bits, manual.whir_bits);
    }

    /// The weak test parameters are refused with the machine, the score and the key in the message;
    /// the same fixture keygen'd under the recursion preset is admitted.
    #[test]
    fn admit_production_vk_refuses_a_key_below_the_budget() {
        let keygen = |params: SystemParams| {
            let engine = KoalaBearPoseidon2RefEngine::<DuplexSponge>::new(params.clone());
            MixtureFixture::standard(4, KoalaBearPoseidon2Config::default_from_params(params))
                .keygen(&engine)
                .1
        };

        let weak = keygen(test_system_params_small(2, 5, 3));
        let err = admit_production_vk("fixture", "cpu", &weak).unwrap_err();
        let bits = SoundnessCalculator::calculate_from_vk(&weak).total_bits;
        assert_eq!(err.bits, bits);
        assert!(bits < PRODUCTION_SECURITY_BITS);
        let msg = err.to_string();
        assert!(
            msg.starts_with(&format!(
                "fixture verifying key scores {bits:.2} bits, below the 100-bit production budget"
            )),
            "{msg}"
        );
        assert!(
            msg.contains(&format!("vk_pre_hash {:?}", weak.pre_hash)),
            "{msg}"
        );

        let production = keygen(recursion_params_with_100_bits_security());
        let s = admit_production_vk("fixture", "cpu", &production).unwrap();
        assert!(s.total_bits >= PRODUCTION_SECURITY_BITS);
    }

    /// No component scores lower at any admissible GKR depth than at depth 0, on the production
    /// presets and over the whole range the field bound admits.
    #[test]
    fn worst_case_depth_is_zero() {
        let presets = [
            riscv_params_with_100_bits_security(23),
            recursion_params_with_100_bits_security(),
        ];
        // (max_constraints_per_air, num_airs, num_trace_columns): assumed bounds and measured shapes.
        let shapes = [
            (5000, 100, 40_000),
            (3188, 50, 32_211),
            (1000, 50, 2000),
            (148, 21, 1277),
        ];
        for params in &presets {
            let field_bound = 31 - params.l_skip; // ceil(log2 p) - l_skip
            for &(max_c, num_airs, cols) in &shapes {
                let score = |n_logup: usize| {
                    SoundnessCalculator::calculate(
                        params,
                        base_field_order::<KoalaBearPoseidon2Config>(),
                        challenge_field_bits::<KoalaBearPoseidon2Config>(),
                        max_c,
                        num_airs,
                        params.max_constraint_degree,
                        params.log_stacked_height(),
                        cols,
                        params.w_stack,
                        n_logup,
                    )
                };
                let worst = score(WORST_CASE_N_LOGUP);
                for n_logup in 0..=field_bound {
                    let s = score(n_logup);
                    assert!(worst.logup_bits <= s.logup_bits);
                    assert!(worst.gkr_sumcheck_bits <= s.gkr_sumcheck_bits);
                    assert!(worst.gkr_batching_bits <= s.gkr_batching_bits);
                    assert!(worst.zerocheck_sumcheck_bits <= s.zerocheck_sumcheck_bits);
                    assert!(worst.constraint_batching_bits <= s.constraint_batching_bits);
                    assert!(worst.stacked_reduction_bits <= s.stacked_reduction_bits);
                    assert!(worst.whir_bits <= s.whir_bits);
                    assert!(worst.total_bits <= s.total_bits);
                }
            }
        }
    }
}
