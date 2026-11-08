//! A proof's wire size from its shape alone.
//!
//! Every length the codec writes follows from the verifying key and the trace heights: which AIRs
//! are present and how tall, the stacking widths, the GKR depth, the column openings. A
//! [`ProofShape`] collects those counts and [`ProofShape::encoded_len`] prices them field by field,
//! as [`Encode`] writes a [`Proof`]. [`ProofShape::from_heights`] needs no proof, so a key whose
//! heights are fixed (every whitelist-mode recursion key, padded to its tier row) has its proof
//! size before any proof exists; [`ProofShape::from_proof`] reads the heights off a proof.
//!
//! The counts are those of `verify_proof_shape`, which re-derives every length from the same two
//! inputs; the tests hold [`ProofShape::encoded_len`] against [`Encode::encode_to_vec`].

use itertools::Itertools;
use p3_field::PrimeCharacteristicRing;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    config::{StarkProtocolConfig, SystemParams},
    keygen::types::MultiStarkVerifyingKeyInner,
    protocol::{
        codec::{EncodableConfig, Encode},
        proof::Proof,
        stacking::{present_gkr_shape, stacking_sort_key, StackedLayout, StackedPcsError},
    },
};

/// Heights no proof under the key can have: the verifier rejects each of these.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProofShapeError {
    #[error("{actual} heights for a key of {expected} AIRs")]
    HeightCount { expected: usize, actual: usize },
    #[error("no AIR is present")]
    NoTracesPresent,
    #[error("required AIR {air_idx} is absent")]
    RequiredAirAbsent { air_idx: usize },
    #[error("AIR {air_idx} has a preprocessed trace of log-height {expected}, not {actual}")]
    PreprocessedHeight {
        air_idx: usize,
        expected: usize,
        actual: usize,
    },
    #[error("total stacked width {actual} exceeds w_stack {w_stack}")]
    StackedWidth { w_stack: usize, actual: usize },
    #[error(transparent)]
    Layout(#[from] StackedPcsError),
}

/// A proof's shape for one key and one set of trace heights: the counts its encoding follows from,
/// and the per-proof shape inputs of a soundness calculator.
///
/// Every count is over the present AIRs except `num_airs`. So the last three fields are a proof's,
/// where the key-level `VkShape` of `config::soundness` counts every AIR of the key at the stacked
/// height.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProofShape {
    /// AIRs in the key, present or not: the trace-presence bitmap and the public-values vector
    /// have one entry each.
    pub num_airs: usize,
    /// AIRs with a trace: one trace-data entry, batch-constraint terms and opening parts each.
    pub num_airs_present: usize,
    /// The tallest present trace's log-height.
    pub max_log_height: usize,
    /// Column openings in the batch-constraint proof: one per column, two for the columns of an
    /// AIR that reads the next row.
    pub num_column_openings: usize,
    /// Opening parts: per present AIR, its common main, its preprocessed trace if any, and each
    /// cached main.
    pub num_opening_parts: usize,
    /// Cached-trace commitments carried in the trace data.
    pub num_cached_commitments: usize,
    /// Public values of the present AIRs.
    pub num_public_values: usize,
    /// LogUp-GKR layers, `l_skip + n_logup` (0 without interactions).
    pub num_gkr_rounds: usize,
    /// Stacked width of each commitment in WHIR's initial round: common main first.
    pub stacking_widths: Vec<usize>,
    /// Columns of the present traces: preprocessed, cached and common main.
    pub num_trace_columns: usize,
    /// The most constraints of a present AIR.
    pub max_constraints_per_air: usize,
    /// The most interactions of a present AIR.
    pub max_interactions_per_air: usize,
}

impl ProofShape {
    /// The shape of a proof under `vk` whose AIR `i` is present at log-height `heights[i]`, or
    /// absent at `None`.
    ///
    /// # Errors
    /// Heights the verifier rejects: a count other than the key's AIRs, no AIR present, a required
    /// AIR absent, a preprocessed AIR away from its trace's height, a trace above the stacked
    /// height, or a total stacked width above `w_stack`.
    pub fn from_heights<SC: StarkProtocolConfig>(
        vk: &MultiStarkVerifyingKeyInner<SC>,
        heights: &[Option<usize>],
    ) -> Result<Self, ProofShapeError> {
        if heights.len() != vk.per_air.len() {
            return Err(ProofShapeError::HeightCount {
                expected: vk.per_air.len(),
                actual: heights.len(),
            });
        }
        let l_skip = vk.params.l_skip;
        let log_stacked_height = vk.params.log_stacked_height();
        for (air_idx, (avk, h)) in vk.per_air.iter().zip(heights).enumerate() {
            match (h, &avk.preprocessed_data) {
                (None, _) if avk.is_required => {
                    return Err(ProofShapeError::RequiredAirAbsent { air_idx })
                }
                (Some(h), Some(pdata)) => {
                    let expected = (pdata.hypercube_dim + l_skip as isize) as usize;
                    if *h != expected {
                        return Err(ProofShapeError::PreprocessedHeight {
                            air_idx,
                            expected,
                            actual: *h,
                        });
                    }
                }
                _ => {}
            }
        }
        // The prover's stacking order, as `verify_proof_shape` derives it.
        let per_trace: Vec<(usize, usize)> = heights
            .iter()
            .enumerate()
            .filter_map(|(air_idx, h)| h.map(|h| (air_idx, h)))
            .sorted_by_key(|&(air_idx, h)| stacking_sort_key(h, air_idx))
            .collect();
        if per_trace.is_empty() {
            return Err(ProofShapeError::NoTracesPresent);
        }
        let layout = |matrices: Vec<(usize, usize)>| {
            StackedLayout::new(l_skip, log_stacked_height, matrices).map(|l| l.width())
        };

        let mut stacking_widths = vec![layout(
            per_trace
                .iter()
                .map(|&(air_idx, h)| (vk.per_air[air_idx].params.width.common_main, h))
                .collect(),
        )?];
        if vk.merged_preprocessed_commit.is_some() {
            // One commitment holding every preprocessed matrix, then one per cached main.
            stacking_widths.push(layout(
                per_trace
                    .iter()
                    .filter_map(|&(air_idx, h)| {
                        let avk = &vk.per_air[air_idx];
                        avk.preprocessed_data
                            .as_ref()
                            .and(avk.params.width.preprocessed)
                            .map(|width| (width, h))
                    })
                    .collect(),
            )?);
            for &(air_idx, h) in &per_trace {
                for &width in &vk.per_air[air_idx].params.width.cached_mains {
                    stacking_widths.push(layout(vec![(width, h)])?);
                }
            }
        } else {
            // One commitment per preprocessed trace and per cached main.
            for &(air_idx, h) in &per_trace {
                let width = &vk.per_air[air_idx].params.width;
                for &w in width.preprocessed.iter().chain(&width.cached_mains) {
                    stacking_widths.push(layout(vec![(w, h)])?);
                }
            }
        }
        let stacked_width: usize = stacking_widths.iter().sum();
        if stacked_width > vk.params.w_stack {
            return Err(ProofShapeError::StackedWidth {
                w_stack: vk.params.w_stack,
                actual: stacked_width,
            });
        }

        let (_, num_gkr_rounds, _) = present_gkr_shape(
            l_skip,
            per_trace
                .iter()
                .map(|&(air_idx, h)| (vk.per_air[air_idx].num_interactions(), h)),
        );
        let mut shape = Self {
            num_airs: vk.per_air.len(),
            num_airs_present: per_trace.len(),
            max_log_height: per_trace[0].1,
            num_column_openings: 0,
            num_opening_parts: 0,
            num_cached_commitments: 0,
            num_public_values: 0,
            num_gkr_rounds,
            stacking_widths,
            num_trace_columns: 0,
            max_constraints_per_air: 0,
            max_interactions_per_air: 0,
        };
        for &(air_idx, _) in &per_trace {
            let avk = &vk.per_air[air_idx];
            let width = &avk.params.width;
            let columns = width.preprocessed.unwrap_or(0) + width.main_width();
            shape.num_trace_columns += columns;
            shape.num_column_openings += columns * if avk.params.need_rot { 2 } else { 1 };
            shape.num_opening_parts += avk.num_parts();
            shape.num_cached_commitments += avk.num_cached_mains();
            shape.num_public_values += avk.params.num_public_values;
            shape.max_constraints_per_air = shape
                .max_constraints_per_air
                .max(avk.symbolic_constraints.constraints.constraint_idx.len());
            shape.max_interactions_per_air =
                shape.max_interactions_per_air.max(avk.num_interactions());
        }
        Ok(shape)
    }

    /// The shape of `proof`, with the heights it carries.
    ///
    /// # Errors
    /// As [`Self::from_heights`].
    pub fn from_proof<SC: StarkProtocolConfig>(
        vk: &MultiStarkVerifyingKeyInner<SC>,
        proof: &Proof<SC>,
    ) -> Result<Self, ProofShapeError> {
        let heights: Vec<Option<usize>> = proof
            .trace_vdata
            .iter()
            .map(|vdata| vdata.as_ref().map(|v| v.log_height))
            .collect();
        Self::from_heights(vk, &heights)
    }

    /// The total stacked width, the `Σw` the verifier bounds by `w_stack`.
    pub fn stacked_width(&self) -> usize {
        self.stacking_widths.iter().sum()
    }

    /// Bytes [`Encode`] writes for a proof of this shape, in `SC`'s encoding. `params` must be the
    /// parameters of the key the shape was derived under.
    pub fn encoded_len<SC: EncodableConfig>(&self, params: &SystemParams) -> usize {
        let f = encoded(|w| SC::encode_base_field(&SC::F::ZERO, w));
        let ef = encoded(|w| SC::encode_extension_field(&SC::EF::ZERO, w));
        let digest = encoded(|w| SC::encode_digest(&SC::Digest::default(), w));
        let len = encoded(|w| 0usize.encode(w));
        let version = encoded(|w| 0u32.encode(w));

        let l_skip = params.l_skip;
        let k = params.k_whir();
        let rounds = params.num_whir_rounds();
        let sumcheck_rounds = params.num_whir_sumcheck_rounds();
        let queries: Vec<usize> = params.whir.rounds.iter().map(|r| r.num_queries).collect();
        let degree = params.max_constraint_degree;
        let present = self.num_airs_present;
        let commits = self.stacking_widths.len();
        let width = self.stacked_width();
        let n_max = self.max_log_height.saturating_sub(l_skip);

        // Version, common-main commitment, presence bitmap, present traces' data, public values.
        let preamble = version
            + digest
            + len
            + self.num_airs.div_ceil(8)
            + present * 2 * len
            + self.num_cached_commitments * digest
            + len
            + self.num_airs * len
            + self.num_public_values * f;

        // Grinding witness, root denominator, per-layer claims, and layer j's j cubic rounds.
        let r = self.num_gkr_rounds;
        let gkr = f + ef + len + r * 4 * ef + r * r.saturating_sub(1) / 2 * 3 * ef;

        // Numerator and denominator terms, the univariate round, the multilinear rounds, and the
        // column openings of each present AIR's parts.
        let mut batch_constraint = (len + present * ef)
            + present * ef
            + (len + ((degree + 1) * ((1 << l_skip) - 1) + 1) * ef)
            + len;
        if n_max > 0 {
            batch_constraint += len + n_max * (degree + 1) * ef;
        }
        batch_constraint +=
            present * len + self.num_opening_parts * len + self.num_column_openings * ef;

        // The univariate round, `n_stack` quadratic rounds, and each commitment's openings.
        let stacking = (len + (2 * ((1 << l_skip) - 1) + 1) * ef)
            + len
            + params.n_stack * 2 * ef
            + len
            + commits * len
            + width * ef;

        // Grinding witnesses, folding rounds, codeword commitments and out-of-domain values, the
        // initial round's opened rows and Merkle paths, each later round's, and the final
        // polynomial. A Merkle path of round i is `log_codeword_len - k - i` digests long.
        let log_codeword_len = params.log_stacked_height() + params.log_blowup;
        let mut whir = f
            + (len + sumcheck_rounds * 2 * ef)
            + (len + (rounds - 1) * digest)
            + (rounds - 1) * ef
            + sumcheck_rounds * f
            + rounds * f
            + len
            + len;
        if queries[0] > 0 {
            whir += len
                + commits * len
                + queries[0] * (1 << k) * width * f
                + commits * queries[0] * log_codeword_len.saturating_sub(k) * digest;
        }
        for &q in &queries[1..] {
            whir += len + q * (1 << k) * ef;
        }
        whir += len;
        for (round, &q) in queries.iter().enumerate().skip(1) {
            whir += q * log_codeword_len.saturating_sub(k + round) * digest;
        }
        whir += len + (1 << params.log_final_poly_len()) * ef;

        preamble + gkr + batch_constraint + stacking + whir
    }
}

fn encoded(write: impl FnOnce(&mut Vec<u8>) -> std::io::Result<()>) -> usize {
    let mut buf = Vec::new();
    write(&mut buf).expect("encoding into a Vec cannot fail");
    buf.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::koala_bear_poseidon2::{DuplexSponge, KoalaBearPoseidon2Config},
        engine::koala_bear_poseidon2::KoalaBearPoseidon2RefEngine,
        poly::matrix::MatrixDimensions,
        test_utils::{
            test_system_params_small, FibFixture, MixtureFixture, PreprocessedAndCachedFixture,
            TestFixture, TwoPreprocessedFixture,
        },
        StarkEngine,
    };

    type Engine = KoalaBearPoseidon2RefEngine<DuplexSponge>;

    fn assert_priced_exactly(
        vk: &MultiStarkVerifyingKeyInner<KoalaBearPoseidon2Config>,
        proof: &Proof<KoalaBearPoseidon2Config>,
    ) {
        let shape = ProofShape::from_proof(vk, proof).expect("a proof's heights are valid");
        let actual = proof.encode_to_vec().expect("encode").len();
        assert_eq!(
            shape.encoded_len::<KoalaBearPoseidon2Config>(&vk.params),
            actual,
            "{shape:?}"
        );
        let widths: Vec<usize> = proof
            .whir_proof
            .initial_round_opened_rows
            .iter()
            .map(|rows| rows[0][0].len())
            .collect();
        assert_eq!(shape.stacking_widths, widths);
        assert_eq!(shape.num_gkr_rounds, proof.gkr_proof.claims_per_layer.len());
    }

    /// Per-AIR preprocessed commitments, a cached main, interactions, and AIRs that read the next
    /// row.
    #[test]
    fn a_mixture_proof_is_priced_exactly() {
        let params = test_system_params_small(2, 5, 3);
        let engine = Engine::new(params.clone());
        let fixture =
            MixtureFixture::standard(4, KoalaBearPoseidon2Config::default_from_params(params));
        let (vk, proof) = fixture.keygen_and_prove(&engine);
        assert!(proof
            .trace_vdata
            .iter()
            .any(|v| v.as_ref().is_some_and(|v| !v.cached_commitments.is_empty())));
        assert_priced_exactly(&vk.inner, &proof);
    }

    /// Absent AIRs still take a bitmap bit and an (empty) public-values entry.
    #[test]
    fn a_proof_with_absent_airs_is_priced_exactly() {
        let params = test_system_params_small(2, 5, 3);
        let engine = Engine::new(params);
        let fixture =
            FibFixture::new_with_num_airs(0, 1, 1 << 4, 9).with_empty_air_indices([1, 4, 8]);
        let (vk, proof) = fixture.keygen_and_prove(&engine);
        assert_eq!(proof.trace_vdata.iter().filter(|v| v.is_none()).count(), 3);
        assert_priced_exactly(&vk.inner, &proof);
    }

    /// Traces no taller than `2^l_skip`: no multilinear batch-constraint rounds.
    #[test]
    fn a_proof_of_short_traces_is_priced_exactly() {
        let params = test_system_params_small(2, 5, 3);
        let engine = Engine::new(params.clone());
        let (vk, proof) = FibFixture::new(0, 1, 1 << params.l_skip).keygen_and_prove(&engine);
        assert_eq!(
            ProofShape::from_proof(&vk.inner, &proof)
                .unwrap()
                .max_log_height,
            params.l_skip
        );
        assert_priced_exactly(&vk.inner, &proof);
    }

    /// One merged preprocessed commitment, as every recursion key has, with cached mains after it.
    #[test]
    fn merged_preprocessed_proofs_are_priced_exactly() {
        let log_trace_height = 5;
        let params = SystemParams::new_for_testing(log_trace_height);
        let engine = Engine::new(params.clone());
        let sels = (0..(1 << log_trace_height))
            .map(|i| i % 2 == 0)
            .collect::<Vec<_>>();
        let sels_small = (0..(1 << (log_trace_height - 1)))
            .map(|i| i % 3 == 0)
            .collect::<Vec<_>>();

        let with_cached = PreprocessedAndCachedFixture::new(
            sels.clone(),
            KoalaBearPoseidon2Config::default_from_params(params),
            2,
        );
        let (pk, vk) = engine.keygen_merged_preprocessed(&with_cached.airs());
        assert!(vk.inner.merged_preprocessed_commit.is_some());
        assert_priced_exactly(&vk.inner, &with_cached.prove(&engine, &pk));

        let two = TwoPreprocessedFixture::new(sels_small, sels);
        let (pk, vk) = engine.keygen_merged_preprocessed(&two.airs());
        assert_priced_exactly(&vk.inner, &two.prove(&engine, &pk));
    }

    /// The heights a trace has before proving give the proof's size: no proof needed.
    #[test]
    fn heights_before_proving_give_the_proofs_size() {
        let params = test_system_params_small(2, 5, 3);
        let engine = Engine::new(params.clone());
        let fixture =
            MixtureFixture::standard(4, KoalaBearPoseidon2Config::default_from_params(params));
        let (pk, vk) = fixture.keygen(&engine);
        let mut heights = vec![None; vk.inner.per_air.len()];
        for (air_idx, ctx) in fixture.generate_proving_ctx().per_trace {
            heights[air_idx] = Some(ctx.common_main.height().ilog2() as usize);
        }
        let shape = ProofShape::from_heights(&vk.inner, &heights).unwrap();
        let proof = fixture.prove(&engine, &pk);
        assert_eq!(
            shape.encoded_len::<KoalaBearPoseidon2Config>(&vk.inner.params),
            proof.encode_to_vec().expect("encode").len()
        );
    }

    /// Heights the verifier rejects are refused.
    #[test]
    fn heights_no_proof_can_have_are_refused() {
        let params = test_system_params_small(2, 5, 3);
        let engine = Engine::new(params.clone());
        let (_, vk) = FibFixture::new_with_num_airs(0, 1, 1 << 4, 2).keygen(&engine);
        let too_tall = params.log_stacked_height() + 1;
        assert!(matches!(
            ProofShape::from_heights(&vk.inner, &[Some(4), Some(too_tall)]),
            Err(ProofShapeError::Layout(
                StackedPcsError::LayoutHeightExceeded { .. }
            ))
        ));
        assert_eq!(
            ProofShape::from_heights(&vk.inner, &[None, None]),
            Err(ProofShapeError::NoTracesPresent)
        );
        assert_eq!(
            ProofShape::from_heights(&vk.inner, &[Some(4)]),
            Err(ProofShapeError::HeightCount {
                expected: 2,
                actual: 1
            })
        );
    }
}
