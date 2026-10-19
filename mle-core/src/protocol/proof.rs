use std::io::{Error, Read, Result, Write};

use derivative::Derivative;
use p3_field::PrimeCharacteristicRing;
use serde::{Deserialize, Serialize};

use crate::{
    codec::{with_capacity_capped, DecodableConfig, Decode, EncodableConfig, Encode},
    StarkProtocolConfig,
};

/// A single-chunk MLE/WHIR proof for the collection of AIRs sharing one verifying key.
///
/// This struct has two serializations: the hand-rolled versioned codec ([`Encode`]/[`Decode`]) is
/// the canonical wire format; the `serde` derive is for debugging / interop only.
#[derive(Derivative, Serialize, Deserialize)]
#[derivative(
    Clone(bound = ""),
    Debug(bound = ""),
    PartialEq(bound = ""),
    Eq(bound = "")
)]
#[serde(bound = "")]
pub struct Proof<SC: StarkProtocolConfig> {
    /// The commitment to the data in common_main.
    pub common_main_commit: SC::Digest,

    /// For each AIR in vkey order, the corresponding trace shape, or None if
    /// the trace is empty. In a valid proof, if `vk.per_air[i].is_required`,
    /// then `trace_vdata[i]` must be `Some(_)`.
    pub trace_vdata: Vec<Option<TraceVData<SC>>>,

    /// For each AIR in vkey order, the public values. Public values should be empty if the AIR has
    /// an empty trace.
    pub public_values: Vec<Vec<SC::F>>,

    /// GKR proof for the fractional-sum (LogUp) bus-balancing argument.
    pub gkr_proof: GkrProof<SC>,
    /// Batched-constraint proof reducing all AIR constraints (and interaction messages) to the
    /// per-column opening claims carried in its `column_openings`.
    pub batch_constraint_proof: BatchConstraintProof<SC>,
    /// Stacked-PCS reduction proof: reduces the per-column opening claims to a single opening claim
    /// on the stacked polynomial.
    pub stacking_proof: StackingProof<SC>,
    /// WHIR proof for the final stacked-polynomial opening.
    pub whir_proof: WhirProof<SC>,
}

#[derive(Derivative, Serialize, Deserialize)]
#[derivative(
    Clone(bound = ""),
    Debug(bound = ""),
    PartialEq(bound = ""),
    Eq(bound = ""),
    Default(bound = "")
)]
#[serde(bound = "")]
pub struct TraceVData<SC: StarkProtocolConfig> {
    /// The base 2 logarithm of the trace height. This should be a nonnegative integer and is
    /// allowed to be `< l_skip`.
    ///
    /// If the corresponding AIR has a preprocessed trace, this must match the
    /// value in the vkey.
    pub log_height: usize,
    /// The cached commitments used.
    ///
    /// The length must match the value in the vkey.
    pub cached_commitments: Vec<SC::Digest>,
}

#[derive(Derivative, Serialize, Deserialize)]
#[derivative(
    Clone(bound = ""),
    Debug(bound = ""),
    PartialEq(bound = ""),
    Eq(bound = "")
)]
#[serde(bound = "")]
pub struct GkrProof<SC: StarkProtocolConfig> {
    /// The grinding proof-of-work witness before sampling LogUp alpha,beta
    pub logup_pow_witness: SC::F,
    /// The denominator of the root layer.
    ///
    /// Note that the numerator claim is always zero, so we don't include it in
    /// the proof. Despite that the numerator is zero, the representation of the
    /// denominator is important for the verification procedure and thus must be
    /// provided.
    pub q0_claim: SC::EF,
    /// The claims for p_j(xi, 0), p_j(xi, 1), q_j(xi, 0), and q_j(xi, 0) for each layer j > 0.
    pub claims_per_layer: Vec<GkrLayerClaims<SC>>,
    /// The sumcheck polynomials for each layer, for each sumcheck round, given by their
    /// evaluations on {1, 2, 3}.
    pub sumcheck_polys: Vec<Vec<[SC::EF; 3]>>,
}

#[derive(Derivative, Serialize, Deserialize)]
#[derivative(
    Clone(bound = ""),
    Debug(bound = ""),
    PartialEq(bound = ""),
    Eq(bound = "")
)]
#[serde(bound = "")]
pub struct GkrLayerClaims<SC: StarkProtocolConfig> {
    pub p_xi_0: SC::EF,
    pub p_xi_1: SC::EF,
    pub q_xi_0: SC::EF,
    pub q_xi_1: SC::EF,
}

#[derive(Derivative, Serialize, Deserialize)]
#[derivative(
    Clone(bound = ""),
    Debug(bound = ""),
    PartialEq(bound = ""),
    Eq(bound = "")
)]
#[serde(bound = "")]
pub struct BatchConstraintProof<SC: StarkProtocolConfig> {
    /// The terms \textnormal{sum}_{\hat{p}, T, I} of the batch-constraint round, per present AIR
    /// **in sorted AIR order**.
    pub numerator_term_per_air: Vec<SC::EF>,
    /// The terms \textnormal{sum}_{\hat{q}, T, I} of the batch-constraint round, per present AIR
    /// **in sorted AIR order**.
    pub denominator_term_per_air: Vec<SC::EF>,

    /// Polynomial for initial round, given by `(vk.d + 1) * (2^{l_skip} - 1) + 1` coefficients.
    pub univariate_round_coeffs: Vec<SC::EF>,
    /// For rounds `1, ..., n_max`; evaluations on `{1, ..., vk.d + 1}`.
    pub sumcheck_round_polys: Vec<Vec<SC::EF>>,

    /// Per AIR **in sorted AIR order**, per AIR part, per column index in that part, openings for
    /// the prismalinear column polynomial and (optionally) its rotational convolution. All column
    /// openings are stored in a flat way, so only column openings or them interleaved with
    /// rotations.
    /// For example, if the rotated claims are included for a trace part, then the corresponding
    /// list of openings will look like [col_1, rot_1, col_2, rot_2, ...], and should be treated
    /// as "the i-th column's plain and rotated claims are (col_i, rot_i)".
    /// Otherwise, it will look like [col_1, col_2, col_3, ...], and should be treated as "the
    /// i-th column's plain and rotated claims are (col_i, 0)".
    /// The trace parts are ordered: [CommonMain (part 0), Preprocessed (if any), Cached(0),
    /// Cached(1), ...]
    pub column_openings: Vec<Vec<Vec<SC::EF>>>,
}

pub fn column_openings_by_rot<'a, EF: PrimeCharacteristicRing + Copy + 'a>(
    openings: &'a [EF],
    need_rot: bool,
) -> Box<dyn Iterator<Item = (EF, EF)> + 'a> {
    if need_rot {
        Box::new(
            openings
                .as_chunks::<2>()
                .0
                .iter()
                .map(|chunk| (chunk[0], chunk[1])),
        )
    } else {
        Box::new(openings.iter().map(|&claim| (claim, EF::ZERO)))
    }
}

#[derive(Derivative, Serialize, Deserialize)]
#[derivative(
    Clone(bound = ""),
    Debug(bound = ""),
    PartialEq(bound = ""),
    Eq(bound = "")
)]
#[serde(bound = "")]
pub struct StackingProof<SC: StarkProtocolConfig> {
    /// Polynomial for round 0, given by `2 * (2^{l_skip} - 1) + 1` coefficients.
    pub univariate_round_coeffs: Vec<SC::EF>,
    /// Rounds 1, ..., n_stack; evaluations at {1, 2}.
    pub sumcheck_round_polys: Vec<[SC::EF; 2]>,
    /// Per commit, per column.
    pub stacking_openings: Vec<Vec<SC::EF>>,
}

pub type MerkleProof<Digest> = Vec<Digest>;

/// WHIR polynomial opening proof for multiple polynomials of the same height, committed to in
/// multiple commitments.
#[derive(Derivative, Serialize, Deserialize)]
#[derivative(
    Clone(bound = ""),
    Debug(bound = ""),
    PartialEq(bound = ""),
    Eq(bound = "")
)]
#[serde(bound = "")]
pub struct WhirProof<SC: StarkProtocolConfig> {
    /// Proof-of-work witness for μ batching challenge.
    pub mu_pow_witness: SC::F,
    /// Per sumcheck round; evaluations on {1, 2}. This list is "flattened" with respect to the
    /// WHIR rounds.
    pub whir_sumcheck_polys: Vec<[SC::EF; 2]>,
    /// The codeword commits after each fold, except the final round.
    pub codeword_commits: Vec<SC::Digest>,
    /// The out-of-domain values "y0" per round, except the final round.
    pub ood_values: Vec<SC::EF>,
    /// For each sumcheck round, the folding PoW witness. Length is `num_whir_sumcheck_rounds =
    /// num_whir_rounds * k_whir`.
    pub folding_pow_witnesses: Vec<SC::F>,
    /// For each WHIR round, the query phase PoW witness. Length is `num_whir_rounds`.
    pub query_phase_pow_witnesses: Vec<SC::F>,
    /// For the initial round: per committed matrix, per in-domain query.
    // num_commits x num_queries x (1 << k) x stacking_width[i]
    pub initial_round_opened_rows: Vec<Vec<Vec<Vec<SC::F>>>>,
    pub initial_round_merkle_proofs: Vec<Vec<MerkleProof<SC::Digest>>>,
    /// Per non-initial round, per in-domain-query.
    pub codeword_opened_values: Vec<Vec<Vec<SC::EF>>>,
    pub codeword_merkle_proofs: Vec<Vec<MerkleProof<SC::Digest>>>,
    /// Coefficients of the polynomial after the final round.
    pub final_poly: Vec<SC::EF>,
}

// ==================== Encode implementations ====================

impl<SC: EncodableConfig> Encode for TraceVData<SC> {
    fn encode<W: Write>(&self, writer: &mut W) -> Result<()> {
        self.log_height.encode(writer)?;
        SC::encode_digest_slice(&self.cached_commitments, writer)
    }
}

impl<SC: EncodableConfig> Encode for GkrLayerClaims<SC> {
    fn encode<W: Write>(&self, writer: &mut W) -> Result<()> {
        SC::encode_extension_field(&self.p_xi_0, writer)?;
        SC::encode_extension_field(&self.p_xi_1, writer)?;
        SC::encode_extension_field(&self.q_xi_0, writer)?;
        SC::encode_extension_field(&self.q_xi_1, writer)?;
        Ok(())
    }
}

/// Codec version should change only when proof system or proof format changes.
/// The codec version **must** change if the verifying key serialization/deserialization format
/// changes. It does _not_ correspond to the main protocol version (which may change more frequently).
/// v4: `MultiStarkVerifyingKey0` gained `merged_preprocessed_commit` (merged-preprocessed
/// keygen mode for the recursion machines).
pub const CODEC_VERSION: u32 = 4;

/// Vk-blind upper bound on `num_commits` when decoding a [`WhirProof`]. Valid proofs have
/// `num_commits ≤ w_stack` (≤ 4096 in use), so `2^16` never rejects one; it only caps a hostile
/// prefix. Anti-DoS only — `verify_proof_shape` re-derives the exact count from the vk.
const MAX_NUM_COMMITS: usize = 1 << 16;

/// Vk-blind upper bound on the WHIR folding factor `k_whir` when decoding a [`WhirProof`].
/// Structurally `k_whir ≤ field two-adicity (24)`; production is 4. Bounds `1 << k_whir` against a
/// release-mode masked shift / capacity-overflow abort. Anti-DoS only (re-derived from the vk).
const MAX_K_WHIR: usize = 32;

impl<SC: EncodableConfig> Encode for Proof<SC> {
    fn encode<W: Write>(&self, writer: &mut W) -> Result<()> {
        // We explicitly implement Encode for Proof to add CODEC_VERSION
        CODEC_VERSION.encode(writer)?;
        SC::encode_digest(&self.common_main_commit, writer)?;

        // We encode trace_vdata by encoding the number of AIRs, encoding a bitmap of
        // which AIRs are present, and then encoding each present TraceVData.
        let num_airs: usize = self.trace_vdata.len();
        num_airs.encode(writer)?;
        for chunk in self.trace_vdata.chunks(8) {
            let mut ret = 0u8;
            for (i, vdata) in chunk.iter().enumerate() {
                ret |= (vdata.is_some() as u8) << (i as u8);
            }
            ret.encode(writer)?;
        }
        for vdata in self.trace_vdata.iter().flatten() {
            vdata.encode(writer)?;
        }

        // public_values: Vec<Vec<SC::F>>
        self.public_values.len().encode(writer)?;
        for pv in &self.public_values {
            SC::encode_base_field_slice(pv, writer)?;
        }
        self.gkr_proof.encode(writer)?;
        self.batch_constraint_proof.encode(writer)?;
        self.stacking_proof.encode(writer)?;
        self.whir_proof.encode(writer)
    }
}

impl<SC: EncodableConfig> Encode for GkrProof<SC> {
    fn encode<W: Write>(&self, writer: &mut W) -> Result<()> {
        SC::encode_base_field(&self.logup_pow_witness, writer)?;
        SC::encode_extension_field(&self.q0_claim, writer)?;
        self.claims_per_layer.encode(writer)?;
        // We should know the length of sumcheck_polys and each nested vector based
        // on the length of claims_per_layer.
        for round in &self.sumcheck_polys {
            for arr in round {
                SC::encode_extension_field_iter(arr.iter(), writer)?;
            }
        }
        Ok(())
    }
}

impl<SC: EncodableConfig> Encode for BatchConstraintProof<SC> {
    fn encode<W: Write>(&self, writer: &mut W) -> Result<()> {
        // Length of numerator_term_per_air is number of present AIRs
        SC::encode_extension_field_slice(&self.numerator_term_per_air, writer)?;
        SC::encode_extension_field_iter(self.denominator_term_per_air.iter(), writer)?;

        SC::encode_extension_field_slice(&self.univariate_round_coeffs, writer)?;

        // Each nested vector should be the same length
        let n_max = self.sumcheck_round_polys.len();
        n_max.encode(writer)?;
        if n_max > 0 {
            self.sumcheck_round_polys[0].len().encode(writer)?;
            for round_polys in &self.sumcheck_round_polys {
                SC::encode_extension_field_iter(round_polys.iter(), writer)?;
            }
        }

        // There is one outer vector per present AIR
        // column_openings: Vec<Vec<Vec<SC::EF>>>
        for part_col_openings in &self.column_openings {
            // part_col_openings: Vec<Vec<SC::EF>>
            part_col_openings.len().encode(writer)?;
            for col_opening in part_col_openings {
                SC::encode_extension_field_slice(col_opening, writer)?;
            }
        }
        Ok(())
    }
}

impl<SC: EncodableConfig> Encode for StackingProof<SC> {
    fn encode<W: Write>(&self, writer: &mut W) -> Result<()> {
        SC::encode_extension_field_slice(&self.univariate_round_coeffs, writer)?;
        // sumcheck_round_polys: Vec<[SC::EF; 2]>
        self.sumcheck_round_polys.len().encode(writer)?;
        for arr in &self.sumcheck_round_polys {
            SC::encode_extension_field_iter(arr.iter(), writer)?;
        }
        // stacking_openings: Vec<Vec<SC::EF>>
        self.stacking_openings.len().encode(writer)?;
        for opening in &self.stacking_openings {
            SC::encode_extension_field_slice(opening, writer)?;
        }
        Ok(())
    }
}

impl<SC: EncodableConfig> Encode for WhirProof<SC> {
    fn encode<W: Write>(&self, writer: &mut W) -> Result<()> {
        SC::encode_base_field(&self.mu_pow_witness, writer)?;
        // whir_sumcheck_polys: Vec<[SC::EF; 2]>
        self.whir_sumcheck_polys.len().encode(writer)?;
        for arr in &self.whir_sumcheck_polys {
            SC::encode_extension_field_iter(arr.iter(), writer)?;
        }
        let num_whir_sumcheck_rounds = self.whir_sumcheck_polys.len();

        // Each length can be derived from num_whir_rounds
        SC::encode_digest_slice(&self.codeword_commits, writer)?;
        SC::encode_extension_field_iter(self.ood_values.iter(), writer)?;
        let num_whir_rounds = self.codeword_commits.len() + 1;
        if !num_whir_sumcheck_rounds.is_multiple_of(num_whir_rounds) {
            return Err(Error::new(
                std::io::ErrorKind::InvalidData,
                "num_whir_sumcheck_rounds must be a multiple of num_whir_rounds",
            ));
        }
        assert_eq!(num_whir_rounds, self.query_phase_pow_witnesses.len());
        SC::encode_base_field_iter(self.folding_pow_witnesses.iter(), writer)?;
        SC::encode_base_field_iter(self.query_phase_pow_witnesses.iter(), writer)?;

        let num_commits = self.initial_round_opened_rows.len();
        assert!(num_commits > 0);
        num_commits.encode(writer)?;
        let initial_num_whir_queries = self.initial_round_opened_rows[0].len();
        initial_num_whir_queries.encode(writer)?;

        if initial_num_whir_queries > 0 {
            let merkle_depth = self.initial_round_merkle_proofs[0][0].len();
            merkle_depth.encode(writer)?;

            // We avoid per-row Vec length prefixes by encoding each commit's stacked width,
            // which we can use to determine the shapes of the remaining WHIR proof fields.
            let widths: Vec<usize> = self
                .initial_round_opened_rows
                .iter()
                .map(|commit_rows| {
                    // If there are any queries/rows, infer width from the first row.
                    commit_rows
                        .first()
                        .and_then(|q| q.first())
                        .map(|row| row.len())
                        .unwrap_or(0)
                })
                .collect();

            // Encode widths (length is implicit via num_commits).
            for w in &widths {
                w.encode(writer)?;
            }

            // Encode all opened row values (no per-row length prefixes).
            for (commit_rows, &width) in self.initial_round_opened_rows.iter().zip(&widths) {
                debug_assert_eq!(commit_rows.len(), initial_num_whir_queries);
                for query_rows in commit_rows {
                    for row in query_rows {
                        debug_assert_eq!(row.len(), width);
                        SC::encode_base_field_iter(row.iter(), writer)?;
                    }
                }
            }

            for merkle_proofs in &self.initial_round_merkle_proofs {
                for proof in merkle_proofs {
                    SC::encode_digest_iter(proof.iter(), writer)?;
                }
            }
        }

        // Length of outer vector is num_whir_rounds
        for non_init_round in &self.codeword_opened_values {
            let num_queries = non_init_round.len();
            num_queries.encode(writer)?;
            // Length of nested vector is num_whir_queries, then k_whir_exp.
            for query_vals in non_init_round {
                SC::encode_extension_field_iter(query_vals.iter(), writer)?;
            }
        }

        // Length of outer vector is num_whir_rounds, then num_whir_queries. Each
        // inner vector length is one less than the one that precedes it.
        let mut first_merkle_depth = 0;
        if num_whir_rounds > 1 && initial_num_whir_queries > 0 {
            first_merkle_depth = self.codeword_merkle_proofs[0][0].len();
        }
        first_merkle_depth.encode(writer)?;
        for round_proofs in &self.codeword_merkle_proofs {
            for proof in round_proofs {
                SC::encode_digest_iter(proof.iter(), writer)?;
            }
        }

        SC::encode_extension_field_slice(&self.final_poly, writer)
    }
}

// ==================== Decode implementations ====================

impl<SC: DecodableConfig> Decode for TraceVData<SC> {
    fn decode<R: Read>(reader: &mut R) -> Result<Self> {
        Ok(Self {
            log_height: usize::decode(reader)?,
            cached_commitments: SC::decode_digest_vec(reader)?,
        })
    }
}

impl<SC: DecodableConfig> Decode for GkrLayerClaims<SC> {
    fn decode<R: Read>(reader: &mut R) -> Result<Self> {
        Ok(Self {
            p_xi_0: SC::decode_extension_field(reader)?,
            p_xi_1: SC::decode_extension_field(reader)?,
            q_xi_0: SC::decode_extension_field(reader)?,
            q_xi_1: SC::decode_extension_field(reader)?,
        })
    }
}

impl<SC: DecodableConfig> Decode for Proof<SC> {
    fn decode<R: Read>(reader: &mut R) -> Result<Self> {
        // We explicitly implement Decode for Proof to check CODEC_VERSION
        let codec_version = u32::decode(reader)?;
        if codec_version != CODEC_VERSION {
            return Err(Error::other(format!(
                "CODEC_VERSION mismatch, expected: {}, actual: {}",
                CODEC_VERSION, codec_version
            )));
        }
        let common_main_commit = SC::decode_digest(reader)?;

        let num_airs = usize::decode(reader)?;
        let bitmap_len = num_airs.div_ceil(8);
        let mut bitmap: Vec<u8> = with_capacity_capped(bitmap_len);
        for _ in 0..bitmap_len {
            bitmap.push(u8::decode(reader)?);
        }
        let mut trace_vdata = with_capacity_capped(num_airs);
        for byte in bitmap {
            for i in 0u8..8 {
                if trace_vdata.len() >= num_airs {
                    // Reject non-canonical padding: at the break `i == num_airs % 8`, so `byte >> i`
                    // is the trailing padding bits a valid encoding always leaves zero (canonicity
                    // guard). `num_airs % 8 == 0` ⇒ no break ⇒ correct no-op.
                    if byte >> i != 0 {
                        return Err(Error::new(
                            std::io::ErrorKind::InvalidData,
                            "non-canonical trace-presence bitmap: padding bits set",
                        ));
                    }
                    break;
                }
                if byte & (1u8 << i) != 0 {
                    trace_vdata.push(Some(TraceVData::decode(reader)?));
                } else {
                    trace_vdata.push(None);
                }
            }
        }

        // public_values: Vec<Vec<SC::F>>
        let num_pvs = usize::decode(reader)?;
        let mut public_values = with_capacity_capped(num_pvs);
        for _ in 0..num_pvs {
            public_values.push(SC::decode_base_field_vec(reader)?);
        }

        Ok(Self {
            common_main_commit,
            trace_vdata,
            public_values,
            gkr_proof: GkrProof::decode(reader)?,
            batch_constraint_proof: BatchConstraintProof::decode(reader)?,
            stacking_proof: StackingProof::decode(reader)?,
            whir_proof: WhirProof::decode(reader)?,
        })
    }
}

impl<SC: DecodableConfig> Decode for GkrProof<SC> {
    fn decode<R: Read>(reader: &mut R) -> Result<Self> {
        let logup_pow_witness = SC::decode_base_field(reader)?;
        let q0_claim = SC::decode_extension_field(reader)?;
        let claims_per_layer = Vec::<GkrLayerClaims<SC>>::decode(reader)?;

        let num_sumcheck_polys = claims_per_layer.len().saturating_sub(1);
        let mut sumcheck_polys = with_capacity_capped(num_sumcheck_polys);
        for round_idx_minus_one in 0..num_sumcheck_polys {
            let n = round_idx_minus_one + 1;
            let mut round = with_capacity_capped(n);
            for _ in 0..n {
                round.push([
                    SC::decode_extension_field(reader)?,
                    SC::decode_extension_field(reader)?,
                    SC::decode_extension_field(reader)?,
                ]);
            }
            sumcheck_polys.push(round);
        }

        Ok(Self {
            logup_pow_witness,
            q0_claim,
            claims_per_layer,
            sumcheck_polys,
        })
    }
}

impl<SC: DecodableConfig> Decode for BatchConstraintProof<SC> {
    fn decode<R: Read>(reader: &mut R) -> Result<Self> {
        let numerator_term_per_air = SC::decode_extension_field_vec(reader)?;
        let num_present_airs = numerator_term_per_air.len();
        let denominator_term_per_air = SC::decode_extension_field_n(reader, num_present_airs)?;

        let univariate_round_coeffs = SC::decode_extension_field_vec(reader)?;

        let n_max = usize::decode(reader)?;
        let mut sumcheck_round_polys = with_capacity_capped(n_max);
        if n_max > 0 {
            let max_degree_plus_one = usize::decode(reader)?;
            for _ in 0..n_max {
                sumcheck_round_polys
                    .push(SC::decode_extension_field_n(reader, max_degree_plus_one)?);
            }
        }

        let mut column_openings = with_capacity_capped(num_present_airs);
        for _ in 0..num_present_airs {
            // Vec<Vec<SC::EF>>: length-prefixed outer, then each inner
            let num_parts = usize::decode(reader)?;
            let mut parts = with_capacity_capped(num_parts);
            for _ in 0..num_parts {
                parts.push(SC::decode_extension_field_vec(reader)?);
            }
            column_openings.push(parts);
        }

        Ok(Self {
            numerator_term_per_air,
            denominator_term_per_air,
            univariate_round_coeffs,
            sumcheck_round_polys,
            column_openings,
        })
    }
}

impl<SC: DecodableConfig> Decode for StackingProof<SC> {
    fn decode<R: Read>(reader: &mut R) -> Result<Self> {
        let univariate_round_coeffs = SC::decode_extension_field_vec(reader)?;
        // sumcheck_round_polys: Vec<[SC::EF; 2]>
        let num_rounds = usize::decode(reader)?;
        let mut sumcheck_round_polys = with_capacity_capped(num_rounds);
        for _ in 0..num_rounds {
            sumcheck_round_polys.push([
                SC::decode_extension_field(reader)?,
                SC::decode_extension_field(reader)?,
            ]);
        }
        // stacking_openings: Vec<Vec<SC::EF>>
        let num_openings = usize::decode(reader)?;
        let mut stacking_openings = with_capacity_capped(num_openings);
        for _ in 0..num_openings {
            stacking_openings.push(SC::decode_extension_field_vec(reader)?);
        }
        Ok(Self {
            univariate_round_coeffs,
            sumcheck_round_polys,
            stacking_openings,
        })
    }
}

impl<SC: DecodableConfig> Decode for WhirProof<SC> {
    fn decode<R: Read>(reader: &mut R) -> Result<Self> {
        let mu_pow_witness = SC::decode_base_field(reader)?;
        // whir_sumcheck_polys: Vec<[SC::EF; 2]>
        let num_whir_sumcheck_rounds = usize::decode(reader)?;
        let mut whir_sumcheck_polys = with_capacity_capped(num_whir_sumcheck_rounds);
        for _ in 0..num_whir_sumcheck_rounds {
            whir_sumcheck_polys.push([
                SC::decode_extension_field(reader)?,
                SC::decode_extension_field(reader)?,
            ]);
        }

        let codeword_commits = SC::decode_digest_vec(reader)?;
        let num_whir_rounds = codeword_commits.len() + 1;
        if num_whir_sumcheck_rounds % num_whir_rounds != 0 {
            return Err(Error::new(
                std::io::ErrorKind::InvalidData,
                "num_whir_sumcheck_rounds must be a multiple of num_whir_rounds",
            ));
        }
        let k_whir = num_whir_sumcheck_rounds / num_whir_rounds;
        // `k_whir` drives the `1 << k_whir` opened-row loops below, so it must lie in 1..=MAX_K_WHIR:
        // zero yields a degenerate opened-row shape, and the upper bound caps the loop counts.
        if k_whir == 0 || k_whir > MAX_K_WHIR {
            return Err(Error::new(
                std::io::ErrorKind::InvalidData,
                "k_whir is zero or exceeds the maximum supported folding factor",
            ));
        }
        let ood_values = SC::decode_extension_field_n(reader, num_whir_rounds - 1)?;
        let folding_pow_witnesses = SC::decode_base_field_n(reader, num_whir_sumcheck_rounds)?;
        let query_phase_pow_witnesses = SC::decode_base_field_n(reader, num_whir_rounds)?;

        let num_commits = usize::decode(reader)?;
        // Zero is malformed (encoder asserts `> 0`); the upper bound keeps the eager
        // `vec![0usize; num_commits]` fill below bounded — the one site `with_capacity` can't cap,
        // since it reads no bytes so EOF can't stop it. See `MAX_NUM_COMMITS`.
        if num_commits == 0 || num_commits > MAX_NUM_COMMITS {
            return Err(Error::new(
                std::io::ErrorKind::InvalidData,
                "num_commits is zero or exceeds the maximum supported number of commitments",
            ));
        }
        let initial_num_whir_queries = usize::decode(reader)?;
        let k_whir_exp = 1 << k_whir;
        let mut merkle_depth = 0;
        if initial_num_whir_queries > 0 {
            merkle_depth = usize::decode(reader)?;
        }

        // Bounded by `MAX_NUM_COMMITS`; length must stay `num_commits` even when queries == 0 (the
        // commit-indexed loops below still run `num_commits` times).
        let mut widths = vec![0usize; num_commits];
        if initial_num_whir_queries > 0 {
            for width in &mut widths {
                *width = usize::decode(reader)?;
            }
        }

        let mut initial_round_opened_rows = with_capacity_capped(num_commits);
        for width in widths {
            let mut opened_rows = with_capacity_capped(initial_num_whir_queries);
            for _ in 0..initial_num_whir_queries {
                // Each query has k_whir_exp rows. Each row is a fixed-width list of F elements.
                let mut rows = with_capacity_capped(k_whir_exp);
                for _ in 0..k_whir_exp {
                    rows.push(SC::decode_base_field_n(reader, width)?);
                }
                opened_rows.push(rows);
            }
            initial_round_opened_rows.push(opened_rows);
        }

        let mut initial_round_merkle_proofs = with_capacity_capped(num_commits);
        for _ in 0..num_commits {
            let mut merkle_proofs = with_capacity_capped(initial_num_whir_queries);
            for _ in 0..initial_num_whir_queries {
                merkle_proofs.push(SC::decode_digest_n(reader, merkle_depth)?);
            }
            initial_round_merkle_proofs.push(merkle_proofs);
        }

        let mut codeword_opened_values = with_capacity_capped(num_whir_rounds - 1);
        for _ in 0..num_whir_rounds - 1 {
            let num_queries = usize::decode(reader)?;
            let mut opened_values = with_capacity_capped(num_queries);
            for _ in 0..num_queries {
                opened_values.push(SC::decode_extension_field_n(reader, k_whir_exp)?);
            }
            codeword_opened_values.push(opened_values);
        }

        merkle_depth = usize::decode(reader)?;
        let mut codeword_merkle_proofs = with_capacity_capped(num_whir_rounds - 1);
        for opened_values in codeword_opened_values.iter() {
            let num_queries = opened_values.len();
            let mut merkle_proof: Vec<_> = with_capacity_capped(num_queries);
            for _ in 0..num_queries {
                merkle_proof.push(SC::decode_digest_n(reader, merkle_depth)?);
            }
            codeword_merkle_proofs.push(merkle_proof);
            // Next round is one level shallower; `saturating_sub` avoids a malformed-input wrap to
            // `usize::MAX` (→ capacity-overflow abort).
            merkle_depth = merkle_depth.saturating_sub(1);
        }

        let final_poly = SC::decode_extension_field_vec(reader)?;

        Ok(Self {
            mu_pow_witness,
            whir_sumcheck_polys,
            codeword_commits,
            ood_values,
            folding_pow_witnesses,
            query_phase_pow_witnesses,
            initial_round_opened_rows,
            initial_round_merkle_proofs,
            codeword_opened_values,
            codeword_merkle_proofs,
            final_poly,
        })
    }
}

#[cfg(test)]
mod tests {
    use p3_field::PrimeCharacteristicRing;

    use super::*;
    use crate::{
        codec::EncodableConfig,
        config::koala_bear_poseidon2::{DuplexSponge, KoalaBearPoseidon2Config, EF, F},
        engine::koala_bear_poseidon2::KoalaBearPoseidon2RefEngine,
        test_utils::{
            test_system_params_small, CachedFixture11, FibFixture, InteractionsFixture11,
            TestFixture,
        },
        StarkEngine, SystemParams,
    };

    type Sc = KoalaBearPoseidon2Config;
    type Engine = KoalaBearPoseidon2RefEngine<DuplexSponge>;

    fn params() -> SystemParams {
        test_system_params_small(2, 5, 3)
    }

    /// Encode → decode must reproduce the proof exactly, and re-encoding the decoded proof must be
    /// byte-identical (canonical round-trip).
    fn assert_roundtrips(proof: &Proof<Sc>) {
        let bytes = proof.encode_to_vec().expect("encode");
        let decoded = Proof::<Sc>::decode_from_bytes(&bytes).expect("decode");
        assert_eq!(proof, &decoded, "decoded proof differs from original");
        let reencoded = decoded.encode_to_vec().expect("re-encode");
        assert_eq!(bytes, reencoded, "re-encode is not byte-identical");
    }

    #[test]
    fn roundtrip_fib() {
        let engine = Engine::new(params());
        let (_vk, proof) = FibFixture::new(0, 1, 1 << 5).keygen_and_prove(&engine);
        assert_roundtrips(&proof);
    }

    #[test]
    fn roundtrip_interactions() {
        let engine = Engine::new(params());
        let (_vk, proof) = InteractionsFixture11.keygen_and_prove(&engine);
        assert_roundtrips(&proof);
    }

    #[test]
    fn roundtrip_cached() {
        let engine = Engine::new(params());
        let config = KoalaBearPoseidon2Config::default_from_params(params());
        let (_vk, proof) = CachedFixture11::new(config).keygen_and_prove(&engine);
        assert_roundtrips(&proof);
    }

    /// A corrupted codec version is rejected rather than mis-parsed.
    #[test]
    fn rejects_wrong_codec_version() {
        let engine = Engine::new(params());
        let (_vk, proof) = FibFixture::new(0, 1, 1 << 5).keygen_and_prove(&engine);
        let mut bytes = proof.encode_to_vec().unwrap();
        bytes[0] ^= 0xff; // flip the version's low byte
        assert!(Proof::<Sc>::decode_from_bytes(&bytes).is_err());
    }

    /// A trace-presence bitmap with a non-canonical padding bit set is rejected, so distinct byte
    /// strings cannot decode to the same proof.
    #[test]
    fn rejects_bitmap_padding_bit() {
        let engine = Engine::new(params());
        // A single AIR ⇒ the bitmap is one byte with only bit 0 meaningful (bits 1..7 are padding).
        let (_vk, proof) = FibFixture::new(0, 1, 1 << 5).keygen_and_prove(&engine);
        assert_eq!(proof.trace_vdata.len(), 1);
        let mut bytes = proof.encode_to_vec().unwrap();

        // The bitmap byte follows CODEC_VERSION (u32) + common_main_commit digest + num_airs (u32).
        let digest_len = {
            let mut d = Vec::new();
            Sc::encode_digest(&proof.common_main_commit, &mut d).unwrap();
            d.len()
        };
        let bitmap_off = 4 + digest_len + 4;
        assert_eq!(bytes[bitmap_off], 0b0000_0001, "present single-AIR bitmap");

        // Honest bytes decode; setting a padding bit is rejected as InvalidData.
        assert!(Proof::<Sc>::decode_from_bytes(&bytes).is_ok());
        bytes[bitmap_off] |= 0b0000_0010;
        let err = Proof::<Sc>::decode_from_bytes(&bytes).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    /// A truncated WHIR tail hits EOF and returns an error instead of panicking.
    #[test]
    fn rejects_truncated_whir_tail() {
        let engine = Engine::new(params());
        let (_vk, proof) = FibFixture::new(0, 1, 1 << 5).keygen_and_prove(&engine);
        let mut bytes = proof.encode_to_vec().unwrap();
        bytes.truncate(bytes.len() - 1); // drop the final byte of `final_poly`
        assert!(Proof::<Sc>::decode_from_bytes(&bytes).is_err());
    }

    // ---- WHIR decode-hardening via hand-crafted headers ----

    /// A WHIR byte stream with `num_whir_rounds = 1` (so `k_whir == num_whir_sumcheck_rounds`), up
    /// to `num_commits`/`initial_num_whir_queries`. Real encoders keep field sizes correct; decoding
    /// is expected to error at (or before) the field under test, so no tail is appended.
    fn whir_header(
        num_whir_sumcheck_rounds: usize,
        num_commits: usize,
        initial_num_whir_queries: usize,
    ) -> Vec<u8> {
        let mut b = Vec::new();
        Sc::encode_base_field(&F::ZERO, &mut b).unwrap(); // mu_pow_witness
        num_whir_sumcheck_rounds.encode(&mut b).unwrap(); // whir_sumcheck_polys length prefix
        for _ in 0..num_whir_sumcheck_rounds {
            Sc::encode_extension_field(&EF::ZERO, &mut b).unwrap();
            Sc::encode_extension_field(&EF::ZERO, &mut b).unwrap();
        }
        0usize.encode(&mut b).unwrap(); // codeword_commits length 0 ⇒ num_whir_rounds = 1
                                        // ood_values: num_whir_rounds - 1 = 0 elements (nothing)
        for _ in 0..num_whir_sumcheck_rounds {
            Sc::encode_base_field(&F::ZERO, &mut b).unwrap(); // folding_pow_witnesses
        }
        Sc::encode_base_field(&F::ZERO, &mut b).unwrap(); // query_phase_pow_witnesses (length 1)
        num_commits.encode(&mut b).unwrap();
        initial_num_whir_queries.encode(&mut b).unwrap();
        b
    }

    /// `num_commits == 0` is malformed and must be a typed error, not an `assert!` panic.
    #[test]
    fn rejects_num_commits_zero() {
        let err = WhirProof::<Sc>::decode_from_bytes(&whir_header(2, 0, 1)).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    /// An oversized `num_commits` is rejected before the `vec![0usize; num_commits]` eager fill it
    /// guards (paired with `initial_num_whir_queries == 0`, the byte-free fill path).
    #[test]
    fn rejects_num_commits_oversized() {
        let err =
            WhirProof::<Sc>::decode_from_bytes(&whir_header(2, u32::MAX as usize, 0)).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    /// An oversized `k_whir` ratio is rejected before `1 << k_whir`, preventing a shift-mask /
    /// compute-DoS. With `num_whir_rounds = 1`, `k_whir == num_whir_sumcheck_rounds`.
    #[test]
    fn rejects_oversized_k_whir() {
        let err =
            WhirProof::<Sc>::decode_from_bytes(&whir_header(MAX_K_WHIR + 1, 1, 1)).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }
}
