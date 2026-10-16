use core::fmt::Debug;

use getset::Getters;
use p3_field::{BasedVectorSpace, ExtensionField, PrimeField64, TwoAdicField};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{hasher::MerkleHasher, interaction::LogUpSecurityParameters};

pub const DEFAULT_K_WHIR: usize = 4;

/// Query-phase PoW bits, preset for every production config. Lowering it cuts the
/// (exponential) opening grind; `WhirConfig::new` auto-adds cheap merkle queries to hold the
/// security target. SOUNDNESS: re-validate (soundness calculator) before shipping a lowered value.
pub const DEFAULT_QUERY_PHASE_POW_BITS: usize = 20;

/// Upper bound on one WHIR round's query count. Production rounds draw at most 193, and the weakest
/// nonzero per-query figure any (regime, integer rate) gives, `ListDecoding { m: 2 }` at rate 1/2
/// (0.18 bits), needs fewer than 600 for a 100-bit target. A larger count can only come from a
/// broken target, and the prover sizes per-query buffers by it. It is deliberately not a bound by
/// the round's domain: queries are drawn with replacement, and the small test schedules draw more
/// queries than a late round's domain has points.
pub const MAX_WHIR_QUERIES: usize = 1 << 16;

/// Trait that holds the associated types for the MLE proof system. These are the types needed by
/// the verifier and must be independent of the prover backend.
///
/// This trait only holds the associated types and the struct implementing the trait does not hold
/// the system parameters. System parameters are specified and stored separated in [SystemParams].
///
/// The trait has an **implicit** associated Fiat-Shamir transcript type, including the hash used.
/// There is no explicit associated type because the concrete implementation of the transcript may
/// differ between prover and verifier and the verifier may further employ different implementations
/// for logging or debugging purposes. The trait controlling concrete implementations of the
/// transcript is specified by [`FiatShamirTranscript`](crate::FiatShamirTranscript).
pub trait StarkProtocolConfig: 'static + Clone + Send + Sync {
    /// The prime base field.
    type F: TwoAdicField + PrimeField64;
    /// The extension field, used for random challenges.
    type EF: TwoAdicField + ExtensionField<Self::F>;
    /// The digest type used for commitments.
    type Digest: Copy
        + Send
        + Sync
        + Debug
        + Default
        + PartialEq
        + Eq
        + Serialize
        + for<'de> Deserialize<'de>;
    /// The merkle tree hasher used by the polynomial commitment scheme.
    type Hasher: MerkleHasher<F = Self::F, Digest = Self::Digest>;

    /// Degree of the extension field.
    const D_EF: usize = <Self::EF as BasedVectorSpace<Self::F>>::DIMENSION;

    /// The digest viewed as this config's own field elements, when it is made of them.
    ///
    /// Hashed preimages must not depend on Plonky3's field serde: 0.5 switched `MontyField31` to
    /// the Montgomery representation, which would silently move every vk pre-hash and constraint
    /// digest. Configs whose digest is a slice of `Self::F` return `Some` and are serialized
    /// through `canonical_serde`; a config whose digest lives in a *different* field (the BN254
    /// embed transcript) returns `None` and keeps its own serde, which that change does not touch.
    fn digest_as_base(_digest: &Self::Digest) -> Option<&[Self::F]> {
        None
    }

    fn params(&self) -> &SystemParams;

    fn hasher(&self) -> &Self::Hasher;
}

/// Type alias for backwards compatibility. New implementations should use `SC::F`.
pub type Val<SC> = <SC as StarkProtocolConfig>::F;
/// Type alias for backwards compatibility. New implementations should use `SC::Digest`.
pub type Com<SC> = <SC as StarkProtocolConfig>::Digest;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Getters)]
pub struct SystemParams {
    /// The univariate-skip parameter `ℓ` ([Gru24]): the first `l_skip`
    /// hyperdimensions of every polynomial are univariate over the smooth multiplicative
    /// subgroup `D ⊂ F^×` of order `2^l_skip`; the remaining dimensions are multilinear, so a
    /// trace of height `2^{l_skip + n}` lives on the hyperprism `D_n = D × {0,1}^n`.
    /// A trace shorter than `2^l_skip` (negative `n_T`) is lifted onto a subgroup of `D` when
    /// stacked.
    pub l_skip: usize,
    /// Stacked hypercube dimension: the stacked trace matrix lives on the hyperprism
    /// `D_{n_stack}`, i.e. has height `2^{l_skip + n_stack}`. Every trace must satisfy
    /// `log_height <= l_skip + n_stack`.
    pub n_stack: usize,
    /// Maximum number of stacked polynomials (i.e. stacked matrix width). This implies a max
    /// stacked cell count of `w_stack * 2^(n_stack + l_skip)`.
    pub w_stack: usize,
    /// `-log_2` of the rate for the initial Reed-Solomon code.
    pub log_blowup: usize,
    #[getset(get = "pub")]
    pub whir: WhirConfig,
    pub logup: LogUpSecurityParameters,
    /// Global max constraint degree enforced across all AIR and Interaction constraints
    pub max_constraint_degree: usize,
}

impl SystemParams {
    pub fn logup_pow_bits(&self) -> usize {
        self.logup.pow_bits
    }

    pub fn k_whir(&self) -> usize {
        self.whir.k
    }

    #[inline]
    pub fn log_stacked_height(&self) -> usize {
        self.l_skip + self.n_stack
    }

    #[inline]
    pub fn log_final_poly_len(&self) -> usize {
        self.whir.log_final_poly_len(self.log_stacked_height())
    }

    #[inline]
    pub fn num_whir_rounds(&self) -> usize {
        self.whir.num_whir_rounds()
    }

    #[inline]
    pub fn num_whir_sumcheck_rounds(&self) -> usize {
        self.whir.num_sumcheck_rounds()
    }

    /// Constructor with many configuration options. Only `k_whir` and `query_phase_pow_bits` are
    /// preset with constants; `max_constraint_degree` is the global bound the machine's AIRs must
    /// satisfy (keygen rejects any AIR above it) and sets the zerocheck sumcheck round degree.
    ///
    /// The `security_bits` is the target bits of security. It is used to select the number of WHIR
    /// queries, but does **not** guarantee the target security level is achieved by the overall
    /// protocol using these parameters. Use the soundness calculator to ensure the target security
    /// level is met.
    ///
    /// This function should only be used for internal cryptography libraries. Most users should
    /// instead use preset parameters provided in SDKs.
    ///
    /// Panics with the [`ParamsError`] that [`Self::try_new`] returns.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        log_blowup: usize,
        l_skip: usize,
        n_stack: usize,
        w_stack: usize,
        log_final_poly_len: usize,
        folding_pow_bits: usize,
        mu_pow_bits: usize,
        proximity: WhirProximityStrategy,
        security_bits: usize,
        logup: LogUpSecurityParameters,
        max_constraint_degree: usize,
    ) -> SystemParams {
        Self::try_new(
            log_blowup,
            l_skip,
            n_stack,
            w_stack,
            log_final_poly_len,
            folding_pow_bits,
            mu_pow_bits,
            proximity,
            security_bits,
            logup,
            max_constraint_degree,
        )
        .unwrap_or_else(|err| panic!("{err}"))
    }

    /// [`Self::new`], refusing a WHIR schedule the prover cannot run (see
    /// [`WhirConfig::try_new`]). Field-agnostic: [`check_field_admissible`] checks the result
    /// against a field, in the presets and when keygen starts.
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        log_blowup: usize,
        l_skip: usize,
        n_stack: usize,
        w_stack: usize,
        log_final_poly_len: usize,
        folding_pow_bits: usize,
        mu_pow_bits: usize,
        proximity: WhirProximityStrategy,
        security_bits: usize,
        logup: LogUpSecurityParameters,
        max_constraint_degree: usize,
    ) -> Result<SystemParams, ParamsError> {
        let whir_query_phase_pow_bits = DEFAULT_QUERY_PHASE_POW_BITS;

        let k_whir = DEFAULT_K_WHIR;
        let log_stacked_height = l_skip + n_stack;

        Ok(SystemParams {
            l_skip,
            n_stack,
            w_stack,
            log_blowup,
            whir: WhirConfig::try_new(
                log_blowup,
                log_stacked_height,
                WhirParams {
                    k: k_whir,
                    log_final_poly_len,
                    query_phase_pow_bits: whir_query_phase_pow_bits,
                    proximity,
                    folding_pow_bits,
                    mu_pow_bits,
                },
                security_bits,
            )?,
            logup,
            max_constraint_degree,
        })
    }
}

/// Refuses an initial RS domain of `2^(log_stacked_height + log_blowup)` points that `F` has no
/// subgroup for: encoding the stacked trace needs a root of unity of that order.
pub fn check_rs_domain<F: TwoAdicField>(
    log_stacked_height: usize,
    log_blowup: usize,
) -> Result<(), ParamsError> {
    let log_rs_domain_size = log_stacked_height.saturating_add(log_blowup);
    if log_rs_domain_size > F::TWO_ADICITY {
        return Err(ParamsError::RsDomainTooLarge {
            log_stacked_height,
            log_blowup,
            log_rs_domain_size,
            two_adicity: F::TWO_ADICITY,
        });
    }
    Ok(())
}

/// The widest sample [`FiatShamirTranscript::sample_bits`](crate::FiatShamirTranscript::sample_bits)
/// draws over `F`: the low bits of one field element, so the mask must stay below the field's order.
pub fn max_sample_bits<F: PrimeField64>() -> usize {
    ((F::ORDER_U64 - 1).ilog2() as usize).min(u32::BITS as usize - 1)
}

/// Refuses a parameter set asking the transcript for a sample wider than [`max_sample_bits`]: every
/// grinding check and the WHIR query indices are drawn with `sample_bits`, which panics past that
/// width mid-proof. The query index is widest in the first round,
/// `log_stacked_height + log_blowup - k`, the width the recursion circuit derives from the
/// verifying key.
pub fn check_sample_widths<F: PrimeField64>(params: &SystemParams) -> Result<(), ParamsError> {
    let max_bits = max_sample_bits::<F>();
    let widths = [
        ("LogUp grinding", params.logup.pow_bits),
        ("WHIR μ grinding", params.whir.mu_pow_bits),
        ("WHIR folding grinding", params.whir.folding_pow_bits),
        ("WHIR query grinding", params.whir.query_phase_pow_bits),
        (
            "WHIR query index",
            (params.log_stacked_height() + params.log_blowup).saturating_sub(params.whir.k),
        ),
    ];
    for (sample, bits) in widths {
        if bits > max_bits {
            return Err(ParamsError::SampleTooWide {
                sample,
                bits,
                max_bits,
            });
        }
    }
    Ok(())
}

/// [`check_rs_domain`] and [`check_sample_widths`] over `F`: the checks a built [`SystemParams`]
/// owes the field it will be proved over.
pub fn check_field_admissible<F: TwoAdicField + PrimeField64>(
    params: &SystemParams,
) -> Result<(), ParamsError> {
    check_rs_domain::<F>(params.log_stacked_height(), params.log_blowup)?;
    check_sample_widths::<F>(params)
}

/// A parameter set the prover cannot run, refused when it is built rather than when proving reaches
/// the step that breaks.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum ParamsError {
    #[error(
        "RS domain 2^{log_rs_domain_size} (log_stacked_height {log_stacked_height} + log_blowup \
         {log_blowup}) has no subgroup in a field of two-adicity {two_adicity}"
    )]
    RsDomainTooLarge {
        log_stacked_height: usize,
        log_blowup: usize,
        log_rs_domain_size: usize,
        two_adicity: usize,
    },
    #[error("WHIR folding factor k = 0 folds no variable, so no round makes progress")]
    ZeroFoldingFactor,
    #[error(
        "RS domain 2^{log_rs_domain_size} has more points than a usize indexes, so no field and no \
         prover holds it"
    )]
    RsDomainUnaddressable { log_rs_domain_size: usize },
    /// The verifier reads the first round's query count and the prover sizes its codeword buffers
    /// by `num_rounds - 1`, so a schedule with no round cannot be proved.
    #[error(
        "log_final_poly_len {log_final_poly_len} is not below log_stacked_height \
         {log_stacked_height}, so the schedule has no WHIR round"
    )]
    NoWhirRound {
        log_stacked_height: usize,
        log_final_poly_len: usize,
    },
    #[error(
        "{num_rounds} WHIR rounds of k = {k} fold more variables than log_stacked_height \
         {log_stacked_height} has"
    )]
    WhirRoundsOverrun {
        log_stacked_height: usize,
        k: usize,
        num_rounds: usize,
    },
    #[error(
        "security_bits {security_bits} leaves nothing for the queries once query_phase_pow_bits \
         {query_phase_pow_bits} is taken, so no WHIR round would check a query"
    )]
    NoQueries {
        security_bits: usize,
        query_phase_pow_bits: usize,
    },
    #[error(
        "WHIR round {round}: {regime:?} at rate 2^-{log_inv_rate} gives no security per query, so \
         no query count reaches the target"
    )]
    NoQuerySecurity {
        round: usize,
        regime: ProximityRegime,
        log_inv_rate: usize,
    },
    #[error(
        "WHIR round {round} needs {num_queries} queries, past the cap of {}",
        MAX_WHIR_QUERIES
    )]
    TooManyQueries { round: usize, num_queries: usize },
    #[error(
        "{sample} asks for {bits}-bit samples, but the transcript derives at most {max_bits} bits \
         from one field element"
    )]
    SampleTooWide {
        sample: &'static str,
        bits: usize,
        max_bits: usize,
    },
}

/// Configurable parameters that are used to determine the [WhirConfig] for a target security level.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct WhirParams {
    pub k: usize,
    /// WHIR rounds will stop as soon as `log2` of the final polynomial length is `<=
    /// log_final_poly_len`.
    pub log_final_poly_len: usize,
    pub query_phase_pow_bits: usize,
    /// Proximity regime to use within each WHIR round. This is used to determine the number of
    /// queries in each round for a target security level.
    pub proximity: WhirProximityStrategy,
    /// Number of bits of grinding to increase security of each folding step.
    pub folding_pow_bits: usize,
    /// Number of bits of grinding before sampling the μ batching challenge.
    pub mu_pow_bits: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct WhirConfig {
    /// Constant folding factor. This means that `2^k` terms are folded per round.
    pub k: usize,
    pub rounds: Vec<WhirRoundConfig>,
    /// Number of bits of grinding before sampling the μ batching challenge.
    pub mu_pow_bits: usize,
    /// Number of bits of grinding for the query phase of each WHIR round.
    /// The PoW bits can vary per round, but for simplicity we use the same number for all rounds.
    pub query_phase_pow_bits: usize,
    /// Number of bits of grinding before sampling folding randomness in each WHIR round.
    /// The folding PoW bits can vary per round, but for simplicity (and efficiency of the
    /// recursion circuit) we use the same number for all rounds.
    pub folding_pow_bits: usize,
    /// Proximity regimes for WHIR rounds. We use only proven error bounds.
    ///
    /// Note: this field is not needed by the verifier as it is only used to determine the number
    /// of queries in the `rounds` field. However we store it in `WhirConfig` for security analysis
    /// purposes.
    pub proximity: WhirProximityStrategy,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct WhirRoundConfig {
    /// Number of in-domain queries sampled in this WHIR round.
    pub num_queries: usize,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum WhirProximityStrategy {
    /// Unique decoding regime in every WHIR round.
    UniqueDecoding,
    /// Unique decoding regime in the initial `list_start_round` WHIR rounds. Then list decoding
    /// regime with the same proximity radius derived from `m` (see `ListDecoding`) for all
    /// subsequent WHIR rounds (0-indices `>= list_start_round`). Note that a WHIR round
    /// consists of codewords of different degrees with the same rate. The WHIR round changes
    /// when the rate changes.
    SplitUniqueList { m: usize, list_start_round: usize },
    /// List decoding regime in every WHIR round, with the same proximity radius derived from `m`,
    /// where `m = ceil(sqrt(\rho) / 2 \eta), \eta = 1 - sqrt(\rho) - \delta, where \delta is the
    /// proximity radius.
    ListDecoding { m: usize },
}

impl WhirProximityStrategy {
    pub fn initial_round(&self) -> ProximityRegime {
        self.in_round(0)
    }

    pub fn in_round(&self, whir_round: usize) -> ProximityRegime {
        match *self {
            Self::UniqueDecoding => ProximityRegime::UniqueDecoding,
            Self::SplitUniqueList {
                m,
                list_start_round,
            } => {
                if whir_round < list_start_round {
                    ProximityRegime::UniqueDecoding
                } else {
                    ProximityRegime::ListDecoding { m }
                }
            }
            Self::ListDecoding { m } => ProximityRegime::ListDecoding { m },
        }
    }
}

/// Defines the proximity regime for the proof system.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProximityRegime {
    /// Unique decoding guarantees a single valid witness.
    UniqueDecoding,
    /// List decoding bounded by multiplicity `m`.
    ListDecoding { m: usize },
}

impl ProximityRegime {
    /// Maximum fraction of the RS domain on which a far word can agree with a codeword (the
    /// per-query evasion probability under ideal uniform query sampling), `1 - δ`.
    ///
    /// - `UniqueDecoding`: `(1 + ρ) / 2`, i.e. `δ = (1 - ρ) / 2`, the unique-decoding radius itself.
    ///   WHIR states its unique-decoding results (Cor. 4.11) for `δ` strictly below that radius,
    ///   but Lemma 4.10 gives the agreement bound `(1 + ρ) / 2 - 1 / (2|L|)` at the radius, so the
    ///   boundary value is admissible.
    /// - `ListDecoding { m }`: `sqrt(ρ) (1 + 1/(2m))`, i.e. `δ = 1 - sqrt(ρ) - η` with
    ///   `η = sqrt(ρ) / (2m)`, the form in which WHIR (ePrint 2024/1586) states the Johnson-bound
    ///   list-decoding radius. The soundness calculator evaluates its list-size and proximity-gap
    ///   terms ([BCHKS25], ECCC TR25-169) at this same `δ`, so the derived query counts and the
    ///   charged error terms refer to one radius. (The tighter Guruswami–Sudan threshold
    ///   `sqrt(ρ(1 + 1/m))` is valid on its own but does not match the `δ` those terms use.)
    pub fn max_agreement(&self, log_inv_rate: usize) -> f64 {
        let rho = 2.0_f64.powf(-(log_inv_rate as f64));
        let max_agreement = match *self {
            ProximityRegime::UniqueDecoding => (1.0 + rho) / 2.0,
            ProximityRegime::ListDecoding { m } => {
                let m = m.max(1) as f64;
                rho.sqrt() * (1.0 + 1.0 / (2.0 * m))
            }
        };
        // Keep the `log2` well-defined.
        max_agreement.clamp(f64::MIN_POSITIVE, 1.0)
    }

    /// Returns total security bits for `num_queries` WHIR queries under ideal (uniform) query
    /// sampling. See [`crate::config::soundness::SoundnessCalculator`] for the variant that
    /// additionally charges the `sample_bits` sampling bias.
    pub fn whir_query_security_bits(&self, num_queries: usize, log_inv_rate: usize) -> f64 {
        -(num_queries as f64) * self.max_agreement(log_inv_rate).log2()
    }

    /// Returns the per-query security bits for WHIR query sampling.
    pub fn whir_per_query_security_bits(&self, log_inv_rate: usize) -> f64 {
        self.whir_query_security_bits(1, log_inv_rate)
    }
}

impl WhirConfig {
    /// Sets parameters targeting `security_bits` of provable security (including grinding), using
    /// the given proximity regime.
    ///
    /// Panics with the [`ParamsError`] that [`Self::try_new`] returns.
    pub fn new(
        log_blowup: usize,
        log_stacked_height: usize,
        whir_params: WhirParams,
        security_bits: usize,
    ) -> Self {
        Self::try_new(log_blowup, log_stacked_height, whir_params, security_bits)
            .unwrap_or_else(|err| panic!("{err}"))
    }

    /// [`Self::new`], refusing a folding factor of zero, an RS domain too large to index, a
    /// schedule with no round, rounds that fold more variables than the stacked height has, or a
    /// round whose query count is not a positive integer within [`MAX_WHIR_QUERIES`].
    pub fn try_new(
        log_blowup: usize,
        log_stacked_height: usize,
        whir_params: WhirParams,
        security_bits: usize,
    ) -> Result<Self, ParamsError> {
        let query_phase_pow_bits = whir_params.query_phase_pow_bits;
        let protocol_security_level = security_bits.saturating_sub(query_phase_pow_bits);
        let k_whir = whir_params.k;
        if k_whir == 0 {
            return Err(ParamsError::ZeroFoldingFactor);
        }
        let log_rs_domain_size = log_stacked_height.saturating_add(log_blowup);
        if log_rs_domain_size >= usize::BITS as usize {
            return Err(ParamsError::RsDomainUnaddressable { log_rs_domain_size });
        }
        let log_final_poly_len = whir_params.log_final_poly_len;
        let num_rounds = match log_stacked_height.checked_sub(log_final_poly_len) {
            Some(folded) if folded > 0 => folded.div_ceil(k_whir),
            _ => {
                return Err(ParamsError::NoWhirRound {
                    log_stacked_height,
                    log_final_poly_len,
                })
            }
        };
        if num_rounds * k_whir > log_stacked_height {
            return Err(ParamsError::WhirRoundsOverrun {
                log_stacked_height,
                k: k_whir,
                num_rounds,
            });
        }
        if protocol_security_level == 0 {
            return Err(ParamsError::NoQueries {
                security_bits,
                query_phase_pow_bits,
            });
        }
        let mut log_inv_rate = log_blowup;
        let proximity = whir_params.proximity;

        let mut round_parameters = Vec::with_capacity(num_rounds);
        for round in 0..num_rounds {
            // Queries are set w.r.t. to old rate, while the rest to the new rate
            let next_rate = log_inv_rate + (k_whir - 1);

            let num_queries = Self::round_queries(
                round,
                proximity.in_round(round),
                protocol_security_level,
                log_inv_rate,
            )?;
            round_parameters.push(WhirRoundConfig { num_queries });

            log_inv_rate = next_rate;
        }

        Ok(Self {
            k: k_whir,
            rounds: round_parameters,
            mu_pow_bits: whir_params.mu_pow_bits,
            query_phase_pow_bits,
            folding_pow_bits: whir_params.folding_pow_bits,
            proximity,
        })
    }

    #[inline]
    pub fn log_final_poly_len(&self, log_stacked_height: usize) -> usize {
        log_stacked_height
            .checked_sub(self.num_sumcheck_rounds())
            .unwrap_or_else(|| {
                panic!(
                    "{}",
                    ParamsError::WhirRoundsOverrun {
                        log_stacked_height,
                        k: self.k,
                        num_rounds: self.num_whir_rounds(),
                    }
                )
            })
    }

    pub fn num_whir_rounds(&self) -> usize {
        self.rounds.len()
    }

    #[inline]
    pub fn num_sumcheck_rounds(&self) -> usize {
        self.num_whir_rounds() * self.k
    }

    /// Pure function to calculate the number of queries necessary for a given WHIR round.
    /// - `protocol_security_level` refers to the target bits of security without grinding.
    /// - `log_inv_rate` is the log blowup for the WHIR round we want to calculate the number of
    ///   queries for.
    ///
    /// Uncapped: a zero per-query figure divides to +/-inf, which the cast saturates to
    /// `usize::MAX` or 0. [`Self::try_new`] refuses both through [`Self::round_queries`].
    // Source: https://github.com/WizardOfMenlo/whir/blob/cf1599b56ff50e09142ebe6d2e2fbd86875c9986/src/whir/parameters.rs#L457
    pub fn queries(
        proximity_regime: ProximityRegime,
        protocol_security_level: usize,
        log_inv_rate: usize,
    ) -> usize {
        let per_query_bits = proximity_regime.whir_per_query_security_bits(log_inv_rate);
        let num_queries_f = (protocol_security_level as f64) / per_query_bits;
        num_queries_f.ceil() as usize
    }

    /// [`Self::queries`] for one round, refused unless it is a count the prover can run. The
    /// per-query figure is zero where the regime leaves no distance at this rate (unique decoding
    /// at rate 1, `ListDecoding { m: 1 }` at rate 1/2); with a positive figure and a positive
    /// `protocol_security_level`, the count is at least 1.
    fn round_queries(
        round: usize,
        regime: ProximityRegime,
        protocol_security_level: usize,
        log_inv_rate: usize,
    ) -> Result<usize, ParamsError> {
        let per_query_bits = regime.whir_per_query_security_bits(log_inv_rate);
        if per_query_bits <= 0.0 || !per_query_bits.is_finite() {
            return Err(ParamsError::NoQuerySecurity {
                round,
                regime,
                log_inv_rate,
            });
        }
        let num_queries = Self::queries(regime, protocol_security_level, log_inv_rate);
        if num_queries > MAX_WHIR_QUERIES {
            return Err(ParamsError::TooManyQueries { round, num_queries });
        }
        Ok(num_queries)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_whir_list_decoding_query_bits_monotone_in_num_queries() {
        let regime = ProximityRegime::ListDecoding { m: 2 };
        let sec_10 = regime.whir_query_security_bits(10, 1);
        let sec_20 = regime.whir_query_security_bits(20, 1);
        assert!(sec_20 > sec_10);
        assert!(sec_10 > 0.0);
    }
}
