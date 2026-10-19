use std::sync::Arc;

use itertools::Itertools;
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_matrix::dense::RowMajorMatrix;

use self::dummy_airs::{
    fib_air::air::FibonacciAir,
    fib_selector_air::air::FibonacciSelectorAir,
    interaction::{
        dummy_interaction_air::DummyInteractionAir,
        self_interaction_air::{SelfInteractionAir, SelfInteractionChip},
    },
    preprocessed_cached_air::air::PreprocessedCachedAir,
};
use crate::{
    interaction::LogUpSecurityParameters,
    keygen::types::{MultiStarkProvingKey, MultiStarkVerifyingKey},
    lookup::LookupType,
    poly::matrix::{ColMajorMatrix, MatrixDimensions},
    proof::Proof,
    prover::{
        stacked_pcs::stacked_commit, AirProvingContext, CommittedTraceData, DeviceDataTransporter,
        DeviceMultiStarkProvingKey, MultiRapProver, Prover, ProvingContext,
        ReferenceColMajorBackend,
    },
    AirRef, StarkEngine, StarkProtocolConfig, SystemParams, WhirConfig, WhirParams,
    WhirProximityStrategy,
};

pub mod dummy_airs;

/// Macro to create a `Vec<AirRef<SC>>` from a list of AIRs.
#[macro_export]
macro_rules! any_air_arc_vec {
    ($($air:expr),+ $(,)?) => {
        vec![$(std::sync::Arc::new($air) as $crate::AirRef<_>),+]
    };
}

#[allow(clippy::type_complexity)]
pub fn prove_up_to_batch_constraints<E: StarkEngine>(
    engine: &E,
    transcript: &mut E::TS,
    pk: &DeviceMultiStarkProvingKey<E::PB>,
    ctx: ProvingContext<E::PB>,
) -> (
    <E::PD as MultiRapProver<E::PB, E::TS>>::PartialProof,
    <E::PD as MultiRapProver<E::PB, E::TS>>::Artifacts,
) {
    engine
        .device()
        .prove_rap_constraints(transcript, pk, &ctx)
        .unwrap()
}

fn get_fib_number<F: PrimeField64>(mut a: u64, mut b: u64, n: usize) -> u64 {
    for _ in 0..n - 1 {
        let c = (a + b) % F::ORDER_U64;
        a = b;
        b = c;
    }
    b
}

fn get_conditional_fib_number<F: PrimeField64>(mut a: u64, mut b: u64, sels: &[bool]) -> u64 {
    for &s in sels[0..sels.len() - 1].iter() {
        if s {
            let c = (a + b) % F::ORDER_U64;
            a = b;
            b = c;
        }
    }
    b
}

fn commit_cached_trace<SC: StarkProtocolConfig>(
    config: &SC,
    trace: ColMajorMatrix<SC::F>,
) -> CommittedTraceData<ReferenceColMajorBackend<SC>> {
    let params = config.params();
    let (commitment, data) = stacked_commit(
        config.hasher(),
        params.l_skip,
        params.n_stack,
        params.log_blowup,
        params.k_whir(),
        &[&trace],
    )
    .unwrap();
    CommittedTraceData {
        commitment,
        trace,
        data: Arc::new(data),
    }
}
/// Trait for object responsible for generating the collection of AIRs and trace matrices for a
/// single test case.
pub trait TestFixture<SC: StarkProtocolConfig> {
    fn airs(&self) -> Vec<AirRef<SC>>;

    fn generate_proving_ctx(&self) -> ProvingContext<ReferenceColMajorBackend<SC>>;

    fn keygen<E: StarkEngine<SC = SC>>(
        &self,
        engine: &E,
    ) -> (MultiStarkProvingKey<SC>, MultiStarkVerifyingKey<SC>) {
        engine.keygen(&self.airs())
    }

    fn prove<E: StarkEngine<SC = SC>>(
        &self,
        engine: &E,
        pk: &MultiStarkProvingKey<SC>,
    ) -> Proof<SC> {
        self.prove_from_transcript(engine, pk, &mut engine.initial_transcript())
    }

    /// Prove using CPU tracegen and transport to device.
    fn prove_from_transcript<E: StarkEngine<SC = SC>>(
        &self,
        engine: &E,
        pk: &MultiStarkProvingKey<SC>,
        transcript: &mut E::TS,
    ) -> Proof<SC> {
        let ctx = self.generate_proving_ctx();
        let device = engine.device();
        let d_pk = device.transport_pk_to_device(pk);
        let d_ctx = device.transport_proving_ctx_to_device(&ctx);
        let mut prover = engine.prover_from_transcript(transcript.clone());
        let proof = prover.prove(&d_pk, d_ctx).unwrap();
        *transcript = prover.transcript;
        proof
    }

    fn keygen_and_prove<E: StarkEngine<SC = SC>>(
        &self,
        engine: &E,
    ) -> (MultiStarkVerifyingKey<SC>, Proof<SC>) {
        let (pk, vk) = self.keygen(engine);
        let proof = self.prove(engine, &pk);
        (vk, proof)
    }
}

pub struct FibFixture {
    pub a: u64,
    pub b: u64,
    pub n: usize,
    pub num_airs: usize,
    pub empty_air_indices: Vec<usize>,
}

impl FibFixture {
    pub fn new(a: u64, b: u64, n: usize) -> Self {
        FibFixture {
            a,
            b,
            n,
            num_airs: 1,
            empty_air_indices: vec![],
        }
    }

    pub fn new_with_num_airs(a: u64, b: u64, n: usize, num_airs: usize) -> Self {
        FibFixture {
            a,
            b,
            n,
            num_airs,
            empty_air_indices: vec![],
        }
    }

    pub fn with_empty_air_indices(mut self, empty_air_indices: impl Into<Vec<usize>>) -> Self {
        self.empty_air_indices = empty_air_indices.into();
        self
    }
}

impl<SC: StarkProtocolConfig> TestFixture<SC> for FibFixture {
    fn airs(&self) -> Vec<AirRef<SC>> {
        let air = Arc::new(FibonacciAir);
        vec![air; self.num_airs]
    }

    fn generate_proving_ctx(&self) -> ProvingContext<ReferenceColMajorBackend<SC>> {
        use crate::test_utils::dummy_airs::fib_air::trace::generate_trace_rows;
        let f_n = get_fib_number::<SC::F>(self.a, self.b, self.n);
        let pis = [self.a, self.b, f_n].map(SC::F::from_u64);

        ProvingContext::new(
            (0..self.num_airs)
                .filter(|i| !self.empty_air_indices.contains(i))
                .map(|i| {
                    (
                        i,
                        AirProvingContext::simple(
                            ColMajorMatrix::from_row_major(&generate_trace_rows::<SC::F>(
                                self.a, self.b, self.n,
                            )),
                            pis.to_vec(),
                        ),
                    )
                })
                .collect_vec(),
        )
    }
}

/// Interactions fixture with 1 sender and 1 receiver
pub struct InteractionsFixture11;

impl<SC: StarkProtocolConfig> TestFixture<SC> for InteractionsFixture11 {
    fn airs(&self) -> Vec<AirRef<SC>> {
        let sender_air = DummyInteractionAir::new(1, true, LookupType::Byte);
        let receiver_air = DummyInteractionAir::new(1, false, LookupType::Byte);
        any_air_arc_vec!(sender_air, receiver_air)
    }

    fn generate_proving_ctx(&self) -> ProvingContext<ReferenceColMajorBackend<SC>> {
        let sender_trace = RowMajorMatrix::new(
            [0, 1, 3, 5, 7, 4, 546, 889]
                .into_iter()
                .map(SC::F::from_usize)
                .collect(),
            2,
        );

        let receiver_trace = RowMajorMatrix::new(
            [1, 5, 3, 4, 4, 4, 2, 5, 0, 123, 545, 889, 1, 889, 0, 456]
                .into_iter()
                .map(SC::F::from_usize)
                .collect(),
            2,
        );

        ProvingContext::new(
            [sender_trace, receiver_trace]
                .into_iter()
                .enumerate()
                .map(|(air_idx, trace)| {
                    (
                        air_idx,
                        AirProvingContext::simple_no_pis(ColMajorMatrix::from_row_major(&trace)),
                    )
                })
                .collect(),
        )
    }
}

/// Dummy interaction AIRs with cached trace: 1 sender, 1 receiver
#[derive(derive_new::new)]
pub struct CachedFixture11<SC> {
    pub config: SC,
}

impl<SC: StarkProtocolConfig> TestFixture<SC> for CachedFixture11<SC> {
    fn airs(&self) -> Vec<AirRef<SC>> {
        let sender_air = DummyInteractionAir::new(1, true, LookupType::Byte).partition();
        let receiver_air = DummyInteractionAir::new(1, false, LookupType::Byte).partition();
        any_air_arc_vec!(sender_air, receiver_air)
    }

    fn generate_proving_ctx(&self) -> ProvingContext<ReferenceColMajorBackend<SC>> {
        let sender_trace = ColMajorMatrix::new(
            [0, 3, 7, 546].into_iter().map(SC::F::from_usize).collect(),
            1,
        );
        let sender_cached_trace = ColMajorMatrix::new(
            [1, 5, 4, 889].into_iter().map(SC::F::from_usize).collect(),
            1,
        );

        let receiver_trace = ColMajorMatrix::new(
            [1, 3, 4, 2, 0, 545, 1, 0]
                .into_iter()
                .map(SC::F::from_usize)
                .collect(),
            1,
        );
        let receiver_cached_trace = ColMajorMatrix::new(
            [5, 4, 4, 5, 123, 889, 889, 456]
                .into_iter()
                .map(SC::F::from_usize)
                .collect(),
            1,
        );

        let config = &self.config;
        let params = config.params();
        ProvingContext::new(
            [
                (sender_trace, sender_cached_trace),
                (receiver_trace, receiver_cached_trace),
            ]
            .map(|(common, cached)| {
                let (commit, data) = stacked_commit(
                    config.hasher(),
                    params.l_skip,
                    params.n_stack,
                    params.log_blowup,
                    params.k_whir(),
                    &[&cached],
                )
                .unwrap();
                assert_eq!(common.height(), cached.height());
                let cached_data = CommittedTraceData {
                    commitment: commit,
                    trace: cached,
                    data: Arc::new(data),
                };
                AirProvingContext {
                    cached_mains: vec![cached_data],
                    common_main: common,
                    public_values: vec![],
                }
            })
            .into_iter()
            .enumerate()
            .collect(),
        )
    }
}

#[derive(derive_new::new)]
pub struct PreprocessedFibFixture {
    pub a: u64,
    pub b: u64,
    pub sels: Vec<bool>,
}

impl<SC: StarkProtocolConfig> TestFixture<SC> for PreprocessedFibFixture {
    fn airs(&self) -> Vec<AirRef<SC>> {
        let air = Arc::new(FibonacciSelectorAir::new(self.sels.clone(), false));
        vec![air]
    }

    fn generate_proving_ctx(&self) -> ProvingContext<ReferenceColMajorBackend<SC>> {
        use crate::test_utils::dummy_airs::fib_selector_air::trace::generate_trace_rows;
        let trace = generate_trace_rows::<SC::F>(self.a, self.b, &self.sels);
        let f_n = get_conditional_fib_number::<SC::F>(self.a, self.b, &self.sels);
        let pis = [self.a, self.b, f_n].map(SC::F::from_u64);

        let single_ctx =
            AirProvingContext::simple(ColMajorMatrix::from_row_major(&trace), pis.to_vec());
        ProvingContext::new(vec![(0, single_ctx)])
    }
}

/// Two preprocessed AIRs with DIFFERENT trace heights, with the SMALLER one at AIR index 0.
/// The verifier's trace ordering (`(Reverse(log_height), air_id)`) then differs from AIR-id
/// order, exercising the merged-preprocessed matrix ordering and claim mapping non-trivially.
///
/// # Known limitation: no need_rot / width discrimination
///
/// Both AIRs are `FibonacciSelectorAir` — same `need_rot` (true) and same prep width — so a
/// bug that permuted the per-matrix `need_rot` flags or widths inside the merged commitment
/// would NOT be caught by tests built on this fixture (any permutation of equal values looks
/// the same). It discriminates matrix ORDERING only. To also pin the flag/width mapping,
/// build a fixture mixing AIRs with different `need_rot` values and different prep widths.
#[derive(derive_new::new)]
pub struct TwoPreprocessedFixture {
    pub sels_small: Vec<bool>,
    pub sels_big: Vec<bool>,
}

impl<SC: StarkProtocolConfig> TestFixture<SC> for TwoPreprocessedFixture {
    fn airs(&self) -> Vec<AirRef<SC>> {
        assert!(self.sels_small.len() < self.sels_big.len());
        vec![
            Arc::new(FibonacciSelectorAir::new(self.sels_small.clone(), false)),
            Arc::new(FibonacciSelectorAir::new(self.sels_big.clone(), false)),
        ]
    }

    fn generate_proving_ctx(&self) -> ProvingContext<ReferenceColMajorBackend<SC>> {
        use crate::test_utils::dummy_airs::fib_selector_air::trace::generate_trace_rows;
        let per_trace = [&self.sels_small, &self.sels_big]
            .into_iter()
            .enumerate()
            .map(|(air_idx, sels)| {
                let trace = generate_trace_rows::<SC::F>(0, 1, sels);
                let f_n = get_conditional_fib_number::<SC::F>(0, 1, sels);
                let pis = [0, 1, f_n].map(SC::F::from_u64);
                (
                    air_idx,
                    AirProvingContext::simple(ColMajorMatrix::from_row_major(&trace), pis.to_vec()),
                )
            })
            .collect();
        ProvingContext::new(per_trace)
    }
}

#[derive(derive_new::new)]
pub struct PreprocessedAndCachedFixture<SC> {
    pub sels: Vec<bool>,
    pub config: SC,
    pub num_cached_parts: usize,
}

impl<SC: StarkProtocolConfig> TestFixture<SC> for PreprocessedAndCachedFixture<SC> {
    fn airs(&self) -> Vec<AirRef<SC>> {
        vec![Arc::new(PreprocessedCachedAir::new(
            self.sels.clone(),
            self.num_cached_parts,
        ))]
    }

    fn generate_proving_ctx(&self) -> ProvingContext<ReferenceColMajorBackend<SC>> {
        assert!(self.sels.len().is_power_of_two());

        let common_main =
            ColMajorMatrix::new((0..self.sels.len()).map(SC::F::from_usize).collect(), 1);
        let cached_mains = (0..self.num_cached_parts)
            .map(|part| {
                let trace = ColMajorMatrix::new(
                    self.sels
                        .iter()
                        .enumerate()
                        .map(|(i, &sel)| {
                            SC::F::from_usize(i)
                                + SC::F::from_usize(part + 1) * SC::F::from_bool(sel)
                        })
                        .collect(),
                    1,
                );
                commit_cached_trace(&self.config, trace)
            })
            .collect();

        ProvingContext::new(vec![(
            0,
            AirProvingContext::new(cached_mains, common_main, vec![]),
        )])
    }
}
#[derive(derive_new::new)]
pub struct SelfInteractionFixture {
    pub widths: Vec<usize>,
    pub log_height: usize,
    pub kind: LookupType,
}

impl<SC: StarkProtocolConfig> TestFixture<SC> for SelfInteractionFixture {
    fn airs(&self) -> Vec<AirRef<SC>> {
        self.widths
            .iter()
            .map(|&width| {
                Arc::new(SelfInteractionAir {
                    width,
                    kind: self.kind,
                }) as AirRef<SC>
            })
            .collect_vec()
    }

    fn generate_proving_ctx(&self) -> ProvingContext<ReferenceColMajorBackend<SC>> {
        let per_trace = self
            .widths
            .iter()
            .map(|&width| {
                let chip = SelfInteractionChip {
                    width,
                    log_height: self.log_height,
                };
                chip.generate_proving_ctx::<SC>()
            })
            .enumerate()
            .collect_vec();
        ProvingContext { per_trace }
    }
}

pub struct MixtureFixture<SC> {
    pub fxs: Vec<MixtureFixtureEnum<SC>>,
}

pub enum MixtureFixtureEnum<SC> {
    FibFixture(FibFixture),
    InteractionsFixture11(InteractionsFixture11),
    CachedFixture11(CachedFixture11<SC>),
    PreprocessedFibFixture(PreprocessedFibFixture),
    SelfInteractionFixture(SelfInteractionFixture),
}

impl<SC: StarkProtocolConfig> MixtureFixtureEnum<SC> {
    fn airs(&self) -> Vec<AirRef<SC>> {
        use crate::test_utils::MixtureFixtureEnum::*;
        match self {
            FibFixture(fx) => fx.airs(),
            InteractionsFixture11(fx) => fx.airs(),
            CachedFixture11(fx) => fx.airs(),
            PreprocessedFibFixture(fx) => fx.airs(),
            SelfInteractionFixture(fx) => fx.airs(),
        }
    }

    fn generate_air_proving_ctxs(&self) -> Vec<AirProvingContext<ReferenceColMajorBackend<SC>>> {
        use crate::test_utils::MixtureFixtureEnum::*;
        let ctx = match self {
            FibFixture(fx) => fx.generate_proving_ctx(),
            InteractionsFixture11(fx) => fx.generate_proving_ctx(),
            CachedFixture11(fx) => fx.generate_proving_ctx(),
            PreprocessedFibFixture(fx) => fx.generate_proving_ctx(),
            SelfInteractionFixture(fx) => fx.generate_proving_ctx(),
        };
        ctx.per_trace
            .into_iter()
            .map(|(_, trace_ctx)| trace_ctx)
            .collect_vec()
    }
}

impl<SC> MixtureFixture<SC> {
    pub fn new(fxs: Vec<MixtureFixtureEnum<SC>>) -> Self {
        Self { fxs }
    }

    pub fn standard(log_height: usize, config: SC) -> Self {
        let height = 1usize << log_height;
        let sels = (0..height).map(|i| i % 2 == 0).collect_vec();
        let widths = vec![4, 7, 8, 8, 10, 100];
        Self::new(vec![
            MixtureFixtureEnum::FibFixture(FibFixture::new(8, 8, height)),
            MixtureFixtureEnum::InteractionsFixture11(InteractionsFixture11),
            MixtureFixtureEnum::CachedFixture11(CachedFixture11::new(config)),
            MixtureFixtureEnum::PreprocessedFibFixture(PreprocessedFibFixture::new(7, 3, sels)),
            MixtureFixtureEnum::SelfInteractionFixture(SelfInteractionFixture::new(
                widths,
                log_height,
                LookupType::Byte,
            )),
        ])
    }
}

impl<SC: StarkProtocolConfig> TestFixture<SC> for MixtureFixture<SC> {
    fn airs(&self) -> Vec<AirRef<SC>> {
        self.fxs.iter().flat_map(|fx| fx.airs()).collect_vec()
    }

    fn generate_proving_ctx(&self) -> ProvingContext<ReferenceColMajorBackend<SC>> {
        let per_trace = self
            .fxs
            .iter()
            .flat_map(|fx| fx.generate_air_proving_ctxs())
            .enumerate()
            .collect_vec();
        ProvingContext { per_trace }
    }
}

impl SystemParams {
    /// Parameters for testing traces of height up to `2^log_trace_height` with **toy security
    /// parameters** for faster testing.
    ///
    /// **These parameters should not be used in production!**
    pub fn new_for_testing(log_trace_height: usize) -> Self {
        let l_skip = 4;
        let k_whir = 4;
        let mut params = test_system_params_small(l_skip, log_trace_height - l_skip, k_whir);
        params.max_constraint_degree = 4;
        params
    }
}

/// Trace heights cannot exceed `2^{l_skip + n_stack}` and stacked cells cannot exceed
/// `w_stack * 2^{l_skip + n_stack}` when using these system params.
pub fn test_system_params_small(l_skip: usize, n_stack: usize, k_whir: usize) -> SystemParams {
    let log_final_poly_len = (n_stack + l_skip) % k_whir;
    test_system_params_small_with_poly_len(l_skip, n_stack, k_whir, log_final_poly_len, 3)
}

pub fn test_system_params_small_with_poly_len(
    l_skip: usize,
    n_stack: usize,
    k_whir: usize,
    log_final_poly_len: usize,
    max_constraint_degree: usize,
) -> SystemParams {
    assert!(log_final_poly_len < l_skip + n_stack);
    let log_blowup = 1;
    SystemParams {
        l_skip,
        n_stack,
        w_stack: 1 << 12,
        log_blowup,
        whir: test_whir_config_small(log_blowup, l_skip + n_stack, k_whir, log_final_poly_len),
        logup: LogUpSecurityParameters {
            max_interaction_count: 1 << 30,
            log_max_message_length: 7,
            pow_bits: 2,
        },
        max_constraint_degree,
    }
}

pub fn test_whir_config_small(
    log_blowup: usize,
    log_stacked_height: usize,
    k_whir: usize,
    log_final_poly_len: usize,
) -> WhirConfig {
    let params = WhirParams {
        k: k_whir,
        log_final_poly_len,
        query_phase_pow_bits: 1,
        folding_pow_bits: 2,
        mu_pow_bits: 3,
        proximity: WhirProximityStrategy::SplitUniqueList {
            m: 3,
            list_start_round: 1,
        },
    };
    let security_bits = 5;
    WhirConfig::new(log_blowup, log_stacked_height, params, security_bits)
}

pub fn default_test_params_small() -> SystemParams {
    test_system_params_small(2, 8, 3)
}
