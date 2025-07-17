use crate::{
    cuda_adaptor::{
        log2_strict_usize, poseidon_constant::get_poseidon2_constants,
        quotient::compute_quotient_values_cuda_gm, quotient_2::compute_quotient_values_cuda_gm_2,
        setup_keys_gm::BaseProvingKeyCuda, transmute, Arc, ChipBehavior, CudaMemPool,
        GPUMerkleTree, Hash, KoalaBear, MetaChip, Poseidon2Constants, StarkGenericConfig,
        TwoAdicMultiplicativeCoset,
    },
    machine::{
        folder::ProverConstraintFolder,
        proof::{
            BaseCommitments, BaseOpenedValues, BaseProof, ChipOpenedValues, MainTraceCommitments,
        },
        utils::order_chips,
    },
};
use cudart::stream::CudaStream;
use itertools::Itertools;
use p3_commit::Pcs;
use std::{
    alloc::{dealloc, Layout},
    any::TypeId,
    array,
    time::Instant,
};

use p3_air::Air;
use p3_challenger::{CanObserve, CanSample, CanSampleBits, FieldChallenger, GrindingChallenger};
use p3_commit::PolynomialSpace;
use p3_field::{Field, FieldAlgebra, FieldExtensionAlgebra};

//
use crate::cuda_adaptor::gpuacc_struct::{
    fri_open::{FriData, OpenProof},
    matrix::{DeviceMatrixConcrete, DeviceMatrixStatic},
    poseidon::DIGEST_ELEMS,
};

//
use std::ffi::c_void;

extern "C" {
    fn rustffi_fri_open(
        rounds: *mut c_void,
        challenger: *mut usize,
        fri_data: *mut c_void,
        cuda_stream: *const c_void,
        mem_pool: *const c_void,
        hash_type: HashType,
    ) -> *mut c_void;

    fn rustffi_split_evals_impl(
        a: *mut c_void,
        cuda_stream: *const usize,
        mem_pool: *const c_void,
        log_quotient: usize,
    ) -> *mut c_void;
}

//
const ONE_HALF: KoalaBear = unsafe { transmute(16777215) };

//
use crate::{
    configs::config::{Com, PcsProof},
    cuda_adaptor::gpuacc_struct::fri_commit::HashType,
};
use p3_field::extension::BinomialExtensionField;
type Val = KoalaBear;
type Challenge = BinomialExtensionField<Val, 4>;

//
pub trait KoalaBearSC:
    StarkGenericConfig<Val = Val, Challenge = Challenge, Domain = TwoAdicMultiplicativeCoset<Val>>
{
    const HASH_TYPE: HashType;
    fn get_log_blow_up(pcs: &Self::Pcs) -> usize;
    fn get_num_queries(pcs: &Self::Pcs) -> usize;
    fn get_proof_of_work_bits(pcs: &Self::Pcs) -> usize;
    fn to_commit(a: [Val; DIGEST_ELEMS]) -> Com<Self>;
    fn get_default_fri_data<'a>(
        poseidon2_constants: &'a Poseidon2Constants,
        log_blow_up: usize,
        num_queries: usize,
        proof_of_work_bits: usize,
    ) -> FriData<'a, Val, Challenge, Self::Challenger>;
    fn convert_open_proof(
        gpu_proof: &OpenProof<Val, Challenge>,
    ) -> (Vec<Vec<Vec<Vec<Challenge>>>>, PcsProof<Self>);
}

//
use p3_fri::{BatchOpening, CommitPhaseProofStep, FriProof, QueryProof};

pub type InnerVal = crate::configs::stark_config::kb_poseidon2::SC_Val;
pub type InnerValMmcs = crate::configs::stark_config::kb_poseidon2::SC_ValMmcs;
pub type InnerPcs = crate::configs::stark_config::kb_poseidon2::SC_Pcs;
pub type InnerChallenge = crate::configs::stark_config::kb_poseidon2::SC_Challenge;
pub type InnerChallenger = crate::configs::stark_config::kb_poseidon2::SC_Challenger;
pub type InnerChallengeMmcs = crate::configs::stark_config::kb_poseidon2::SC_ChallengeMmcs;
pub type InnerDigestHash = crate::configs::stark_config::kb_poseidon2::SC_DigestHash;

pub type InnerQueryProof = QueryProof<InnerChallenge, InnerChallengeMmcs, InnerInputProof>;
pub type InnerBatchOpening = BatchOpening<InnerVal, InnerValMmcs>;
pub type InnerInputProof = Vec<BatchOpening<InnerVal, InnerValMmcs>>;
pub type InnerFriProof = FriProof<InnerChallenge, InnerChallengeMmcs, InnerVal, InnerInputProof>;
pub type InnerCommitPhaseStep = CommitPhaseProofStep<InnerChallenge, InnerChallengeMmcs>;

use crate::configs::stark_config::KoalaBearPoseidon2;
//
impl KoalaBearSC for KoalaBearPoseidon2 {
    const HASH_TYPE: HashType = HashType::Poseidon2KoalaBear;
    fn get_log_blow_up(pcs: &InnerPcs) -> usize {
        pcs.fri.log_blowup
    }
    fn get_num_queries(pcs: &InnerPcs) -> usize {
        pcs.fri.num_queries
    }
    fn get_proof_of_work_bits(pcs: &InnerPcs) -> usize {
        pcs.fri.proof_of_work_bits
    }
    fn to_commit(a: [Val; DIGEST_ELEMS]) -> InnerDigestHash {
        a.into()
    }
    fn get_default_fri_data<'a>(
        poseidon2_constants: &'a Poseidon2Constants,
        log_blow_up: usize,
        num_queries: usize,
        proof_of_work_bits: usize,
    ) -> FriData<'a, Val, Challenge, InnerChallenger> {
        FriData {
            sample: InnerChallenger::sample,
            observe_hash: |c, i| {
                c.observe(Self::to_commit(i));
            },
            observe_ext: InnerChallenger::observe_ext_element,
            check_witness: InnerChallenger::check_witness,
            sample_bits: InnerChallenger::sample_bits,
            get_pow_data: |c| {
                Some((
                    unsafe { transmute(c.sponge_state.as_ptr()) },
                    unsafe { transmute(c.input_buffer.as_ptr()) },
                    c.input_buffer.len(),
                ))
            },
            hash_type: Self::HASH_TYPE,
            poseidon2_constants,
            grind: InnerChallenger::grind,
            proof_of_work_bits,
            compute_host_scale: |z, log_n| {
                let n = 1 << log_n;
                let shift = Val::GENERATOR;
                let zerofier = p3_field::two_adic_coset_zerofier::<Challenge>(
                    log_n,
                    Challenge::from_base(shift),
                    z,
                );
                let denominator = Val::from_canonical_usize(n) * shift.exp_u64(n as u64 - 1);
                zerofier * denominator.inverse()
            },
            exp_u64: |x, e| x.exp_u64(e),
            generator: Val::GENERATOR,
            log_blow_up,
            one_half: ONE_HALF,
            compute_half_beta: |beta| beta * ONE_HALF,
            num_queries,
        }
    }
    fn convert_open_proof(
        gpu_proof: &OpenProof<Val, Challenge>,
    ) -> (Vec<Vec<Vec<Vec<Challenge>>>>, InnerFriProof) {
        let all_opend_values = gpu_proof.all_opened_values.clone();
        let commit_phase_commits: Vec<InnerDigestHash> = gpu_proof
            .commit_phase_commits
            .iter()
            .map(|i| Self::to_commit(i.clone()))
            .collect();
        let final_poly = gpu_proof.final_poly;
        let pow_witness = gpu_proof.pow_witness;
        let query_proofs: Vec<_> = gpu_proof
            .input_proof_values
            .iter()
            .zip(gpu_proof.input_proof_paths.iter())
            .zip(gpu_proof.commit_phase_sibling.iter())
            .zip(gpu_proof.commit_phase_paths.iter())
            .map(
                |(
                    ((input_proof_value, input_proof_path), commit_phase_sibling),
                    commit_phase_path,
                )| {
                    let input_proof: Vec<InnerBatchOpening> = input_proof_value
                        .into_iter()
                        .zip(input_proof_path.into_iter())
                        .map(|(v, p)| InnerBatchOpening {
                            opened_values: v.clone(),
                            opening_proof: p.clone(),
                        })
                        .collect();
                    let commit_phase_openings: Vec<InnerCommitPhaseStep> = commit_phase_sibling
                        .into_iter()
                        .zip(commit_phase_path.into_iter())
                        .map(|(s, p)| InnerCommitPhaseStep {
                            sibling_value: s.clone(),
                            opening_proof: p.clone(),
                        })
                        .collect();
                    InnerQueryProof {
                        input_proof,
                        commit_phase_openings,
                    }
                },
            )
            .collect();
        (
            all_opend_values,
            InnerFriProof {
                commit_phase_commits,
                query_proofs,
                final_poly,
                pow_witness,
            },
        )
    }
}

//
use crate::instances::configs::embed_kb_bn254_poseidon2::KoalaBearBn254Poseidon2;
pub type OuterVal = crate::instances::configs::embed_kb_bn254_poseidon2::SC_Val;
pub type OuterPcs = crate::instances::configs::embed_kb_bn254_poseidon2::SC_Pcs;
pub type OuterDigestHash = crate::instances::configs::embed_kb_bn254_poseidon2::SC_DigestHash;
pub type OuterChallenge = crate::instances::configs::embed_kb_bn254_poseidon2::SC_Challenge;
pub type OuterChallenger = crate::instances::configs::embed_kb_bn254_poseidon2::SC_Challenger;
pub type OuterChallengeMmcs = crate::instances::configs::embed_kb_bn254_poseidon2::SC_ChallengeMmcs;
pub type OuterInputProof = crate::instances::configs::embed_kb_bn254_poseidon2::SC_InputProof;
pub type OuterBatchOpening = crate::instances::configs::embed_kb_bn254_poseidon2::SC_BatchOpening;
pub type OuterCommitPhaseStep =
    crate::instances::configs::embed_kb_bn254_poseidon2::SC_CommitPhaseStep;
pub type OuterQueryProof = crate::instances::configs::embed_kb_bn254_poseidon2::SC_QueryProof;

pub type OuterFriProof = FriProof<OuterChallenge, OuterChallengeMmcs, OuterVal, OuterInputProof>;

use p3_bn254_fr::Bn254Fr;
//
impl KoalaBearSC for KoalaBearBn254Poseidon2 {
    const HASH_TYPE: HashType = HashType::Poseidon2Bn254;
    fn get_log_blow_up(pcs: &OuterPcs) -> usize {
        pcs.fri.log_blowup
    }
    fn get_num_queries(pcs: &OuterPcs) -> usize {
        pcs.fri.num_queries
    }
    fn get_proof_of_work_bits(pcs: &OuterPcs) -> usize {
        pcs.fri.proof_of_work_bits
    }
    fn to_commit(a: [Val; DIGEST_ELEMS]) -> OuterDigestHash {
        unsafe { transmute(a) }
    }
    fn get_default_fri_data<'a>(
        poseidon2_constants: &'a Poseidon2Constants,
        log_blow_up: usize,
        num_queries: usize,
        proof_of_work_bits: usize,
    ) -> FriData<'a, Val, Challenge, OuterChallenger> {
        FriData {
            sample: OuterChallenger::sample,
            observe_hash: |c, i| {
                c.observe(Self::to_commit(i));
            },
            observe_ext: OuterChallenger::observe_ext_element,
            check_witness: OuterChallenger::check_witness,
            sample_bits: OuterChallenger::sample_bits,
            get_pow_data: |c| {
                Some((
                    unsafe { transmute(c.sponge_state.as_ptr()) },
                    unsafe { transmute(c.input_buffer.as_ptr()) },
                    c.input_buffer.len(),
                ))
            },
            hash_type: Self::HASH_TYPE,
            poseidon2_constants,
            grind: OuterChallenger::grind,
            proof_of_work_bits,
            compute_host_scale: |z, log_n| {
                let n = 1 << log_n;
                let shift = Val::GENERATOR;
                let zerofier = p3_field::two_adic_coset_zerofier::<Challenge>(
                    log_n,
                    Challenge::from_base(shift),
                    z,
                );
                let denominator = Val::from_canonical_usize(n) * shift.exp_u64(n as u64 - 1);
                zerofier * denominator.inverse()
            },
            exp_u64: |x, e| x.exp_u64(e),
            generator: Field::GENERATOR,
            log_blow_up,
            one_half: ONE_HALF,
            compute_half_beta: |beta| beta * ONE_HALF,
            num_queries,
        }
    }
    fn convert_open_proof(
        gpu_proof: &OpenProof<Val, Challenge>,
    ) -> (Vec<Vec<Vec<Vec<Challenge>>>>, OuterFriProof) {
        let all_opend_values = gpu_proof.all_opened_values.clone();
        let commit_phase_commits: Vec<OuterDigestHash> = gpu_proof
            .commit_phase_commits
            .iter()
            .map(|i| Self::to_commit(i.clone()))
            .collect();
        let final_poly = gpu_proof.final_poly;
        let pow_witness = gpu_proof.pow_witness;

        let transmute_hash = |a: &Vec<[Val; DIGEST_ELEMS]>| -> Vec<[Bn254Fr; 1]> {
            a.into_iter()
                .map(|i| unsafe { transmute::<_, [Bn254Fr; 1]>(i.clone()) })
                .collect()
        };
        let query_proofs: Vec<_> = gpu_proof
            .input_proof_values
            .iter()
            .zip(gpu_proof.input_proof_paths.iter())
            .zip(gpu_proof.commit_phase_sibling.iter())
            .zip(gpu_proof.commit_phase_paths.iter())
            .map(
                |(
                    ((input_proof_value, input_proof_path), commit_phase_sibling),
                    commit_phase_path,
                )| {
                    let input_proof: Vec<OuterBatchOpening> = input_proof_value
                        .into_iter()
                        .zip(input_proof_path.into_iter())
                        .map(|(v, p)| OuterBatchOpening {
                            opened_values: v.clone(),
                            opening_proof: transmute_hash(p),
                        })
                        .collect();
                    let commit_phase_openings: Vec<OuterCommitPhaseStep> = commit_phase_sibling
                        .into_iter()
                        .zip(commit_phase_path.into_iter())
                        .map(|(s, p)| OuterCommitPhaseStep {
                            sibling_value: s.clone(),
                            opening_proof: transmute_hash(p),
                        })
                        .collect();
                    OuterQueryProof {
                        input_proof,
                        commit_phase_openings,
                    }
                },
            )
            .collect();
        (
            all_opend_values,
            OuterFriProof {
                commit_phase_commits,
                query_proofs,
                final_poly,
                pow_witness,
            },
        )
    }
}

//
//
//
pub fn prove_impl<SC: StarkGenericConfig, C, KSC: KoalaBearSC>(
    config: &SC,
    chips: &[MetaChip<SC::Val, C>],
    challenger: &mut SC::Challenger,
    num_public_values: usize,
    main_commitment_gm: MainTraceCommitments<
        SC,
        Vec<DeviceMatrixConcrete<'static, KoalaBear>>,
        GPUMerkleTree<'static, KoalaBear>,
    >,
    pk_gm: &BaseProvingKeyCuda<SC>,
    stream: &'static CudaStream,
    mem_pool: &CudaMemPool,
    dev_id: usize,
) -> BaseProof<SC>
where
    SC: StarkGenericConfig + 'static,
    C: Air<ProverConstraintFolder<SC>> + ChipBehavior<SC::Val>,
{
    let start = Instant::now();
    // construct challenger
    let mut challenger_gm: <SC as StarkGenericConfig>::Challenger = challenger.clone();

    //
    let chips = order_chips::<SC, C>(chips, &main_commitment_gm.main_chip_ordering).collect_vec();
    let traces = &main_commitment_gm.main_traces;
    assert_eq!(chips.len(), traces.len());

    let main_degrees = traces.iter().map(|t| 1 << t.log_n).collect_vec();
    let log_main_degrees = main_degrees
        .iter()
        .map(|degree| log2_strict_usize(*degree))
        .collect::<Arc<[_]>>();

    // Observe the public values and the main commitment.
    let public_values_kb = &main_commitment_gm.public_values[0..num_public_values];
    let public_values_sc: &[SC::Val] = unsafe { transmute(public_values_kb) };
    challenger_gm.observe_slice(public_values_sc);

    let commitment_kb = &main_commitment_gm.commitment;
    let commitment_sc: &Com<SC> = unsafe { transmute(commitment_kb) };
    challenger_gm.observe(commitment_sc.clone());

    // Obtain the challenges used for the regional permutation argument.
    let regional_permutation_challenges: [SC::Challenge; 2] =
        array::from_fn(|_| challenger_gm.sample_ext_element());

    let main_traces_gm: &Vec<DeviceMatrixConcrete<'_, KoalaBear>> = &main_commitment_gm.main_traces;
    println!("prove_impl - init for perm Duration: {:?}", start.elapsed());

    let start = Instant::now();
    let preprocessed_traces = chips
        .iter()
        .map(|chip| {
            pk_gm
                .preprocessed_chip_ordering
                .get(&chip.name())
                .map(|index| &pk_gm.preprocessed_trace[*index])
        })
        .collect::<Vec<_>>();

    let ((permutation_traces, _prep_traces), (global_cumulative_sums, local_cumulative_sums)): (
        (Vec<_>, Vec<_>),
        (Vec<_>, Vec<_>),
    ) = chips
        .iter()
        .zip(main_traces_gm.into_iter())
        .zip(preprocessed_traces.into_iter())
        .enumerate()
        .map(|(_, ((chip, main_trace), preprocessed_trace))| {
            use crate::cuda_adaptor::permutation_cuda;
            use p3_field::extension::BinomialExtensionField;
            use p3_koala_bear::KoalaBear;
            use std::any::TypeId;
            type InnerVal = KoalaBear;
            type InnerChallenge = BinomialExtensionField<InnerVal, 4>;
            assert!(TypeId::of::<SC::Val>() == TypeId::of::<InnerVal>());
            assert!(TypeId::of::<SC::Challenge>() == TypeId::of::<InnerChallenge>());
            let (debug_perm_device, debug_regional, debug_global) =
                permutation_cuda::generate_permutation_trace_gm(
                    chip,
                    preprocessed_trace,
                    &main_trace,
                    &regional_permutation_challenges,
                );
            (
                (debug_perm_device, preprocessed_trace),
                (debug_global, debug_regional),
            )
        })
        .unzip();
    println!("prove_impl - generate perm Duration: {:?}", start.elapsed());

    let start = Instant::now();
    use crate::cuda_adaptor::fri_commit::fri_commit_from_device;
    use p3_field::Field;
    let pcs = config.pcs();
    let mut permutation_traces_kb: Vec<DeviceMatrixStatic<KoalaBear>> =
        unsafe { transmute(permutation_traces) };
    let perm_merkle = fri_commit_from_device::<SC>(
        permutation_traces_kb
            .iter_mut()
            .map(|i| (KoalaBear::GENERATOR, i.into_ref()))
            .collect(),
        pcs,
        stream,
        mem_pool,
    );
    stream.synchronize().unwrap();
    println!("prove_impl - commit perm Duration: {:?}", start.elapsed());

    let start = Instant::now();
    // Quotient
    println!(
        "GPU Memory before Quotient{:?}",
        cudart::memory::memory_get_info()
    );
    let log_degrees: Vec<usize> = main_traces_gm
        .iter()
        .map(|trace| trace.log_n)
        .collect::<Vec<_>>();
    let log_quotient_degrees: Vec<usize> = chips
        .iter()
        .map(|chip| chip.get_log_quotient_degree())
        .collect::<Vec<_>>();

    let quotient_degrees = log_quotient_degrees
        .iter()
        .map(|log_degree| 1 << log_degree)
        .collect::<Vec<_>>();

    let trace_domains = log_degrees
        .iter()
        .map(|log_degree| TwoAdicMultiplicativeCoset {
            log_n: *log_degree,
            shift: KoalaBear::ONE,
        })
        .collect::<Vec<_>>();
    let quotient_domains = log_quotient_degrees
        .iter()
        .zip(log_degrees.iter())
        .map(
            |(log_quotient_degree, log_degree)| TwoAdicMultiplicativeCoset {
                log_n: *log_quotient_degree + log_degree,
                shift: KoalaBear::GENERATOR,
            },
        )
        .collect::<Vec<_>>();

    // Observe the permutation commitment and cumulative sums.
    let permutation_commit_ref: &Com<SC> = unsafe { transmute(&perm_merkle.merkle_root) };
    let permutation_commit = permutation_commit_ref.clone();
    challenger_gm.observe(permutation_commit.clone());
    for (regional_sum, global_sum) in local_cumulative_sums
        .iter()
        .zip(global_cumulative_sums.iter())
    {
        challenger_gm.observe_slice(regional_sum.as_base_slice());
        challenger_gm.observe_slice(&global_sum.0.x.0);
        challenger_gm.observe_slice(&global_sum.0.y.0);
    }

    let alpha: SC::Challenge = challenger_gm.sample_ext_element();
    println!(
        "prove_impl - quotient prepare Duration: {:?}",
        start.elapsed()
    );

    let start = Instant::now();
    let quotient_values: Vec<DeviceMatrixConcrete<KoalaBear>> = quotient_domains
        .iter()
        .zip(trace_domains.iter())
        .enumerate()
        .map(|(i, (quotient_domain, trace_domain))| {
            let log_quotient = quotient_domain.log_n - trace_domain.log_n;
            let mut preprocessed_trace_on_quotient_domain = pk_gm
                .preprocessed_chip_ordering
                .get(&chips[i].name())
                .map(|&index| {
                    pk_gm.preprocessed_prover_data.get_evaluations(
                        index,
                        trace_domain.log_n,
                        log_quotient,
                        stream,
                        mem_pool,
                    )
                });
            let mut main_trace_on_quotient_domain = main_commitment_gm.data.get_evaluations(
                i,
                trace_domain.log_n,
                log_quotient,
                stream,
                mem_pool,
            );
            let mut permutation_trace_on_quotient_domain =
                perm_merkle.get_evaluations(i, trace_domain.log_n, log_quotient, stream, mem_pool);

            let start = Instant::now();
            // println!(" *** quotient chip: {:?}", chips[i].name());
            // let res = compute_quotient_values_cuda_gm(
            //     chips[i],
            //     &local_cumulative_sums[i],
            //     &global_cumulative_sums[i],
            //     *trace_domain,
            //     *quotient_domain,
            //     preprocessed_trace_on_quotient_domain
            //         .as_mut()
            //         .map(|i| i.into_ref()),
            //     main_trace_on_quotient_domain.into_ref(),
            //     permutation_trace_on_quotient_domain.into_ref(),
            //     &regional_permutation_challenges,
            //     alpha,
            //     &*main_commitment_gm.public_values,
            //     stream,
            //     mem_pool,
            //     dev_id,
            // );
            let res = compute_quotient_values_cuda_gm_2(
                chips[i],
                &local_cumulative_sums[i],
                &global_cumulative_sums[i],
                *trace_domain,
                *quotient_domain,
                preprocessed_trace_on_quotient_domain
                    .as_mut()
                    .map(|i| i.into_ref()),
                main_trace_on_quotient_domain.into_ref(),
                permutation_trace_on_quotient_domain.into_ref(),
                &regional_permutation_challenges,
                alpha,
                &*main_commitment_gm.public_values,
                stream,
                mem_pool,
                dev_id,
            );
            // todo!();

            // println!(" *** quotient duration: {:?}", start.elapsed());
            drop(preprocessed_trace_on_quotient_domain);
            drop(main_trace_on_quotient_domain);
            drop(permutation_trace_on_quotient_domain);

            DeviceMatrixConcrete {
                values: res,
                log_n: quotient_domain.log_n,
                num_poly: <<SC as StarkGenericConfig>::Challenge as FieldExtensionAlgebra<
                    SC::Val,
                >>::D,
            }
        })
        .collect::<Vec<_>>();

    stream.synchronize().unwrap();
    println!(
        "prove_impl - quotient caculate Duration: {:?}",
        start.elapsed()
    );

    //
    let start = Instant::now();
    let mut quotient_domains_and_chunks = quotient_domains
        .into_iter()
        .zip(quotient_values)
        .zip(log_quotient_degrees.iter())
        .flat_map(
            |((quotient_domain, mut quotient_values), &log_quotient_degree)| {
                let ref_quotient_values = quotient_values.into_ref();

                let quotient_chunks = unsafe {
                    let ptr = rustffi_split_evals_impl(
                        transmute(&ref_quotient_values),
                        transmute(stream),
                        transmute(mem_pool),
                        transmute(log_quotient_degree),
                    );

                    let convert_ptr: *mut Vec<DeviceMatrixConcrete<KoalaBear>> = transmute(ptr);

                    let value: Vec<DeviceMatrixConcrete<KoalaBear>> = std::ptr::read(convert_ptr);
                    let layout = Layout::new::<Vec<DeviceMatrixConcrete<KoalaBear>>>();
                    dealloc(convert_ptr as *mut u8, layout);
                    value
                };

                let qc_domains = quotient_domain.split_domains(1 << log_quotient_degree);
                qc_domains.into_iter().zip(quotient_chunks)
            },
        )
        .collect::<Vec<_>>();
    stream.synchronize().unwrap();
    println!(
        "prove_impl - quotient domain Duration: {:?}",
        start.elapsed()
    );

    //
    let start = Instant::now();
    let pcs = config.pcs();
    let num_quotient_chunks = quotient_domains_and_chunks.len();
    assert_eq!(
        num_quotient_chunks,
        chips
            .iter()
            .map(|c| 1 << c.get_log_quotient_degree())
            .sum::<usize>()
    );
    let quotient_merkle = fri_commit_from_device::<SC>(
        quotient_domains_and_chunks
            .iter_mut()
            .map(|(dom, mat)| (KoalaBear::GENERATOR / dom.shift, mat.into_ref()))
            .collect(),
        pcs,
        stream,
        mem_pool,
    );
    stream.synchronize().unwrap();
    println!(
        "prove_impl - quotient commit Duration: {:?}",
        start.elapsed()
    );

    //
    let start = Instant::now();
    let quotient_commit_ref: &Com<SC> = unsafe { transmute(&quotient_merkle.merkle_root) };
    let quotient_commit = quotient_commit_ref.clone();
    challenger_gm.observe(quotient_commit.clone());

    let zeta: SC::Challenge = challenger_gm.sample_ext_element();
    let zeta_kb: &InnerChallenge = unsafe { transmute(&zeta) };

    // get_default_fri_data
    let hash_type = KSC::HASH_TYPE;
    let poseidon2_constants = get_poseidon2_constants(hash_type);

    let pcs = config.pcs();
    let two_adic_pcs: &KSC::Pcs = unsafe { transmute(&pcs) };
    let log_blow_up = KSC::get_log_blow_up(two_adic_pcs);
    let num_queries = KSC::get_num_queries(two_adic_pcs);
    let proof_of_work_bits = KSC::get_proof_of_work_bits(two_adic_pcs);
    let fri_data = KSC::get_default_fri_data(
        &poseidon2_constants,
        log_blow_up,
        num_queries,
        proof_of_work_bits,
    );
    stream.synchronize().unwrap();
    println!("prove_impl - get fri Duration: {:?}", start.elapsed());

    //
    let start = Instant::now();

    //
    let preprocessed_opening_points = pk_gm
        .preprocessed_trace
        .iter()
        .zip(pk_gm.local_only.iter())
        .map(|(trace, local_only)| {
            let domain = Pcs::<Challenge, KSC::Challenger>::natural_domain_for_degree(
                two_adic_pcs,
                1 << trace.log_n,
            );
            if !local_only {
                vec![*zeta_kb, domain.next_point(*zeta_kb).unwrap()]
            } else {
                vec![*zeta_kb]
            }
        })
        .collect::<Vec<_>>();
    let main_trace_opening_points = trace_domains
        .iter()
        .zip(chips.iter())
        .map(|(domain, chip)| {
            if !chip.local_only() {
                vec![*zeta_kb, domain.next_point(*zeta_kb).unwrap()]
            } else {
                vec![*zeta_kb]
            }
        })
        .collect::<Vec<_>>();
    let permutation_trace_opening_points = trace_domains
        .iter()
        .map(|domain| vec![*zeta_kb, domain.next_point(*zeta_kb).unwrap()])
        .collect::<Vec<_>>();
    let quotient_opening_points = (0..num_quotient_chunks)
        .map(|_| vec![*zeta_kb])
        .collect::<Vec<_>>();
    //
    println!(
        "prove_impl - 4 opening points Duration: {:?}",
        start.elapsed()
    );

    //
    let start = Instant::now();

    let gpu_opening_proof = unsafe {
        let ptr = rustffi_fri_open(
            transmute(&vec![
                (&pk_gm.preprocessed_prover_data, preprocessed_opening_points),
                (&main_commitment_gm.data, main_trace_opening_points.clone()),
                (&perm_merkle, permutation_trace_opening_points.clone()),
                (&quotient_merkle, quotient_opening_points),
            ]),
            transmute(&challenger_gm.clone()),
            transmute(&fri_data),
            transmute(stream),
            transmute(mem_pool),
            KSC::HASH_TYPE,
        );
        let open_proof_ptr: *mut OpenProof<Val, Challenge> = transmute(ptr);

        let value: OpenProof<Val, Challenge> = std::ptr::read(open_proof_ptr);
        let layout = Layout::new::<OpenProof<Val, Challenge>>();
        dealloc(open_proof_ptr as *mut u8, layout);
        value
    };
    stream.synchronize().unwrap();
    println!("prove_impl - fri_open Duration: {:?}", start.elapsed());

    //
    let start = Instant::now();

    //
    let (openings, opening_proof) = KSC::convert_open_proof(&gpu_opening_proof);
    let [preprocessed_values, main_values, permutation_values, mut quotient_values] =
        openings.try_into().unwrap();
    assert!(main_values.len() == chips.len());
    println!(
        "prove_impl - convert_open_proof Duration: {:?}",
        start.elapsed()
    );

    //
    let start = Instant::now();

    //
    let preprocessed_opened_values = preprocessed_values
        .into_iter()
        .zip(pk_gm.local_only.iter())
        .map(|(op, local_only)| {
            if !local_only {
                let [local, next] = op.try_into().unwrap();
                (local, next)
            } else {
                let [local] = op.try_into().unwrap();
                let width = local.len();
                (local, vec![Challenge::ZERO; width])
            }
        })
        .collect_vec();

    let main_opened_values = main_values
        .into_iter()
        .zip(chips.iter())
        .map(|(op, chip)| {
            if !chip.local_only() {
                let [local, next] = op.try_into().unwrap();
                (local, next)
            } else {
                let [local] = op.try_into().unwrap();
                let width = local.len();
                (local, vec![Challenge::ZERO; width])
            }
        })
        .collect_vec();
    let permutation_opened_values = permutation_values
        .into_iter()
        .map(|op| {
            let [local, next] = op.try_into().unwrap();
            (local, next)
        })
        .collect_vec();

    let mut quotient_opened_values = Vec::with_capacity(quotient_degrees.len());
    for degree in quotient_degrees.iter() {
        let slice = quotient_values.drain(0..*degree);
        quotient_opened_values.push(slice.map(|mut v| v.pop().unwrap()).collect::<Vec<_>>());
    }

    println!(
        "prove_impl - prepare for opened value Duration: {:?}",
        start.elapsed()
    );

    //
    let start = Instant::now();

    let opened_values = main_opened_values
        .into_iter()
        .zip_eq(permutation_opened_values)
        .zip_eq(quotient_opened_values)
        .zip_eq(local_cumulative_sums)
        .zip_eq(global_cumulative_sums)
        .zip_eq(log_main_degrees.iter().copied())
        .enumerate()
        .map(
            |(
                i,
                (
                    (
                        (((main, permutation), quotient), regional_cumulative_sum),
                        global_cumulative_sum,
                    ),
                    log_main_degree,
                ),
            )| {
                let preprocessed = pk_gm
                    .preprocessed_chip_ordering
                    .get(&chips[i].name())
                    .map(|&index| preprocessed_opened_values[index].clone())
                    .unwrap_or((vec![], vec![]));

                let (preprocessed_local, preprocessed_next) = preprocessed;
                let (main_local, main_next) = main;
                let (permutation_local, permutation_next) = permutation;
                let regional_cumulative_sum_kb: &Challenge =
                    unsafe { transmute(&regional_cumulative_sum) };
                Arc::new(ChipOpenedValues {
                    preprocessed_local,
                    preprocessed_next,
                    main_local,
                    main_next,
                    permutation_local,
                    permutation_next,
                    quotient,
                    global_cumulative_sum,
                    regional_cumulative_sum: *regional_cumulative_sum_kb,
                    log_main_degree,
                })
            },
        )
        .collect::<Arc<[_]>>();
    println!(
        "prove_impl - compute opened value Duration: {:?}",
        start.elapsed()
    );

    //
    let start = Instant::now();

    // final base proof
    let main_commit_sc: &<<SC as StarkGenericConfig>::Pcs as Pcs<
        SC::Challenge,
        SC::Challenger,
    >>::Commitment = unsafe { transmute(&main_commitment_gm.commitment) };
    let permutation_commit_sc: &<<SC as StarkGenericConfig>::Pcs as Pcs<
        SC::Challenge,
        SC::Challenger,
    >>::Commitment = unsafe { transmute(&permutation_commit) };
    let quotient_commit_sc: &<<SC as StarkGenericConfig>::Pcs as Pcs<
        SC::Challenge,
        SC::Challenger,
    >>::Commitment = unsafe { transmute(&quotient_commit) };
    let public_values_sc: &Arc<[SC::Val]> = unsafe { transmute(&main_commitment_gm.public_values) };

    let opened_values_sc: &Arc<[Arc<ChipOpenedValues<SC::Val, SC::Challenge>>]> =
        unsafe { transmute(&opened_values) };

    let opening_proof_sc: &<<SC as StarkGenericConfig>::Pcs as Pcs<
        <SC as StarkGenericConfig>::Challenge,
        <SC as StarkGenericConfig>::Challenger,
    >>::Proof = unsafe { transmute(&opening_proof) };

    println!(
        "prove_impl - prepare for proof value Duration: {:?}",
        start.elapsed()
    );

    BaseProof::<SC> {
        commitments: BaseCommitments {
            main_commit: main_commit_sc.clone(),
            permutation_commit: permutation_commit_sc.clone(),
            quotient_commit: quotient_commit_sc.clone(),
        },
        opened_values: BaseOpenedValues {
            chips_opened_values: opened_values_sc.clone(),
        },
        opening_proof: opening_proof_sc.clone(),
        log_main_degrees: log_main_degrees.clone(),
        log_quotient_degrees: log_quotient_degrees.into(),
        main_chip_ordering: main_commitment_gm.main_chip_ordering.clone(),
        public_values: public_values_sc.clone(),
    }
}
