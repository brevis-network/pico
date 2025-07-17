use crate::{
    configs::stark_config::{KoalaBearBn254Poseidon2, KoalaBearPoseidon2},
    cuda_adaptor::{
        fri_commit::fri_commit,
        fri_open::{InnerPcs, KoalaBearSC, OuterPcs},
        gpuacc_struct::fri_commit::HashType,
        log2_strict_usize, memory_copy_async, Arc, BaseProver, BaseVerifyingKey, ChipBehavior,
        CudaMemPool, DevicePoolAllocation, GPUMerkleTree, HashMap, KoalaBear, Matrix, MetaChip,
        Pcs, ProgramBehavior, SepticDigest, StarkGenericConfig,
    },
};
use cudart::{device::set_device, stream::CudaStream};
use p3_field::Field;
use std::{mem::transmute, time::Instant};
//
use crate::{configs::config::Com, cuda_adaptor::gpuacc_struct::matrix::DeviceMatrixConcrete};
//

use std::any::TypeId;
//
pub struct BaseProvingKeyCuda<SC: StarkGenericConfig> {
    /// The commitment to the named traces.
    pub commit: Com<SC>,
    /// start pc of program
    pub pc_start: KoalaBear,
    /// named preprocessed traces.
    pub preprocessed_trace: Vec<DeviceMatrixConcrete<'static, KoalaBear>>,
    /// The pcs data for the preprocessed traces.
    pub preprocessed_prover_data: GPUMerkleTree<'static, KoalaBear>,
    /// the index of for chips, chip name for key
    pub preprocessed_chip_ordering: Arc<HashMap<String, usize>>,
    /// The starting global digest of the program, after incorporating the initial memory.
    pub initial_global_cumulative_sum: SepticDigest<KoalaBear>,
    /// The preprocessed chip local only information.
    pub local_only: Vec<bool>,
}
unsafe impl<SC: StarkGenericConfig> Sync for BaseProvingKeyCuda<SC> {}
unsafe impl<SC: StarkGenericConfig> Send for BaseProvingKeyCuda<SC> {}

pub fn setup_keys_gm<SC, C>(
    baseprover: &BaseProver<SC, C>,
    config: &SC,
    chips: &[MetaChip<SC::Val, C>],
    program: &C::Program,
    stream: &'static CudaStream,
    mem_pool: &CudaMemPool,
    dev_id: usize,
) -> (BaseProvingKeyCuda<SC>, BaseVerifyingKey<SC>)
where
    SC: StarkGenericConfig + 'static,
    C: ChipBehavior<SC::Val>,
{
    let chips_and_preprocessed = baseprover.generate_preprocessed(chips, program);

    let local_only = chips_and_preprocessed
        .iter()
        .map(|(_, local_only, _)| *local_only)
        .collect();

    // Get the chip ordering.
    let preprocessed_chip_ordering: HashMap<_, _> = chips_and_preprocessed
        .iter()
        .enumerate()
        .map(|(i, (name, _, _))| (name.to_owned(), i))
        .collect();
    let preprocessed_chip_ordering = Arc::new(preprocessed_chip_ordering);

    let pcs = config.pcs();

    //let (preprocessed_info, domains_and_preprocessed): (Arc<[_]>, Vec<_>) =
    let preprocessed_iter = chips_and_preprocessed.iter().map(|(name, _, trace)| {
        let domain = pcs.natural_domain_for_degree(trace.height());
        (name, trace, domain)
    });
    let preprocessed_info: Arc<
        [(
            String,
            <SC as StarkGenericConfig>::Domain,
            p3_matrix::Dimensions,
        )],
    > = preprocessed_iter
        .clone()
        .map(|(name, trace, domain)| (name.to_owned(), domain, trace.dimensions()))
        .collect();

    let pc_start = program.pc_start();
    let pc_start_kb: &KoalaBear = unsafe { transmute(&pc_start) };
    let initial_global_cumulative_sum: SepticDigest<<SC as StarkGenericConfig>::Val> =
        program.initial_global_cumulative_sum();
    let initial_global_cumulative_sum_kb: &SepticDigest<KoalaBear> =
        unsafe { transmute(&initial_global_cumulative_sum) };

    let preprocessed_trace = chips_and_preprocessed
        .into_iter()
        .map(|t| t.2)
        .collect::<Vec<_>>();

    let start = Instant::now();
    let device_evaluation: Vec<DeviceMatrixConcrete<SC::Val>> = preprocessed_trace
        .iter()
        .map(|e| {
            let e = e.clone().transpose();
            set_device(dev_id as _).unwrap();
            let mut temp = DevicePoolAllocation::<SC::Val>::alloc_from_pool_async(
                e.values.len(),
                mem_pool,
                stream,
            )
            .unwrap();
            memory_copy_async(&mut temp, &e.values, stream).unwrap();
            DeviceMatrixConcrete {
                values: temp,
                log_n: log2_strict_usize(e.width()),
                num_poly: e.height(),
            }
        })
        .collect();

    let mut device_evaluation_kb: Vec<DeviceMatrixConcrete<KoalaBear>> =
        unsafe { transmute(device_evaluation) };

    //
    let (hash_type, log_blow_up) = if TypeId::of::<SC>() == TypeId::of::<KoalaBearPoseidon2>() {
        let two_adic_pcs: &InnerPcs = unsafe { transmute(&pcs) };
        (HashType::Poseidon2KoalaBear, two_adic_pcs.fri.log_blowup)
    } else if TypeId::of::<SC>() == TypeId::of::<KoalaBearBn254Poseidon2>() {
        let two_adic_pcs: &OuterPcs = unsafe { transmute(&pcs) };
        (HashType::Poseidon2Bn254, two_adic_pcs.fri.log_blowup)
    } else {
        panic!("Unexpected SC type")
    };
    //

    //
    let preprocessed_merkle = fri_commit(
        device_evaluation_kb
            .iter_mut()
            .map(|i| (KoalaBear::GENERATOR, i.into_ref()))
            .collect(),
        log_blow_up,
        stream,
        mem_pool,
        hash_type,
    );
    let commit: &Com<SC> = unsafe { transmute(&preprocessed_merkle.merkle_root) };
    println!("setup_keys_gm {:?}", preprocessed_merkle.merkle_root);
    println!(
        "---- ongpu setup_keys_gm data trans & fri commit: {:?}",
        start.elapsed()
    );

    (
        BaseProvingKeyCuda::<SC> {
            commit: commit.clone(),
            pc_start: *pc_start_kb,
            preprocessed_trace: device_evaluation_kb,
            preprocessed_prover_data: preprocessed_merkle,
            preprocessed_chip_ordering: preprocessed_chip_ordering.clone(),
            initial_global_cumulative_sum: *initial_global_cumulative_sum_kb,
            local_only,
        },
        BaseVerifyingKey::<SC> {
            commit: commit.clone(),
            pc_start,
            initial_global_cumulative_sum,
            preprocessed_info,
            preprocessed_chip_ordering,
        },
    )
}
