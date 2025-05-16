use crate::{
    configs::{config::StarkGenericConfig, stark_config::KoalaBearPoseidon2},
    cuda_adaptor::{
        fri_commit::{fri_commit, host2device_fast},
        gpuacc_struct::{fri_commit::MerkleTree as GPUMerkleTree, matrix::DeviceMatrixConcrete},
        pico_poseidon2kb_init_poseidon2constants,
        resource_pool::mem_pool::get_buffer,
        transmute, Field, InnerDigestHash, TwoAdicFriPcsGm,
    },
    emulator::record::RecordBehavior,
    machine::{chip::ChipBehavior, proof::MainTraceCommitments},
};
use cudart::{memory_pools::CudaMemPool, stream::CudaStream};
use hashbrown::HashMap;
use p3_koala_bear::KoalaBear;
use p3_matrix::dense::{DenseMatrix, RowMajorMatrix};
use std::time::Instant;

pub fn commit_main_gpumemory_fast<SC, C>(
    config: &SC,
    record: &C::Record,
    chips_and_main: Vec<(String, RowMajorMatrix<SC::Val>)>,
    stream: &'static CudaStream,
    mem_pool: &CudaMemPool,
    dev_id: usize,
) -> Option<
    MainTraceCommitments<
        KoalaBearPoseidon2,
        Vec<DeviceMatrixConcrete<'static, KoalaBear>>,
        GPUMerkleTree<'static, KoalaBear>,
    >,
>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<SC::Val>,
    C::Record: RecordBehavior,
{
    if chips_and_main.is_empty() {
        return None;
    }
    let start = Instant::now();
    let pcs = config.pcs();

    let two_adic_pcs: &TwoAdicFriPcsGm = unsafe { transmute(&pcs) };
    let log_blow_up = two_adic_pcs.fri.log_blowup;
    let (_, poseidon2_constants) = pico_poseidon2kb_init_poseidon2constants();

    //
    let main_chip_ordering = chips_and_main
        .iter()
        .enumerate()
        .map(|(i, (name, _))| (name.to_owned(), i))
        .collect::<HashMap<_, _>>()
        .into();

    // FAST
    let traces = chips_and_main
        .iter()
        .map(|(_name, trace)| trace)
        .collect::<Vec<_>>();

    let start = Instant::now();
    let mut buffer = get_buffer(dev_id).lock().unwrap();
    let traces_kb: Vec<&DenseMatrix<KoalaBear>> = unsafe { transmute(traces) };
    let mut preprocessed_trace =
        host2device_fast(traces_kb.into_iter(), stream, mem_pool, &mut buffer);
    println!(
        "---- ongpu Commmit main device_evaluation DevicePoolAllocation duration: {:?}",
        start.elapsed()
    );

    let start = Instant::now();
    let main_merkle = fri_commit(
        preprocessed_trace
            .iter_mut()
            .map(|i| (KoalaBear::GENERATOR, i.into_ref()))
            .collect(),
        log_blow_up,
        stream,
        &poseidon2_constants,
        mem_pool,
    );
    println!(
        "---- ongpu Commmit main fri_commit duration: {:?}",
        start.elapsed()
    );
    let commit: InnerDigestHash = main_merkle.merkle_root.into();

    Some(MainTraceCommitments {
        main_traces: preprocessed_trace,
        main_chip_ordering,
        commitment: commit,
        data: main_merkle,
        public_values: record.public_values().into(),
    })
}
