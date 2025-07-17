use crate::{
    configs::{
        config::StarkGenericConfig,
        stark_config::{KoalaBearBn254Poseidon2, KoalaBearPoseidon2},
    },
    cuda_adaptor::{
        fri_open::{InnerPcs, OuterPcs},
        gpuacc_struct::{
            fri_commit::{HashType, MerkleTree as GPUMerkleTree},
            matrix::{DeviceMatrixConcrete, DeviceMatrixRef},
        },
        log2_strict_usize,
        poseidon_constant::get_poseidon2_constants,
        KoalaBear,
    },
};
use cudart::{
    memory::memory_copy_async,
    memory_pools::{CudaMemPool, DevicePoolAllocation},
    slice::{CudaSlice, CudaSliceMut},
    stream::CudaStream,
};
use cudart_sys::cudaStream_t;
use p3_commit::TwoAdicMultiplicativeCoset;
use p3_field::Field as FieldTrait;
use p3_koala_bear::KoalaBear as Field;
use p3_matrix::{
    dense::{DenseMatrix, RowMajorMatrix},
    Matrix,
};
use std::{
    alloc::{dealloc, Layout},
    any::TypeId,
    collections::HashMap,
    ffi::c_void,
    mem::transmute,
    time::Instant,
};

pub struct CosetLdeOutput<'stream> {
    pub layer_leaves_storage: HashMap<usize, DevicePoolAllocation<'stream, KoalaBear>>,
    pub matrixs_output: Vec<DeviceMatrixRef<KoalaBear>>,
}
extern "C" {
    fn rustffi_coset_lde(
        matrixs_input: *mut c_void,
        log_blowup: usize,
        stream: *const c_void,
        mem_pool: *const c_void,
    ) -> *mut c_void;

    fn rustffi_transpose_outplace(
        input: *const c_void,
        output: *mut c_void,
        num_rows: usize,
        num_cols: usize,
        stream: cudaStream_t,
    );

    pub fn rustffi_memcpy_with_overlapping_u2d(
        dst: *mut c_void,
        src: *const c_void,
        size: usize,
        buffer_host_register_ptr: *mut c_void,
        buffer_len: usize,
    );
}

//
pub fn fri_commit_from_host<SC: StarkGenericConfig + 'static>(
    domains_and_traces: Vec<(SC::Domain, DenseMatrix<<SC>::Val>)>,
    pcs: SC::Pcs,
    stream: &'static CudaStream,
    mem_pool: &CudaMemPool,
) -> GPUMerkleTree<'static, Field> {
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

    let mut device_evaluation: Vec<DeviceMatrixConcrete<SC::Val>> = domains_and_traces
        .iter()
        .map(|(_, e)| {
            let e = e.clone().transpose();
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

    let matrixs_input: Vec<(Field, DeviceMatrixRef<SC::Val>)> = device_evaluation
        .iter_mut()
        .enumerate()
        .map(|(i, m)| {
            let mydomain: &TwoAdicMultiplicativeCoset<Field> =
                unsafe { transmute(&domains_and_traces[i].0) };
            let shift = Field::GENERATOR / mydomain.shift;
            let m = m.into_ref();
            (shift, m)
        })
        .collect();

    let matrixs_input_field: &Vec<(Field, DeviceMatrixRef<Field>)> =
        unsafe { transmute(&matrixs_input) };

    let merkle_result_gpu = fri_commit(
        matrixs_input_field.clone(),
        log_blow_up,
        stream,
        mem_pool,
        hash_type,
    );
    merkle_result_gpu
}

pub fn fri_commit_from_device<SC: StarkGenericConfig + 'static>(
    matrixs_input: Vec<(Field, DeviceMatrixRef<Field>)>,
    pcs: SC::Pcs,
    stream: &'static CudaStream,
    mem_pool: &CudaMemPool,
) -> GPUMerkleTree<'static, Field> {
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

    let merkle_result_gpu = fri_commit(matrixs_input, log_blow_up, stream, mem_pool, hash_type);
    // println!("by from device: {:?}", merkle_result_gpu.merkle_root);

    merkle_result_gpu
}

pub fn fri_commit(
    matrixs_input: Vec<(KoalaBear, DeviceMatrixRef<KoalaBear>)>,
    log_blow_up: usize,
    stream: &'static CudaStream,
    mem_pool: &CudaMemPool,
    hash_type: HashType,
) -> GPUMerkleTree<'static, KoalaBear> {
    let poseidon2_constants = get_poseidon2_constants(hash_type);

    let start = Instant::now();
    let (layer_leaves_storage, matrixs_output) = unsafe {
        let ptr = rustffi_coset_lde(
            transmute(&matrixs_input),
            log_blow_up,
            transmute(stream),
            transmute(mem_pool),
        ) as *mut CosetLdeOutput;
        let value: CosetLdeOutput = std::ptr::read(ptr);
        let layout = Layout::new::<CosetLdeOutput>();
        dealloc(ptr as *mut u8, layout);
        (value.layer_leaves_storage, value.matrixs_output)
    };
    println!("rustffi_coset_lde duration: {:?}", start.elapsed());

    let start = Instant::now();
    let merkle_result_gpu = GPUMerkleTree::<KoalaBear>::new_from_lde(
        layer_leaves_storage,
        matrixs_output,
        stream,
        hash_type,
        &poseidon2_constants,
        mem_pool,
    );
    println!("new_from_lde duration: {:?}", start.elapsed());
    merkle_result_gpu
}

pub fn host2device_fast<'stream, 'a, I: Iterator<Item = &'a RowMajorMatrix<KoalaBear>>>(
    traces: I,
    stream: &'stream CudaStream,
    mem_pool: &CudaMemPool,
    buffer_host_register: &mut [KoalaBear],
) -> Vec<DeviceMatrixConcrete<'stream, KoalaBear>> {
    let traces: Vec<_> = traces.collect();
    let mut concrete_matrixs: Vec<DeviceMatrixConcrete<'stream, KoalaBear>> = vec![];
    let mut max_matrix_size = 0;
    for trace in traces.clone() {
        max_matrix_size = std::cmp::max(max_matrix_size, trace.values.len());
        let values = DevicePoolAllocation::<KoalaBear>::alloc_from_pool_async(
            trace.values.len(),
            mem_pool,
            stream,
        )
        .unwrap();
        let device_matrix = DeviceMatrixConcrete {
            values,
            log_n: log2_strict_usize(trace.height()),
            num_poly: trace.width(),
        };
        concrete_matrixs.push(device_matrix);
    }
    let mut ping_pong_buffer = [0, 1].map(|_| {
        DevicePoolAllocation::<KoalaBear>::alloc_from_pool_async(max_matrix_size, mem_pool, stream)
            .unwrap()
    });
    stream.synchronize().unwrap();
    unsafe {
        rustffi_memcpy_with_overlapping_u2d(
            ping_pong_buffer[0].as_mut_c_void_ptr(),
            traces[0].values.as_c_void_ptr(),
            traces[0].values.len(),
            buffer_host_register.as_mut_c_void_ptr(),
            buffer_host_register.len(),
        );
    };

    for i in 0..traces.len() {
        let ready_index: usize = i & 0x01;
        unsafe {
            rustffi_transpose_outplace(
                ping_pong_buffer[ready_index].as_c_void_ptr(),
                concrete_matrixs[i].values.as_mut_c_void_ptr(),
                traces[i].height() as _,
                traces[i].width() as _,
                (stream).into(),
            );
        }
        if i < traces.len() - 1 {
            let next_idx = i + 1;
            unsafe {
                rustffi_memcpy_with_overlapping_u2d(
                    ping_pong_buffer[0x01 ^ ready_index].as_mut_c_void_ptr(),
                    traces[next_idx].values.as_c_void_ptr(),
                    traces[next_idx].values.len(),
                    buffer_host_register.as_mut_c_void_ptr(),
                    buffer_host_register.len(),
                );
            };
        }
        stream.synchronize().unwrap();
    }
    concrete_matrixs
}
