use crate::{
    configs::config::StarkGenericConfig,
    cuda_adaptor::{
        gpuacc_struct::{
            fri_commit::{LeavesHashType, MerkleTree as GPUMerkleTree},
            matrix::DeviceMatrixRef,
        },
        log2_strict_usize, KoalaBear,
    },
};
use cudart::{
    memory::memory_copy_async,
    memory_pools::{CudaMemPool, DevicePoolAllocation},
    slice::{CudaSlice, CudaSliceMut},
    stream::CudaStream,
};
use cudart_sys::cudaStream_t;
use p3_koala_bear::KoalaBear as Field;
use p3_matrix::{
    dense::{DenseMatrix, RowMajorMatrix},
    Matrix,
};
use std::{
    alloc::{dealloc, Layout},
    collections::HashMap,
    ffi::c_void,
    mem::transmute,
};

//
use crate::cuda_adaptor::gpuacc_struct::{
    matrix::DeviceMatrixConcrete,
    poseidon::{Poseidon2Constants, DIGEST_ELEMS},
};

//
use p3_field::Field as FieldTrait;
use p3_fri::TwoAdicFriPcs;
use p3_symmetric::PaddingFreeSponge;

use p3_commit::{ExtensionMmcs, TwoAdicMultiplicativeCoset};
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_koala_bear::Poseidon2KoalaBear;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::TruncatedPermutation;

const WIDTH: usize = 16;
const RATE: usize = 8;
const HASHTYPE: LeavesHashType = LeavesHashType::Hash16;

type FieldExt4 = BinomialExtensionField<Field, 4>;
pub type Perm = Poseidon2KoalaBear<WIDTH>;
pub type MyHash = PaddingFreeSponge<Perm, WIDTH, RATE, DIGEST_ELEMS>;
pub type MyCompress = TruncatedPermutation<Perm, 2, DIGEST_ELEMS, WIDTH>;
pub type Dft = Radix2DitParallel<Field>;
pub type ValMmcs = MerkleTreeMmcs<
    <Field as FieldTrait>::Packing,
    <Field as FieldTrait>::Packing,
    MyHash,
    MyCompress,
    DIGEST_ELEMS,
>;
type FieldExt4Mmcs = ExtensionMmcs<Field, FieldExt4, ValMmcs>;

//
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

    fn rustffi_memcpy_with_overlapping_u2d(
        dst: *mut c_void,
        src: *const c_void,
        size: usize,
        buffer_host_register_ptr: *mut c_void,
        buffer_len: usize,
    );
}

//
pub fn fri_commit_from_host<SC: StarkGenericConfig>(
    domains_and_traces: Vec<(SC::Domain, DenseMatrix<<SC>::Val>)>,
    pcs: SC::Pcs,
    stream: &'static CudaStream,
    mem_pool: &CudaMemPool,
) -> GPUMerkleTree<'static, Field> {
    let two_adic_pcs: &TwoAdicFriPcs<Field, Dft, ValMmcs, FieldExt4Mmcs> =
        unsafe { transmute(&pcs) };

    assert!(
        std::any::TypeId::of::<SC::Pcs>()
            == std::any::TypeId::of::<TwoAdicFriPcs<Field, Dft, ValMmcs, FieldExt4Mmcs>>()
    );
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

    let (layer_leaves_storage, matrixs_output) = unsafe {
        let ptr = rustffi_coset_lde(
            transmute(matrixs_input_field),
            two_adic_pcs.fri.log_blowup,
            transmute(stream),
            transmute(mem_pool),
        ) as *mut CosetLdeOutput;
        let value: CosetLdeOutput = std::ptr::read(ptr);
        let layout = Layout::new::<CosetLdeOutput>();
        dealloc(ptr as *mut u8, layout);
        (value.layer_leaves_storage, value.matrixs_output)
    };

    use crate::cuda_adaptor::pico_poseidon2kb_init_poseidon2constants;
    let (_, poseidon2_constants) = pico_poseidon2kb_init_poseidon2constants();

    let merkle_result_gpu = GPUMerkleTree::<Field>::new_from_lde(
        layer_leaves_storage,
        matrixs_output,
        stream,
        HASHTYPE,
        &poseidon2_constants,
        &poseidon2_constants,
        mem_pool,
    );    
    merkle_result_gpu
}

pub fn fri_commit_from_device<SC: StarkGenericConfig>(
    matrixs_input: Vec<(Field, DeviceMatrixRef<Field>)>,
    pcs: SC::Pcs,
    stream: &'static CudaStream,
    mem_pool: &CudaMemPool,
) -> GPUMerkleTree<'static, Field> {
    assert!(
        std::any::TypeId::of::<SC::Pcs>()
            == std::any::TypeId::of::<TwoAdicFriPcs<Field, Dft, ValMmcs, FieldExt4Mmcs>>()
    );

    use crate::cuda_adaptor::pico_poseidon2kb_init_poseidon2constants;
    let (_, poseidon2_constants) = pico_poseidon2kb_init_poseidon2constants();

    //
    let two_adic_pcs: &TwoAdicFriPcs<Field, Dft, ValMmcs, FieldExt4Mmcs> =
        unsafe { transmute(&pcs) };
    let log_blow_up = two_adic_pcs.fri.log_blowup;

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
    let merkle_result_gpu = GPUMerkleTree::<Field>::new_from_lde(
        layer_leaves_storage,
        matrixs_output,
        stream,
        LeavesHashType::Hash16,
        &poseidon2_constants,
        &poseidon2_constants,
        mem_pool,
    );
    merkle_result_gpu
}

pub fn fri_commit(
    matrixs_input: Vec<(KoalaBear, DeviceMatrixRef<KoalaBear>)>,
    log_blow_up: usize,
    stream: &'static CudaStream,
    poseidon2_constants: &Poseidon2Constants,
    mem_pool: &CudaMemPool,
) -> GPUMerkleTree<'static, KoalaBear> {
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
    let merkle_result_gpu = GPUMerkleTree::<KoalaBear>::new_from_lde(
        layer_leaves_storage,
        matrixs_output,
        stream,
        LeavesHashType::Hash16,
        poseidon2_constants,
        poseidon2_constants,
        mem_pool,
    );
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
