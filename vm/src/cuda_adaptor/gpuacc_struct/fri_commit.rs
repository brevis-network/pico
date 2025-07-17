use crate::cuda_adaptor::gpuacc_struct::{
    matrix::{DeviceMatrixConcrete, DeviceMatrixRef},
    poseidon::{Poseidon2Constants, DIGEST_ELEMS},
};
use cudart::{
    memory::memory_copy,
    memory_pools::{CudaMemPool, DevicePoolAllocation},
    slice::{CudaSlice, CudaSliceMut},
    stream::CudaStream,
};
use cudart_sys::cudaStream_t;
use std::{
    collections::HashMap,
    ffi::c_void,
    fmt::Debug,
    mem::{size_of, transmute},
    usize,
};

extern "C" {
    fn rustffi_hash_matrix_16_8(
        matrix: *const c_void,
        hashs: *mut c_void,
        log_n: u32,
        num_poly: u32,
        hash_stride: u32,
        host_p: *const Poseidon2Constants,
        stream: cudaStream_t,
    );

    fn rustffi_hash_matrix_24_16(
        matrix: *const c_void,
        hashs: *mut c_void,
        log_n: u32,
        num_poly: u32,
        hash_stride: u32,
        host_p: *const Poseidon2Constants,
        stream: cudaStream_t,
    );

    fn rustffi_compress_layer(
        hashs: *mut c_void,
        hash_stride: u32,
        log_next: u32,
        host_p: *const Poseidon2Constants,
        stream: cudaStream_t,
    );

    fn rustffi_inject_layer(
        hashs: *mut c_void,
        hash_stride: u32,
        log_next: u32,
        host_p: *const Poseidon2Constants,
        stream: cudaStream_t,
    );

    fn rustffi_transpose_outplace(
        input: *const c_void,
        output: *mut c_void,
        num_rows: usize,
        num_cols: usize,
        stream: cudaStream_t,
    );

    fn rustffi_pcs_get_evaluations(
        input: *const c_void,
        output: *mut c_void,
        num_poly: u32,
        log_n: u32,
        log_blow_up: u32,
        log_quotient: u32,
        stream: cudaStream_t,
    );

    fn rustffi_hash_matrix_bn254(
        matrix: *const c_void,
        hashs: *mut c_void,
        log_n: u32,
        num_poly: u32,
        hash_stride: u32,
        host_p: *const Poseidon2Constants,
        stream: cudaStream_t,
    );

    fn rustffi_compress_layer_bn254(
        hashs: *mut c_void,
        hash_stride: u32,
        log_next: u32,
        host_p: *const Poseidon2Constants,
        stream: cudaStream_t,
    );

    fn rustffi_inject_layer_bn254(
        hashs: *mut c_void,
        hash_stride: u32,
        log_next: u32,
        host_p: *const Poseidon2Constants,
        stream: cudaStream_t,
    );
}

//
#[derive(Copy, Clone)]
#[repr(C)]
pub enum HashType {
    Poseidon2KoalaBear,
    Poseidon2Bn254,
}

pub fn uninit_vec<T: Sized>(length: usize) -> Vec<T> {
    let mut ret = Vec::with_capacity(length);
    unsafe { ret.set_len(length) };
    ret
}

pub struct MerkleTree<'stream, T: Sized + Debug> {
    pub layer_leaves_storage: HashMap<usize, DevicePoolAllocation<'stream, T>>,
    pub matrixs_ref: Vec<DeviceMatrixRef<T>>,
    pub digests: DevicePoolAllocation<'stream, T>,
    pub merkle_root: [T; DIGEST_ELEMS],
    pub max_log_n: usize,
}
impl<'stream, T: Sized + Debug + Clone + Copy> MerkleTree<'stream, T> {
    pub fn new_from_lde(
        layer_leaves_storage: HashMap<usize, DevicePoolAllocation<'stream, T>>,
        matrixs_ref: Vec<DeviceMatrixRef<T>>,
        stream: &'stream CudaStream,
        hash_type: HashType,
        poseidon2_constants: &Poseidon2Constants,
        mem_pool: &CudaMemPool,
    ) -> Self {
        assert!(size_of::<T>() == size_of::<u32>());
        let max_log_n = *layer_leaves_storage.keys().max().unwrap();
        let hash_stride = 2 << max_log_n;
        let mut digests: DevicePoolAllocation<T> = DevicePoolAllocation::alloc_from_pool_async(
            DIGEST_ELEMS * hash_stride,
            mem_pool,
            stream,
        )
        .unwrap();

        let mut temp_log_n = max_log_n;
        let temp_layer_matrixs = layer_leaves_storage.get(&temp_log_n).unwrap();
        let temp_layer_num_poly = temp_layer_matrixs.len() >> temp_log_n;
        assert_eq!(temp_layer_num_poly << temp_log_n, temp_layer_matrixs.len());
        unsafe {
            let leaves_hasher = match hash_type {
                HashType::Poseidon2KoalaBear => rustffi_hash_matrix_16_8,
                HashType::Poseidon2Bn254 => rustffi_hash_matrix_bn254,
            };
            let compress_hasher = match hash_type {
                HashType::Poseidon2KoalaBear => rustffi_compress_layer,
                HashType::Poseidon2Bn254 => rustffi_compress_layer_bn254,
            };
            let inject_hasher = match hash_type {
                HashType::Poseidon2KoalaBear => rustffi_inject_layer,
                HashType::Poseidon2Bn254 => rustffi_inject_layer_bn254,
            };

            leaves_hasher(
                temp_layer_matrixs.as_c_void_ptr(),
                transmute(digests.as_mut_ptr().offset((1 << temp_log_n) as _)),
                temp_log_n as _,
                temp_layer_num_poly as _,
                hash_stride as _,
                poseidon2_constants,
                stream.into(),
            );

            while temp_log_n != 0 {
                temp_log_n -= 1;
                compress_hasher(
                    digests.as_mut_c_void_ptr(),
                    hash_stride as u32,
                    temp_log_n as u32,
                    poseidon2_constants,
                    stream.into(),
                );

                if let Some(temp_layer_matrixs) = layer_leaves_storage.get(&temp_log_n) {
                    let temp_layer_num_poly = temp_layer_matrixs.len() >> temp_log_n;
                    assert_eq!(temp_layer_num_poly << temp_log_n, temp_layer_matrixs.len());
                    leaves_hasher(
                        temp_layer_matrixs.as_c_void_ptr(),
                        digests.as_mut_c_void_ptr(),
                        temp_log_n as _,
                        temp_layer_num_poly as _,
                        hash_stride as _,
                        poseidon2_constants,
                        stream.into(),
                    );
                    inject_hasher(
                        digests.as_mut_c_void_ptr(),
                        hash_stride as u32,
                        temp_log_n as u32,
                        poseidon2_constants,
                        stream.into(),
                    );
                }
            }
        }
        stream.synchronize().unwrap();
        let mut merkle_root: [T; DIGEST_ELEMS] = uninit_vec(DIGEST_ELEMS).try_into().unwrap();
        for i in 0..DIGEST_ELEMS {
            memory_copy(
                &mut merkle_root[i..(i + 1)],
                &digests[(i * hash_stride + 1)..(i * hash_stride + 2)],
            )
            .unwrap();
        }
        Self {
            layer_leaves_storage,
            matrixs_ref,
            digests,
            merkle_root,
            max_log_n,
        }
    }

    pub fn commit_matrix_ext<ET: Sized + Debug + Clone + Copy, C: CudaSlice<ET> + ?Sized>(
        input: &C,
        log_n: usize,
        stream: &'stream CudaStream,
        hash_type: HashType,
        poseidon2_constants: &Poseidon2Constants,
        mem_pool: &CudaMemPool,
    ) -> Self {
        assert!(size_of::<T>() == size_of::<u32>());
        assert!(size_of::<ET>() == size_of::<[u32; 4]>());
        assert!(1 << log_n == input.len());
        let n = 1 << log_n;
        let half_n = n >> 1;
        let mut layer_leaves_storage =
            DevicePoolAllocation::<T>::alloc_from_pool_async(4 << log_n, mem_pool, stream).unwrap();
        unsafe {
            rustffi_transpose_outplace(
                input.as_c_void_ptr(),
                layer_leaves_storage.as_mut_c_void_ptr(),
                half_n,
                8,
                stream.into(),
            );
        }
        let matrixs_ref = DeviceMatrixRef {
            ptr: layer_leaves_storage.as_mut_ptr(),
            log_n: log_n - 1,
            num_poly: 8,
        };
        let layer_leaves_storage: HashMap<usize, DevicePoolAllocation<T>> =
            HashMap::from_iter(Some((log_n - 1, layer_leaves_storage)));
        Self::new_from_lde(
            layer_leaves_storage,
            vec![matrixs_ref],
            stream,
            hash_type,
            poseidon2_constants,
            mem_pool,
        )
    }

    pub fn get_evaluations(
        &self,
        mat_idx: usize,
        log_n: usize,
        log_quotient: usize,
        stream: &'stream CudaStream,
        mem_pool: &CudaMemPool,
    ) -> DeviceMatrixConcrete<'stream, T> {
        let log_n_quotient = log_n + log_quotient;
        let mat = &self.matrixs_ref[mat_idx];
        let log_blow_up = mat.log_n - log_n;
        assert!(log_blow_up >= log_quotient);
        let mut ret = DeviceMatrixConcrete {
            values: DevicePoolAllocation::<'stream, T>::alloc_from_pool_async(
                mat.num_poly << log_n_quotient,
                mem_pool,
                stream,
            )
            .unwrap(),
            num_poly: mat.num_poly,
            log_n: log_n_quotient,
        };
        unsafe {
            rustffi_pcs_get_evaluations(
                mat.as_c_void_ptr(),
                ret.values.as_mut_c_void_ptr(),
                mat.num_poly as _,
                log_n as _,
                log_blow_up as _,
                log_quotient as _,
                stream.into(),
            );
            stream.synchronize().unwrap();
        }
        ret
    }
}
