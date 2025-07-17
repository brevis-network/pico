pub mod chips_analyzer;
pub mod commit_main_gm;
pub mod fri_commit;
pub mod fri_open;
pub mod permutation_cuda;
pub mod poseidon_constant;
pub mod quotient;
pub mod quotient_2;
pub mod setup_keys_gm;

pub mod gpuacc_struct;
pub mod h_poly_struct;
pub mod resource_pool;

use crate::{
    compiler::program::ProgramBehavior,
    configs::config::StarkGenericConfig,
    cuda_adaptor::fri_open::{InnerChallenge, InnerChallenger, InnerVal},
    machine::{
        chip::{ChipBehavior, MetaChip},
        keys::BaseVerifyingKey,
        prover::BaseProver,
        septic::SepticDigest,
    },
};
use cudart::{
    memory::memory_copy_async,
    memory_pools::{CudaMemPool, DevicePoolAllocation},
};

use hashbrown::HashMap;
use p3_challenger::DuplexChallenger;
use p3_commit::{
    ExtensionMmcs, LagrangeSelectors, Pcs, PolynomialSpace, TwoAdicMultiplicativeCoset,
};
use p3_dft::Radix2DitParallel;
use p3_field::{extension::BinomialExtensionField, Field, FieldAlgebra};
use p3_fri::{BatchOpening, FriProof, TwoAdicFriPcs};
use p3_koala_bear::{KoalaBear, Poseidon2KoalaBear};
use p3_matrix::Matrix;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{Hash, PaddingFreeSponge, TruncatedPermutation};
use p3_util::log2_strict_usize;
use std::{mem::transmute, sync::Arc};

//
use gpuacc_struct::{
    fri_commit::MerkleTree as GPUMerkleTree,
    poseidon::{Poseidon2Constants, DIGEST_ELEMS},
};

// check layout
//
use cudart::stream::CudaStream;
use std::{
    alloc::{alloc, dealloc, handle_alloc_error, Layout},
    ffi::c_void,
    mem::offset_of,
};

pub fn assert_vec_layout<T>() {
    unsafe {
        assert!(size_of::<Vec<T>>() == 24);
        assert!(align_of::<Vec<T>>() == 8);
        let capacity: usize = rand::random::<usize>() % 10000usize;
        let len: usize = rand::random::<usize>() % capacity;
        let layout = Layout::array::<T>(capacity).unwrap();
        let ptr = alloc(layout) as *mut T;
        if ptr.is_null() {
            handle_alloc_error(layout);
        }
        let temp_vec = Vec::<T>::from_raw_parts(ptr, len, capacity);
        let temp_vec: [usize; 3] = transmute(temp_vec);
        assert_eq!(temp_vec[0], capacity);
        assert_eq!(temp_vec[1], ptr as usize);
        assert_eq!(temp_vec[2], len);
        dealloc(ptr as *mut u8, layout);
    }
}

type Val = InnerVal;
type Challenge = InnerChallenge;
type Challenger = InnerChallenger;
use crate::cuda_adaptor::{
    fri_commit::CosetLdeOutput,
    gpuacc_struct::{
        fri_open::{FriData, OpenProof},
        matrix::{DeviceMatrixConcrete, DeviceMatrixRef, DeviceMatrixStatic},
        pico_permutation::CudaDeviceSlice,
        pico_quotient_2::{
            CalculationCrepr, MatrixVarCrepr, ValueSourceCrepr, ValueSourceExtCrepr,
        },
    },
};

fn check_layout() {
    assert!(align_of::<usize>() == 8);
    assert!(size_of::<usize>() == 8);
    assert!(align_of::<*const c_void>() == 8);
    assert!(size_of::<*const c_void>() == 8);
    assert!(align_of::<*const Val>() == 8);
    assert!(size_of::<*const Val>() == 8);
    assert!(align_of::<*mut Val>() == 8);
    assert!(size_of::<*mut Val>() == 8);
    assert!(align_of::<CudaStream>() == 8);
    assert!(size_of::<CudaStream>() == 8);
    assert!(align_of::<CudaMemPool>() == 8);
    assert!(size_of::<CudaMemPool>() == 8);
    assert!(align_of::<&'static CudaStream>() == 8);
    assert!(size_of::<&'static CudaStream>() == 8);
    assert!(align_of::<Val>() == 4);
    assert!(size_of::<Val>() == 4);
    assert!(align_of::<Challenge>() == 4);
    assert!(size_of::<Challenge>() == 16);
    assert!(align_of::<[Val; DIGEST_ELEMS]>() == 4);
    assert!(size_of::<[Val; DIGEST_ELEMS]>() == 32);

    // Challenger
    assert!(align_of::<Challenger>() == 8);
    assert!(size_of::<Challenger>() == 184);
    assert!(offset_of!(Challenger, sponge_state) == 120);
    assert!(offset_of!(Challenger, input_buffer) == 0);
    assert!(offset_of!(Challenger, output_buffer) == 24);
    assert!(offset_of!(Challenger, permutation) == 48);
    assert_vec_layout::<Val>();

    // Poseidon2Constants
    assert!(align_of::<Poseidon2Constants>() == 8);
    assert!(size_of::<Poseidon2Constants>() == 24);
    assert!(offset_of!(Poseidon2Constants, rounds_f) == 0);
    assert!(offset_of!(Poseidon2Constants, rounds_p) == 4);
    assert!(offset_of!(Poseidon2Constants, external_round_constants) == 8);
    assert!(offset_of!(Poseidon2Constants, internal_round_constants) == 16);

    // CudaDeviceSlice
    assert!(align_of::<CudaDeviceSlice<Val>>() == 8);
    assert!(size_of::<CudaDeviceSlice<Val>>() == 16);
    assert!(offset_of!(CudaDeviceSlice<Val>, ptr) == 0);
    assert!(offset_of!(CudaDeviceSlice<Val>, length) == 8);

    // DeviceMatrixConcrete
    assert!(align_of::<DeviceMatrixConcrete<Val>>() == 8);
    assert!(size_of::<DeviceMatrixConcrete<Val>>() == 40);
    assert!(offset_of!(DeviceMatrixConcrete<Val>, values) == 0);
    assert!(offset_of!(DeviceMatrixConcrete<Val>, log_n) == 24);
    assert!(offset_of!(DeviceMatrixConcrete<Val>, num_poly) == 32);
    assert_vec_layout::<DeviceMatrixConcrete<Val>>();

    // DeviceMatrixRef
    assert!(align_of::<DeviceMatrixRef<Val>>() == 8);
    assert!(size_of::<DeviceMatrixRef<Val>>() == 24);
    assert!(offset_of!(DeviceMatrixRef<Val>, ptr) == 0);
    assert!(offset_of!(DeviceMatrixRef<Val>, log_n) == 8);
    assert!(offset_of!(DeviceMatrixRef<Val>, num_poly) == 16);
    assert_vec_layout::<DeviceMatrixRef<Val>>();

    // DeviceMatrixStatic
    assert!(align_of::<DeviceMatrixStatic<Val>>() == 8);
    assert!(size_of::<DeviceMatrixStatic<Val>>() == 32);
    assert!(offset_of!(DeviceMatrixStatic<Val>, values) == 0);
    assert!(offset_of!(DeviceMatrixStatic<Val>, log_n) == 16);
    assert!(offset_of!(DeviceMatrixStatic<Val>, num_poly) == 24);
    assert_vec_layout::<DeviceMatrixStatic<Val>>();

    // CosetLdeOutput
    assert!(align_of::<CosetLdeOutput>() == 8);
    assert!(size_of::<CosetLdeOutput>() == 72);
    assert!(offset_of!(CosetLdeOutput, layer_leaves_storage) == 24);
    assert!(offset_of!(CosetLdeOutput, matrixs_output) == 0);

    // // FriData
    // assert!(align_of::<FriData<Val, Challenge, Challenger>>() == 8);
    // assert!(size_of::<FriData<Val, Challenge, Challenger>>() == 144);
    // assert!(offset_of!(FriData<Val, Challenge, Challenger>, sample) == 24);
    // assert!(offset_of!(FriData<Val, Challenge, Challenger>, observe) == 32);
    // assert!(offset_of!(FriData<Val, Challenge, Challenger>, check_witness) == 40);
    // assert!(offset_of!(FriData<Val, Challenge, Challenger>, sample_bits) == 48);
    // assert!(offset_of!(FriData<Val, Challenge, Challenger>, get_pow_data) == 56);
    // assert!(offset_of!(FriData<Val, Challenge, Challenger>, pow_hash_type) == 136);
    // assert!(offset_of!(FriData<Val, Challenge, Challenger>, poseidon2_constants_pow) == 64);
    // assert!(offset_of!(FriData<Val, Challenge, Challenger>, grind) == 72);
    // assert!(offset_of!(FriData<Val, Challenge, Challenger>, proof_of_work_bits) == 0);
    // assert!(offset_of!(FriData<Val, Challenge, Challenger>, compute_host_scale) == 80);
    // assert!(offset_of!(FriData<Val, Challenge, Challenger>, exp_u64) == 88);
    // assert!(offset_of!(FriData<Val, Challenge, Challenger>, generator) == 128);
    // assert!(offset_of!(FriData<Val, Challenge, Challenger>, log_blow_up) == 8);
    // assert!(offset_of!(FriData<Val, Challenge, Challenger>, leave_hash_type) == 137);
    // assert!(offset_of!(FriData<Val, Challenge, Challenger>, poseidon2_constants_leaves) == 96);
    // assert!(offset_of!(FriData<Val, Challenge, Challenger>, poseidon2_constants_compress) == 104);
    // assert!(offset_of!(FriData<Val, Challenge, Challenger>, one_half) == 132);
    // assert!(offset_of!(FriData<Val, Challenge, Challenger>, compute_half_beta) == 112);
    // assert!(offset_of!(FriData<Val, Challenge, Challenger>, num_queries) == 16);
    // assert!(offset_of!(FriData<Val, Challenge, Challenger>, as_base_slice) ==120);

    // OpenProof
    assert!(align_of::<OpenProof<Val, Challenge>>() == 8);
    assert!(size_of::<OpenProof<Val, Challenge>>() == 168);
    assert!(offset_of!(OpenProof<Val, Challenge>, all_opened_values) == 0);
    assert!(offset_of!(OpenProof<Val, Challenge>, commit_phase_commits) == 24);
    assert!(offset_of!(OpenProof<Val, Challenge>, final_poly) == 144);
    assert!(offset_of!(OpenProof<Val, Challenge>, pow_witness) == 160);
    assert!(offset_of!(OpenProof<Val, Challenge>, input_proof_values) == 48);
    assert!(offset_of!(OpenProof<Val, Challenge>, input_proof_paths) == 72);
    assert!(offset_of!(OpenProof<Val, Challenge>, commit_phase_sibling) == 96);
    assert!(offset_of!(OpenProof<Val, Challenge>, commit_phase_paths) == 120);

    // ValueSourceCrepr
    assert!(align_of::<ValueSourceCrepr>() == 4);
    assert!(size_of::<ValueSourceCrepr>() == 16);
    assert!(offset_of!(ValueSourceCrepr, val_type) == 0);
    assert!(offset_of!(ValueSourceCrepr, generic) == 4);
    assert!(offset_of!(ValueSourceCrepr, poly_index) == 8);
    assert!(offset_of!(ValueSourceCrepr, offset) == 12);

    // ValueSourceExtCrepr
    assert!(align_of::<ValueSourceExtCrepr>() == 4);
    assert!(size_of::<ValueSourceExtCrepr>() == 64);
    assert!(offset_of!(ValueSourceExtCrepr, bases) == 0);

    // CalculationCrepr
    assert!(align_of::<CalculationCrepr>() == 4);
    assert!(size_of::<CalculationCrepr>() == 36);
    assert!(offset_of!(CalculationCrepr, op) == 0);
    assert!(offset_of!(CalculationCrepr, v0) == 4);
    assert!(offset_of!(CalculationCrepr, v1) == 20);

    // MatrixVarCrepr
    assert!(align_of::<MatrixVarCrepr>() == 8);
    assert!(size_of::<MatrixVarCrepr>() == 16);
    assert!(offset_of!(MatrixVarCrepr, ptr) == 0);
    assert!(offset_of!(MatrixVarCrepr, num_poly) == 8);
}

#[test]
// cargo test --release --package pico-vm --lib -- cuda_adaptor::test_layout --exact --show-output
fn test_layout() {
    check_layout();
}
