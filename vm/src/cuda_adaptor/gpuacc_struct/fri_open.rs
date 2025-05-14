use std::ffi::c_void;
use std::fmt::Debug;
use crate::cuda_adaptor::LeavesHashType;
use crate::cuda_adaptor::Poseidon2Constants;
use crate::cuda_adaptor::DIGEST_ELEMS;

#[derive(Clone)]
pub struct FriData<
    'a,
    T: Sized + Debug + Clone + Copy,
    ET: Sized + Debug + Clone + Copy,
    Challenger,
> {
    pub sample: fn(&mut Challenger) -> ET,
    pub observe: fn(&mut Challenger, &[T]),
    pub check_witness: fn(&mut Challenger, usize, T) -> bool,
    pub sample_bits: fn(&mut Challenger, usize) -> usize,
    pub get_pow_data: fn(&Challenger) -> Option<(*const c_void, *const c_void, usize)>, // state_ptr, input_ptr, input_length
    pub pow_hash_type: LeavesHashType,
    pub poseidon2_constants_pow: &'a Poseidon2Constants,
    pub grind: fn(&mut Challenger, usize) -> T,
    pub proof_of_work_bits: usize,
    pub compute_host_scale: fn(ET, usize) -> ET,
    pub exp_u64: fn(ET, u64) -> ET,
    pub generator: T,
    pub log_blow_up: usize,
    pub leave_hash_type: LeavesHashType,
    pub poseidon2_constants_leaves: &'a Poseidon2Constants,
    pub poseidon2_constants_compress: &'a Poseidon2Constants,
    pub one_half: T,
    pub compute_half_beta: fn(ET) -> ET,
    pub num_queries: usize,
    pub as_base_slice: fn(&ET) -> &[T],
}
#[derive(Debug, Clone)]
pub struct OpenProof<T: Sized + Debug + Clone + Copy, ET: Sized + Debug + Clone + Copy> {
    pub all_opened_values: Vec<Vec<Vec<Vec<ET>>>>,
    pub commit_phase_commits: Vec<[T; DIGEST_ELEMS]>,
    pub final_poly: ET,
    pub pow_witness: T,
    pub input_proof_values: Vec<Vec<Vec<Vec<T>>>>,
    pub input_proof_paths: Vec<Vec<Vec<[T; DIGEST_ELEMS]>>>,
    pub commit_phase_sibling: Vec<Vec<ET>>,
    pub commit_phase_paths: Vec<Vec<Vec<[T; DIGEST_ELEMS]>>>,
}