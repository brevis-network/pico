use crate::{
    configs::config::StarkGenericConfig,
    cuda_adaptor::{
        chips_analyzer::{insert, SELECTORS},
        DevicePoolAllocation,
        TwoAdicMultiplicativeCoset,
    },
    machine::{
        chip::{ChipBehavior, MetaChip},
        folder::ProverConstraintFolder,
        septic::SepticDigest,
    },
};
use cudart::{memory_pools::CudaMemPool, slice::CudaSliceMut};
use p3_air::Air;
use p3_commit::PolynomialSpace;
use p3_field::{FieldAlgebra, FieldExtensionAlgebra};
use p3_koala_bear::KoalaBear;
use std::mem::transmute;

use std::{ffi::c_void, usize};
use cudart_sys::cudaStream_t;
use cudart::stream::CudaStream;

//
use crate::cuda_adaptor::gpuacc_struct::matrix::DeviceMatrixRef;
use crate::cuda_adaptor::chips_analyzer::host_slice_2_device_vec;

//
extern "C" {
    fn rustffi_pico_quotient_values_cuda(
        threads_per_block: usize,
        blocks_num: usize,
        quotient_size: usize,
        ext_degree: usize,
        d_is_f_row_slice: *mut c_void,
        d_is_l_row_slice: *mut c_void,
        d_is_t_row_slice: *mut c_void,
        d_invz_row_slice: *mut c_void,
        public_values_len: usize,
        d_pub_value_slice: *mut c_void,
        max_perm_challenge_pow: usize,
        d_perm_challenge_slice: *mut c_void,
        d_local_cumulative_sum_slice: *mut c_void,
        d_global_cumulative_sum_slice: *mut c_void,
        prep_width: usize,
        d_prep_trace_slice: *mut c_void,
        main_width: usize,
        d_main_trace_slice: *mut c_void,
        perm_width: usize,
        d_perm_trace_slice: *mut c_void,
        alpha_pow_len: usize,
        d_alpha_pows_slice: *mut c_void,
        inst_len: usize,
        d_gpu_vec_inst_slice: *mut usize,
        d_reg: *mut c_void,
        d_res: *mut c_void,
        stream: cudaStream_t,
    );
}

#[allow(clippy::needless_pass_by_value)]
#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_lines)]
#[allow(clippy::needless_range_loop)]
#[allow(clippy::print_stdout)]
pub fn compute_quotient_values_cuda_gm<'stream, SC, C>(
    chip: &MetaChip<SC::Val, C>,
    local_cumulative_sum: &<SC as StarkGenericConfig>::Challenge,
    global_cumulative_sum: &SepticDigest<SC::Val>,
    trace_domain: TwoAdicMultiplicativeCoset<KoalaBear>,
    quotient_domain: TwoAdicMultiplicativeCoset<KoalaBear>,
    preprocessed_trace_on_quotient_domain: Option<DeviceMatrixRef<KoalaBear>>,
    mut main_trace_on_quotient_domain: DeviceMatrixRef<KoalaBear>,
    mut permutation_trace_on_quotient_domain: DeviceMatrixRef<KoalaBear>,
    perm_challenges: &[<SC as StarkGenericConfig>::Challenge; 2],
    alpha: <SC as StarkGenericConfig>::Challenge,
    public_values: &[KoalaBear],
    stream: &'stream CudaStream,
    mem_pool: &CudaMemPool,
    dev_id: usize,
) -> DevicePoolAllocation<'stream, KoalaBear>
where
    SC: StarkGenericConfig,
    C: Air<ProverConstraintFolder<SC>> + ChipBehavior<SC::Val>,
{
    // println!("XXX: {:?}", cudart::device::get_device());
    // println!("quotient chip name: {:?}", chip.name());
    let prep_width = preprocessed_trace_on_quotient_domain
        .as_ref()
        .map_or(1, |i| i.num_poly());
    let main_width = main_trace_on_quotient_domain.num_poly();
    let perm_width = permutation_trace_on_quotient_domain.num_poly();
    let quotient_size = quotient_domain.size();
    let trace_size = trace_domain.size();
    const EXT_DEGREE: usize = 4;
    assert_eq!(
        EXT_DEGREE,
        <<SC as StarkGenericConfig>::Challenge as FieldExtensionAlgebra<SC::Val>>::D
    );
    insert(trace_size, quotient_size, dev_id);
    let mut selectors_map = SELECTORS.get().unwrap().get(dev_id).unwrap().lock().unwrap();
    let selector = selectors_map.get_mut(&(trace_size, quotient_size)).unwrap();
    let is_f_row = &mut selector.is_first_row;
    let is_l_row = &mut selector.is_last_row;
    let is_t_row = &mut selector.is_transition;
    let invz_row = &mut selector.inv_zeroifier;

    // gpu_vec_inst
    let abstract_field_map = super::chips_analyzer::CHIPS_GPU_OP_VEC_KB.lock().unwrap();
    let Some(gpu_vec_inst) = abstract_field_map.get(&chip.name()) else {
        todo!("airchip empty: {:?}", chip.name());
    };
    let inst_len = gpu_vec_inst.len() / 10;
    let mut gpu_vec_inst_gm = host_slice_2_device_vec(gpu_vec_inst);

    // alpha
    //
    // alpha pows: D * (max_alpha_pow + 1)
    let abstract_field_map = super::chips_analyzer::CHIPS_MAX_ALPHA_POW.lock().unwrap();
    let Some(max_alpha_pow) = abstract_field_map.get(&chip.name()) else {
        todo!("max_alpha_pow airchip empty: {:?}", chip.name())
    };
    let powers_of_alpha = alpha.powers().take(max_alpha_pow + 1).collect::<Vec<_>>();
    let mut powers_of_alpha_clone: Vec<<SC>::Val> = Vec::new();
    for i in 0..(max_alpha_pow + 1) {
        powers_of_alpha_clone.extend(powers_of_alpha[i].as_base_slice().to_vec());
    }
    let alpha_pow_len = powers_of_alpha_clone.len();
    let mut powers_of_alpha = host_slice_2_device_vec(&powers_of_alpha_clone);

    //
    let abstract_field_map = super::chips_analyzer::CHIPS_MAX_PERM_CHALLENGE_POW
        .lock()
        .unwrap();
    let Some(max_perm_challenge_pow) = abstract_field_map.get(&chip.name()) else {
        todo!("airchip empty")
    };

    //
    let prep_trace_default = vec![KoalaBear::ZERO; quotient_size];
    let mut prep_trace_default = host_slice_2_device_vec(&prep_trace_default);

    let mut perm_challenges_clone: Vec<SC::Val> = perm_challenges[0].as_base_slice().to_vec();
    let perm_challenge_1_pow = perm_challenges[1]
        .powers()
        .take(max_perm_challenge_pow + 1)
        .map(|f| f.as_base_slice().to_vec())
        .collect::<Vec<Vec<SC::Val>>>();
    for i in 1..perm_challenge_1_pow.len() {
        perm_challenges_clone.extend(perm_challenge_1_pow[i].clone());
    }
    let perm_challenges_clone_kb: Vec<KoalaBear> = unsafe { transmute(perm_challenges_clone) };
    let mut perm_challenges = host_slice_2_device_vec(&perm_challenges_clone_kb);

    //
    let local_sum: Vec<SC::Val> = local_cumulative_sum.as_base_slice().to_vec();
    let local_sum_kb: Vec<KoalaBear> = unsafe { transmute(local_sum) };
    let mut local_sum = host_slice_2_device_vec(&local_sum_kb);

    //
    let mut global_cumulative_sum_clone: Vec<SC::Val> = global_cumulative_sum.0.x.0.to_vec();
    global_cumulative_sum_clone.extend(global_cumulative_sum.0.y.0.to_vec());
    let global_cumulative_sum_clone_kb: Vec<KoalaBear> =
        unsafe { transmute(global_cumulative_sum_clone) };
    let mut global_sum = host_slice_2_device_vec(&global_cumulative_sum_clone_kb);

    //
    let mut public_value = host_slice_2_device_vec(&public_values);
    let threads_per_block = 1024;
    let blocks_num = 82;
    let mut d_reg = DevicePoolAllocation::<KoalaBear>::alloc_from_pool_async(
        threads_per_block * blocks_num * 1024,
        mem_pool,
        stream,
    )
    .unwrap();

    // println!("{:?}", cudart::memory::memory_get_info());
    // println!("quotient dres size: {:?}", quotient_size * EXT_DEGREE);
    let mut d_res = DevicePoolAllocation::<KoalaBear>::alloc_from_pool_async(
        quotient_size * EXT_DEGREE,
        mem_pool,
        stream,
    )
    .unwrap();
    unsafe {
        rustffi_pico_quotient_values_cuda(
            threads_per_block,
            blocks_num,
            quotient_size,
            EXT_DEGREE,
            is_f_row.as_mut_c_void_ptr(),
            is_l_row.as_mut_c_void_ptr(),
            is_t_row.as_mut_c_void_ptr(),
            invz_row.as_mut_c_void_ptr(),
            public_value.len(),
            public_value.as_mut_c_void_ptr(),
            *max_perm_challenge_pow,
            perm_challenges.as_mut_c_void_ptr(),
            local_sum.as_mut_c_void_ptr(),
            global_sum.as_mut_c_void_ptr(),
            prep_width,
            preprocessed_trace_on_quotient_domain
                .map(|mut i| i.as_mut_c_void_ptr())
                .unwrap_or(prep_trace_default.as_mut_c_void_ptr()),
            main_width,
            main_trace_on_quotient_domain.as_mut_c_void_ptr(),
            perm_width,
            permutation_trace_on_quotient_domain.as_mut_c_void_ptr(),
            alpha_pow_len,
            powers_of_alpha.as_mut_c_void_ptr(),
            inst_len,
            gpu_vec_inst_gm.as_mut_ptr(),
            d_reg.as_mut_c_void_ptr(),
            d_res.as_mut_c_void_ptr(),
            stream.into(),
        );
        d_res
    }
}
