use crate::cuda_adaptor::{
    chips_analyzer::host_slice_2_device_vec,
    gpuacc_struct::pico_quotient_2::{
        CalculationCrepr, MatrixVarCrepr, ValueSourceCrepr, ValueSourceExtCrepr,
    },
    h_poly_struct::{Calculation, ValueSource},
};

//
use cudart::slice::{CudaSlice, CudaSliceMut};
use p3_commit::PolynomialSpace;
use p3_field::{
    extension::{BinomialExtensionField, BinomiallyExtendable},
    FieldAlgebra,
};
use p3_koala_bear::KoalaBear;
use std::{any::TypeId, ffi::c_void, mem::transmute, ptr::null};
//

use crate::{
    configs::config::StarkGenericConfig,
    cuda_adaptor::{
        chips_analyzer::{insert, SELECTORS},
        DevicePoolAllocation, TwoAdicMultiplicativeCoset,
    },
    machine::{
        chip::{ChipBehavior, MetaChip},
        folder::ProverConstraintFolder,
        septic::SepticDigest,
    },
};
use cudart::memory_pools::CudaMemPool;
use p3_air::Air;

use cudart::stream::CudaStream;
use std::{time::Instant, usize};

//
use crate::cuda_adaptor::gpuacc_struct::matrix::DeviceMatrixRef;
//

extern "C" {
    fn rustffi_quotient_2(
        log_n: u32,
        log_degree: u32,
        caculations: *const c_void,
        len_caculations: u32,
        value_base: *const c_void,
        value_base_alpha_index: *const u32,
        len_value_base: u32,
        value_ext: *const c_void,
        value_ext_alpha_index: *const u32,
        len_value_ext: u32,
        all_mats: *const c_void,
        is_first_row: *const c_void,
        is_last_row: *const c_void,
        is_transition: *const c_void,
        inv_zeroifier: *const c_void,
        alpha_powers: *const c_void,
        result: *mut c_void,
        cuda_stream: *const c_void,
        mem_pool: *const c_void,
        num_registers: u32,
        itmds_map: *const u32,
    );
}

//

pub fn parse_value<F: BinomiallyExtendable<D> + PartialOrd, const D: usize>(
    v: ValueSource<F>,
) -> ValueSourceCrepr {
    let mut ret: ValueSourceCrepr = Default::default();
    match v {
        ValueSource::MatrixVar(a, b, c) => {
            ret.val_type = 0;
            ret.generic = a as u32;
            ret.poly_index = b as u32;
            ret.offset = c as u32;
        }
        ValueSource::ScalarVar(a) => {
            ret.val_type = 1;
            ret.generic = a as u32;
        }
        ValueSource::ConstsVar(a) => {
            ret.val_type = 2;
            let temp: &u32 = unsafe { transmute(&a) };
            ret.generic = temp.clone();
        }
        ValueSource::IsFirstRow => {
            ret.val_type = 3;
        }
        ValueSource::IsLastRow => {
            ret.val_type = 4;
        }
        ValueSource::IsTransition => {
            ret.val_type = 5;
        }
        ValueSource::Intermediate(a) => {
            ret.val_type = 6;
            ret.generic = a as u32;
        }
    }
    ret
}
pub fn parse_caculation<F: BinomiallyExtendable<D> + PartialOrd, const D: usize>(
    c: Calculation<F>,
) -> CalculationCrepr {
    let mut ret: CalculationCrepr = Default::default();
    match c {
        Calculation::Add(v0, v1) => {
            ret.op = 0;
            ret.v0 = parse_value(v0);
            ret.v1 = parse_value(v1);
        }
        Calculation::Sub(v0, v1) => {
            ret.op = 1;
            ret.v0 = parse_value(v0);
            ret.v1 = parse_value(v1);
        }
        Calculation::Mul(v0, v1) => {
            ret.op = 2;
            ret.v0 = parse_value(v0);
            ret.v1 = parse_value(v1);
        }
        Calculation::Neg(v0) => {
            ret.op = 3;
            ret.v0 = parse_value(v0);
        }
    }
    ret
}

pub fn compute_quotient_values_cuda_gm_2<'stream, SC, C>(
    chip: &MetaChip<SC::Val, C>,
    local_cumulative_sum: &<SC as StarkGenericConfig>::Challenge,
    global_cumulative_sum: &SepticDigest<SC::Val>,
    trace_domain: TwoAdicMultiplicativeCoset<KoalaBear>,
    quotient_domain: TwoAdicMultiplicativeCoset<KoalaBear>,
    prep: Option<DeviceMatrixRef<KoalaBear>>,
    mut main: DeviceMatrixRef<KoalaBear>,
    mut perm: DeviceMatrixRef<KoalaBear>,
    perm_challenges: &[<SC as StarkGenericConfig>::Challenge; 2],
    alpha: <SC as StarkGenericConfig>::Challenge,
    public_values: &[KoalaBear],
    cuda_stream: &'stream CudaStream,
    mem_pool: &CudaMemPool,
    dev_id: usize,
) -> DevicePoolAllocation<'stream, KoalaBear>
where
    SC: StarkGenericConfig,
    C: Air<ProverConstraintFolder<SC>> + ChipBehavior<SC::Val>,
    // + Air<folder::ProverConstraintFolder<KoalaBearPoseidon2>>
    // + ChipBehavior<KoalaBear>
    // + Air<SymbolicAirBuilder<KoalaBear, 4>>,
{
    assert!(perm_challenges.len() == 2);
    let log_n = trace_domain.log_n;
    let log_quotient = quotient_domain.log_n;
    let log_degree = log_quotient - log_n;
    let quotient_size = quotient_domain.size();
    let trace_size = trace_domain.size();

    insert(trace_size, quotient_size, dev_id);
    let mut selectors_map = SELECTORS
        .get()
        .unwrap()
        .get(dev_id)
        .unwrap()
        .lock()
        .unwrap();
    let selector = selectors_map.get_mut(&(trace_size, quotient_size)).unwrap();
    let is_first_row = &mut selector.is_first_row;
    let is_last_row = &mut selector.is_last_row;
    let is_transition = &mut selector.is_transition;
    let inv_zeroifier = &mut selector.inv_zeroifier;

    //
    // let num_polys = vec![
    //     prep.map(|i| i.num_poly).unwrap_or(0),
    //     main.num_poly,
    //     perm.num_poly,
    // ];
    // use crate::cuda_adaptor::chips_analyzer::insert_air_data;
    // let chip_kb: &MetaChip<KoalaBear, _> = unsafe { transmute(&chip) };
    // insert_air_data::<C>(chip_kb, num_polys);

    let chip_instruction_map = crate::cuda_adaptor::chips_analyzer::CHIPS_INSTRUCTIONS
        .lock()
        .unwrap();
    let chip_instruction = chip_instruction_map.get(&chip.name()).unwrap();

    //
    let perm_challenges_kb: &[BinomialExtensionField<KoalaBear, 4>; 2] =
        unsafe { transmute(perm_challenges) };
    let local_cumulative_sum_kb: &BinomialExtensionField<KoalaBear, 4> =
        unsafe { transmute(local_cumulative_sum) };
    let global_cumulative_sum_kb: &SepticDigest<KoalaBear> =
        unsafe { transmute(global_cumulative_sum) };

    let mut public_values = public_values.to_vec();
    public_values.resize(207, KoalaBear::ZERO);
    let scalars = crate::cuda_adaptor::h_poly_struct::prepare_scalars(
        &public_values,
        perm_challenges_kb,
        local_cumulative_sum_kb.clone(),
        global_cumulative_sum_kb.clone(),
    );
    let (all_caculations, value_base, value_ext) =
        crate::cuda_adaptor::h_poly_struct::compute_scalar(
            &chip_instruction.all_caculations,
            &chip_instruction.value_base,
            &chip_instruction.value_ext,
            &scalars,
        );
    let (num_registers, itmds_map, all_caculations, value_base, value_ext) =
        crate::cuda_adaptor::h_poly_struct::reduce_register(
            &all_caculations,
            &value_base,
            &value_ext,
        );
    let itmds_map: Vec<u32> = itmds_map.into_iter().map(|i| i as u32).collect();
    let itmds_map = host_slice_2_device_vec(&itmds_map);

    let all_caculations: Vec<CalculationCrepr> =
        all_caculations.into_iter().map(parse_caculation).collect();
    let all_caculations = host_slice_2_device_vec(&all_caculations);

    let value_base_alpha_index: Vec<u32> = value_base.iter().map(|v| v.0 as u32).collect();
    let value_base_alpha_index = host_slice_2_device_vec(&value_base_alpha_index);
    let value_base: Vec<ValueSourceCrepr> =
        value_base.into_iter().map(|v| parse_value(v.1)).collect();
    let value_base = host_slice_2_device_vec(&value_base);

    let value_ext_alpha_index: Vec<u32> = value_ext.iter().map(|v| v.0 as u32).collect();
    let value_ext_alpha_index = host_slice_2_device_vec(&value_ext_alpha_index);
    let value_ext: Vec<ValueSourceExtCrepr> = value_ext
        .into_iter()
        .map(|v| {
            let temp = v.1.map(parse_value);
            let temp: &[ValueSourceCrepr; 4] = unsafe { transmute(&temp) };
            ValueSourceExtCrepr { bases: *temp }
        })
        .collect();
    let value_ext = host_slice_2_device_vec(&value_ext);

    let all_mats: Vec<MatrixVarCrepr> = vec![
        MatrixVarCrepr {
            ptr: prep
                .map(|i| i.ptr.cast::<c_void>() as *const c_void)
                .unwrap_or(null()),
            num_poly: prep.map(|i| i.num_poly as u64).unwrap_or(0),
        },
        MatrixVarCrepr {
            ptr: main.ptr.cast::<c_void>() as *const c_void,
            num_poly: main.num_poly as u64,
        },
        MatrixVarCrepr {
            ptr: perm.ptr.cast::<c_void>() as *const c_void,
            num_poly: perm.num_poly as u64,
        },
    ];
    let all_mats = host_slice_2_device_vec(&all_mats);

    //
    // alpha pows: D * (max_alpha_pow + 1)
    let abstract_field_map = super::chips_analyzer::CHIPS_MAX_ALPHA_POW.lock().unwrap();
    let Some(max_alpha_pow) = abstract_field_map.get(&chip.name()) else {
        todo!("get max_alpha_pow failed, airchip empty")
    };
    let mut powers_of_alpha = alpha.powers().take(max_alpha_pow + 1).collect::<Vec<_>>();
    powers_of_alpha.reverse();
    let alpha_powers = host_slice_2_device_vec(&powers_of_alpha);

    //
    let mut gpu_result = DevicePoolAllocation::<KoalaBear>::alloc_from_pool_async(
        (1 << log_quotient) * 4,
        mem_pool,
        cuda_stream,
    )
    .unwrap();
    unsafe {
        rustffi_quotient_2(
            log_n as _,
            log_degree as _,
            all_caculations.as_c_void_ptr(),
            all_caculations.len() as _,
            value_base.as_c_void_ptr(),
            value_base_alpha_index.as_ptr(),
            value_base.len() as _,
            value_ext.as_c_void_ptr(),
            value_ext_alpha_index.as_ptr(),
            value_ext.len() as _,
            all_mats.as_c_void_ptr(),
            is_first_row.as_c_void_ptr(),
            is_last_row.as_c_void_ptr(),
            is_transition.as_c_void_ptr(),
            inv_zeroifier.as_c_void_ptr(),
            alpha_powers.as_c_void_ptr(),
            gpu_result.as_mut_c_void_ptr(),
            transmute(cuda_stream),
            transmute(mem_pool),
            num_registers as u32,
            itmds_map.as_ptr(),
        );
    }
    gpu_result
}
