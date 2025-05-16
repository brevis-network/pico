use crate::machine::{
    chip::{ChipBehavior, MetaChip},
    lookup::{LookupScope, VirtualPairLookup},
    permutation::get_grouped_maps,
    septic::{SepticCurve, SepticDigest, SepticExtension},
};
use cudart::memory::{memory_copy, DeviceAllocation};
use p3_air::PairCol as OriginPairCol;
use p3_field::{
    extension::BinomialExtensionField, ExtensionField, Field, FieldAlgebra, FieldExtensionAlgebra,
};
use p3_koala_bear::KoalaBear;
use std::{any::TypeId, ffi::c_void, mem::transmute, ptr::null};
type InnerVal = KoalaBear;
pub type InnerChallenge = BinomialExtensionField<InnerVal, 4>;
use cudart::{
    slice::{CudaSlice, CudaSliceMut},
    stream::CudaStream,
};
use cudart_sys::cudaStream_t;

//
use crate::cuda_adaptor::{
    chips_analyzer::host_slice_2_device_vec,
    gpuacc_struct::{
        matrix::{DeviceMatrixConcrete, DeviceMatrixStatic},
        pico_permutation::CudaDeviceSlice,
    },
};

#[repr(C)]
pub struct PairCol {
    poly_index: u32,
    weight: InnerVal,
}
#[repr(C)]
pub struct VirtualPairCol {
    column_weights: CudaDeviceSlice<PairCol>,
    constant: InnerVal,
}
#[repr(C)]
pub struct Interaction {
    argument_index: InnerVal,
    values: CudaDeviceSlice<VirtualPairCol>,
    multiplicity: VirtualPairCol,
    is_send: bool,
}
pub type InteractionBatch = CudaDeviceSlice<Interaction>;
pub type AllInteraction = CudaDeviceSlice<InteractionBatch>;

pub fn convert_pair_col(a: &OriginPairCol, weight: &InnerVal) -> PairCol {
    let poly_index = match a {
        OriginPairCol::Preprocessed(i) => *i as u32 | 0x80000000u32,
        OriginPairCol::Main(i) => *i as u32,
    };
    PairCol {
        poly_index,
        weight: *weight,
    }
}
pub fn convert_device_slice<T>(a: &DeviceAllocation<T>) -> CudaDeviceSlice<T> {
    CudaDeviceSlice {
        ptr: a.as_ptr(),
        length: a.len() as _,
    }
}

pub fn generate_permutation_trace_gm<F: Field, EF: ExtensionField<F>, C: ChipBehavior<F>>(
    chip: &MetaChip<F, C>,
    preprocessed: Option<&DeviceMatrixConcrete<'static, KoalaBear>>,
    main: &DeviceMatrixConcrete<'static, KoalaBear>,
    random_elements: &[EF],
) -> (DeviceMatrixStatic<F>, EF, SepticDigest<F>) {
    assert!(TypeId::of::<F>() == TypeId::of::<InnerVal>());
    assert!(TypeId::of::<EF>() == TypeId::of::<InnerChallenge>());
    assert_eq!(random_elements.len(), 2);
    assert_eq!(4, <EF as FieldExtensionAlgebra<F>>::D);
    const D: usize = 4;
    let batch_size = chip.logup_batch_size();
    let log_n = main.log_n;
    let n = 1 << log_n;

    let looking: &[VirtualPairLookup<InnerVal>] = unsafe { transmute(&chip.looking[..]) };
    let looked: &[VirtualPairLookup<InnerVal>] = unsafe { transmute(&chip.looked[..]) };

    let random_elements: &[InnerChallenge] = unsafe { transmute(random_elements) };

    let (grouped_sends, grouped_receives, grouped_widths) =
        get_grouped_maps(looking, looked, batch_size);
    let empty_vec = vec![];
    let local_sends = grouped_sends
        .get(&LookupScope::Regional)
        .unwrap_or(&empty_vec);
    let local_receives = grouped_receives
        .get(&LookupScope::Regional)
        .unwrap_or(&empty_vec);
    let permutation_trace_width = grouped_widths
        .get(&LookupScope::Regional)
        .cloned()
        .unwrap_or_default();
    let interactions = &local_sends
        .iter()
        .map(|int| (int, true))
        .chain(local_receives.iter().map(|int| (int, false)))
        .collect::<Vec<_>>();

    let mut permutation_trace = DeviceMatrixStatic {
        values: DeviceAllocation::<InnerChallenge>::alloc(permutation_trace_width << log_n)
            .unwrap(),
        log_n,
        num_poly: permutation_trace_width,
    };
    let mut device_pair_col: Vec<DeviceAllocation<PairCol>> = vec![];
    let mut device_virtual: Vec<DeviceAllocation<VirtualPairCol>> = vec![];
    let mut temp: Vec<Interaction> = vec![];
    let mut num_betas = 1;
    for (interaction, is_send) in interactions {
        let column_weights: Vec<_> = interaction
            .mult
            .column_weights
            .iter()
            .map(|(a, b)| convert_pair_col(a, b))
            .collect();
        device_pair_col.push(host_slice_2_device_vec(&column_weights));
        let multy: VirtualPairCol = VirtualPairCol {
            constant: interaction.mult.constant,
            column_weights: device_pair_col.last().map(convert_device_slice).unwrap(),
        };
        let values: Vec<_> = interaction
            .values
            .iter()
            .map(|v| {
                let column_weights: Vec<_> = v
                    .column_weights
                    .iter()
                    .map(|(a, b)| convert_pair_col(a, b))
                    .collect();
                device_pair_col.push(host_slice_2_device_vec(&column_weights));
                let value: VirtualPairCol = VirtualPairCol {
                    constant: v.constant,
                    column_weights: device_pair_col.last().map(convert_device_slice).unwrap(),
                };
                value
            })
            .collect();
        num_betas = std::cmp::max(num_betas, values.len() + 1);
        device_virtual.push(host_slice_2_device_vec(&values));
        let values = device_virtual.last().map(convert_device_slice).unwrap();
        let i = Interaction {
            values,
            multiplicity: multy,
            argument_index: InnerVal::from_canonical_usize(interaction.kind as usize),
            is_send: *is_send,
        };
        temp.push(i);
    }
    let mut device_interactions: Vec<DeviceAllocation<Interaction>> = vec![];
    let mut device_batchs: Vec<InteractionBatch> = vec![];
    for batch in temp.chunks(batch_size) {
        let device_batch = host_slice_2_device_vec(batch);
        device_interactions.push(device_batch);
        device_batchs.push(
            device_interactions
                .last()
                .map(convert_device_slice)
                .unwrap(),
        );
    }
    let device_batchs_storage = host_slice_2_device_vec(&device_batchs);
    let device_batchs = convert_device_slice(&device_batchs_storage);
    unsafe {
        let stream = CudaStream::default();
        let mut device_betas = DeviceAllocation::<InnerChallenge>::alloc(num_betas).unwrap();
        rustffi_distribute_alpha_powers(
            device_betas.as_mut_c_void_ptr(),
            &random_elements[1] as *const InnerChallenge as *const std::ffi::c_void,
            num_betas as _,
            (&stream).into(),
        );
        rustffi_generate_permutation_trace(
            &random_elements[0] as *const InnerChallenge as *const std::ffi::c_void,
            device_betas.as_c_void_ptr(),
            preprocessed
                .as_ref()
                .map(|i| i.values.as_c_void_ptr())
                .unwrap_or(null()),
            preprocessed
                .as_ref()
                .map(|i| i.num_poly as u32)
                .unwrap_or(0),
            // preprocessed.values.as_c_void_ptr(),
            // preprocessed.num_poly as u32,
            main.values.as_c_void_ptr(),
            main.num_poly as u32,
            permutation_trace.values.as_mut_c_void_ptr(),
            transmute::<AllInteraction, CudaDeviceSlice<c_void>>(device_batchs),
            main.log_n as _,
            (&stream).into(),
        );
        stream.synchronize().unwrap();
        let mut permutation_trace_flatten = DeviceMatrixStatic {
            values: DeviceAllocation::<InnerVal>::alloc((permutation_trace_width * D) << log_n)
                .unwrap(),
            log_n,
            num_poly: permutation_trace_width * D,
        };
        rustffi_flatten_perm(
            permutation_trace.values.as_c_void_ptr(),
            permutation_trace_flatten.values.as_mut_c_void_ptr(),
            permutation_trace.num_poly as _,
            permutation_trace.log_n as _,
            (&stream).into(),
        );
        stream.synchronize().unwrap();
        let mut local_cumulative_sum = vec![InnerChallenge::ZERO];
        let sum_offset = (permutation_trace.num_poly << permutation_trace.log_n) - 1;
        memory_copy(
            &mut local_cumulative_sum,
            &permutation_trace.values[sum_offset..(sum_offset + 1)],
        )
        .unwrap();
        let global_sum = if chip.lookup_scope() == LookupScope::Regional {
            SepticDigest::<InnerVal>::zero()
        } else {
            let mut x: SepticExtension<InnerVal> = Default::default();
            let mut y: SepticExtension<InnerVal> = Default::default();
            assert!(main.num_poly >= 14);

            for (i, poly_idx) in ((main.num_poly - 14)..(main.num_poly - 7)).enumerate() {
                let offset = (poly_idx << main.log_n) + n - 1;
                memory_copy(&mut x.0[i..i + 1], &main.values[offset..offset + 1]).unwrap();
            }
            for (i, poly_idx) in ((main.num_poly - 7)..main.num_poly).enumerate() {
                let offset = (poly_idx << main.log_n) + n - 1;
                memory_copy(&mut y.0[i..i + 1], &main.values[offset..offset + 1]).unwrap();
            }

            SepticDigest(SepticCurve { x, y })
        };
        let permutation_trace_flatten: DeviceMatrixStatic<F> = transmute(permutation_trace_flatten);
        let local_cumulative_sum: &Vec<EF> = transmute(&local_cumulative_sum);
        let global_sum: &SepticDigest<F> = transmute(&global_sum);
        return (
            permutation_trace_flatten,
            local_cumulative_sum[0],
            global_sum.clone(),
        );
    }
}

//
extern "C" {
    fn rustffi_distribute_alpha_powers(
        alpha_powers: *mut c_void,
        host_alpha: *const c_void,
        num_poly: u32,
        stream: cudaStream_t,
    );

    fn rustffi_generate_permutation_trace(
        host_alpha: *const c_void,
        beta_powers: *const c_void,
        prep: *const c_void,
        num_poly_prep: u32,
        main: *const c_void,
        num_poly_main: u32,
        all_results: *const c_void,
        all_instraction: CudaDeviceSlice<c_void>,
        log_n: u32,
        cuda_stream: cudaStream_t,
    );

    fn rustffi_flatten_perm(
        inputs: *const c_void,
        outputs: *mut c_void,
        num_poly: u32,
        log_n: u32,
        cuda_stream: cudaStream_t,
    );
}
