use crate::cuda_adaptor::{
    gpuacc_struct::fri_commit::uninit_vec, log2_strict_usize, FieldAlgebra, LagrangeSelectors,
    PolynomialSpace, TwoAdicMultiplicativeCoset,
};
use bincode::{deserialize, serialize};
use cudart::{
    device::get_device_count,
    memory::{memory_copy, DeviceAllocation},
    slice::CudaSlice,
};
use p3_air::BaseAir;
use p3_field::Field;
use p3_koala_bear::KoalaBear;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fs::File,
    io::{Read, Write},
    sync::{Mutex, OnceLock},
};
//

//
// Global All AirChips' Operations Flow
lazy_static::lazy_static! {
    pub static ref CHIPS_GPU_OP_VEC_KB: Mutex<HashMap<String, Vec<usize>>> = Mutex::new(HashMap::new());
}
lazy_static::lazy_static! {
    pub static ref CHIPS_MAX_PERM_CHALLENGE_POW: Mutex<HashMap<String, usize>> = Mutex::new(HashMap::new());
}
lazy_static::lazy_static! {
    pub static ref CHIPS_MAX_ALPHA_POW: Mutex<HashMap<String, usize>> = Mutex::new(HashMap::new());
}

pub type SelectotCache = HashMap<(usize, usize), LagrangeSelectors<DeviceAllocation<KoalaBear>>>;
lazy_static::lazy_static! {
    pub static ref SELECTORS: OnceLock<Vec<Mutex<SelectotCache>>> = OnceLock::new();
}

//
pub fn host_slice_2_device_vec<T: Sized, C: CudaSlice<T> + ?Sized>(a: &C) -> DeviceAllocation<T> {
    let length = a.len();
    let mut ret: DeviceAllocation<T> = DeviceAllocation::alloc(length).unwrap();
    memory_copy(&mut ret, a).unwrap();
    ret
}
pub fn device_slice_2_host_vec<T: Sized, C: CudaSlice<T> + ?Sized>(a: &C) -> Vec<T> {
    let mut ret: Vec<T> = uninit_vec(a.len());
    memory_copy(&mut ret, a).unwrap();
    ret
}

//
pub fn insert(trace_size: usize, quotient_size: usize, device_id: usize) {
    let buffers = SELECTORS.get_or_init(|| {
        let device_count = get_device_count().unwrap() as usize;
        (0..device_count)
            .map(|_| Mutex::new(HashMap::new()))
            .collect()
    });

    if device_id >= buffers.len() {
        panic!(
            "Device ID {} exceeds available devices ({})",
            device_id,
            buffers.len()
        );
    }
    let mut dev_selectors = buffers.get(device_id).unwrap().lock().unwrap();

    if !dev_selectors.contains_key(&(trace_size, quotient_size)) {
        let quotient_domain = TwoAdicMultiplicativeCoset {
            log_n: log2_strict_usize(quotient_size),
            shift: KoalaBear::GENERATOR,
        };
        let trace_domain = TwoAdicMultiplicativeCoset {
            log_n: log2_strict_usize(trace_size),
            shift: KoalaBear::ONE,
        };
        let selector = trace_domain.selectors_on_coset(quotient_domain);
        let device_selector = LagrangeSelectors {
            is_first_row: host_slice_2_device_vec(&selector.is_first_row),
            is_last_row: host_slice_2_device_vec(&selector.is_last_row),
            is_transition: host_slice_2_device_vec(&selector.is_transition),
            inv_zeroifier: host_slice_2_device_vec(&selector.inv_zeroifier),
        };
        dev_selectors.insert((trace_size, quotient_size), device_selector);
    }
}

pub fn initial_chips_load() {
    let _ = load_from_file();
}

#[derive(Serialize, Deserialize)]
struct StorageWrapperHashStringVec {
    data: HashMap<String, Vec<usize>>,
}

#[derive(Serialize, Deserialize)]
struct StorageWrapperHashStringUszie {
    data: HashMap<String, usize>,
}

fn load_from_file() -> Result<(), Box<dyn std::error::Error>> {
    //
    let mut file = File::open("operations_vec.bin")?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    let wrapper: StorageWrapperHashStringVec = deserialize(&buffer)?;
    let mut guard = CHIPS_GPU_OP_VEC_KB.lock().unwrap();
    *guard = wrapper.data;

    //
    let mut file = File::open("perm_challenge_pow.bin")?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    let wrapper: StorageWrapperHashStringUszie = deserialize(&buffer)?;
    let mut guard = CHIPS_MAX_PERM_CHALLENGE_POW.lock().unwrap();
    *guard = wrapper.data;

    //
    let mut file = File::open("max_alpha_pow.bin")?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    let wrapper: StorageWrapperHashStringUszie = deserialize(&buffer)?;
    let mut guard = CHIPS_MAX_ALPHA_POW.lock().unwrap();
    *guard = wrapper.data;
    Ok(())
}

//
// ----------------------------------------------
// Quotient_2 method initialize
// ----------------------------------------------
//
use crate::cuda_adaptor::h_poly_struct::{Calculation, ValueSource};

#[derive(Serialize, Deserialize, Clone)]
pub struct CalculateData {
    pub all_caculations: Vec<Calculation<KoalaBear>>,
    pub value_base: Vec<(usize, ValueSource<KoalaBear>)>,
    pub value_ext: Vec<(usize, [ValueSource<KoalaBear>; 4])>,
}
lazy_static::lazy_static! {
    pub static ref CHIPS_INSTRUCTIONS: Mutex<HashMap<String, CalculateData>> = Mutex::new(HashMap::new());
}

pub fn initial_chips_2() {
    let _ = load_from_file_2();
}

// save & load
#[derive(Serialize, Deserialize)]
struct StorageWrapperHashStringCalculate {
    data: HashMap<String, CalculateData>,
}

fn load_from_file_2() {
    let data = std::fs::read("chips_operations.json").unwrap();
    let wrapper: StorageWrapperHashStringCalculate = serde_json::from_slice(&data).unwrap();
    let mut guard = CHIPS_INSTRUCTIONS.lock().unwrap();
    *guard = wrapper.data;

    let _ = guard.get("MemoryConst").unwrap();
}
