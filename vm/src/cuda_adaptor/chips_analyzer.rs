use crate::cuda_adaptor::{
    log2_strict_usize, FieldAlgebra, LagrangeSelectors, PolynomialSpace, TwoAdicMultiplicativeCoset,
};
use cudart::memory::DeviceAllocation;
use p3_field::Field;
use p3_koala_bear::KoalaBear;
use std::{
    collections::HashMap,
    sync::{Mutex, OnceLock},
};
use cudart::slice::CudaSlice;
use cudart::memory::memory_copy;

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

use cudart::device::get_device_count;

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
    let mut dev_selectors = buffers
        .get(device_id)
        .unwrap()
        .lock()
        .unwrap();

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

//
use std::fs::File;
use std::io::{Read, Write};
use bincode::{serialize, deserialize};
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
struct StorageWrapperHashStringVec {
    data: HashMap<String, Vec<usize>>
}

#[derive(Serialize, Deserialize)]
struct StorageWrapperHashStringUszie {
    data: HashMap<String, usize>
}


fn save_to_file() -> Result<(), Box<dyn std::error::Error>> {
    //
    let guard = CHIPS_GPU_OP_VEC_KB.lock().unwrap();
    let wrapper = StorageWrapperHashStringVec { data: guard.clone() };
    let encoded = serialize(&wrapper)?;
    
    let mut file = File::create("operations_vec.bin")?;
    file.write_all(&encoded)?;

    //
    let guard = CHIPS_MAX_PERM_CHALLENGE_POW.lock().unwrap();
    let wrapper = StorageWrapperHashStringUszie { data: guard.clone() };
    let encoded = serialize(&wrapper)?;
    
    let mut file = File::create("perm_challenge_pow.bin")?;
    file.write_all(&encoded)?;

    //
    let guard = CHIPS_MAX_ALPHA_POW.lock().unwrap();
    let wrapper = StorageWrapperHashStringUszie { data: guard.clone() };
    let encoded = serialize(&wrapper)?;
    
    let mut file = File::create("max_alpha_pow.bin")?;
    file.write_all(&encoded)?;

    Ok(())
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