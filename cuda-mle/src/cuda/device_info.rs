use crate::runtime::error::CudaError;

extern "C" {
    fn _cuda_get_sm_count(device_id: u32, out_sm_count: *mut u32) -> i32;
}

pub fn get_sm_count(device_id: u32) -> Result<u32, CudaError> {
    let mut sm_count = 0u32;
    unsafe { CudaError::from_result(_cuda_get_sm_count(device_id, &mut sm_count))? };
    Ok(sm_count)
}
