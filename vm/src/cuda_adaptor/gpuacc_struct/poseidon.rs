use std::ffi::c_void;
pub const DIGEST_ELEMS: usize = 8;

use cudart::{
    memory::{memory_copy, DeviceAllocation},
    slice::CudaSliceMut,
};
use cudart_sys::{cudaFree, CudaError};

#[repr(C)]
pub struct Poseidon2Constants {
    pub rounds_f: u32,
    pub rounds_p: u32,
    pub external_round_constants: *mut c_void,
    pub internal_round_constants: *mut c_void,
}
impl Poseidon2Constants {
    pub fn new<F: Sized, const WIDTH: usize>(external: &[[F; WIDTH]], internal: &[F]) -> Self {
        let mut external_round_constants: DeviceAllocation<[F; WIDTH]> =
            DeviceAllocation::alloc(external.len()).unwrap();
        let mut internal_round_constants: DeviceAllocation<F> =
            DeviceAllocation::alloc(internal.len()).unwrap();
        memory_copy(&mut external_round_constants, &external[..]).unwrap();
        memory_copy(&mut internal_round_constants, &internal[..]).unwrap();

        let ret = Self {
            rounds_f: external.len() as u32,
            rounds_p: internal.len() as u32,
            external_round_constants: external_round_constants.as_mut_c_void_ptr(),
            internal_round_constants: internal_round_constants.as_mut_c_void_ptr(),
        };
        std::mem::forget(external_round_constants);
        std::mem::forget(internal_round_constants);
        ret
    }
}

impl Drop for Poseidon2Constants {
    fn drop(&mut self) {
        unsafe {
            assert!(cudaFree(self.external_round_constants) == CudaError::Success);
            assert!(cudaFree(self.internal_round_constants) == CudaError::Success);
        };
    }
}
