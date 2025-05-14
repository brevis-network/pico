
//
#[derive(Clone, Copy)]
#[repr(C)]
pub struct CudaDeviceSlice<T> {
    pub ptr: *const T,
    pub length: u32,
}