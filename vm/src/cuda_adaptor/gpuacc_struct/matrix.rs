use std::{ffi::c_void, mem::transmute};

use cudart::{
    memory::{memory_copy, memory_copy_async, DeviceAllocation},
    memory_pools::{CudaMemPool, DevicePoolAllocation},
    slice::{CudaSlice, CudaSliceMut},
    stream::CudaStream,
};
pub struct DeviceMatrixConcrete<'stream, T: Sized> {
    pub values: DevicePoolAllocation<'stream, T>,
    pub log_n: usize,
    pub num_poly: usize,
}

pub struct DeviceMatrixStatic<T: Sized> {
    pub values: DeviceAllocation<T>,
    pub log_n: usize,
    pub num_poly: usize,
}
impl<T: Sized> DeviceMatrixStatic<T> {
    pub fn from_ref(a: &DeviceMatrixRef<T>) -> Self {
        let log_n = a.log_n;
        let num_poly = a.num_poly;
        let mut values = DeviceAllocation::<T>::alloc(num_poly << log_n).unwrap();
        memory_copy(&mut values, a).unwrap();
        Self {
            values,
            log_n,
            num_poly,
        }
    }
    pub fn into_ref(&mut self) -> DeviceMatrixRef<T> {
        DeviceMatrixRef {
            ptr: self.values.as_mut_ptr(),
            log_n: self.log_n,
            num_poly: self.num_poly,
        }
    }
}

impl<'stream, T: Sized> DeviceMatrixConcrete<'stream, T> {
    pub fn into_ref(&mut self) -> DeviceMatrixRef<T> {
        DeviceMatrixRef {
            ptr: self.values.as_mut_ptr(),
            log_n: self.log_n,
            num_poly: self.num_poly,
        }
    }
    pub fn from_ref(
        stream: &'stream CudaStream,
        mem_pool: &CudaMemPool,
        matrix_ref: &DeviceMatrixRef<T>,
    ) -> Self {
        let mut values = DevicePoolAllocation::<'stream, T>::alloc_from_pool_async(
            matrix_ref.num_poly << matrix_ref.log_n,
            mem_pool,
            stream,
        )
        .unwrap();
        memory_copy_async(&mut values, matrix_ref, stream).unwrap();
        stream.synchronize().unwrap();
        Self {
            values,
            log_n: matrix_ref.log_n,
            num_poly: matrix_ref.num_poly,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct DeviceMatrixRef<T: Sized> {
    pub ptr: *mut T,
    pub log_n: usize,
    pub num_poly: usize,
}
impl<T: Sized> CudaSlice<T> for DeviceMatrixRef<T> {
    unsafe fn as_slice(&self) -> &[T] {
        std::slice::from_raw_parts(self.ptr, self.num_poly << self.log_n)
    }
}
impl<T: Sized> CudaSlice<T> for &DeviceMatrixRef<T> {
    unsafe fn as_slice(&self) -> &[T] {
        std::slice::from_raw_parts(self.ptr, self.num_poly << self.log_n)
    }
}
impl<T: Sized> CudaSliceMut<T> for DeviceMatrixRef<T> {
    unsafe fn as_mut_slice(&mut self) -> &mut [T] {
        std::slice::from_raw_parts_mut(self.ptr, self.num_poly << self.log_n)
    }
}
impl<T: Sized> CudaSliceMut<T> for &DeviceMatrixRef<T> {
    unsafe fn as_mut_slice(&mut self) -> &mut [T] {
        std::slice::from_raw_parts_mut(self.ptr, self.num_poly << self.log_n)
    }
}

impl<T: Sized> DeviceMatrixRef<T> {
    pub fn new(ptr: *mut T, log_n: usize, num_poly: usize) -> Self {
        Self {
            ptr,
            log_n,
            num_poly,
        }
    }
    pub fn as_mut_c_void_ptr(&mut self) -> *mut c_void {
        unsafe { transmute(self.ptr) }
    }
    pub fn as_c_void_ptr(&self) -> *const c_void {
        unsafe { transmute(self.ptr) }
    }
    pub fn log_n(&self) -> usize {
        self.log_n
    }
    pub fn num_poly(&self) -> usize {
        self.num_poly
    }
}
