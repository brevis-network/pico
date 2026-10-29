use std::{ffi::c_void, fmt::Debug, ptr};

use crate::runtime::{
    copy::MemCopyD2H,
    error::{check, CudaError},
    memory_manager::{d_free, d_malloc},
    stream::{cudaStreamPerThread, cudaStream_t},
};

#[link(name = "cudart")]
extern "C" {
    pub fn cudaMemsetAsync(
        target: *mut c_void,
        byte: i32,
        bytes: usize,
        on_stream: cudaStream_t,
    ) -> i32;
}

/// Typed device allocation. Holds only the device pointer and the element count; `Drop` returns
/// the memory to the pool unless the buffer is a borrowed view.
#[repr(C)]
pub struct DeviceBuffer<T> {
    base: *mut T,
    count: usize,
    /// `false` for a *view* over memory owned elsewhere (see [`DeviceBuffer::borrowed`]),
    /// which must not be handed to `d_free`. Never crosses FFI: the C side takes
    /// [`DeviceBufferView`] or a raw pointer, so this field's presence is invisible to it.
    owns: bool,
}

/// Untyped `(pointer, byte length)` pair in the layout kernels take. It is a non-owning
/// [`DeviceBuffer`]: dropping it frees nothing. The pointer is `*const` because the C side cannot
/// express mutability anyway.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct DeviceBufferView {
    pub ptr: *const c_void,
    pub size: usize,
}

// SAFETY: the buffer is a handle to device memory; it carries no host-side shared state.
unsafe impl<T> Send for DeviceBuffer<T> {}
unsafe impl<T> Sync for DeviceBuffer<T> {}

impl<T> DeviceBuffer<T> {
    /// A null buffer of length zero; owns nothing until replaced.
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            base: ptr::null_mut(),
            count: 0,
            owns: true,
        }
    }

    /// # Safety
    /// - `ptr` must point at `len` valid elements of `T` in device memory.
    /// - The buffer frees `ptr` on drop, so it must come from `d_malloc`, or the caller must wrap
    ///   the result in `ManuallyDrop` to avoid a double free.
    pub unsafe fn from_raw_parts(ptr: *mut T, len: usize) -> Self {
        Self {
            base: ptr,
            count: len,
            owns: true,
        }
    }

    /// A *view* over `len` elements owned by someone else. Dropping it frees nothing, so it
    /// can name a sub-range of a larger buffer — which is what lets one allocation back a
    /// whole round's worth of matrices.
    ///
    /// # Safety
    /// - `ptr` must be valid for `len` elements of `T` in device memory.
    /// - The owner must outlive every use of the returned buffer.
    pub unsafe fn borrowed(ptr: *mut T, len: usize) -> Self {
        Self {
            base: ptr,
            count: len,
            owns: false,
        }
    }

    /// Allocates room for `len` elements of `T` (contents uninitialised).
    pub fn with_capacity(len: usize) -> Self {
        let elem_bytes = std::mem::size_of::<T>();
        tracing::debug!(len, elem_bytes, "allocating a device buffer");
        assert_ne!(
            len, 0,
            "device buffers cannot be allocated with zero length"
        );
        let total_bytes = elem_bytes * len;
        let untyped = d_malloc(total_bytes).expect("device allocation failed");
        #[cfg(feature = "touchemall")]
        {
            // Poison with 0xff bytes (`Fp::invalid()`), a value no valid trace contains.
            unsafe {
                cudaMemsetAsync(untyped, 0xff, total_bytes, cudaStreamPerThread);
            }
        }
        Self {
            base: untyped as *mut T,
            count: len,
            owns: true,
        }
    }

    /// Zeroes every element.
    pub fn fill_zero(&self) -> Result<(), CudaError> {
        assert_ne!(self.count, 0, "cannot zero an empty device buffer");
        let total_bytes = std::mem::size_of::<T>() * self.count;
        check(unsafe {
            cudaMemsetAsync(self.as_mut_raw_ptr(), 0, total_bytes, cudaStreamPerThread)
        })
    }

    /// Zeroes the elements from index `start_idx` (in elements of `T`) to the end.
    pub fn fill_zero_suffix(&self, start_idx: usize) -> Result<(), CudaError> {
        assert!(
            start_idx < self.count,
            "suffix start {start_idx} is not inside a buffer of {} elements",
            self.count
        );
        let tail_bytes = std::mem::size_of::<T>() * (self.count - start_idx);
        check(unsafe {
            let tail = self.as_mut_ptr().add(start_idx) as *mut c_void;
            cudaMemsetAsync(tail, 0, tail_bytes, cudaStreamPerThread)
        })
    }

    /// Element count.
    pub fn len(&self) -> usize {
        self.count
    }

    /// True when the buffer has no elements or no allocation.
    pub fn is_empty(&self) -> bool {
        self.count == 0 || self.base.is_null()
    }

    /// Typed device pointer.
    pub fn as_mut_ptr(&self) -> *mut T {
        self.base
    }

    /// Typed device pointer, read-only.
    pub fn as_ptr(&self) -> *const T {
        self.base.cast_const()
    }

    /// Untyped device pointer.
    pub fn as_mut_raw_ptr(&self) -> *mut c_void {
        self.base.cast()
    }

    /// Untyped device pointer, read-only.
    pub fn as_raw_ptr(&self) -> *const c_void {
        self.base.cast_const().cast()
    }

    /// Reinterprets the buffer as elements of `U`; `T` must be made of whole `U`s (size and
    /// alignment of `U` divide those of `T`).
    pub fn as_buffer<U>(mut self) -> DeviceBuffer<U> {
        let (t_size, u_size) = (size_of::<T>(), size_of::<U>());
        assert_eq!(t_size % u_size, 0, "size of U must divide size of T");
        assert_eq!(
            align_of::<T>() % align_of::<U>(),
            0,
            "alignment of U must divide alignment of T"
        );
        let reinterpreted = DeviceBuffer {
            base: self.base as *mut U,
            count: self.count * (t_size / u_size),
            owns: self.owns,
        };
        // Leave `self` empty so its drop does not free the memory now owned by `reinterpreted`.
        self.base = ptr::null_mut();
        self.count = 0;
        reinterpreted
    }

    pub fn view(&self) -> DeviceBufferView {
        DeviceBufferView {
            ptr: self.as_raw_ptr(),
            size: self.count * size_of::<T>(),
        }
    }
}

impl<T> Drop for DeviceBuffer<T> {
    fn drop(&mut self) {
        if !self.owns || self.base.is_null() {
            return;
        }
        tracing::debug!(
            len = self.count,
            elem_bytes = size_of::<T>(),
            "freeing a device buffer"
        );
        unsafe {
            d_free(self.base.cast()).expect("device free failed");
        }
        self.base = ptr::null_mut();
        self.count = 0;
    }
}

impl<T: Debug> Debug for DeviceBuffer<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let contents = self.to_host().unwrap();
        f.debug_struct("DeviceBuffer")
            .field("len", &self.count)
            .field("contents", &contents)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::copy::MemCopyH2D;

    #[test]
    fn allocation_has_requested_length() {
        let buf = DeviceBuffer::<f32>::with_capacity(10);
        assert_eq!(buf.len(), 10);
        assert!(!buf.as_ptr().is_null());
        assert!(!buf.is_empty());
    }

    #[test]
    fn fill_zero_clears_contents() {
        let host: Vec<u64> = (0..10).collect();
        let dev = host.to_device().unwrap();
        dev.fill_zero().unwrap();
        assert_eq!(dev.to_host().unwrap(), vec![0; host.len()]);
    }
}
