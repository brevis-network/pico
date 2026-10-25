use std::{fmt::Debug, marker::PhantomData, sync::Arc};

use crate::runtime::{copy::MemCopyD2H, d_buffer::DeviceBuffer, error::MemCopyError};
use mle_core::poly::matrix::MatrixDimensions;

/// Row-count × column-count matrix whose storage is a shared device buffer. Cloning shares the
/// buffer; the memory is released when the last clone is dropped.
pub struct DeviceMatrix<T> {
    storage: Arc<DeviceBuffer<T>>,
    rows: usize,
    cols: usize,
}

// SAFETY: the matrix only hands out device pointers; it holds no host-side shared state.
unsafe impl<T> Send for DeviceMatrix<T> {}
unsafe impl<T> Sync for DeviceMatrix<T> {}

impl<T> DeviceMatrix<T> {
    pub fn new(buffer: Arc<DeviceBuffer<T>>, height: usize, width: usize) -> Self {
        let cells = height * width;
        assert!(
            cells != 0,
            "DeviceMatrix needs non-zero dimensions, got {height}x{width}"
        );
        assert_eq!(
            buffer.len(),
            cells,
            "DeviceMatrix buffer length != height * width"
        );
        Self {
            storage: buffer,
            rows: height,
            cols: width,
        }
    }

    pub fn with_capacity(height: usize, width: usize) -> Self {
        let storage = Arc::new(DeviceBuffer::with_capacity(height * width));
        Self {
            storage,
            rows: height,
            cols: width,
        }
    }

    pub fn buffer(&self) -> &DeviceBuffer<T> {
        self.storage.as_ref()
    }

    /// Number of live handles sharing this matrix's buffer.
    pub fn strong_count(&self) -> usize {
        Arc::strong_count(&self.storage)
    }

    pub fn as_view(&self) -> DeviceMatrixView<'_, T> {
        let base = self.storage.as_ptr();
        // SAFETY: the view borrows `self`, so the buffer outlives it.
        unsafe { DeviceMatrixView::from_raw_parts(base, self.rows, self.cols) }
    }
}

impl<T> MatrixDimensions for DeviceMatrix<T> {
    #[inline]
    fn height(&self) -> usize {
        self.rows
    }

    #[inline]
    fn width(&self) -> usize {
        self.cols
    }
}

impl<T> Clone for DeviceMatrix<T> {
    fn clone(&self) -> Self {
        let storage = Arc::clone(&self.storage);
        Self {
            storage,
            rows: self.rows,
            cols: self.cols,
        }
    }
}

impl<T> Drop for DeviceMatrix<T> {
    fn drop(&mut self) {
        tracing::debug!(
            len = self.storage.len(),
            handles = self.strong_count(),
            "releasing a DeviceMatrix handle"
        );
    }
}

impl<T> MemCopyD2H<T> for DeviceMatrix<T> {
    fn to_host(&self) -> Result<Vec<T>, MemCopyError> {
        self.storage.to_host()
    }
}

impl<T: Debug> Debug for DeviceMatrix<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceMatrix")
            .field("height", &self.rows)
            .field("width", &self.cols)
            .field("buffer", self.buffer())
            .finish()
    }
}

/// Borrowed, non-owning view of a device matrix; dropping it frees nothing.
#[derive(Clone, Copy)]
pub struct DeviceMatrixView<'a, T> {
    base: *const T,
    rows: usize,
    cols: usize,
    _borrow: PhantomData<&'a T>,
}

// SAFETY: as for `DeviceMatrix`, only a device pointer is held.
unsafe impl<T> Send for DeviceMatrixView<'_, T> {}
unsafe impl<T> Sync for DeviceMatrixView<'_, T> {}

impl<T> DeviceMatrixView<'_, T> {
    /// # Safety
    /// `ptr` must stay valid for the view's lifetime and point at `height * width` allocated
    /// elements of `T`.
    pub unsafe fn from_raw_parts(ptr: *const T, height: usize, width: usize) -> Self {
        Self {
            base: ptr,
            rows: height,
            cols: width,
            _borrow: PhantomData,
        }
    }

    pub fn as_ptr(&self) -> *const T {
        self.base
    }
}

impl<T> MatrixDimensions for DeviceMatrixView<'_, T> {
    #[inline]
    fn height(&self) -> usize {
        self.rows
    }

    #[inline]
    fn width(&self) -> usize {
        self.cols
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_matrix_reports_its_shape() {
        let storage = Arc::new(DeviceBuffer::<i32>::with_capacity(12));
        let m = DeviceMatrix::<i32>::new(storage, 3, 4);
        assert_eq!((m.height(), m.width()), (3, 4));
    }
}
