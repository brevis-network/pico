use cudart::{
    memory_pools::DevicePoolAllocation,
    slice::{CudaSlice, CudaSliceMut},
    stream::CudaStream,
};
use cudart_sys::*;
use p3_field::Field;
use p3_koala_bear::KoalaBear;
use p3_matrix::{dense::RowMajorMatrix, Dimensions, Matrix};
use p3_maybe_rayon::prelude::*;

pub enum TraceData<'a, F: Field> {
    // cpu trace
    Cpu(RowMajorMatrix<F>),
    // trace width and gpu trace
    Gpu(usize, DevicePoolAllocation<'a, KoalaBear>),
    // used for debugging, includes both cpu and gpu traces
    Debug(RowMajorMatrix<F>, DevicePoolAllocation<'a, KoalaBear>),
}

impl<F: Field> TraceData<'_, F> {
    pub fn width(&self) -> usize {
        match self {
            Self::Cpu(trace) | Self::Debug(trace, _) => trace.width(),
            Self::Gpu(width, _) => *width,
        }
    }

    pub fn height(&self) -> usize {
        match self {
            Self::Cpu(trace) | Self::Debug(trace, _) => trace.height(),
            Self::Gpu(width, trace) => trace.len() / width,
        }
    }

    pub fn dimensions(&self) -> Dimensions {
        let width = self.width();
        let height = self.height();

        Dimensions { width, height }
    }

    pub fn len(&self) -> usize {
        match self {
            Self::Cpu(trace) | Self::Debug(trace, _) => trace.values.len(),
            Self::Gpu(_, trace) => trace.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn to_host(&self, stream: &CudaStream) -> RowMajorMatrix<F> {
        match self {
            Self::Cpu(trace) => trace.clone(),
            Self::Gpu(width, trace) => {
                let trace_size = trace.len();
                let mut values: Vec<F> = (0..trace_size).into_par_iter().map(|_| F::ZERO).collect();
                unsafe {
                    let _ = cudaMemcpyAsync(
                        values.as_mut_c_void_ptr(),
                        trace.as_c_void_ptr(),
                        trace_size * size_of::<F>(),
                        CudaMemoryCopyKind::DeviceToHost,
                        stream.into(),
                    );
                }

                RowMajorMatrix::new(values, *width)
            }
            Self::Debug(_, _) => panic!("should not call to_host for debugging trace data"),
        }
    }
}

pub trait TraceBorrow<F>
where
    F: Field,
{
    fn borrow_rows<R>(&self) -> &[R];
}

pub trait TraceBorrowMut<F>
where
    F: Field,
{
    fn borrow_rows_mut<R>(&mut self) -> &mut [R];
}

impl<F> TraceBorrow<F> for RowMajorMatrix<F>
where
    F: Field,
{
    fn borrow_rows<R>(&self) -> &[R] {
        let (prefix, rows, suffix) = unsafe { self.values.align_to::<R>() };
        assert!(prefix.is_empty(), "Alignment should match");
        assert!(suffix.is_empty(), "Alignment should match");
        assert_eq!(rows.len(), self.height());
        rows
    }
}

impl<F> TraceBorrowMut<F> for RowMajorMatrix<F>
where
    F: Field,
{
    fn borrow_rows_mut<R: Sized>(&mut self) -> &mut [R] {
        let height = self.height();
        let (prefix, rows, suffix) = unsafe { self.values.align_to_mut::<R>() };
        assert!(prefix.is_empty(), "Alignment should match");
        assert!(suffix.is_empty(), "Alignment should match");
        assert_eq!(rows.len(), height);
        rows
    }
}
