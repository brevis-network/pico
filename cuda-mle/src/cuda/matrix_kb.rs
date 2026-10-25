use crate::runtime::{d_buffer::DeviceBuffer, error::CudaError};

use crate::prelude::{EF, F};

#[link(name = "cuda_kb_all", kind = "static")]
extern "C" {
    fn _kb_batch_expand_pad(
        output: *mut F,
        input: *const F,
        poly_count: u32,
        out_size: u32,
        in_size: u32,
    ) -> i32;

    fn _kb_split_ext_to_base_col_major_matrix(
        d_matrix: *mut F,
        d_poly: *const EF,
        poly_len: u64,
        matrix_height: u32,
    ) -> i32;
}

pub unsafe fn batch_expand_pad(
    output: *mut F,
    input: *const F,
    poly_count: u32,
    out_size: u32,
    in_size: u32,
) -> Result<(), CudaError> {
    CudaError::from_result(_kb_batch_expand_pad(
        output, input, poly_count, out_size, in_size,
    ))
}

pub unsafe fn split_ext_to_base_col_major_matrix(
    d_matrix: &mut DeviceBuffer<F>,
    d_poly: &DeviceBuffer<EF>,
    poly_len: u64,
    matrix_height: u32,
) -> Result<(), CudaError> {
    CudaError::from_result(_kb_split_ext_to_base_col_major_matrix(
        d_matrix.as_mut_ptr(),
        d_poly.as_ptr(),
        poly_len,
        matrix_height,
    ))
}
