use std::marker::PhantomData;

pub mod columns;
mod constraints;
pub mod controller;
pub mod ffi;
mod trace;

#[derive(Default)]
pub struct ShaExtendChip<F>(PhantomData<F>);

#[derive(Default)]
pub struct ShaExtendControlChip<F>(PhantomData<F>);

pub fn sha_extend(w: &mut [u32]) {
    for i in 16..64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
}

#[cfg(test)]
pub mod tests;
