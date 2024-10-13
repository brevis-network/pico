#![allow(clippy::needless_range_loop)]

use std::{
    borrow::{Borrow, BorrowMut},
    marker::PhantomData,
    ops::Deref,
};

use p3_baby_bear::{MONTY_INVERSE, POSEIDON2_INTERNAL_MATRIX_DIAG_16_BABYBEAR_MONTY};
use p3_field::{AbstractField, Field, PrimeField32};

pub mod air;
pub mod columns;
pub mod events;
pub mod trace;

use p3_poseidon2::matmul_internal;

use self::columns::{Poseidon2, Poseidon2Degree3, Poseidon2Degree9, Poseidon2Mut};

/// The width of the permutation.
pub const WIDTH: usize = 16;
pub const RATE: usize = WIDTH / 2;

pub const NUM_EXTERNAL_ROUNDS: usize = 8;
pub const NUM_INTERNAL_ROUNDS: usize = 13;
pub const NUM_ROUNDS: usize = NUM_EXTERNAL_ROUNDS + NUM_INTERNAL_ROUNDS;

/// A chip that implements addition for the opcode ADD.
#[derive(Default)]
pub struct Poseidon2WideChip<const DEGREE: usize, F> {
    pub fixed_log2_rows: Option<usize>,
    pub pad: bool,
    pub _phantom: PhantomData<F>,
}

impl<'a, const DEGREE: usize, F: Field> Poseidon2WideChip<DEGREE, F> {
    /// Transmute a row it to an immutable Poseidon2 instance.
    pub(crate) fn convert<T>(row: impl Deref<Target = [T]>) -> Box<dyn Poseidon2<'a, T> + 'a>
    where
        T: Copy + 'a,
    {
        if DEGREE == 3 {
            let convert: &Poseidon2Degree3<T> = (*row).borrow();
            Box::new(*convert)
        } else if DEGREE == 9 || DEGREE == 17 {
            let convert: &Poseidon2Degree9<T> = (*row).borrow();
            Box::new(*convert)
        } else {
            panic!("Unsupported degree");
        }
    }

    /// Transmute a row it to a mutable Poseidon2 instance.
    pub(crate) fn convert_mut<'b: 'a>(
        &self,
        row: &'b mut [F],
    ) -> Box<dyn Poseidon2Mut<'a, F> + 'a> {
        if DEGREE == 3 {
            let convert: &mut Poseidon2Degree3<F> = row.borrow_mut();
            Box::new(convert)
        } else if DEGREE == 9 || DEGREE == 17 {
            let convert: &mut Poseidon2Degree9<F> = row.borrow_mut();
            Box::new(convert)
        } else {
            panic!("Unsupported degree");
        }
    }
}

pub fn apply_m_4<AF>(x: &mut [AF])
where
    AF: AbstractField,
{
    let t01 = x[0].clone() + x[1].clone();
    let t23 = x[2].clone() + x[3].clone();
    let t0123 = t01.clone() + t23.clone();
    let t01123 = t0123.clone() + x[1].clone();
    let t01233 = t0123.clone() + x[3].clone();
    // The order here is important. Need to overwrite x[0] and x[2] after x[1] and x[3].
    x[3] = t01233.clone() + x[0].double(); // 3*x[0] + x[1] + x[2] + 2*x[3]
    x[1] = t01123.clone() + x[2].double(); // x[0] + 2*x[1] + 3*x[2] + x[3]
    x[0] = t01123 + t01; // 2*x[0] + 3*x[1] + x[2] + x[3]
    x[2] = t01233 + t23; // x[0] + x[1] + 2*x[2] + 3*x[3]
}

pub(crate) fn external_linear_layer<AF: AbstractField>(state: &mut [AF; WIDTH]) {
    for j in (0..WIDTH).step_by(4) {
        apply_m_4(&mut state[j..j + 4]);
    }
    let sums: [AF; 4] = core::array::from_fn(|k| {
        (0..WIDTH)
            .step_by(4)
            .map(|j| state[j + k].clone())
            .sum::<AF>()
    });

    for j in 0..WIDTH {
        state[j] += sums[j % 4].clone();
    }
}

pub(crate) fn internal_linear_layer<F: AbstractField>(state: &mut [F; WIDTH]) {
    let matmul_constants: [<F as AbstractField>::F; WIDTH] =
        POSEIDON2_INTERNAL_MATRIX_DIAG_16_BABYBEAR_MONTY
            .iter()
            .map(|x| <F as AbstractField>::F::from_wrapped_u32(x.as_canonical_u32()))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
    matmul_internal(state, matmul_constants);
    let monty_inverse = F::from_wrapped_u32(MONTY_INVERSE.as_canonical_u32());
    state.iter_mut().for_each(|i| *i *= monty_inverse.clone());
}
