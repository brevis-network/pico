use super::{
    BABYBEAR_POSEIDON2_HD_COL_MAP, BABYBEAR_POSEIDON2_LD_COL_MAP, KOALABEAR_POSEIDON2_COL_MAP,
};
use crate::primitives::consts::{
    BABYBEAR_NUM_EXTERNAL_ROUNDS, BABYBEAR_NUM_INTERNAL_ROUNDS, KOALABEAR_NUM_EXTERNAL_ROUNDS,
    KOALABEAR_NUM_INTERNAL_ROUNDS, PERMUTATION_WIDTH,
};
use pico_derive::AlignedBorrow;
use std::{borrow::BorrowMut, mem::size_of};

#[derive(AlignedBorrow, Clone, Copy)]
#[repr(C)]
pub struct PermutationState<
    T: Copy,
    const NUM_EXTERNAL_ROUNDS: usize,
    const NUM_INTERNAL_ROUNDS_MINUS_ONE: usize,
> {
    pub external_rounds_state: [[T; PERMUTATION_WIDTH]; NUM_EXTERNAL_ROUNDS],
    pub internal_rounds_state: [T; PERMUTATION_WIDTH],
    pub internal_rounds_s0: [T; NUM_INTERNAL_ROUNDS_MINUS_ONE],
    pub output_state: [T; PERMUTATION_WIDTH],
}

#[derive(AlignedBorrow, Clone, Copy)]
#[repr(C)]
pub struct PermutationSBoxState<
    T: Copy,
    const NUM_EXTERNAL_ROUNDS: usize,
    const NUM_INTERNAL_ROUNDS: usize,
> {
    pub external_rounds_sbox_state: [[T; PERMUTATION_WIDTH]; NUM_EXTERNAL_ROUNDS],
    pub internal_rounds_sbox_state: [T; NUM_INTERNAL_ROUNDS],
}

/// Trait that describes getter functions for the permutation columns.
pub trait Poseidon2<
    T: Copy,
    const NUM_EXTERNAL_ROUNDS: usize,
    const NUM_INTERNAL_ROUNDS: usize,
    const NUM_INTERNAL_ROUNDS_MINUS_ONE: usize,
>
{
    fn external_rounds_state(&self) -> &[[T; PERMUTATION_WIDTH]];

    fn internal_rounds_state(&self) -> &[T; PERMUTATION_WIDTH];

    fn internal_rounds_s0(&self) -> &[T; NUM_INTERNAL_ROUNDS_MINUS_ONE];

    fn external_rounds_sbox(&self) -> Option<&[[T; PERMUTATION_WIDTH]; NUM_EXTERNAL_ROUNDS]>;

    fn internal_rounds_sbox(&self) -> Option<&[T; NUM_INTERNAL_ROUNDS]>;

    fn perm_output(&self) -> &[T; PERMUTATION_WIDTH];
}

/// Trait that describes setter functions for the permutation columns.
pub trait Poseidon2Mut<
    T: Copy,
    const NUM_EXTERNAL_ROUNDS: usize,
    const NUM_INTERNAL_ROUNDS: usize,
    const NUM_INTERNAL_ROUNDS_MINUS_ONE: usize,
>
{
    #[allow(clippy::type_complexity)]
    fn get_cols_mut(
        &mut self,
    ) -> (
        &mut [[T; PERMUTATION_WIDTH]],
        &mut [T; PERMUTATION_WIDTH],
        &mut [T; NUM_INTERNAL_ROUNDS_MINUS_ONE],
        Option<&mut [[T; PERMUTATION_WIDTH]; NUM_EXTERNAL_ROUNDS]>,
        Option<&mut [T; NUM_INTERNAL_ROUNDS]>,
        &mut [T; PERMUTATION_WIDTH],
    );
}

/// Permutation columns struct with S-boxes.
#[derive(AlignedBorrow, Clone, Copy)]
#[repr(C)]
pub struct PermutationSBox<
    T: Copy,
    const NUM_EXTERNAL_ROUNDS: usize,
    const NUM_INTERNAL_ROUNDS: usize,
    const NUM_INTERNAL_ROUNDS_MINUS_ONE: usize,
> {
    pub state: PermutationState<T, NUM_EXTERNAL_ROUNDS, NUM_INTERNAL_ROUNDS_MINUS_ONE>,
    pub sbox_state: PermutationSBoxState<T, NUM_EXTERNAL_ROUNDS, NUM_INTERNAL_ROUNDS>,
}

impl<
        T: Copy,
        const NUM_EXTERNAL_ROUNDS: usize,
        const NUM_INTERNAL_ROUNDS: usize,
        const NUM_INTERNAL_ROUNDS_MINUS_ONE: usize,
    > Poseidon2<T, NUM_EXTERNAL_ROUNDS, NUM_INTERNAL_ROUNDS, NUM_INTERNAL_ROUNDS_MINUS_ONE>
    for PermutationSBox<T, NUM_EXTERNAL_ROUNDS, NUM_INTERNAL_ROUNDS, NUM_INTERNAL_ROUNDS_MINUS_ONE>
{
    fn external_rounds_state(&self) -> &[[T; PERMUTATION_WIDTH]] {
        &self.state.external_rounds_state
    }

    fn internal_rounds_state(&self) -> &[T; PERMUTATION_WIDTH] {
        &self.state.internal_rounds_state
    }

    fn internal_rounds_s0(&self) -> &[T; NUM_INTERNAL_ROUNDS_MINUS_ONE] {
        &self.state.internal_rounds_s0
    }

    fn external_rounds_sbox(&self) -> Option<&[[T; PERMUTATION_WIDTH]; NUM_EXTERNAL_ROUNDS]> {
        Some(&self.sbox_state.external_rounds_sbox_state)
    }

    fn internal_rounds_sbox(&self) -> Option<&[T; NUM_INTERNAL_ROUNDS]> {
        Some(&self.sbox_state.internal_rounds_sbox_state)
    }

    fn perm_output(&self) -> &[T; PERMUTATION_WIDTH] {
        &self.state.output_state
    }
}

impl<
        T: Copy,
        const NUM_EXTERNAL_ROUNDS: usize,
        const NUM_INTERNAL_ROUNDS: usize,
        const NUM_INTERNAL_ROUNDS_MINUS_ONE: usize,
    > Poseidon2Mut<T, NUM_EXTERNAL_ROUNDS, NUM_INTERNAL_ROUNDS, NUM_INTERNAL_ROUNDS_MINUS_ONE>
    for PermutationSBox<T, NUM_EXTERNAL_ROUNDS, NUM_INTERNAL_ROUNDS, NUM_INTERNAL_ROUNDS_MINUS_ONE>
{
    fn get_cols_mut(
        &mut self,
    ) -> (
        &mut [[T; PERMUTATION_WIDTH]],
        &mut [T; PERMUTATION_WIDTH],
        &mut [T; NUM_INTERNAL_ROUNDS_MINUS_ONE],
        Option<&mut [[T; PERMUTATION_WIDTH]; NUM_EXTERNAL_ROUNDS]>,
        Option<&mut [T; NUM_INTERNAL_ROUNDS]>,
        &mut [T; PERMUTATION_WIDTH],
    ) {
        (
            &mut self.state.external_rounds_state,
            &mut self.state.internal_rounds_state,
            &mut self.state.internal_rounds_s0,
            Some(&mut self.sbox_state.external_rounds_sbox_state),
            Some(&mut self.sbox_state.internal_rounds_sbox_state),
            &mut self.state.output_state,
        )
    }
}

/// Permutation columns struct without S-boxes.
#[derive(AlignedBorrow, Clone, Copy)]
#[repr(C)]
pub struct PermutationNoSbox<
    T: Copy,
    const NUM_EXTERNAL_ROUNDS: usize,
    const NUM_INTERNAL_ROUNDS_MINUS_ONE: usize,
> {
    pub state: PermutationState<T, NUM_EXTERNAL_ROUNDS, NUM_INTERNAL_ROUNDS_MINUS_ONE>,
}

impl<
        T: Copy,
        const NUM_EXTERNAL_ROUNDS: usize,
        const NUM_INTERNAL_ROUNDS: usize,
        const NUM_INTERNAL_ROUNDS_MINUS_ONE: usize,
    > Poseidon2<T, NUM_EXTERNAL_ROUNDS, NUM_INTERNAL_ROUNDS, NUM_INTERNAL_ROUNDS_MINUS_ONE>
    for PermutationNoSbox<T, NUM_EXTERNAL_ROUNDS, NUM_INTERNAL_ROUNDS_MINUS_ONE>
{
    fn external_rounds_state(&self) -> &[[T; PERMUTATION_WIDTH]] {
        &self.state.external_rounds_state
    }

    fn internal_rounds_state(&self) -> &[T; PERMUTATION_WIDTH] {
        &self.state.internal_rounds_state
    }

    fn internal_rounds_s0(&self) -> &[T; NUM_INTERNAL_ROUNDS_MINUS_ONE] {
        &self.state.internal_rounds_s0
    }

    fn external_rounds_sbox(&self) -> Option<&[[T; PERMUTATION_WIDTH]; NUM_EXTERNAL_ROUNDS]> {
        None
    }

    fn internal_rounds_sbox(&self) -> Option<&[T; NUM_INTERNAL_ROUNDS]> {
        None
    }

    fn perm_output(&self) -> &[T; PERMUTATION_WIDTH] {
        &self.state.output_state
    }
}

impl<
        T: Copy,
        const NUM_EXTERNAL_ROUNDS: usize,
        const NUM_INTERNAL_ROUNDS: usize,
        const NUM_INTERNAL_ROUNDS_MINUS_ONE: usize,
    > Poseidon2Mut<T, NUM_EXTERNAL_ROUNDS, NUM_INTERNAL_ROUNDS, NUM_INTERNAL_ROUNDS_MINUS_ONE>
    for PermutationNoSbox<T, NUM_EXTERNAL_ROUNDS, NUM_INTERNAL_ROUNDS_MINUS_ONE>
{
    fn get_cols_mut(
        &mut self,
    ) -> (
        &mut [[T; PERMUTATION_WIDTH]],
        &mut [T; PERMUTATION_WIDTH],
        &mut [T; NUM_INTERNAL_ROUNDS_MINUS_ONE],
        Option<&mut [[T; PERMUTATION_WIDTH]; NUM_EXTERNAL_ROUNDS]>,
        Option<&mut [T; NUM_INTERNAL_ROUNDS]>,
        &mut [T; PERMUTATION_WIDTH],
    ) {
        (
            &mut self.state.external_rounds_state,
            &mut self.state.internal_rounds_state,
            &mut self.state.internal_rounds_s0,
            None,
            None,
            &mut self.state.output_state,
        )
    }
}

// ... existing code ...

pub fn babybear_permutation_mut<
    'a,
    'b: 'a,
    T,
    const DEGREE: usize,
    const NUM_EXTERNAL_ROUNDS: usize,
    const NUM_INTERNAL_ROUNDS: usize,
    const NUM_INTERNAL_ROUNDS_MINUS_ONE: usize,
>(
    row: &'b mut [T],
) -> &'b mut (dyn Poseidon2Mut<
    T,
    NUM_EXTERNAL_ROUNDS,
    NUM_INTERNAL_ROUNDS,
    NUM_INTERNAL_ROUNDS_MINUS_ONE,
> + 'a)
where
    T: Copy,
{
    assert_eq!(NUM_EXTERNAL_ROUNDS, BABYBEAR_NUM_EXTERNAL_ROUNDS);
    assert_eq!(NUM_INTERNAL_ROUNDS, BABYBEAR_NUM_INTERNAL_ROUNDS);

    if DEGREE == 3 {
        let start = BABYBEAR_POSEIDON2_LD_COL_MAP.state.external_rounds_state[0][0];
        let end = start
            + size_of::<
                PermutationSBox<
                    u8,
                    NUM_EXTERNAL_ROUNDS,
                    NUM_INTERNAL_ROUNDS,
                    NUM_INTERNAL_ROUNDS_MINUS_ONE,
                >,
            >();
        let convert: &mut PermutationSBox<
            T,
            NUM_EXTERNAL_ROUNDS,
            NUM_INTERNAL_ROUNDS,
            NUM_INTERNAL_ROUNDS_MINUS_ONE,
        > = row[start..end].borrow_mut();
        convert
    } else if DEGREE == 9 {
        let start = BABYBEAR_POSEIDON2_HD_COL_MAP.state.external_rounds_state[0][0];
        let end = start
            + size_of::<PermutationNoSbox<u8, NUM_EXTERNAL_ROUNDS, NUM_INTERNAL_ROUNDS_MINUS_ONE>>(
            );
        let convert: &mut PermutationNoSbox<T, NUM_EXTERNAL_ROUNDS, NUM_INTERNAL_ROUNDS_MINUS_ONE> =
            row[start..end].borrow_mut();
        convert
    } else {
        panic!("Unsupported degree");
    }
}

pub fn koalabear_permutation_mut<
    'a,
    'b: 'a,
    T,
    const DEGREE: usize,
    const NUM_EXTERNAL_ROUNDS: usize,
    const NUM_INTERNAL_ROUNDS: usize,
    const NUM_INTERNAL_ROUNDS_MINUS_ONE: usize,
>(
    row: &'b mut [T],
) -> &'b mut (dyn Poseidon2Mut<
    T,
    NUM_EXTERNAL_ROUNDS,
    NUM_INTERNAL_ROUNDS,
    NUM_INTERNAL_ROUNDS_MINUS_ONE,
> + 'a)
where
    T: Copy,
{
    assert_eq!(NUM_EXTERNAL_ROUNDS, KOALABEAR_NUM_EXTERNAL_ROUNDS);
    assert_eq!(NUM_INTERNAL_ROUNDS, KOALABEAR_NUM_INTERNAL_ROUNDS);

    let start = KOALABEAR_POSEIDON2_COL_MAP.state.external_rounds_state[0][0];
    let end = start
        + size_of::<PermutationNoSbox<u8, NUM_EXTERNAL_ROUNDS, NUM_INTERNAL_ROUNDS_MINUS_ONE>>();
    let convert: &mut PermutationNoSbox<T, NUM_EXTERNAL_ROUNDS, NUM_INTERNAL_ROUNDS_MINUS_ONE> =
        row[start..end].borrow_mut();
    convert
}

// ... existing code ...
