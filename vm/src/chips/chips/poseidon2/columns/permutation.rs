use super::{
    BABYBEAR_POSEIDON2_HD_COL_MAP, BABYBEAR_POSEIDON2_LD_COL_MAP, KOALABEAR_POSEIDON2_COL_MAP,
};
use crate::{
    configs::config::Poseidon2Config,
    primitives::consts::{BabyBearConfig, KoalaBearConfig, PERMUTATION_WIDTH},
};
use hybrid_array::{Array, ArraySize};
use pico_derive::AlignedBorrow;
use std::{borrow::BorrowMut, mem::size_of};

type ArrayType<T, N> = <N as ArraySize>::ArrayType<T>;
type Perm<T> = [T; PERMUTATION_WIDTH];

#[derive(AlignedBorrow, Clone)]
#[repr(C)]
pub struct PermutationState<T, Config: Poseidon2Config> {
    pub external_rounds_state: Array<Perm<T>, Config::ExternalRounds>,
    pub internal_rounds_state: Perm<T>,
    pub internal_rounds_s0: Array<T, Config::InternalRoundsM1>,
    pub output_state: Perm<T>,
}

impl<T, Config> Copy for PermutationState<T, Config>
where
    T: Copy,
    Config: Poseidon2Config,
    ArrayType<Perm<T>, Config::ExternalRounds>: Copy,
    ArrayType<T, Config::InternalRoundsM1>: Copy,
{
}

#[derive(AlignedBorrow, Clone)]
#[repr(C)]
pub struct PermutationSBoxState<T, Config: Poseidon2Config> {
    pub external_rounds_sbox_state: Array<Perm<T>, Config::ExternalRounds>,
    pub internal_rounds_sbox_state: Array<T, Config::InternalRounds>,
}

impl<T, Config> Copy for PermutationSBoxState<T, Config>
where
    T: Copy,
    Config: Poseidon2Config,
    ArrayType<Perm<T>, Config::ExternalRounds>: Copy,
    ArrayType<T, Config::InternalRounds>: Copy,
{
}

/// Trait that describes getter functions for the permutation columns.
pub trait Poseidon2<T, Config: Poseidon2Config> {
    fn external_rounds_state(&self) -> &[Perm<T>];

    fn internal_rounds_state(&self) -> &Perm<T>;

    fn internal_rounds_s0(&self) -> &Array<T, Config::InternalRoundsM1>;

    fn external_rounds_sbox(&self) -> Option<&Array<Perm<T>, Config::ExternalRounds>>;

    fn internal_rounds_sbox(&self) -> Option<&Array<T, Config::InternalRounds>>;

    fn perm_output(&self) -> &Perm<T>;
}

/// Trait that describes setter functions for the permutation columns.
pub trait Poseidon2Mut<T, Config: Poseidon2Config> {
    #[allow(clippy::type_complexity)]
    fn get_cols_mut(
        &mut self,
    ) -> (
        &mut [Perm<T>],
        &mut Perm<T>,
        &mut Array<T, Config::InternalRoundsM1>,
        Option<&mut Array<Perm<T>, Config::ExternalRounds>>,
        Option<&mut Array<T, Config::InternalRounds>>,
        &mut Perm<T>,
    );
}

/// Permutation columns struct with S-boxes.
#[derive(AlignedBorrow, Clone)]
#[repr(C)]
pub struct PermutationSBox<T, Config: Poseidon2Config> {
    pub state: PermutationState<T, Config>,
    pub sbox_state: PermutationSBoxState<T, Config>,
}

impl<T, Config> Copy for PermutationSBox<T, Config>
where
    T: Copy,
    Config: Poseidon2Config,
    ArrayType<Perm<T>, Config::ExternalRounds>: Copy,
    ArrayType<T, Config::InternalRounds>: Copy,
    ArrayType<T, Config::InternalRoundsM1>: Copy,
{
}

impl<T, Config: Poseidon2Config> Poseidon2<T, Config> for PermutationSBox<T, Config> {
    fn external_rounds_state(&self) -> &[Perm<T>] {
        &self.state.external_rounds_state
    }

    fn internal_rounds_state(&self) -> &Perm<T> {
        &self.state.internal_rounds_state
    }

    fn internal_rounds_s0(&self) -> &Array<T, Config::InternalRoundsM1> {
        &self.state.internal_rounds_s0
    }

    fn external_rounds_sbox(&self) -> Option<&Array<Perm<T>, Config::ExternalRounds>> {
        Some(&self.sbox_state.external_rounds_sbox_state)
    }

    fn internal_rounds_sbox(&self) -> Option<&Array<T, Config::InternalRounds>> {
        Some(&self.sbox_state.internal_rounds_sbox_state)
    }

    fn perm_output(&self) -> &Perm<T> {
        &self.state.output_state
    }
}

impl<T, Config: Poseidon2Config> Poseidon2Mut<T, Config> for PermutationSBox<T, Config> {
    fn get_cols_mut(
        &mut self,
    ) -> (
        &mut [Perm<T>],
        &mut Perm<T>,
        &mut Array<T, Config::InternalRoundsM1>,
        Option<&mut Array<Perm<T>, Config::ExternalRounds>>,
        Option<&mut Array<T, Config::InternalRounds>>,
        &mut Perm<T>,
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
#[derive(AlignedBorrow, Clone)]
#[repr(C)]
pub struct PermutationNoSbox<T, Config: Poseidon2Config> {
    pub state: PermutationState<T, Config>,
}

impl<T, Config> Copy for PermutationNoSbox<T, Config>
where
    T: Copy,
    Config: Poseidon2Config,
    ArrayType<Perm<T>, Config::ExternalRounds>: Copy,
    ArrayType<T, Config::InternalRoundsM1>: Copy,
{
}

impl<T, Config: Poseidon2Config> Poseidon2<T, Config> for PermutationNoSbox<T, Config> {
    fn external_rounds_state(&self) -> &[Perm<T>] {
        &self.state.external_rounds_state
    }

    fn internal_rounds_state(&self) -> &Perm<T> {
        &self.state.internal_rounds_state
    }

    fn internal_rounds_s0(&self) -> &Array<T, Config::InternalRoundsM1> {
        &self.state.internal_rounds_s0
    }

    fn external_rounds_sbox(&self) -> Option<&Array<Perm<T>, Config::ExternalRounds>> {
        None
    }

    fn internal_rounds_sbox(&self) -> Option<&Array<T, Config::InternalRounds>> {
        None
    }

    fn perm_output(&self) -> &Perm<T> {
        &self.state.output_state
    }
}

impl<T, Config: Poseidon2Config> Poseidon2Mut<T, Config> for PermutationNoSbox<T, Config> {
    fn get_cols_mut(
        &mut self,
    ) -> (
        &mut [Perm<T>],
        &mut Perm<T>,
        &mut Array<T, Config::InternalRoundsM1>,
        Option<&mut Array<Perm<T>, Config::ExternalRounds>>,
        Option<&mut Array<T, Config::InternalRounds>>,
        &mut Perm<T>,
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

pub fn babybear_permutation_mut<T, const DEGREE: usize>(
    row: &mut [T],
) -> &mut (dyn Poseidon2Mut<T, BabyBearConfig>) {
    let start;
    let len;

    if DEGREE == 3 {
        start = BABYBEAR_POSEIDON2_LD_COL_MAP.state.external_rounds_state[0][0];
        len = size_of::<PermutationSBox<u8, BabyBearConfig>>();
        let convert: &mut PermutationSBox<T, BabyBearConfig> = row[start..start + len].borrow_mut();
        convert
    } else if DEGREE == 9 {
        start = BABYBEAR_POSEIDON2_HD_COL_MAP.state.external_rounds_state[0][0];
        len = size_of::<PermutationNoSbox<u8, BabyBearConfig>>();
        let convert: &mut PermutationNoSbox<T, BabyBearConfig> =
            row[start..start + len].borrow_mut();
        convert
    } else {
        panic!("Unsupported degree")
    }
}

pub fn koalabear_permutation_mut<T, const _DEGREE: usize>(
    row: &mut [T],
) -> &mut (dyn Poseidon2Mut<T, KoalaBearConfig>) {
    let start = KOALABEAR_POSEIDON2_COL_MAP.state.external_rounds_state[0][0];
    let len = size_of::<PermutationNoSbox<u8, KoalaBearConfig>>();
    let convert: &mut PermutationNoSbox<T, KoalaBearConfig> = row[start..start + len].borrow_mut();
    convert
}
