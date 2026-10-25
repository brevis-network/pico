use lazy_static::lazy_static;
use p3_field::PrimeCharacteristicRing;
use p3_koala_bear::{GenericPoseidon2LinearLayersKoalaBear, KoalaBear};
use std::borrow::BorrowMut;

use super::{
    columns::{RiscvPoseidon2ValueCols, RISCV_NUM_POSEIDON2_VALUE_COLS},
    traces::populate_perm_riscv,
};
use crate::{
    chips::gadgets::poseidon2::{
        columns::{Poseidon2ValueCols, NUM_POSEIDON2_VALUE_COLS},
        constants::RoundConstants,
        linear_layers::KoalaBearRiscvLinearLayers,
        traces::populate_perm,
    },
    primitives::consts::{KoalaBearConfig, PERMUTATION_WIDTH},
};

lazy_static! {
    /// Padding row of the full-width layout (`Poseidon2ValueCols`): the permutation of the zero
    /// state with `is_real = 0`, under the KoalaBear instance's round constants and the upstream
    /// linear layers. No production trace-gen reads it (both compute the full-width padding row
    /// themselves); it anchors the known-answer tests and the projection check of
    /// `RISCV_DUMMY_ROW_KB` below, which is generated with the riscv chip's own linear-layer type,
    /// so that check also compares the two linear-layer implementations.
    pub static ref DUMMY_ROW_KB: Vec<KoalaBear> = {
        let mut row = vec![KoalaBear::ZERO; NUM_POSEIDON2_VALUE_COLS::<KoalaBearConfig>];
        let cols: &mut Poseidon2ValueCols<KoalaBear, KoalaBearConfig> =
            row.as_mut_slice().borrow_mut();
        populate_perm::<KoalaBear, GenericPoseidon2LinearLayersKoalaBear, KoalaBearConfig>(
            KoalaBear::ZERO,
            cols,
            [KoalaBear::ZERO; PERMUTATION_WIDTH],
            None,
            &RoundConstants::default(),
        );
        row
    };
    /// Padding row of the riscv (rate-8) layout -- the CPU tracegen's dummy slot
    /// (`populate_perm_riscv` on the zero state), i.e. `DUMMY_ROW_KB` without the eight
    /// capacity-input zeros and without the nine uncommitted lanes of the last full round
    /// (`poseidon2_kat::kat_dummy_rows_koalabear` checks exactly this projection). Generated at
    /// first use so the two tracegens share one source.
    pub static ref RISCV_DUMMY_ROW_KB: Vec<KoalaBear> = {
        let mut row = vec![KoalaBear::ZERO; RISCV_NUM_POSEIDON2_VALUE_COLS::<KoalaBearConfig>];
        let cols: &mut RiscvPoseidon2ValueCols<KoalaBear, KoalaBearConfig> =
            row.as_mut_slice().borrow_mut();
        populate_perm_riscv::<KoalaBear, KoalaBearRiscvLinearLayers, KoalaBearConfig>(
            KoalaBear::ZERO,
            cols,
            [KoalaBear::ZERO; PERMUTATION_WIDTH],
            None,
            &RoundConstants::default(),
        );
        row
    };
}
