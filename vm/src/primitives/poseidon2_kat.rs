//! Known-answer and algorithm-identity tests for the riscv-stage Poseidon2 instances: the AIR
//! gadget (`chips::gadgets::poseidon2`), the host permutation
//! (`FieldSpecificPoseidon2Config::permutation`), hash-to-curve,
//! the deferred-proof digest and the padding rows.
//!
//! Two questions are answered independently of each other:
//!
//! - `gadget_matches_host_permutation_*`: the gadget's trace populate reproduces the Plonky3
//!   permutation built from the *same* round constants. This is the algorithm identity under
//!   the constants the chips currently use.
//! - `gadget_with_plonky3_constants_matches_plonky3_vector_*`: the gadget fed with Plonky3 0.5.4's
//!   own round constants reproduces Plonky3's published width-16 test vectors. This shows the
//!   gadget implements Plonky3's algorithm (linear layers, S-box, round structure) and that only
//!   the constants can differ. Only the constants are non-production: it drives the same
//!   `populate_perm` the chips do.
//!
//! The `kat_*` tests pin the current outputs of every outlet so that a refactor is provably
//! behaviour-identical and a constant change is visible in exactly the places it should be.

use std::borrow::BorrowMut;

use hybrid_array::Array;
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_koala_bear::{
    default_koalabear_poseidon2_16, KoalaBear, KOALABEAR_POSEIDON2_RC_16_EXTERNAL_FINAL,
    KOALABEAR_POSEIDON2_RC_16_EXTERNAL_INITIAL, KOALABEAR_POSEIDON2_RC_16_INTERNAL,
};
use p3_symmetric::Permutation;

use crate::{
    chips::{
        chips::riscv_poseidon2::{
            columns::{RiscvPoseidon2ValueCols, RISCV_NUM_POSEIDON2_VALUE_COLS},
            dummy_row::{DUMMY_ROW_KB, RISCV_DUMMY_ROW_KB},
            traces::populate_perm_riscv,
        },
        gadgets::poseidon2::{
            columns::{Poseidon2ValueCols, NUM_POSEIDON2_VALUE_COLS},
            constants::RoundConstants,
            traces::populate_perm,
        },
    },
    machine::{field::FieldSpecificPoseidon2Config, septic::SepticCurve},
    primitives::{
        consts::{KoalaBearConfig, PERMUTATION_WIDTH},
        hash_deferred_proof,
    },
};

fn seq<F: PrimeCharacteristicRing, const N: usize>(start: u32) -> [F; N] {
    core::array::from_fn(|i| F::from_u32(start + i as u32))
}

fn canon<F: PrimeField32, const N: usize>(xs: [F; N]) -> [u32; N] {
    xs.map(|x| x.as_canonical_u32())
}

/// Runs the full-width gadget on `input` with `constants` and returns the permutation output
/// (the post-state of the last ending full round).
fn gadget_permute<F>(
    constants: &RoundConstants<F, F::Poseidon2Config>,
    input: [F; PERMUTATION_WIDTH],
) -> [F; PERMUTATION_WIDTH]
where
    F: FieldSpecificPoseidon2Config + PrimeField32,
{
    let mut row = vec![F::ZERO; NUM_POSEIDON2_VALUE_COLS::<F::Poseidon2Config>];
    let cols: &mut Poseidon2ValueCols<F, F::Poseidon2Config> = row.as_mut_slice().borrow_mut();
    populate_perm::<F, F::LinearLayers, F::Poseidon2Config>(F::ONE, cols, input, None, constants);
    cols.ending_full_rounds
        .last()
        .expect("at least one ending full round")
        .post
}

/// Order-independent, Poseidon2-independent fingerprint of a row: length and a weighted sum of
/// the canonical values. Used for the padding rows, which are several hundred elements long.
fn row_fingerprint<F: PrimeField32>(row: &[F]) -> (usize, u64) {
    let fold = row.iter().enumerate().fold(0u64, |acc, (i, x)| {
        acc.wrapping_add((i as u64 + 1).wrapping_mul(x.as_canonical_u32() as u64))
    });
    (row.len(), fold)
}

fn gadget_matches_host_permutation<F>()
where
    F: FieldSpecificPoseidon2Config + PrimeField32,
{
    let constants = RoundConstants::<F, F::Poseidon2Config>::default();
    let perm = F::permutation();
    for start in [0u32, 1, 4096, 1 << 30] {
        let input: [F; PERMUTATION_WIDTH] = seq(start);
        assert_eq!(
            gadget_permute(&constants, input),
            perm.permute(input),
            "gadget vs host permutation diverged on input starting at {start}"
        );
    }
}

#[test]
fn gadget_matches_host_permutation_koalabear() {
    gadget_matches_host_permutation::<KoalaBear>();
}

/// The riscv rate-8 layout runs the same rounds on a state whose capacity lanes are zero.
#[test]
fn riscv_gadget_matches_host_permutation_koalabear() {
    type F = KoalaBear;
    type LinearLayers = <F as FieldSpecificPoseidon2Config>::RiscvLinearLayers;
    let constants = RoundConstants::<F, KoalaBearConfig>::default();
    let perm = F::permutation();
    for start in [0u32, 7, 1 << 20] {
        let mut input = [F::ZERO; PERMUTATION_WIDTH];
        for (i, lane) in input.iter_mut().take(8).enumerate() {
            *lane = F::from_u32(start + i as u32);
        }
        let mut row = vec![F::ZERO; RISCV_NUM_POSEIDON2_VALUE_COLS::<KoalaBearConfig>];
        let cols: &mut RiscvPoseidon2ValueCols<F, KoalaBearConfig> =
            row.as_mut_slice().borrow_mut();
        // `populate_perm_riscv` asserts the computed output against `expected_output`.
        populate_perm_riscv::<F, LinearLayers, KoalaBearConfig>(
            F::ONE,
            cols,
            input,
            Some(perm.permute(input)),
            &constants,
        );
    }
}

/// Plonky3's `test_default_koalabear_poseidon2_width_16` input.
const PLONKY3_INPUT: [u32; 16] = [
    894848333, 1437655012, 1200606629, 1690012884, 71131202, 1749206695, 1717947831, 120589055,
    19776022, 42382981, 1831865506, 724844064, 171220207, 1299207443, 227047920, 1783754913,
];
/// Plonky3's `test_default_koalabear_poseidon2_width_16` expected output.
const PLONKY3_KOALABEAR_OUTPUT: [u32; 16] = [
    1934285469, 604889435, 133449501, 1026180808, 1830659359, 176667110, 1391183747, 351743874,
    1238264085, 1292768839, 2023573270, 1201586780, 1360691759, 1230682461, 748270449, 651545025,
];

fn plonky3_constants_koalabear() -> RoundConstants<KoalaBear, KoalaBearConfig> {
    RoundConstants {
        beginning_full_round_constants: Array::from(KOALABEAR_POSEIDON2_RC_16_EXTERNAL_INITIAL),
        partial_round_constants: Array::from(KOALABEAR_POSEIDON2_RC_16_INTERNAL),
        ending_full_round_constants: Array::from(KOALABEAR_POSEIDON2_RC_16_EXTERNAL_FINAL),
    }
}

#[test]
fn gadget_with_plonky3_constants_matches_plonky3_vector_koalabear() {
    let input = PLONKY3_INPUT.map(KoalaBear::from_u32);
    assert_eq!(
        canon(default_koalabear_poseidon2_16().permute(input)),
        PLONKY3_KOALABEAR_OUTPUT
    );
    assert_eq!(
        canon(gadget_permute(&plonky3_constants_koalabear(), input)),
        PLONKY3_KOALABEAR_OUTPUT
    );
}

/// One round constant off by one must be visible in the gadget's output.
#[test]
fn gadget_detects_a_perturbed_round_constant() {
    let input = PLONKY3_INPUT.map(KoalaBear::from_u32);
    let mut constants = plonky3_constants_koalabear();
    constants.partial_round_constants[7] += KoalaBear::ONE;
    assert_ne!(
        canon(gadget_permute(&constants, input)),
        PLONKY3_KOALABEAR_OUTPUT
    );
}

// Pinned outputs of the outlets under Plonky3 0.5.4's instances: the permutation of 0..16, the
// hash-to-curve of 1..=8, the deferred-proof digest of 1..=48, and the two padding rows.
// A deliberate constant change re-pins them; nothing else may move them.

const KAT_PERMUTATION_KOALABEAR: [u32; 16] = [
    1259554834, 663463928, 1989430097, 476523442, 836740795, 1803459961, 1229318262, 2023956904,
    2054405130, 1556655036, 1455339712, 1471465890, 423337459, 353979748, 1203410294, 1592576868,
];
const KAT_LIFT_X_OFFSET: u8 = 1;
const KAT_LIFT_X_X: [u32; 7] = [
    713599412, 1927342453, 1421246254, 685920917, 181057545, 1075390513, 1320102087,
];
const KAT_LIFT_X_HASH: [u32; 16] = [
    713599412, 1927342453, 1421246254, 685920917, 181057545, 1075390513, 1320102087, 1377363825,
    1622498141, 1049406434, 235339590, 972553474, 1566684284, 1574094940, 33467439, 1963705452,
];
const KAT_HASH_DEFERRED_PROOF: [u32; 8] = [
    184493143, 734763323, 559066146, 797564627, 968271056, 2011893203, 1492992321, 307463095,
];
const KAT_DUMMY_ROW_KB: (usize, u64) = (165, 15185852523920);
/// Columns of the riscv (rate-8) padding row: `DUMMY_ROW_KB` without the eight capacity-input
/// zeros and without the nine uncommitted lanes of the last full round
/// (1 + 8 + 4·16 + 20 + 3·16 + 7).
const KAT_RISCV_DUMMY_ROW_LEN: usize = 148;
#[test]
fn kat_permutation_koalabear() {
    let actual = canon(KoalaBear::permutation().permute(seq::<KoalaBear, 16>(0)));
    assert_eq!(actual, KAT_PERMUTATION_KOALABEAR, "actual = {actual:?}");
}

#[test]
fn kat_hash_to_curve_koalabear() {
    let (point, offset, _m_trial, m_hash) = SepticCurve::<KoalaBear>::lift_x(seq(1));
    let actual = (offset, canon(point.x.0), canon(m_hash));
    assert_eq!(
        actual,
        (KAT_LIFT_X_OFFSET, KAT_LIFT_X_X, KAT_LIFT_X_HASH),
        "actual = {actual:?}"
    );
}

#[test]
fn kat_hash_deferred_proof_koalabear() {
    let prev: [KoalaBear; 8] = seq(1);
    let vk: [KoalaBear; 8] = seq(9);
    let pv: [KoalaBear; 32] = seq(17);
    let actual = canon(hash_deferred_proof(&prev, &vk, &pv));
    assert_eq!(actual, KAT_HASH_DEFERRED_PROOF, "actual = {actual:?}");
}

/// The full-width padding row is pinned by fingerprint; the riscv padding row must be exactly its
/// projection: drop `inputs[8..16]` (cells 9..17) and `ending_full_rounds[3].post[7..16]` (the
/// last nine cells). This is the column-level statement that the riscv padding row commits exactly
/// a subset of the full-width witness; that no constraint reads the dropped lanes is a separate,
/// constraint-level fact (the riscv chip's round driver asserts only the committed lanes).
#[test]
fn kat_dummy_rows_koalabear() {
    let actual = row_fingerprint(&DUMMY_ROW_KB[..]);
    assert_eq!(actual, KAT_DUMMY_ROW_KB, "actual = {actual:?}");

    let full = &DUMMY_ROW_KB[..];
    let projected: Vec<KoalaBear> = full[..1 + 8]
        .iter()
        .chain(&full[1 + PERMUTATION_WIDTH..full.len() - (PERMUTATION_WIDTH - 7)])
        .copied()
        .collect();
    assert_eq!(projected.len(), KAT_RISCV_DUMMY_ROW_LEN);
    assert_eq!(RISCV_DUMMY_ROW_KB.len(), KAT_RISCV_DUMMY_ROW_LEN);
    assert_eq!(RISCV_DUMMY_ROW_KB[..], projected[..]);
}
