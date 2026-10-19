//! Known-answer tests for the Poseidon2 instances the MLE stack is built on (permutation, Merkle
//! hasher, compressor). They pin the exact outputs so that a change of Plonky3 version, of the
//! round constants or of the sponge wiring is caught here, independently of the transcript
//! fingerprint and the vk pre-hashes. The permutation is Plonky3 0.5's
//! `default_koalabear_poseidon2_16` (cross-checked against upstream's own vector below).

use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_symmetric::Permutation;

use crate::config::hasher::MerkleHasher;

fn seq<F: PrimeCharacteristicRing, const N: usize>(start: u32) -> [F; N] {
    core::array::from_fn(|i| F::from_u32(start + i as u32))
}

fn canon<F: PrimeField32, const N: usize>(xs: [F; N]) -> [u32; N] {
    xs.map(|x| x.as_canonical_u32())
}

/// Permutation of 0..16, hasher over 1..=20, compressor of (1..=8, 9..=16), and the
/// capacity-carrying compress.
#[derive(Debug, PartialEq, Eq)]
struct Vectors {
    permutation: [u32; 16],
    hash_slice: [u32; 8],
    compress: [u32; 8],
    compress_with_capacity: ([u32; 8], [u32; 8]),
}

fn kb_vectors() -> Vectors {
    use crate::config::koala_bear_poseidon2::{
        default_koalabear_hasher, default_koalabear_poseidon2_16, poseidon2_compress_with_capacity,
        F,
    };
    let perm = default_koalabear_poseidon2_16();
    let mut state: [F; 16] = seq(0);
    perm.permute_mut(&mut state);
    let hasher = default_koalabear_hasher();
    let msg: [F; 20] = seq(1);
    let (l, r) = poseidon2_compress_with_capacity(seq(1), seq(9));
    Vectors {
        permutation: canon(state),
        hash_slice: canon(hasher.hash_slice(&msg)),
        compress: canon(hasher.compress(seq(1), seq(9))),
        compress_with_capacity: (canon(l), canon(r)),
    }
}

/// Pinned on Plonky3 0.5.4 (`default_koalabear_poseidon2_16`, the round constants Plonky3 #1398
/// corrected). The permutation half is cross-checked against Plonky3's own test vector below.
#[test]
fn kb_poseidon2_known_answers() {
    let v = kb_vectors();
    // The compressor is the first half of the same permutation; the capacity half is what the
    // GPU sponge kernels carry along.
    assert_eq!(v.compress_with_capacity.0, v.compress);
    assert_eq!(
        v,
        Vectors {
            permutation: [
                1259554834, 663463928, 1989430097, 476523442, 836740795, 1803459961, 1229318262,
                2023956904, 2054405130, 1556655036, 1455339712, 1471465890, 423337459, 353979748,
                1203410294, 1592576868
            ],
            hash_slice: [
                210648391, 1164046507, 456567629, 507746877, 1097177737, 191726484, 70678446,
                882479225
            ],
            compress: [
                1371112431, 1393558871, 1976442961, 1730918830, 749302612, 2033925358, 1522282530,
                1526670208
            ],
            compress_with_capacity: (
                [
                    1371112431, 1393558871, 1976442961, 1730918830, 749302612, 2033925358,
                    1522282530, 1526670208
                ],
                [
                    1199443128, 1595506622, 1212006516, 1201894165, 1396886514, 139943261,
                    121014419, 1451683053
                ]
            ),
        }
    );
}

/// Plonky3's `test_default_koalabear_poseidon2_width_16` vector, replayed through the instance the
/// MLE config exposes — the permutation this crate hashes and Fiat-Shamirs with is upstream's.
#[test]
fn kb_poseidon2_matches_plonky3_vector() {
    use crate::config::koala_bear_poseidon2::{default_koalabear_poseidon2_16, F};
    let mut input: [F; 16] = [
        894848333, 1437655012, 1200606629, 1690012884, 71131202, 1749206695, 1717947831, 120589055,
        19776022, 42382981, 1831865506, 724844064, 171220207, 1299207443, 227047920, 1783754913,
    ]
    .map(F::from_u32);
    default_koalabear_poseidon2_16().permute_mut(&mut input);
    assert_eq!(
        canon(input),
        [
            1934285469, 604889435, 133449501, 1026180808, 1830659359, 176667110, 1391183747,
            351743874, 1238264085, 1292768839, 2023573270, 1201586780, 1360691759, 1230682461,
            748270449, 651545025,
        ]
    );
}
