//! Known answers for every hook in [`default_hook_map`].
//!
//! The guest decides how many values to read next from a hook's first answer and constrains the
//! rest, so a changed answer sends it down another path, or to a proof that cannot be satisfied.
//! The decompression hint's protocol is tested beside its chip, in
//! `chips::precompiles::edwards::tests`; it appears here for the requests those tests leave out.

use super::{
    default_hook_map, FD_BLS12_381_INVERSE, FD_BLS12_381_SQRT, FD_EDDECOMPRESS, FD_FP_INV,
    FD_FP_SQRT, SECP256K1_ECRECOVER,
};
use crate::chips::gadgets::{
    curves::{
        edwards::{
            ed25519::{Ed25519BaseField, Ed25519Parameters},
            EdwardsParameters,
        },
        weierstrass::{
            bls381::Bls381BaseField,
            secp256k1::{Secp256k1BaseField, Secp256k1Parameters},
            WeierstrassParameters,
        },
    },
    utils::field_params::FieldParameters,
};
use num_bigint::BigUint;
use num_traits::{One, Zero};
use std::panic::catch_unwind;

/// A request, and the answer it must get; `None` for a request the hook must refuse by panicking.
type Case = (Vec<u8>, Option<Vec<Vec<u8>>>);

/// The fds are protocol, shared with the guest's `sdk/patch-libs/src/io.rs`: renumbering one here
/// strands every guest built against it.
#[test]
fn the_default_hook_map_serves_exactly_the_hook_fds() {
    let mut served: Vec<u32> = default_hook_map().keys().copied().collect();
    served.sort_unstable();
    assert_eq!(served, [5, 8, 10, 11, 12, 13]);
}

#[test]
fn every_hook_gives_its_known_answers() {
    let hooks = default_hook_map();
    let cases = [
        (SECP256K1_ECRECOVER, ecrecover_cases()),
        (FD_EDDECOMPRESS, ed_decompress_cases()),
        (FD_FP_SQRT, fp_sqrt_cases()),
        (FD_FP_INV, fp_inverse_cases()),
        (FD_BLS12_381_SQRT, bls12_381_sqrt_cases()),
        (FD_BLS12_381_INVERSE, bls12_381_inverse_cases()),
    ];

    let mut covered: Vec<u32> = cases.iter().map(|(fd, _)| *fd).collect();
    covered.sort_unstable();
    let mut served: Vec<u32> = hooks.keys().copied().collect();
    served.sort_unstable();
    assert_eq!(covered, served, "every served fd needs known answers here");

    for (fd, cases) in &cases {
        let hook = hooks[fd];
        for (i, (request, expected)) in cases.iter().enumerate() {
            match (catch_unwind(|| hook(request)), expected) {
                (Ok(answer), Some(expected)) => {
                    assert_eq!(&answer, expected, "fd {fd}, case {i}: wrong answer")
                }
                (Err(_), None) => {}
                (Ok(answer), None) => {
                    panic!("fd {fd}, case {i}: answered {answer:?} where it must refuse")
                }
                (Err(_), Some(_)) => panic!("fd {fd}, case {i}: refused where it must answer"),
            }
        }
    }
}

/// `flags || r || alpha`, where the top bit of `flags` asks for an odd `y`. `r` is the
/// generator's `x`, so `alpha = x^3 + 7` has the roots `y` and `-y`.
fn ecrecover_cases() -> Vec<Case> {
    let p = Secp256k1BaseField::modulus();
    let (x, y) = Secp256k1Parameters::generator();
    let alpha = (x.pow(3) + 7u32) % &p;
    // 3 is the hook's non-residue: `3 * alpha` is not a square, and the hook answers with a root
    // of `9 * alpha`: `3y` or `-3y`.
    let non_square = (&alpha * 3u32) % &p;
    let request_with_r = |flags: u8, r: &BigUint, alpha: &BigUint| {
        let mut buf = vec![flags];
        buf.extend(be(r, 32));
        buf.extend(be(alpha, 32));
        buf
    };
    let request = |flags: u8, alpha: &BigUint| request_with_r(flags, &x, alpha);
    // `x^-1` modulo the group order.
    let r_inv = be_hex(
        "1dd887b3eaf153260a95e8b9fd31f60ac115d26ccbe1f572c0b8d7a6dec520fe",
        32,
    );
    // The generator's `y` is even.
    let (y_even, y_odd) = (be(&y, 32), be(&(&p - &y), 32));
    vec![
        (
            request(0, &alpha),
            Some(vec![vec![1], y_even, r_inv.clone()]),
        ),
        (request(0x80, &alpha), Some(vec![vec![1], y_odd, r_inv])),
        (
            request(0, &non_square),
            Some(vec![vec![0], be(&(&p - &y * 3u32), 32)]),
        ),
        (request(0, &BigUint::zero()), Some(vec![vec![0]])),
        // `r = 0` has no inverse, even beside an `alpha` with a root.
        (
            request_with_r(0, &BigUint::zero(), &alpha),
            Some(vec![vec![0]]),
        ),
        // `r` is not canonical.
        (request_with_r(0, &p, &alpha), None),
        (vec![0; 64], Some(vec![vec![0]])),
    ]
}

/// The compressed point, then the guest's `v = d*y^2 + 1`, both little-endian.
fn ed_decompress_cases() -> Vec<Case> {
    let p = Ed25519BaseField::modulus();
    let v = |y: &BigUint| ((y * y) % &p * Ed25519Parameters::d_biguint() + BigUint::one()) % &p;
    let request_with_v = |y: &BigUint, negative: bool, v: &BigUint| {
        let mut buf = le(y, 32);
        if negative {
            buf[31] |= 0x80;
        }
        buf.extend(le(v, 32));
        buf
    };
    let request = |y: &BigUint, negative: bool| request_with_v(y, negative, &v(y));
    let (_, basepoint_y) = Ed25519Parameters::generator();
    vec![
        // The sign bit is the syscall's, not part of `y`.
        (request(&basepoint_y, true), Some(vec![vec![1]])),
        // `v` is not reduced.
        (
            request_with_v(&basepoint_y, false, &(v(&basepoint_y) + &p)),
            None,
        ),
        // `y = 2` is the smallest canonical `y` off the curve: `v^-1` and a root of `2 * u/v`.
        (
            request(&BigUint::from(2u32), false),
            Some(vec![
                vec![0],
                unhex("3651c90543fd9fdbaa1718094ddb713267c14fe8d62d9ac9da9f3bd745045a75"),
                unhex("12602e991ffb040ef76aac57d447726fac039ca99b8cb989e67ec816ef37ba3e"),
            ]),
        ),
    ]
}

/// `len || element || modulus || nqr`, each big-endian in `len` bytes. 23 and the secp256k1
/// prime are 3 mod 4, 17 and 2^255 - 19 are 1 mod 4, which takes the two square-root
/// algorithms; the 32-byte requests show byte order, which a one-byte request cannot.
fn fp_sqrt_cases() -> Vec<Case> {
    let n = |x: u32| BigUint::from(x);
    let secp256k1 = Secp256k1BaseField::modulus();
    let ed25519 = Ed25519BaseField::modulus();
    let answer =
        |is_square: u8, root: &BigUint, len: usize| Some(vec![vec![is_square], be(root, len)]);
    vec![
        (fp_request(1, &[&n(4), &n(23), &n(5)]), answer(1, &n(2), 1)),
        // 5 is not a square mod 23; 18 is a root of 5 * 5.
        (fp_request(1, &[&n(5), &n(23), &n(5)]), answer(0, &n(18), 1)),
        (fp_request(1, &[&n(0), &n(23), &n(5)]), answer(1, &n(0), 1)),
        (fp_request(1, &[&n(4), &n(17), &n(3)]), answer(1, &n(2), 1)),
        // 3 is not a square mod 17; 14 is a root of 3 * 3.
        (fp_request(1, &[&n(3), &n(17), &n(3)]), answer(0, &n(14), 1)),
        (
            fp_request(32, &[&n(4), &secp256k1, &n(3)]),
            answer(1, &n(2), 32),
        ),
        // 12 is not a square mod the secp256k1 prime; the root of 36 is `-6`.
        (
            fp_request(32, &[&n(12), &secp256k1, &n(3)]),
            answer(0, &(&secp256k1 - 6u32), 32),
        ),
        (
            fp_request(32, &[&n(4), &ed25519, &n(2)]),
            answer(1, &(&ed25519 - 2u32), 32),
        ),
        // 2 is not a square mod 2^255 - 19; the root of 4 is `-2`.
        (
            fp_request(32, &[&n(2), &ed25519, &n(2)]),
            answer(0, &(&ed25519 - 2u32), 32),
        ),
        // The element, then the non-residue, not canonical; then truncated.
        (fp_request(1, &[&n(23), &n(23), &n(5)]), None),
        (fp_request(1, &[&n(5), &n(23), &n(23 + 5)]), None),
        (vec![0, 0, 0, 1, 4, 23], None),
    ]
}

/// `len || element || modulus`, each big-endian in `len` bytes.
fn fp_inverse_cases() -> Vec<Case> {
    let n = |x: u32| BigUint::from(x);
    let secp256k1 = Secp256k1BaseField::modulus();
    vec![
        (fp_request(1, &[&n(5), &n(23)]), Some(vec![vec![14]])),
        (
            fp_request(32, &[&n(5), &secp256k1]),
            Some(vec![be_hex(
                "99999999999999999999999999999999999999999999999999999998fffffdb6",
                32,
            )]),
        ),
        (fp_request(1, &[&n(0), &n(23)]), None),
        (vec![0, 0, 0, 1, 5], None),
    ]
}

/// A 48-byte big-endian element. The BLS12-381 prime is 3 mod 4.
fn bls12_381_sqrt_cases() -> Vec<Case> {
    let p = Bls381BaseField::modulus();
    vec![
        (
            bls12_381_element(4),
            Some(vec![vec![1], be(&(&p - 2u32), 48)]),
        ),
        // 2 is the hook's non-residue: 5 is not a square, and the answer is a root of 10.
        (
            bls12_381_element(5),
            Some(vec![
                vec![0],
                be_hex(
                    "02782469829c84f8970eb3cb2b699ed6886076ad6283d5f2b25133269c0244c68ebd66819ae0540ed5329791c9d9696a",
                    48,
                ),
            ]),
        ),
        (bls12_381_element(0), Some(vec![vec![1], vec![0; 48]])),
        (vec![0; 47], None),
    ]
}

fn bls12_381_inverse_cases() -> Vec<Case> {
    let p = Bls381BaseField::modulus();
    vec![
        // `(p + 1) / 4`, as the prime is 3 mod 4.
        (
            bls12_381_element(4),
            Some(vec![be(&((&p + 1u32) / 4u32), 48)]),
        ),
        (
            bls12_381_element(5),
            Some(vec![be_hex(
                "0a66d3f74a33290a84717648e7b7debc8e961e352e353ab2f613877395e06274d911999913bb33331732ccccccccaaab",
                48,
            )]),
        ),
        (bls12_381_element(0), None),
        (vec![0; 47], None),
    ]
}

fn fp_request(len: usize, values: &[&BigUint]) -> Vec<u8> {
    let mut buf = (len as u32).to_be_bytes().to_vec();
    for value in values {
        buf.extend(be(value, len));
    }
    buf
}

fn bls12_381_element(x: u8) -> Vec<u8> {
    let mut buf = vec![0; 48];
    buf[47] = x;
    buf
}

fn le(x: &BigUint, len: usize) -> Vec<u8> {
    let mut bytes = x.to_bytes_le();
    bytes.resize(len, 0);
    bytes
}

fn be(x: &BigUint, len: usize) -> Vec<u8> {
    let mut bytes = le(x, len);
    bytes.reverse();
    bytes
}

fn be_hex(hex: &str, len: usize) -> Vec<u8> {
    be(&BigUint::parse_bytes(hex.as_bytes(), 16).unwrap(), len)
}

fn unhex(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}
