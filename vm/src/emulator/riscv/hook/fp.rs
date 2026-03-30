use super::super::emulator::RiscvEmulator;
use num_bigint::BigUint;
use num_traits::{One, Zero};

fn pad_to_be(val: &BigUint, len: usize) -> Vec<u8> {
    let mut bytes = val.to_bytes_le();
    bytes.resize(len, 0);
    bytes.reverse();
    bytes
}

pub fn hook_fp_inverse(_: &RiscvEmulator, buf: &[u8]) -> Vec<Vec<u8>> {
    let len: usize = u32::from_be_bytes(buf[0..4].try_into().unwrap()) as usize;

    assert!(buf.len() == 4 + 2 * len, "FpOp Hook: Invalid buffer length");

    let buf = &buf[4..];
    let element = BigUint::from_bytes_be(&buf[..len]);
    let modulus = BigUint::from_bytes_be(&buf[len..2 * len]);

    assert!(!element.is_zero(), "FpOp: Inverse called with zero");

    let inverse = element.modpow(&(&modulus - BigUint::from(2u64)), &modulus);

    vec![pad_to_be(&inverse, len)]
}

pub fn hook_fp_sqrt(_: &RiscvEmulator, buf: &[u8]) -> Vec<Vec<u8>> {
    let len: usize = u32::from_be_bytes(buf[0..4].try_into().unwrap()) as usize;

    assert!(buf.len() == 4 + 3 * len, "FpOp Hook: Invalid buffer length");

    let buf = &buf[4..];
    let element = BigUint::from_bytes_be(&buf[..len]);
    let modulus = BigUint::from_bytes_be(&buf[len..2 * len]);
    let nqr = BigUint::from_bytes_be(&buf[2 * len..3 * len]);

    assert!(
        element < modulus,
        "Element is not less than modulus, the hook only accepts canonical representations"
    );
    assert!(
        nqr < modulus,
        "NQR is zero or non-canonical, the hook only accepts canonical representations"
    );

    if element.is_zero() {
        return vec![vec![1], vec![0; len]];
    }

    if let Some(root) = sqrt_fp(&element, &modulus, &nqr) {
        vec![vec![1], pad_to_be(&root, len)]
    } else {
        let qr = (&nqr * &element) % &modulus;
        let root = sqrt_fp(&qr, &modulus, &nqr).unwrap();

        vec![vec![0], pad_to_be(&root, len)]
    }
}

fn sqrt_fp(element: &BigUint, modulus: &BigUint, nqr: &BigUint) -> Option<BigUint> {
    if modulus % BigUint::from(4u64) == BigUint::from(3u64) {
        let maybe_root = element.modpow(
            &((modulus + BigUint::from(1u64)) / BigUint::from(4u64)),
            modulus,
        );

        return Some(maybe_root).filter(|root| root * root % modulus == *element);
    }

    tonelli_shanks(element, modulus, nqr)
}

#[allow(clippy::many_single_char_names)]
fn tonelli_shanks(element: &BigUint, modulus: &BigUint, nqr: &BigUint) -> Option<BigUint> {
    if legendre_symbol(element, modulus) != BigUint::one() {
        return None;
    }

    let mut s = BigUint::zero();
    let mut q = modulus - BigUint::one();
    while &q % &BigUint::from(2u64) == BigUint::zero() {
        s += BigUint::from(1u64);
        q /= BigUint::from(2u64);
    }

    let z = nqr;
    let mut c = z.modpow(&q, modulus);
    let mut r = element.modpow(&((&q + BigUint::from(1u64)) / BigUint::from(2u64)), modulus);
    let mut t = element.modpow(&q, modulus);
    let mut m = s;

    while t != BigUint::one() {
        let mut i = BigUint::zero();
        let mut tt = t.clone();
        while tt != BigUint::one() {
            tt = &tt * &tt % modulus;
            i += BigUint::from(1u64);

            if i == m {
                return None;
            }
        }

        let b_pow = BigUint::from(2u64).pow((&m - &i - BigUint::from(1u64)).try_into().unwrap());
        let b = c.modpow(&b_pow, modulus);

        r = &r * &b % modulus;
        c = &b * &b % modulus;
        t = &t * &c % modulus;
        m = i;
    }

    Some(r)
}

fn legendre_symbol(element: &BigUint, modulus: &BigUint) -> BigUint {
    assert!(!element.is_zero(), "FpOp: Legendre symbol of zero called.");

    element.modpow(&((modulus - BigUint::one()) / BigUint::from(2u64)), modulus)
}
