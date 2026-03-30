use crate::emulator::AotEmulatorCore;
use curve25519_dalek::edwards::CompressedEdwardsY;
use hashbrown::HashMap;
use k256::{elliptic_curve::ff::PrimeField, FieldBytes, FieldElement, Scalar as K256Scalar};
use num_bigint::BigUint;
use num_traits::{One, Zero};
use pico_vm::chips::gadgets::{
    curves::{edwards::ed25519::decompress, weierstrass::bls381::Bls381BaseField},
    utils::field_params::FieldParameters,
};

pub type Hook = fn(&AotEmulatorCore, &[u8]) -> Vec<Vec<u8>>;

const SECP256K1_ECRECOVER: u32 = 5;
pub const FD_EDDECOMPRESS: u32 = 8;
pub const FD_FP_SQRT: u32 = 10;
pub const FD_FP_INV: u32 = 11;
pub const FD_BLS12_381_SQRT: u32 = 12;
pub const FD_BLS12_381_INVERSE: u32 = 13;

pub fn default_hook_map() -> HashMap<u32, Hook> {
    let hooks: [(u32, Hook); _] = [
        (SECP256K1_ECRECOVER, ecrecover),
        (FD_EDDECOMPRESS, ed_decompress),
        (FD_FP_SQRT, hook_fp_sqrt),
        (FD_FP_INV, hook_fp_inverse),
        (FD_BLS12_381_SQRT, hook_bls12_381_sqrt),
        (FD_BLS12_381_INVERSE, hook_bls12_381_inverse),
    ];
    HashMap::from_iter(hooks)
}

const NQR: [u8; 32] = {
    let mut nqr = [0; 32];
    nqr[31] = 3;
    nqr
};

const NQR_BLS12_381: [u8; 48] = {
    let mut nqr = [0; 48];
    nqr[47] = 2;
    nqr
};

fn pad_to_be(val: &BigUint, len: usize) -> Vec<u8> {
    let mut bytes = val.to_bytes_le();
    bytes.resize(len, 0);
    bytes.reverse();
    bytes
}

pub fn ecrecover(_: &AotEmulatorCore, buf: &[u8]) -> Vec<Vec<u8>> {
    if buf.len() != 65 {
        return vec![vec![0]];
    }

    let r_is_y_odd = buf[0] & 0b1000_0000 != 0;

    let r_bytes: [u8; 32] = buf[1..33].try_into().unwrap();
    let alpha_bytes: [u8; 32] = buf[33..65].try_into().unwrap();

    let r = FieldElement::from_bytes(&FieldBytes::from(r_bytes)).unwrap();
    let alpha = FieldElement::from_bytes(&FieldBytes::from(alpha_bytes)).unwrap();

    if bool::from(r.is_zero()) || bool::from(alpha.is_zero()) {
        return vec![vec![0]];
    }

    if let Some(mut y_coord) = alpha.sqrt().into_option().map(|y| y.normalize()) {
        let r = K256Scalar::from_repr(r.to_bytes()).unwrap();
        let r_inv = r.invert().expect("Non zero r scalar");

        if r_is_y_odd != bool::from(y_coord.is_odd()) {
            y_coord = y_coord.negate(1);
            y_coord = y_coord.normalize();
        }

        vec![
            vec![1],
            y_coord.to_bytes().to_vec(),
            r_inv.to_bytes().to_vec(),
        ]
    } else {
        let nqr_field = FieldElement::from_bytes(&FieldBytes::from(NQR)).unwrap();
        let qr = alpha * nqr_field;
        let root = qr
            .sqrt()
            .expect("if alpha is not a square, then qr should be a square");

        vec![vec![0], root.to_bytes().to_vec()]
    }
}

#[must_use]
pub fn ed_decompress(_: &AotEmulatorCore, buf: &[u8]) -> Vec<Vec<u8>> {
    let Ok(point) = CompressedEdwardsY::from_slice(buf) else {
        return vec![vec![0]];
    };

    if decompress(&point).is_some() {
        vec![vec![1]]
    } else {
        vec![vec![0]]
    }
}

pub fn hook_fp_inverse(_: &AotEmulatorCore, buf: &[u8]) -> Vec<Vec<u8>> {
    let len: usize = u32::from_be_bytes(buf[0..4].try_into().unwrap()) as usize;

    assert!(buf.len() == 4 + 2 * len, "FpOp Hook: Invalid buffer length");

    let buf = &buf[4..];
    let element = BigUint::from_bytes_be(&buf[..len]);
    let modulus = BigUint::from_bytes_be(&buf[len..2 * len]);

    assert!(!element.is_zero(), "FpOp: Inverse called with zero");

    let inverse = element.modpow(&(&modulus - BigUint::from(2u64)), &modulus);

    vec![pad_to_be(&inverse, len)]
}

pub fn hook_fp_sqrt(_: &AotEmulatorCore, buf: &[u8]) -> Vec<Vec<u8>> {
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

pub fn hook_bls12_381_sqrt(_: &AotEmulatorCore, buf: &[u8]) -> Vec<Vec<u8>> {
    assert!(buf.len() == 48, "BLS12-381 sqrt input must be 48 bytes");

    let field_element = BigUint::from_bytes_be(buf);

    if field_element.is_zero() {
        return vec![vec![1], vec![0; 48]];
    }

    let modulus = BigUint::from_bytes_le(Bls381BaseField::MODULUS);
    let exp = (&modulus + BigUint::from(1u64)) / BigUint::from(4u64);
    let sqrt = field_element.modpow(&exp, &modulus);

    let square = (&sqrt * &sqrt) % &modulus;
    if square != field_element {
        let nqr = BigUint::from_bytes_be(&NQR_BLS12_381);
        let qr = (&nqr * &field_element) % &modulus;
        let root = qr.modpow(&exp, &modulus);

        assert!((&root * &root) % &modulus == qr, "NQR sanity check failed");

        return vec![vec![0], pad_to_be(&root, 48)];
    }

    vec![vec![1], pad_to_be(&sqrt, 48)]
}

pub fn hook_bls12_381_inverse(_: &AotEmulatorCore, buf: &[u8]) -> Vec<Vec<u8>> {
    assert!(buf.len() == 48, "BLS12-381 inverse input must be 48 bytes");

    let field_element = BigUint::from_bytes_be(buf);
    assert!(
        !field_element.is_zero(),
        "Field element is the additive identity"
    );

    let modulus = BigUint::from_bytes_le(Bls381BaseField::MODULUS);
    let inverse = field_element.modpow(&(&modulus - BigUint::from(2u64)), &modulus);

    vec![pad_to_be(&inverse, 48)]
}

#[cfg(test)]
mod tests {
    use super::{
        default_hook_map, FD_BLS12_381_INVERSE, FD_BLS12_381_SQRT, FD_EDDECOMPRESS, FD_FP_INV,
        FD_FP_SQRT,
    };

    #[test]
    fn phase5_default_hook_map_matches_baseline_fd_surface() {
        let hook_map = default_hook_map();

        for fd in [
            5,
            FD_EDDECOMPRESS,
            FD_FP_SQRT,
            FD_FP_INV,
            FD_BLS12_381_SQRT,
            FD_BLS12_381_INVERSE,
        ] {
            assert!(hook_map.contains_key(&fd), "missing hook fd {fd}");
        }
    }
}
