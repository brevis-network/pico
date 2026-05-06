use super::super::emulator::RiscvEmulator;
use crate::chips::gadgets::{
    curves::weierstrass::bls381::Bls381BaseField, utils::field_params::FieldParameters,
};
use num_bigint::BigUint;
use num_traits::Zero;

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

pub fn hook_bls12_381_sqrt(_: &RiscvEmulator, buf: &[u8]) -> Vec<Vec<u8>> {
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

pub fn hook_bls12_381_inverse(_: &RiscvEmulator, buf: &[u8]) -> Vec<Vec<u8>> {
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
