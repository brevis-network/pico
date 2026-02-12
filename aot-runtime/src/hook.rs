use crate::emulator::AotEmulatorCore;
use curve25519_dalek::edwards::CompressedEdwardsY;
use hashbrown::HashMap;
use k256::{elliptic_curve::ff::PrimeField, FieldBytes, FieldElement, Scalar as K256Scalar};
use pico_vm::chips::gadgets::curves::edwards::ed25519::decompress;

pub type Hook = fn(&AotEmulatorCore, &[u8]) -> Vec<Vec<u8>>;

const SECP256K1_ECRECOVER: u32 = 5;
pub const FD_EDDECOMPRESS: u32 = 8;

pub fn default_hook_map() -> HashMap<u32, Hook> {
    let hooks: [(u32, Hook); _] = [
        (SECP256K1_ECRECOVER, ecrecover),
        (FD_EDDECOMPRESS, ed_decompress),
    ];
    HashMap::from_iter(hooks)
}

const NQR: [u8; 32] = {
    let mut nqr = [0; 32];
    nqr[31] = 3;
    nqr
};

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
