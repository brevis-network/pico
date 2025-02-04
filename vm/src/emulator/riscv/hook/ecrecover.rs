use super::super::riscv_emulator::RiscvEmulator;
use k256::{elliptic_curve::ff::PrimeField, FieldBytes, FieldElement, Scalar as K256Scalar};

/// The non-quadratic residue for the curve for secp256k1.
const NQR: [u8; 32] = {
    let mut nqr = [0; 32];
    nqr[31] = 3;
    nqr
};

pub fn ecrecover(_: &RiscvEmulator, buf: &[u8]) -> Vec<Vec<u8>> {
    // Early return if the buffer length is incorrect
    if buf.len() != 65 {
        return vec![vec![0]];
    }

    let r_is_y_odd = buf[0] & 0b1000_0000 != 0;

    // Directly convert slices to arrays without intermediate steps
    let r_bytes: [u8; 32] = buf[1..33].try_into().unwrap();
    let alpha_bytes: [u8; 32] = buf[33..65].try_into().unwrap();

    // Convert bytes to field elements
    let r = FieldElement::from_bytes(&FieldBytes::from(r_bytes)).unwrap();
    let alpha = FieldElement::from_bytes(&FieldBytes::from(alpha_bytes)).unwrap();

    // Early return if r or alpha is zero
    if bool::from(r.is_zero()) || bool::from(alpha.is_zero()) {
        return vec![vec![0]];
    }

    // Normalize the y-coordinate always to be consistent.
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
        let nqr_field = FieldElement::from_bytes(FieldBytes::from_slice(&NQR)).unwrap();
        let qr = alpha * nqr_field;
        let root = qr
            .sqrt()
            .expect("if alpha is not a square, then qr should be a square");

        vec![vec![0], root.to_bytes().to_vec()]
    }
}
