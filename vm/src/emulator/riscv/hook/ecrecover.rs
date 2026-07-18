use super::super::riscv_emulator::RiscvEmulator;
use k256::{elliptic_curve::ff::PrimeField, FieldBytes, FieldElement, Scalar as K256Scalar};

/// The non-quadratic residue for the curve for secp256k1.
const NQR: [u8; 32] = {
    let mut nqr = [0; 32];
    nqr[31] = 3;
    nqr
};

pub fn ecrecover(_: &RiscvEmulator, buf: &[u8]) -> Vec<Vec<u8>> {
    ecrecover_bytes(buf)
}

/// Executes the secp256k1 recovery hook without depending on an emulator instance.
///
/// Invalid guest encodings use the hook's ordinary failure response and never panic.
pub fn ecrecover_bytes(buf: &[u8]) -> Vec<Vec<u8>> {
    // Early return if the buffer length is incorrect
    if buf.len() != 65 {
        return vec![vec![0]];
    }

    let r_is_y_odd = buf[0] & 0b1000_0000 != 0;

    // Directly convert slices to arrays without intermediate steps
    let Ok(r_bytes): Result<[u8; 32], _> = buf[1..33].try_into() else {
        return vec![vec![0]];
    };
    let Ok(alpha_bytes): Result<[u8; 32], _> = buf[33..65].try_into() else {
        return vec![vec![0]];
    };

    // Convert bytes to field elements
    let Some(r) =
        Option::<FieldElement>::from(FieldElement::from_bytes(&FieldBytes::from(r_bytes)))
    else {
        return vec![vec![0]];
    };
    let Some(alpha) =
        Option::<FieldElement>::from(FieldElement::from_bytes(&FieldBytes::from(alpha_bytes)))
    else {
        return vec![vec![0]];
    };

    // Early return if r or alpha is zero
    if bool::from(r.is_zero()) || bool::from(alpha.is_zero()) {
        return vec![vec![0]];
    }

    // Normalize the y-coordinate always to be consistent.
    if let Some(mut y_coord) = alpha.sqrt().into_option().map(|y| y.normalize()) {
        let Some(r) = Option::<K256Scalar>::from(K256Scalar::from_repr(r.to_bytes())) else {
            return vec![vec![0]];
        };
        let Some(r_inv) = Option::<K256Scalar>::from(r.invert()) else {
            return vec![vec![0]];
        };

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

#[cfg(test)]
mod tests {
    use super::ecrecover_bytes;

    const SCALAR_MODULUS: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36,
        0x41, 0x41,
    ];

    fn one() -> [u8; 32] {
        let mut value = [0; 32];
        value[31] = 1;
        value
    }

    fn input(r: [u8; 32], alpha: [u8; 32]) -> [u8; 65] {
        let mut input = [0; 65];
        input[1..33].copy_from_slice(&r);
        input[33..65].copy_from_slice(&alpha);
        input
    }

    #[test]
    fn rejects_invalid_guest_encodings_without_panicking() {
        let failure = vec![vec![0]];

        assert_eq!(ecrecover_bytes(&[]), failure);
        assert_eq!(ecrecover_bytes(&input([0xff; 32], one())), failure);
        assert_eq!(ecrecover_bytes(&input(one(), [0xff; 32])), failure);
        assert_eq!(ecrecover_bytes(&input(SCALAR_MODULUS, one())), failure);
        assert_eq!(ecrecover_bytes(&input([0; 32], one())), failure);
        assert_eq!(ecrecover_bytes(&input(one(), [0; 32])), failure);
    }

    #[test]
    fn accepts_canonical_nonzero_input() {
        let output = ecrecover_bytes(&input(one(), one()));

        assert_eq!(output.len(), 3);
        assert_eq!(output[0], vec![1]);
        assert_eq!(output[1].len(), 32);
        assert_eq!(output[2], one());
    }
}
