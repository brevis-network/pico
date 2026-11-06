//! EIP-4844 point evaluation: the KZG proof check, on the BLS12-381 pairing. The caller checks
//! the versioned hash.

use bls12_381::{
    multi_miller_loop, G1Affine, G1Projective, G2Affine, G2Prepared, G2Projective, Gt, Scalar,
};

use super::{arg, hex_literal, out, ZkvmStatus, ZKVM_EFAIL, ZKVM_EOK};

/// `[τ]G2` from the Ethereum KZG ceremony: the second G2 point of the trusted setup, compressed.
/// Point evaluation needs no other setup point.
const TAU_G2: [u8; 96] = hex_literal(
    b"b5bfd7dd8cdeb128843bc287230af38926187075cbfbefa81009a2ce615ac53d2914e5870cb452d2afaaab24f3499f72185cbfee53492714734429b7b38608e23926c911cceceac9a36851477ba4c60b087041de621000edc98edada20c1def2",
);

/// `zkvm_status zkvm_kzg_point_eval(const zkvm_kzg_commitment* commitment, const
/// zkvm_kzg_field_element* z, const zkvm_kzg_field_element* y, const zkvm_kzg_proof* proof, bool*
/// verified)`: whether `proof` shows that the polynomial committed to evaluates to `y` at `z`.
/// A malformed point or field element fails.
///
/// # Safety
///
/// `commitment` and `proof` point to 48 bytes, `z` and `y` to 32, `verified` to a `bool`.
#[cfg_attr(target_os = "zkvm", no_mangle)]
pub unsafe extern "C" fn zkvm_kzg_point_eval(
    commitment: *const [u8; 48],
    z: *const [u8; 32],
    y: *const [u8; 32],
    proof: *const [u8; 48],
    verified: *mut bool,
) -> ZkvmStatus {
    const F: &str = "zkvm_kzg_point_eval";
    let (commitment, proof) = (arg(commitment, F, "commitment"), arg(proof, F, "proof"));
    let (z, y) = (arg(z, F, "z"), arg(y, F, "y"));
    let verified = out(verified, F, "verified");
    let decoded = (|| {
        Some((
            Option::<G1Affine>::from(G1Affine::from_compressed(&commitment))?,
            field_element(&z)?,
            field_element(&y)?,
            Option::<G1Affine>::from(G1Affine::from_compressed(&proof))?,
        ))
    })();
    let Some((commitment, z, y, proof)) = decoded else {
        return ZKVM_EFAIL;
    };
    verified.write(verify(commitment, z, y, proof));
    ZKVM_EOK
}

/// `e(C - [y]G1, -G2) * e(π, [τ - z]G2) == 1`.
fn verify(commitment: G1Affine, z: Scalar, y: Scalar, proof: G1Affine) -> bool {
    let tau_g2 = G2Affine::from_compressed(&TAU_G2).unwrap();
    let x_minus_z = G2Affine::from(G2Projective::from(tau_g2) - G2Projective::generator() * z);
    let p_minus_y = G1Affine::from(G1Projective::from(commitment) - G1Projective::generator() * y);
    let terms = [
        (&p_minus_y, &G2Prepared::from(-G2Affine::generator())),
        (&proof, &G2Prepared::from(x_minus_z)),
    ];
    multi_miller_loop(&terms).final_exponentiation() == Gt::identity()
}

/// A BLS scalar field element: 32 bytes, big-endian, below the modulus.
fn field_element(bytes: &[u8; 32]) -> Option<Scalar> {
    let mut le = *bytes;
    le.reverse();
    Scalar::from_bytes(&le).into()
}
