#![no_main]
pico_sdk::entrypoint!(main);

use bls12_381::{
    fp::Fp, fp2::Fp2, multi_miller_loop, pairing, G1Projective, G2Affine, G2Prepared, G2Projective,
    Scalar,
};

pub fn main() {
    // Fp operations
    {
        let lhs = Fp::one();
        let rhs = Fp::one();

        println!("cycle-tracker-start: bls12_381-add-fp");
        let _ = lhs + rhs;
        println!("cycle-tracker-end: bls12_381-add-fp");

        println!("cycle-tracker-start: bls12_381-sub-fp");
        let _ = lhs - rhs;
        println!("cycle-tracker-end: bls12_381-sub-fp");

        println!("cycle-tracker-start: bls12_381-mul-fp");
        let _ = lhs * rhs;
        println!("cycle-tracker-end: bls12_381-mul-fp");

        println!("cycle-tracker-start: bls12_381-inverse-fp");
        let _ = lhs.invert().into_option().map(|v| v.to_bytes().to_vec());
        println!("cycle-tracker-end: bls12_381-inverse-fp");
    }

    // Fp2 operations
    {
        let lhs = Fp2::one();
        let rhs = Fp2::one();

        println!("cycle-tracker-start: bls12_381-add-fp2");
        let _ = lhs + rhs;
        println!("cycle-tracker-end: bls12_381-add-fp2");

        println!("cycle-tracker-start: bls12_381-sub-fp2");
        let _ = lhs - rhs;
        println!("cycle-tracker-end: bls12_381-sub-fp2");

        println!("cycle-tracker-start: bls12_381-mul-fp2");
        let _ = lhs * rhs;
        println!("cycle-tracker-end: bls12_381-mul-fp2");

        println!("cycle-tracker-start: bls12_381-inverse-fp2");
        let _ = lhs.invert().into_option().map(|v| v.to_bytes().to_vec());
        println!("cycle-tracker-end: bls12_381-inverse-fp2");
    }

    // Scalar operations
    {
        let lhs = Scalar::one();
        let rhs = Scalar::one();

        println!("cycle-tracker-start: bls12_381-add-scalar");
        let _ = lhs + rhs;
        println!("cycle-tracker-end: bls12_381-add-scalar");

        println!("cycle-tracker-start: bls12_381-sub-scalar");
        let _ = lhs - rhs;
        println!("cycle-tracker-end: bls12_381-sub-scalar");

        println!("cycle-tracker-start: bls12_381-mul-scalar");
        let _ = lhs * rhs;
        println!("cycle-tracker-end: bls12_381-mul-scalar");
    }

    // G1 operations
    {
        let scalar1 = Scalar::from(5u64);
        let scalar2 = Scalar::from(7u64);
        let scalar3 = Scalar::from(10u64);
        let lhs = G1Projective::generator() * scalar1;
        let rhs = G1Projective::generator() * scalar2;

        println!("cycle-tracker-start: bls12_381-double-g1");
        let _ = lhs.double();
        println!("cycle-tracker-end: bls12_381-add-g1");

        println!("cycle-tracker-start: bls12_381-add-g1");
        let _ = lhs + rhs;
        println!("cycle-tracker-end: bls12_381-add-g1");

        println!("cycle-tracker-start: bls12_381-mul-g1");
        let _ = lhs * scalar3;
        println!("cycle-tracker-end: bls12_381-mul-g1");
    }

    // G2 operations
    {
        let scalar1 = Scalar::from(5u64);
        let scalar2 = Scalar::from(7u64);
        let scalar3 = Scalar::from(10u64);
        let lhs = G2Projective::generator() * scalar1;
        let rhs = G2Projective::generator() * scalar2;

        println!("cycle-tracker-start: bls12_381-double-g2");
        let _ = lhs.double();
        println!("cycle-tracker-end: bls12_381-add-g2");

        println!("cycle-tracker-start: bls12_381-add-g2");
        let _ = lhs + rhs;
        println!("cycle-tracker-end: bls12_381-add-g2");

        println!("cycle-tracker-start: bls12_381-mul-g2");
        let _ = lhs * scalar3;
        println!("cycle-tracker-end: bls12_381-mul-g2");
    }

    // Pairing
    {
        let scalar1 = Scalar::from(5u64);
        let scalar2 = Scalar::from(7u64);
        let p1 = G1Projective::generator() * scalar1;
        let p2 = G2Projective::generator() * scalar2;

        println!("cycle-tracker-start: bls12_381-pairing");
        let _ = pairing(&p1.into(), &p2.into());
        println!("cycle-tracker-end: bls12_381-pairing");
    }

    // Pairing Check
    {
        let scalar1 = Scalar::from(5u64);
        let scalar2 = Scalar::from(7u64);
        let p1 = G1Projective::generator() * scalar1;
        let q1 = G2Projective::generator() * scalar2;
        let p2 = G1Projective::generator() * scalar2;
        let q2 = G2Projective::generator() * scalar1;
        let q1_affine: G2Affine = q1.into();
        let q2_affine: G2Affine = q2.into();
        let q1_prepared = G2Prepared::from(q1_affine);
        let q2_prepared = G2Prepared::from(q2_affine);

        println!("cycle-tracker-start: bls12_381-pairing-check");
        multi_miller_loop(&[(&p1.into(), &q1_prepared), (&p2.into(), &q2_prepared)])
            .final_exponentiation();
        println!("cycle-tracker-end: bls12_381-pairing-check");
    }
}
