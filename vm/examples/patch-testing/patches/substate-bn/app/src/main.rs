#![no_main]
pico_sdk::entrypoint!(main);

use substrate_bn::{pairing, pairing_batch, AffineG1, Fq, Fq2, Fr, Group, G1, G2};
use pico_sdk::io::commit_bytes;

const ITERATIONS: usize = 6000;

pub fn main() {
    // ==========================================================
    // 1. Affine ADD Operation Loop (P + Q)
    // ==========================================================
    {
        let mut val = AffineG1::one();
        let step = AffineG1::one();

        for _ in 0..ITERATIONS {
            val = val + step;
        }

        let mut bytes = [0u8; 32];
        val.x().to_big_endian(&mut bytes).expect("Serialization failed");
        commit_bytes(&bytes);
    }

    // ==========================================================
    // 2. Affine DOUBLE Operation Loop (P + P)
    // ==========================================================
    {
        let mut val = AffineG1::one();

        for _ in 0..ITERATIONS {
            val = val + val;
        }

        let mut bytes = [0u8; 32];
        val.x().to_big_endian(&mut bytes).expect("Serialization failed");
        commit_bytes(&bytes);
    }

    // Fq operations
    {
        let lhs = Fq::one();
        let rhs = Fq::one();

        println!("cycle-tracker-start: bn254-add-fp");
        let _ = lhs + rhs;
        println!("cycle-tracker-end: bn254-add-fp");

        println!("cycle-tracker-start: bn254-sub-fp");
        let _ = lhs - rhs;
        println!("cycle-tracker-end: bn254-sub-fp");

        println!("cycle-tracker-start: bn254-mul-fp");
        let _ = lhs * rhs;
        println!("cycle-tracker-end: bn254-mul-fp");

        println!("cycle-tracker-start: bn254-inverse-fp");
        let _ = lhs.inverse().unwrap().into_u256();
        println!("cycle-tracker-end: bn254-inverse-fp");

        println!("cycle-tracker-start: bn254-sqrt-fp");
        let _ = lhs.sqrt().unwrap().into_u256();
        println!("cycle-tracker-end: bn254-sqrt-fp");
    }

    // Fr operations
    {
        let lhs = Fr::one();
        let rhs = Fr::one();

        println!("cycle-tracker-start: bn254-add-fr");
        let _ = lhs + rhs;
        println!("cycle-tracker-end: bn254-add-fr");

        println!("cycle-tracker-start: bn254-sub-fr");
        let _ = lhs - rhs;
        println!("cycle-tracker-end: bn254-sub-fr");

        println!("cycle-tracker-start: bn254-mul-fr");
        let _ = lhs * rhs;
        println!("cycle-tracker-end: bn254-mul-fr");

        println!("cycle-tracker-start: bn254-inverse-fr");
        let _ = lhs.inverse().unwrap().into_u256();
        println!("cycle-tracker-end: bn254-inverse-fr");
    }

    // Fq2 operations
    {
        let lhs = Fq2::new(Fq::one(), Fq::one());
        let rhs = Fq2::new(Fq::one(), Fq::one());

        println!("cycle-tracker-start: bn254-add-fq2");
        let _ = lhs + rhs;
        println!("cycle-tracker-end: bn254-add-fq2");

        println!("cycle-tracker-start: bn254-sub-fq2");
        let _ = lhs - rhs;
        println!("cycle-tracker-end: bn254-sub-fq2");

        println!("cycle-tracker-start: bn254-mul-fq2");
        let _ = lhs * rhs;
        println!("cycle-tracker-end: bn254-mul-fq2");
    }

    // G1 operations
    {
        let lhs = G1::one();
        let rhs = G1::one();

        println!("cycle-tracker-start: bn254-add-g1");
        let _ = lhs + rhs;
        println!("cycle-tracker-end: bn254-add-g1");

        println!("cycle-tracker-start: bn254-mul-g1");
        let _ = lhs * Fr::one();
        println!("cycle-tracker-end: bn254-mul-g1");

        println!("cycle-tracker-start: bn254-double-g1");
        let _ = lhs.double();
        println!("cycle-tracker-end: bn254-double-g1");
    }

    // G2 operations
    {
        let lhs = G2::one();
        let rhs = G2::one();

        println!("cycle-tracker-start: bn254-add-g2");
        let _ = lhs + rhs;
        println!("cycle-tracker-end: bn254-add-g2");

        println!("cycle-tracker-start: bn254-mul-g2");
        let _ = lhs * Fr::one();
        println!("cycle-tracker-end: bn254-mul-g2");
    }

    // Pairing
    {
        let p1 = G1::one();
        let p2 = G2::one();

        println!("cycle-tracker-start: bn254-pairing");
        let _ = pairing(p1, p2);
        println!("cycle-tracker-end: bn254-pairing");
    }

    // Batch pairing
    {
        let p1 = G1::one();
        let q1 = G2::one();
        let p2 = G1::one();
        let q2 = G2::one();

        println!("cycle-tracker-start: bn254-pairing-check");
        pairing_batch(&[(p1, q1), (p2, q2)]).final_exponentiation();
        println!("cycle-tracker-end: bn254-pairing-check");
    }
}
