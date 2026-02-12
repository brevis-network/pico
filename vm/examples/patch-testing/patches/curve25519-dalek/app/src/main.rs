#![no_main]
pico_sdk::entrypoint!(main);

use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT,
    edwards::CompressedEdwardsY,
    scalar::Scalar,
    EdwardsPoint,
};
use pico_sdk::io::commit_bytes;

const ITERATIONS: usize = 50;

pub fn main() {
    // ==========================================================
    // 1. Point Addition Loop (P = P + G)
    // ==========================================================
    {
        let mut point = ED25519_BASEPOINT_POINT;
        let step = ED25519_BASEPOINT_POINT;

        for _ in 0..ITERATIONS {
            point = point + step;
        }

        commit_bytes(point.compress().as_bytes());
    }

    // ==========================================================
    // 2. Scalar Multiplication Loop (P = P * s)
    // ==========================================================
    {
        let mut point = ED25519_BASEPOINT_POINT;
        let scalar = Scalar::from(1234u64);

        for _ in 0..ITERATIONS {
            point = point * scalar;
        }

        commit_bytes(point.compress().as_bytes());
    }

    // ==========================================================
    // 3. Decompress & Compress Loop
    // ==========================================================
    {
        let mut compressed = ED25519_BASEPOINT_POINT.compress();
        let step_point = ED25519_BASEPOINT_POINT;

        for _ in 0..200*ITERATIONS {
            // A. Decompress (Bytes -> Point)
            let point = compressed.decompress().unwrap();

            let next_point = point + step_point;

            // C. Compress (Point -> Bytes)
            compressed = next_point.compress();
        }

        commit_bytes(compressed.as_bytes());
    }

    // ==========================================================
    // 4. MSM (Multi-Scalar Multiplication) Loop
    // ==========================================================
    {
        let mut point = ED25519_BASEPOINT_POINT;
        let scalar_a = Scalar::from(5u64);
        let scalar_b = Scalar::from(7u64);

        for _ in 0..ITERATIONS {
            // result = scalar_a * point + scalar_b * BASEPOINT
            point = EdwardsPoint::vartime_double_scalar_mul_basepoint(
                &scalar_a,
                &point,
                &scalar_b
            );
        }

        commit_bytes(point.compress().as_bytes());
    }
}