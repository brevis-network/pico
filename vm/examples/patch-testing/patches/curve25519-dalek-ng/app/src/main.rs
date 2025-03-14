#![no_main]
pico_sdk::entrypoint!(main);

use curve25519_dalek::{
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
};

pub fn main() {
    let mut byte_arrays = [[0u8; 32]; 4];
    for byte_array in &mut byte_arrays {
        *byte_array = pico_sdk::io::read_as();
    }
    let [bytes1, bytes2, bytes3, bytes4] = byte_arrays;

    // Decompress
    let compressed1 = CompressedEdwardsY(bytes1);
    let point1 = compressed1.decompress().unwrap();
    let compressed2 = CompressedEdwardsY(bytes2);
    let point2 = compressed2.decompress().unwrap();

    // Compress
    let _ = point1.compress().as_bytes();

    // Add
    let _ = point1 + point2;

    // Scalar Mul
    let scalar1 = Scalar::from_bytes_mod_order(bytes3);
    let _ = point1 * scalar1;

    // MSM
    let scalar2 = Scalar::from_bytes_mod_order(bytes4);
    let _ = EdwardsPoint::vartime_double_scalar_mul_basepoint(&scalar1, &point1, &scalar2);
}
