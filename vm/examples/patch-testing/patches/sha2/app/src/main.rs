#![no_main]
pico_sdk::entrypoint!(main);

use sha2::{Digest, Sha256};

const ITERATIONS: usize = 66000;

pub fn main() {
    let mut data = pico_sdk::io::read_vec();

    // Run the hashing logic in a loop
    for _ in 0..ITERATIONS {
        // Hash the current data
        let digest = sha256(&data);

        // Update 'data' with the result to create a dependency chain
        // This ensures every iteration must be executed sequentially
        data = digest.to_vec();
    }

    // Commit the final hash after all iterations
    pico_sdk::io::commit(&data);
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}