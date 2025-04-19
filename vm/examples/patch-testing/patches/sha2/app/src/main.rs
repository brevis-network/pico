#![no_main]
pico_sdk::entrypoint!(main);

use sha2::{Digest, Sha256};

pub fn main() {
    let preimage = pico_sdk::io::read_vec();
    let digest = sha256(&preimage);
    pico_sdk::io::commit(&digest);
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest: [u8; 32] = hasher.finalize().into();

    digest
}
