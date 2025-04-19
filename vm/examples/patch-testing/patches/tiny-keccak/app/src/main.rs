#![no_main]
pico_sdk::entrypoint!(main);

use tiny_keccak::{Hasher, Keccak};

pub fn main() {
    let preimage = pico_sdk::io::read_vec();
    let result = keccak256(&preimage);
    pico_sdk::io::commit(&result);
}

fn keccak256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    hasher.update(bytes);
    let mut digest = [0u8; 32];
    hasher.finalize(&mut digest);

    digest
}
