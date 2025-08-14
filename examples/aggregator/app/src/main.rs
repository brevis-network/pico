#![no_main]
pico_sdk::entrypoint!(main);

use pico_sdk::{
    io::{commit, read_as},
    verify::verify_pico_proof,
};
use sha2::{Digest, Sha256};

pub fn main() {
    let vk_digests: Vec<[u32; 8]> = read_as();
    let public_values: Vec<Vec<u8>> = read_as();

    assert_eq!(vk_digests.len(), public_values.len());
    for i in 0..vk_digests.len() {
        let vk_digest = &vk_digests[i];
        let public_value = &public_values[i];
        let public_value_digest = Sha256::digest(public_value);
        verify_pico_proof(vk_digest, &public_value_digest.into());
    }

    for (i, (vk_digest, pv)) in vk_digests.iter().zip(&public_values).enumerate() {
        println!(
            "#{:02} vk_digest = {:?}, pv ({} bytes) = {:?}",
            i,
            vk_digest,
            pv.len(),
            pv
        );
    }
    commit(&vk_digests);
    commit(&public_values);
}
