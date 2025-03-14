#![no_main]
pico_sdk::entrypoint!(main);

use alloy_sol_types::private::primitives::hex;
use ed25519_consensus::{Signature, VerificationKey};

pub fn main() {
    let vk = hex!("9194c3ead03f5848111db696fe1196fbbeffc69342d51c7cf5e91c502de91eb4");
    let msg = hex!("656432353531392d636f6e73656e7375732074657374206d657373616765");
    let sig = hex!(
        "69261ea5df799b20fc6eeb49aa79f572c8f1e2ba88b37dff184cc55d4e3653d876419bffcc47e5343cdd5fd78121bb32f1c377a5ed505106ad37f19980218f0d"
    );

    let vk: VerificationKey = vk.try_into().unwrap();
    let sig: Signature = sig.into();

    println!("cycle-tracker-start: ed25519-consensus verify");
    vk.verify(&sig, &msg).unwrap();
    println!("cycle-tracker-end: ed25519-consensus verify");
}
