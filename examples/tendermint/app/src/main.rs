#![no_main]

use pico_sdk::io::{commit_bytes, read_vec};
use tendermint_lib::verify_update;
use tendermint_light_client_verifier::{types::LightBlock, Verdict};

pico_sdk::entrypoint!(main);

fn main() {
    println!("cycle-tracker-start: io");
    println!("cycle-tracker-start: reading bytes");
    let encoded_1 = read_vec();
    let encoded_2 = read_vec();
    println!("cycle-tracker-end: reading bytes");
    println!("first 10 bytes: {:?}", &encoded_1[..10]);
    println!("first 10 bytes: {:?}", &encoded_2[..10]);

    println!("cycle-tracker-start: serde");
    let light_block_1: LightBlock = serde_cbor::from_slice(&encoded_1).unwrap();
    let light_block_2: LightBlock = serde_cbor::from_slice(&encoded_2).unwrap();
    println!("cycle-tracker-end: serde");
    println!("cycle-tracker-end: io");

    println!(
        "LightBlock1 number of validators: {}",
        light_block_1.validators.validators().len()
    );
    println!(
        "LightBlock2 number of validators: {}",
        light_block_2.validators.validators().len()
    );

    println!("cycle-tracker-start: header hash");
    let header_hash_1 = light_block_1.signed_header.header.hash();
    let header_hash_2 = light_block_2.signed_header.header.hash();
    println!("cycle-tracker-end: header hash");

    println!("cycle-tracker-start: public input headers");
    commit_bytes(header_hash_1.as_bytes());
    commit_bytes(header_hash_2.as_bytes());
    println!("cycle-tracker-end: public input headers");

    println!("cycle-tracker-start: verify");
    let verdict = verify_update(&light_block_1, &light_block_2).unwrap();
    println!("cycle-tracker-end: verify");

    println!("cycle-tracker-start: public inputs verdict");
    let verdict_encoded = serde_cbor::to_vec(&verdict).unwrap();
    commit_bytes(verdict_encoded.as_slice());
    println!("cycle-tracker-end: public inputs verdict");

    match verdict {
        Verdict::Success => {
            println!("success");
        }
        v => panic!("expected success, got: {:?}", v),
    }
}
