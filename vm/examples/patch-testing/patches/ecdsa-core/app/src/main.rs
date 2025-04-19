#![no_main]
pico_sdk::entrypoint!(main);

use alloy_primitives::{fixed_bytes, B256, B512};
use ecdsa::VerifyingKey;
use k256::{
    ecdsa::{Error, RecoveryId, Signature},
    Secp256k1,
};
use std::hint::black_box;
use tiny_keccak::{Hasher, Keccak};

pub fn ecrecover_internal(sig: &B512, mut recid: u8, msg: &B256) -> Result<B256, Error> {
    // parse signature
    let mut sig = Signature::from_slice(sig.as_slice())?;

    // normalize signature and flip recovery id if needed.
    if let Some(sig_normalized) = sig.normalize_s() {
        sig = sig_normalized;
        recid ^= 1;
    }
    let recid = RecoveryId::from_byte(recid).expect("recovery ID is valid");

    // recover key
    let recovered_key = VerifyingKey::<Secp256k1>::recover_from_prehash(&msg[..], &sig, recid)?;
    // hash it
    let mut hash = [0; 32];
    let mut hasher = Keccak::v256();
    hasher.update(&recovered_key.to_encoded_point(false).as_bytes()[1..]);
    hasher.finalize(&mut hash);

    // truncate to 20 bytes
    hash[..12].fill(0);
    Ok(hash.into())
}
pub fn main() {
    let sig = fixed_bytes!(
            "46c05b6368a44b8810d79859441d819b8e7cdc8bfd371e35c53196f4bcacdb5135c7facce2a97b95eacba8a586d87b7958aaf8368ab29cee481f76e871dbd9cb"
        );
    let msg = fixed_bytes!("17785b60642be70df014c6b34c0ee4374a8d755761ecf2dde5564f5935b540a9");
    let addr = fixed_bytes!("0000000000000000000000005f6b4244628186ff21c6facb9dee41835ddc1b10");
    let recid = 1;

    let rec_addr = black_box(ecrecover_internal(&sig, recid, &msg)).expect("no error");
    assert_eq!(addr, rec_addr);
}
