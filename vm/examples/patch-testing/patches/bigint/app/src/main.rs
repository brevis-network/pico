#![no_main]
pico_sdk::entrypoint!(main);

use crypto_bigint::{Limb, U256};

pub fn main() {
    let a = U256::from(3u8);
    let b = U256::from(2u8);
    let c = Limb(8);
    let _ = a.mul_mod_special(&b, c);
}
