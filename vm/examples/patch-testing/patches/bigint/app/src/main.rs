#![no_main]
pico_sdk::entrypoint!(main);

use crypto_bigint::{Limb, U256};

const ITERATIONS: usize = 65000;

pub fn main() {
    let mut a = U256::from(3u8);
    let b = U256::from(2u8);
    let c = Limb(8);

    // Run the logic in a loop to increase trace size
    for _ in 0..ITERATIONS {
        // We update 'a' with the result to create a dependency chain
        // This prevents the compiler from skipping iterations
        a = a.mul_mod_special(&b, c);
    }
}