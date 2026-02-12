#![no_main]
pico_sdk::entrypoint!(main);

use p3_field::{FieldAlgebra, PrimeField32};
use p3_koala_bear::KoalaBear;
use pico_sdk::poseidon2_hash::Poseidon2;

const ITERATIONS: usize = 67000;

pub fn main() {

    let mut inputs: Vec<KoalaBear> = vec![KoalaBear::ONE; 32];

    println!("Starting Poseidon2 loop...");

    for _ in 0..ITERATIONS {
        let result = Poseidon2::hash_many(&inputs);
        inputs.fill(result);
    }
    println!("Finished Poseidon2 loop.");
}