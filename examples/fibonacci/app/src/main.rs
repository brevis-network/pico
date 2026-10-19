#![no_main]

use alloy_sol_types::SolType;
use fibonacci_lib::{fibonacci, PublicValuesStruct};
use pico_sdk::io::{commit_bytes, read_as};
use std::hint::black_box;

pico_sdk::entrypoint!(main);

pub fn main() {
    // Read inputs `n` from the environment
    let n: u32 = read_as();
    println!("n: {}", n);

    let a: u32 = 0;
    let b: u32 = 1;

    // Compute Fibonacci values starting from `a` and `b`
    let (a_result, b_result) = fibonacci(black_box(a), black_box(b), black_box(n));
    let _ = (black_box(a_result), black_box(b_result));

    println!("a: {}", a_result);
    println!("b: {}", b_result);

    // ABI-encoded, so a Solidity verifier decodes the public values as `PublicValuesStruct`.
    commit_bytes(&PublicValuesStruct::abi_encode(&PublicValuesStruct {
        n,
        a: a_result,
        b: b_result,
    }));
}
