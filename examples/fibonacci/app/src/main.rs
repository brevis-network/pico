#![no_main]

pico_sdk::entrypoint!(main);
use alloy_sol_types::SolValue;
use fibonacci_lib::{fibonacci, PublicValuesStruct};
use pico_sdk::io::{commit_bytes, read_as};

pub fn main() {
    // Read inputs `n` from the environment
    let n: u32 = read_as();

    let a: u32 = 0;
    let b: u32 = 1;

    // Compute Fibonacci values starting from `a` and `b`
    let (a_result, b_result) = fibonacci(a, b, n);

    // Encode the result into ABI format
    let result = PublicValuesStruct {
        n,
        a: a_result,
        b: b_result,
    };
    let encoded_bytes = result.abi_encode();

    commit_bytes(&encoded_bytes);
}
