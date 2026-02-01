#![no_main]

use alloy_primitives::U256;
use alloy_sol_types::SolValue;
use fibonacci_lib::*;
use pico_sdk::io::{commit_bytes, read_as};
use std::hint::black_box;

pico_sdk::entrypoint!(main);

pub fn main() {
    // Read inputs `n` from the environment
    // let n: u32 = read_as();
    // let n: u32 = 9_000_000_u32;
    let n: u32 = 100_000_u32;

    let a: u32 = 0;
    let b: u32 = 1;

    // Compute Fibonacci values starting from `a` and `b`
    // let (a_result, b_result) = fibonacci(a, b, n);
    // let (a_result, b_result) = fibonacci_u64(a as u64, b as u64, n as u64);
    // let (a_result, b_result) = fib_add(a, b, n);
    // let (a_result, b_result) = fib_mul(a, b, n);
    // let (a_result, b_result) = fib_add_u64(a as u64, b as u64, n as u64);
    // let (a_result, b_result) = fib_mul_u64(a as u64, b as u64, n as u64);
    // let (a_result, b_result) = fib_add_u256(a as u64, b as u64, n as u64);
    let (a_result, b_result) = fib_mul_u256(a as u64, b as u64, n as u64);
    println!("{a_result:?}, {b_result:?}");

    /*
    // Encode the result into ABI format
    let result = PublicValuesStruct {
        n,
        a: a_result,
        b: b_result,
    };
    let encoded_bytes = result.abi_encode();

    commit_bytes(&encoded_bytes);
    */
}
