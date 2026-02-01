use std::fs;

use alloy_primitives::U256;
use alloy_sol_types::sol;

sol! {
    /// The public values encoded as a struct that can be easily deserialized inside Solidity.
    struct PublicValuesStruct {
        uint32 n;
        uint32 a;
        uint32 b;
    }
}

pub fn fib_add(mut a: u32, mut b: u32, n: u32) -> (u32, u32) {
    for _ in 0..n {
        let next = a.wrapping_add(b);
        a = b;
        b = next;
    }
    (a, b)
}

pub fn fib_add_u64(mut a: u64, mut b: u64, n: u64) -> (u64, u64) {
    for _ in 0..n {
        let next = a.wrapping_add(b);
        a = b;
        b = next;
    }
    (a, b)
}

pub fn fib_add_u256(mut a: u64, mut b: u64, n: u64) -> (u64, u64) {
    let mut a: U256 = U256::from(a);
    let mut b: U256 = U256::from(b);
    for _ in 0..n {
        let next = a.wrapping_add(b);
        a = b;
        b = next;
    }
    (
        a.to_be_bytes::<{ U256::BYTES }>()[0] as u64,
        b.to_be_bytes::<{ U256::BYTES }>()[0] as u64,
    )
}

pub fn fib_mul(mut a: u32, mut b: u32, n: u32) -> (u32, u32) {
    for _ in 0..n {
        let next = a.wrapping_mul(b);
        a = b;
        b = next;
    }
    (a, b)
}

pub fn fib_mul_u64(mut a: u64, mut b: u64, n: u64) -> (u64, u64) {
    for _ in 0..n {
        let next = a.wrapping_mul(b);
        a = b;
        b = next;
    }
    (a, b)
}

pub fn fib_mul_u256(mut a: u64, mut b: u64, n: u64) -> (u64, u64) {
    let mut a: U256 = U256::from(a);
    let mut b: U256 = U256::from(b);
    for _ in 0..n {
        let next = a.wrapping_mul(b);
        a = b;
        b = next;
    }
    (
        a.to_be_bytes::<{ U256::BYTES }>()[0] as u64,
        b.to_be_bytes::<{ U256::BYTES }>()[0] as u64,
    )
}

/// Loads an ELF file from the specified path.
pub fn load_elf(path: &str) -> Vec<u8> {
    fs::read(path).unwrap_or_else(|err| {
        panic!("Failed to load ELF file from {}: {}", path, err);
    })
}
