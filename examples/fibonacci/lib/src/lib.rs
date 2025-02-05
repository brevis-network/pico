use std::fs;

use alloy_sol_types::sol;

sol! {
    /// The public values encoded as a struct that can be easily deserialized inside Solidity.
    struct PublicValuesStruct {
        uint32 n;
        uint32 a;
        uint32 b;
    }
}

/// Computes the Fibonacci sequence starting from `a` and `b` up to the `n`-th iteration.
/// Returns the last two values in the sequence: (a, b).
pub fn fibonacci(mut a: u32, mut b: u32, n: u32) -> (u32, u32) {
    for _ in 0..n {
        let next = a.wrapping_add(b);
        a = b;
        b = next;
    }
    (a, b)
}

/// Loads an ELF file from the specified path.
pub fn load_elf(path: &str) -> Vec<u8> {
    fs::read(path).unwrap_or_else(|err| {
        panic!("Failed to load ELF file from {}: {}", path, err);
    })
}
