#![no_main]

pico_sdk::entrypoint!(main);

use std::hint::black_box;

fn fibonacci(n: u32) -> u32 {
    let mut a = 0;
    let mut b = 1;
    for _ in 0..n {
        let sum = (a + b) % 7919; // Mod to avoid overflow
        a = b;
        b = sum;
    }
    b
}

pub fn main() {
    let n: u32 = pico_sdk::io::read_as();
    let result = black_box(fibonacci(black_box(n)));
    println!("result: {}", result);
}
