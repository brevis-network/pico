//! A guest on the zkevm-standards IO interface: it calls `read_input` and `write_output` through
//! their C ABI, as a C guest does.
//!
//! It reads its input twice through `read_input` and once through `pico_sdk::io::input()`, and
//! panics unless the three agree. Then it writes `b"io:"`, the input in 7-byte pieces, a
//! zero-length write from NULL, and the input's length as a little-endian `u64`. The host
//! therefore expects `b"io:" ++ input ++ (input.len() as u64).to_le_bytes()`.
//!
//! `sdk/prover/src/tests/standard_io.rs` runs it. The built ELF ships as
//! `perf/bench_data/rv64/standard-io-elf`.

#![no_main]
pico_sdk::entrypoint!(main);

extern "C" {
    fn read_input(buf_ptr: *mut *const u8, buf_size: *mut usize);
    fn write_output(output: *const u8, size: usize);
}

pub fn main() {
    let (mut first_ptr, mut first_len) = (core::ptr::null(), 0);
    let (mut second_ptr, mut second_len) = (core::ptr::null(), 0);
    // SAFETY: both out-parameters are valid for writes.
    unsafe {
        read_input(&mut first_ptr, &mut first_len);
        read_input(&mut second_ptr, &mut second_len);
    }
    assert_eq!(
        (first_ptr, first_len),
        (second_ptr, second_len),
        "read_input returned two different blocks"
    );
    let input = pico_sdk::io::input();
    assert_eq!(
        (input.as_ptr(), input.len()),
        (first_ptr, first_len),
        "pico_sdk::io::input() is not the block read_input returns"
    );

    let length = (input.len() as u64).to_le_bytes();
    // SAFETY: every pointer is valid for the length passed with it, and NULL goes with 0.
    unsafe {
        write_output(b"io:".as_ptr(), 3);
        for piece in input.chunks(7) {
            write_output(piece.as_ptr(), piece.len());
        }
        write_output(core::ptr::null(), 0);
        write_output(length.as_ptr(), length.len());
    }
}
