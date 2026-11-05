//! The guest runtime's memory functions against byte-by-byte references.
//!
//! `memcpy` and `memset` are `pico-sdk`'s assembly; `memmove` is `compiler_builtins`'. Each is
//! called through its C symbol, so the compiler cannot inline or rewrite the call, at every
//! source and destination alignment from 0 to 7, at every length from 0 to 40 and at a few
//! longer ones. Each case checks the bytes written, that the bytes around them are untouched, and
//! the returned pointer. `memmove` also runs over overlapping ranges, both ways.
//!
//! The references and the comparisons touch one byte at a time through volatile accesses: slice
//! copies, fills, clones and `==` lower to `memcpy` / `memset` / `bcmp`, and LLVM turns a plain
//! byte loop into one too, which would check each function against itself.
//!
//! `main` returns 0 when every case holds, and otherwise the function's number (1 `memcpy`,
//! 2 `memset`, 3 `memmove`), after printing the failing case to stderr.
//! `sdk/prover/src/tests/memory_functions.rs` runs it; the built ELF ships as
//! `perf/bench_data/rv64/memory-functions-elf`.

#![no_main]
pico_sdk::entrypoint!(main);

use core::ffi::{c_int, c_void};

extern "C" {
    fn memcpy(dst: *mut c_void, src: *const c_void, n: usize) -> *mut c_void;
    fn memset(dst: *mut c_void, c: c_int, n: usize) -> *mut c_void;
    fn memmove(dst: *mut c_void, src: *const c_void, n: usize) -> *mut c_void;
}

/// Room for the longest case, its largest offset and a guard on each side.
const BUF: usize = 320;
const GUARD: usize = 16;
const LENGTHS: [usize; 3] = [64, 255, 257];

fn lengths() -> impl Iterator<Item = usize> {
    (0..=40).chain(LENGTHS)
}

/// Distinct, non-zero bytes, so a byte copied from the wrong place shows.
fn pattern(i: usize, salt: u8) -> u8 {
    (i as u8).wrapping_mul(31).wrapping_add(salt) | 1
}

/// How much of the buffer a case of length `n` can touch, its guards included: the largest
/// offset (7, plus memmove's distance of 9) and a guard on each side. Only this much is filled and
/// compared, which keeps the run near 40 M cycles.
fn span(n: usize) -> usize {
    GUARD + 7 + 9 + n + GUARD
}

/// A buffer whose first `len` bytes are `pattern(_, salt)`, written byte by byte.
fn filled(salt: u8, len: usize) -> [u8; BUF] {
    let mut buf = [0u8; BUF];
    for i in 0..len {
        put(&mut buf, i, pattern(i, salt));
    }
    buf
}

fn get(buf: &[u8; BUF], i: usize) -> u8 {
    unsafe { core::ptr::read_volatile(&buf[i]) }
}

fn put(buf: &mut [u8; BUF], i: usize, v: u8) {
    unsafe { core::ptr::write_volatile(&mut buf[i], v) }
}

/// The first index below `len` where the two differ.
fn differs(a: &[u8; BUF], b: &[u8; BUF], len: usize) -> Option<usize> {
    (0..len).find(|&i| get(a, i) != get(b, i))
}

pub fn main() -> i32 {
    if let Err(case) = check_memcpy() {
        eprintln!("memcpy fails: {case}");
        return 1;
    }
    if let Err(case) = check_memset() {
        eprintln!("memset fails: {case}");
        return 2;
    }
    if let Err(case) = check_memmove() {
        eprintln!("memmove fails: {case}");
        return 3;
    }
    0
}

fn check_memcpy() -> Result<(), String> {
    let src = filled(7, BUF);
    for s in 0..8 {
        for d in 0..8 {
            for n in lengths() {
                let (from, to) = (GUARD + s, GUARD + d);
                let mut dst = filled(5, span(n));
                let mut want = filled(5, span(n));
                for k in 0..n {
                    put(&mut want, to + k, get(&src, from + k));
                }
                let ret = unsafe {
                    memcpy(
                        dst.as_mut_ptr().add(to).cast(),
                        src.as_ptr().add(from).cast(),
                        n,
                    )
                };
                if ret.cast::<u8>() != unsafe { dst.as_mut_ptr().add(to) } {
                    return Err(format!(
                        "src offset {s}, dst offset {d}, n {n}: return value"
                    ));
                }
                if let Some(i) = differs(&dst, &want, span(n)) {
                    return Err(format!("src offset {s}, dst offset {d}, n {n}: byte {i}"));
                }
            }
        }
    }
    Ok(())
}

fn check_memset() -> Result<(), String> {
    // 0x1ab: only the low byte, 0xab, is stored.
    for c in [0, 0x5a, 0xff, 0x1ab] {
        for d in 0..8 {
            for n in lengths() {
                let to = GUARD + d;
                let mut dst = filled(3, span(n));
                let mut want = filled(3, span(n));
                for k in 0..n {
                    put(&mut want, to + k, c as u8);
                }
                let ret = unsafe { memset(dst.as_mut_ptr().add(to).cast(), c, n) };
                if ret.cast::<u8>() != unsafe { dst.as_mut_ptr().add(to) } {
                    return Err(format!("value {c:#x}, dst offset {d}, n {n}: return value"));
                }
                if let Some(i) = differs(&dst, &want, span(n)) {
                    return Err(format!("value {c:#x}, dst offset {d}, n {n}: byte {i}"));
                }
            }
        }
    }
    Ok(())
}

fn check_memmove() -> Result<(), String> {
    for s in 0..8 {
        for d in 0..8 {
            for n in lengths() {
                // Within one buffer, 9 bytes apart: the ranges overlap whenever `n` exceeds the
                // distance, with the destination after the source and then before it.
                for (from, to) in [(GUARD + s, GUARD + d + 9), (GUARD + s + 9, GUARD + d)] {
                    let mut buf = filled(11, span(n));
                    let original = filled(11, span(n));
                    let mut want = filled(11, span(n));
                    for k in 0..n {
                        put(&mut want, to + k, get(&original, from + k));
                    }
                    let ret = unsafe {
                        memmove(
                            buf.as_mut_ptr().add(to).cast(),
                            buf.as_ptr().add(from).cast(),
                            n,
                        )
                    };
                    if ret.cast::<u8>() != unsafe { buf.as_mut_ptr().add(to) } {
                        return Err(format!("from {from}, to {to}, n {n}: return value"));
                    }
                    if let Some(i) = differs(&buf, &want, span(n)) {
                        return Err(format!("from {from}, to {to}, n {n}: byte {i}"));
                    }
                }
            }
        }
    }
    Ok(())
}
