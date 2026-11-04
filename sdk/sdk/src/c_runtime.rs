//! The C library's failure entry points: `abort()`, and the two names a failed `assert()` calls.
//! Each ends the run abnormally with [`TerminationReason::Abort`] and exit code 134, the code a
//! native process gets from `SIGABRT`.
//!
//! They are weak, so a C library linked into the guest that brings its own wins without a
//! duplicate-symbol error; a freestanding C guest, linked only against `libpico_zkvm.a`, gets
//! these. Rust guests carry them too: the static library is this crate.
//!
//! [`TerminationReason::Abort`]: pico_vm::emulator::riscv::emulator::TerminationReason::Abort

use core::ffi::{c_char, c_int, c_uint, CStr};

use crate::riscv_ecalls::{exit_code, halt_reason, halt_with_reason, sys_write};

/// `void abort(void)`.
#[no_mangle]
#[linkage = "weak"]
pub extern "C" fn abort() -> ! {
    halt_with_reason(exit_code::ABORT, halt_reason::ABORT)
}

/// `__assert_func(file, line, func, expr)`: newlib's and picolibc's failed `assert()`.
///
/// # Safety
///
/// Each pointer is NULL or a NUL-terminated string.
#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn __assert_func(
    file: *const c_char,
    line: c_int,
    func: *const c_char,
    expr: *const c_char,
) -> ! {
    assertion_failed(expr, file, line as i64, func)
}

/// `__assert_fail(expr, file, line, func)`: glibc's and musl's failed `assert()`.
///
/// # Safety
///
/// Each pointer is NULL or a NUL-terminated string.
#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn __assert_fail(
    expr: *const c_char,
    file: *const c_char,
    line: c_uint,
    func: *const c_char,
) -> ! {
    assertion_failed(expr, file, i64::from(line), func)
}

/// Writes `assertion failed: <expr>, <func> at <file>:<line>` to stderr, then aborts. Nothing here
/// allocates: the heap may be what failed.
unsafe fn assertion_failed(
    expr: *const c_char,
    file: *const c_char,
    line: i64,
    func: *const c_char,
) -> ! {
    write_stderr(b"assertion failed: ");
    write_c_str(expr);
    write_stderr(b", ");
    write_c_str(func);
    write_stderr(b" at ");
    write_c_str(file);
    write_stderr(b":");
    let mut digits = [0u8; 20];
    write_stderr(decimal(line, &mut digits));
    write_stderr(b"\n");
    abort()
}

fn write_stderr(bytes: &[u8]) {
    sys_write(2, bytes.as_ptr(), bytes.len());
}

unsafe fn write_c_str(s: *const c_char) {
    if s.is_null() {
        write_stderr(b"?");
    } else {
        write_stderr(CStr::from_ptr(s).to_bytes());
    }
}

/// `n` in decimal, in the tail of `buf`.
fn decimal(n: i64, buf: &mut [u8; 20]) -> &[u8] {
    let mut v = n.unsigned_abs();
    let mut i = buf.len();
    loop {
        i -= 1;
        buf[i] = b'0' + (v % 10) as u8;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    if n < 0 {
        i -= 1;
        buf[i] = b'-';
    }
    &buf[i..]
}
