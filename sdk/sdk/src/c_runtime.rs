//! What a C or C++ guest needs from the C library's startup and exit, for a guest that links no C
//! library: the failure entry points, `abort()` and the two names a failed `assert()` calls, and
//! the exit handlers, `atexit` and `__cxa_atexit`, through which C++ runs its static destructors.
//!
//! The failure entry points end the run abnormally with [`TerminationReason::Abort`] and exit
//! code 134, the code a native process gets from `SIGABRT`.
//!
//! Every symbol here is weak, so a C library linked into the guest that brings its own wins
//! without a duplicate-symbol error; a freestanding guest, linked only against `libpico_zkvm.a`,
//! gets these. Rust guests carry them too: the static library is this crate.
//!
//! [`TerminationReason::Abort`]: pico_vm::emulator::riscv::emulator::TerminationReason::Abort

use core::ffi::{c_char, c_int, c_uint, c_void, CStr};

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

/// One registered exit handler.
#[derive(Clone, Copy)]
enum ExitHandler {
    /// `atexit(f)`.
    Plain(extern "C" fn()),
    /// `__cxa_atexit(f, arg, _)`: a C++ static destructor and its object.
    WithArg(unsafe extern "C" fn(*mut c_void), *mut c_void),
}

/// C guarantees at least 32 `atexit` registrations; C++ registers one per static object with a
/// destructor. A fixed table, so registering never allocates.
const MAX_EXIT_HANDLERS: usize = 256;

/// The guest has one thread.
static mut EXIT_HANDLERS: [Option<ExitHandler>; MAX_EXIT_HANDLERS] = [None; MAX_EXIT_HANDLERS];
static mut EXIT_HANDLER_COUNT: usize = 0;

fn register(handler: ExitHandler) -> c_int {
    // SAFETY: one thread, and `run_exit_handlers` runs only after `main` returns.
    unsafe {
        let count = core::ptr::addr_of!(EXIT_HANDLER_COUNT).read();
        if count == MAX_EXIT_HANDLERS {
            return -1;
        }
        core::ptr::addr_of_mut!(EXIT_HANDLERS[count]).write(Some(handler));
        core::ptr::addr_of_mut!(EXIT_HANDLER_COUNT).write(count + 1);
    }
    0
}

/// `int atexit(void (*f)(void))`: `f` runs after `main` returns, latest registered first.
#[no_mangle]
#[linkage = "weak"]
pub extern "C" fn atexit(f: extern "C" fn()) -> c_int {
    register(ExitHandler::Plain(f))
}

/// `int __cxa_atexit(void (*f)(void*), void* arg, void* dso)`: how C++ registers a static
/// object's destructor. The guest is one image, so `dso` is not needed.
#[no_mangle]
#[linkage = "weak"]
pub extern "C" fn __cxa_atexit(
    f: unsafe extern "C" fn(*mut c_void),
    arg: *mut c_void,
    _dso: *mut c_void,
) -> c_int {
    register(ExitHandler::WithArg(f, arg))
}

/// The handle C++ passes to `__cxa_atexit`, which a C library's `crtbegin.o` would define.
#[no_mangle]
#[linkage = "weak"]
pub static __dso_handle: u8 = 0;

/// Runs the registered exit handlers, latest first, each once; `_start` calls it after `main`.
pub(crate) fn run_exit_handlers() {
    // SAFETY: one thread. A handler may register another, which then runs next, as C requires.
    unsafe {
        loop {
            let count = core::ptr::addr_of!(EXIT_HANDLER_COUNT).read();
            if count == 0 {
                return;
            }
            core::ptr::addr_of_mut!(EXIT_HANDLER_COUNT).write(count - 1);
            match core::ptr::addr_of!(EXIT_HANDLERS[count - 1]).read() {
                Some(ExitHandler::Plain(f)) => f(),
                Some(ExitHandler::WithArg(f, arg)) => f(arg),
                None => {}
            }
        }
    }
}
