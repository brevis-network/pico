//! SDK APIs for the Pico zkVM.
//!
//! Documentation for these syscalls can be found in the zkVM entrypoint
//! `pico_sdk::riscv_ecalls` module.

// The C failure entry points and the `__atomic_*` functions are weak symbols.
#![cfg_attr(target_os = "zkvm", feature(linkage))]

extern crate alloc;

#[cfg(target_os = "zkvm")]
mod atomics;
#[cfg(target_os = "zkvm")]
mod c_runtime;

pub mod command;
pub mod heap;
pub mod io;
#[cfg(feature = "logger")]
mod logger;
pub mod zkvm_io;

#[cfg(feature = "logger")]
pub use logger::init_logger;
#[cfg(feature = "logger")]
#[doc(hidden)]
pub use logger::SILENCED as SILENCED_LOG_TARGETS;

#[cfg(all(target_os = "zkvm", feature = "libm"))]
mod libm;
pub mod poseidon2;
// The reason for this attribute changed with the precompile's return to the machine, so the
// wording did too. It is no longer "the syscall is unregistered, you will hit
// UnsupportedSyscall" -- that is fixed, and a guest calling this now produces a provable trace.
// What is left is that this hasher's output is a *single* field element. Under KoalaBear that is
// about 31 bits, so the birthday bound puts collision resistance near 2^15.5 for every entry
// point here, `hash_single` and `hash_two` included. The machine's own hasher returns
// `[F; DIGEST_SIZE]` -- eight elements -- for the same permutation.
//
// The streaming path compounds it: `update` absorbs into 15 of the 16 state elements, leaving one
// element of capacity, so a multi-block input is bounded the same way from a second direction.
// (`pico-mle-core`'s sponge uses RATE = 8 at WIDTH = 16.)
//
// As a compression function over field elements it is a reasonable shape; as the hash its name
// suggests it is not. The hash is `poseidon2::hash`, the machine's own eight-element sponge. Unlike
// `hash_many` it adds no padding, so it is for fixed-length input: `[a]` and `[a, 0]` collide under
// it, and data whose length varies needs its length in the input. This module stays, deprecated,
// for callers that use it as a compression function.
#[deprecated(
    note = "this hasher returns a single field element (~31 bits under KoalaBear), so its \
            collision resistance is near 2^15.5 by the birthday bound -- for every entry point, \
            not just the streaming one, whose sponge additionally leaves only one element of \
            capacity. For a hash use `pico_sdk::poseidon2::hash`, which returns eight elements -- \
            the machine's own sponge. Unlike `hash_many` it adds no padding: hash fixed-length \
            input with it, or make the length the first element. Use this one as a compression \
            function over field elements if that is what you need; do not use it as a \
            collision-resistant hash. The precompile behind it works -- this is about the \
            construction on top of it."
)]
pub mod poseidon2_hash;
pub mod riscv_ecalls;

pub mod verify;
pub mod zkvm_accelerators;

/// The number of 32 bit words that the public values digest is composed of.
pub const PV_DIGEST_NUM_WORDS: usize = 8;
pub const POSEIDON_NUM_WORDS: usize = 8;

pub type ZkField = p3_koala_bear::KoalaBear;

#[cfg(target_os = "zkvm")]
mod zkvm {
    use super::ZkField as F;
    use crate::riscv_ecalls::syscall_halt;
    use p3_field::PrimeCharacteristicRing;
    use sha2::{Digest, Sha256};

    #[allow(static_mut_refs)]
    pub static mut PUBLIC_VALUES_HASHER: Option<Sha256> = None;

    #[allow(static_mut_refs)]
    pub static mut COPROCESSOR_OUTPUT_VALUES_HASHER: Option<Sha256> = None;

    #[allow(static_mut_refs)]
    pub static mut DEFERRED_PROOFS_DIGEST: Option<[F; 8]> = None;

    /// Runs every function in a linker-built table, `[start, end)`.
    unsafe fn run_table(start: *const u8, end: *const u8, reverse: bool) {
        type Entry = unsafe extern "C" fn();
        let len = (end as usize - start as usize) / core::mem::size_of::<Entry>();
        let table = core::slice::from_raw_parts(start as *const Entry, len);
        if reverse {
            table.iter().rev().for_each(|f| f());
        } else {
            table.iter().for_each(|f| f());
        }
    }

    /// What `_start` calls once `sp` and `gp` are set: IO, the C++ static constructors, `main`,
    /// the exit handlers and static destructors, then the halt with `main`'s return value.
    #[no_mangle]
    unsafe extern "C" fn __start() -> ! {
        PUBLIC_VALUES_HASHER = Some(Sha256::new());
        COPROCESSOR_OUTPUT_VALUES_HASHER = Some(Sha256::new());
        DEFERRED_PROOFS_DIGEST = Some([F::ZERO; 8]);

        // `int main(void)`, and the tables `pico.ld` builds.
        extern "C" {
            fn main() -> i32;
            static __preinit_array_start: u8;
            static __preinit_array_end: u8;
            static __init_array_start: u8;
            static __init_array_end: u8;
            static __fini_array_start: u8;
            static __fini_array_end: u8;
        }
        run_table(&__preinit_array_start, &__preinit_array_end, false);
        run_table(&__init_array_start, &__init_array_end, false);
        let exit_code = main();
        // As C's `exit`: the `atexit` / `__cxa_atexit` handlers, which hold C++'s static
        // destructors, then the destructor table.
        crate::c_runtime::run_exit_handlers();
        run_table(&__fini_array_start, &__fini_array_end, true);

        // The host sees the 32-bit two's complement: `return -1` arrives as 0xffff_ffff.
        syscall_halt(exit_code as u32);
    }

    // `_start`, `memcpy` and `memset` in one `global_asm!`, which is one object file: the one
    // `_start` is in, which every link takes because `_start` is the entry point. So these strong
    // definitions are always linked, and always win over `compiler_builtins`' weak ones (the
    // guest build enables `compiler-builtins-mem`). In separate `global_asm!`s they could land in
    // another object that a link need not take, and lose without an error; reth's ELF did, at a
    // cost of 5 % of its instructions. `cargo pico build` checks the outcome through the
    // `__pico_memcpy` / `__pico_memset` aliases. `_stack_top` and `__global_pointer$` come from
    // `pico.ld`.
    // With `c-memory-functions`, the static library's build, `memmove`, `memcmp`, `bcmp` and
    // `strlen` join them: that build has no `compiler_builtins` copies of the family.
    macro_rules! start_and_memory_functions {
        ($($more:tt)*) => {
            core::arch::global_asm!(
                r#"
    .section .text._start;
    .globl _start;
    _start:
        .option push;
        .option norelax;
        la gp, __global_pointer$;
        .option pop;
        la sp, _stack_top;
        call __start;
    "#,
                include_str!("memcpy.s"),
                // `memset.s` names no section, and `memcpy.s` ends in `.note.GNU-stack`.
                ".text",
                include_str!("memset.s"),
                $($more)*
                r#"
    .globl __pico_memcpy;
    .set __pico_memcpy, memcpy;
    .globl __pico_memset;
    .set __pico_memset, memset;
    "#
            );
        };
    }
    #[cfg(not(feature = "c-memory-functions"))]
    start_and_memory_functions!();
    // Each file ends in another section, so `.text` before the next.
    #[cfg(feature = "c-memory-functions")]
    start_and_memory_functions!(
        ".text",
        include_str!("memmove.s"),
        ".text",
        include_str!("memcmp.s"),
        ".text",
        include_str!("strlen.s"),
        ".text",
        ".globl bcmp\n.set bcmp, memcmp\n",
    );

    pub fn zkvm_getrandom(_s: &mut [u8]) -> Result<(), getrandom::Error> {
        // unsafe {
        //     crate::riscv_ecalls::sys_rand(s.as_mut_ptr(), s.len());
        // }

        Ok(())
    }

    getrandom::register_custom_getrandom!(zkvm_getrandom);

    /// The same no-op backend for getrandom 0.4, which registers by symbol rather than by macro
    /// and is selected by the `getrandom_backend="custom"` cfg the guest build passes.
    #[no_mangle]
    unsafe fn __getrandom_v03_custom(
        dest: *mut u8,
        len: usize,
    ) -> Result<(), getrandom_v04::Error> {
        // 0.4 hands over uninitialized memory and treats `Ok` as "initialized", so this must
        // write the whole buffer even though it has no entropy to put there.
        core::ptr::write_bytes(dest, 0, len);
        Ok(())
    }
}

/// What a guest's entry function may return: nothing, for success, or a C-style exit code, where
/// zero is success and anything else ends the run abnormally with that code.
pub trait MainReturn {
    fn exit_code(self) -> i32;
}

impl MainReturn for () {
    fn exit_code(self) -> i32 {
        0
    }
}

impl MainReturn for i32 {
    fn exit_code(self) -> i32 {
        self
    }
}

/// Declares the guest's entry function, `fn()` or `fn() -> i32` (see [`MainReturn`]), and the
/// `int main(void)` that `_start` calls with it.
#[macro_export]
macro_rules! entrypoint {
    ($path:path) => {
        fn __pico_zkvm_entry() -> i32 {
            $crate::MainReturn::exit_code($path())
        }

        use $crate::heap::SimpleAlloc;

        #[global_allocator]
        static HEAP: SimpleAlloc = SimpleAlloc;

        mod zkvm_generated_main {

            #[no_mangle]
            extern "C" fn main() -> i32 {
                // Link to the actual entrypoint only when compiling for zkVM. Doing this avoids
                // compilation errors when building for the host target.
                //
                // Note that, however, it's generally considered wasted effort compiling zkVM
                // programs against the host target. This just makes it such that doing so wouldn't
                // result in an error, which can happen when building a Cargo workspace containing
                // zkVM program crates.
                #[cfg(target_os = "zkvm")]
                return super::__pico_zkvm_entry();
                // Named on the host too, or the guest's own `main` is dead code there and a
                // workspace lint under `-D warnings` fails on it.
                #[cfg(not(target_os = "zkvm"))]
                {
                    let _ = super::__pico_zkvm_entry;
                    0
                }
            }
        }
    };
}

/// Loads an ELF file from the specified path.
pub fn load_elf(path: &str) -> Vec<u8> {
    use std::fs;
    fs::read(path).unwrap_or_else(|err| {
        panic!("Failed to load ELF file from {}: {}", path, err);
    })
}
