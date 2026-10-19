//! SDK APIs for the Pico zkVM.
//!
//! Documentation for these syscalls can be found in the zkVM entrypoint
//! `pico_sdk::riscv_ecalls` module.

extern crate alloc;

pub mod command;
pub mod heap;
pub mod io;
mod logger;

pub use logger::init_logger;
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

    #[no_mangle]
    unsafe extern "C" fn __start() {
        {
            PUBLIC_VALUES_HASHER = Some(Sha256::new());

            COPROCESSOR_OUTPUT_VALUES_HASHER = Some(Sha256::new());

            DEFERRED_PROOFS_DIGEST = Some([F::ZERO; 8]);

            extern "C" {
                fn main();
            }
            main()
        }

        syscall_halt(0);
    }

    core::arch::global_asm!(include_str!("memset.s"));
    core::arch::global_asm!(include_str!("memcpy.s"));

    static STACK_TOP: u64 = 0x7800_0000;
    core::arch::global_asm!(
        r#"
    .section .text._start;
    .globl _start;
    _start:
        .option push;
        .option norelax;
        la gp, __global_pointer$;
        .option pop;
        la sp, {0}
        ld sp, 0(sp)
        call __start;
    "#,
        sym STACK_TOP
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

#[macro_export]
macro_rules! entrypoint {
    ($path:path) => {
        const ZKVM_ENTRY: fn() = $path;

        use $crate::heap::SimpleAlloc;

        #[global_allocator]
        static HEAP: SimpleAlloc = SimpleAlloc;

        mod zkvm_generated_main {

            #[no_mangle]
            fn main() {
                // Link to the actual entrypoint only when compiling for zkVM. Doing this avoids
                // compilation errors when building for the host target.
                //
                // Note that, however, it's generally considered wasted effort compiling zkVM
                // programs against the host target. This just makes it such that doing so wouldn't
                // result in an error, which can happen when building a Cargo workspace containing
                // zkVM program crates.
                #[cfg(target_os = "zkvm")]
                super::ZKVM_ENTRY();
                // Named on the host too, or the guest's own `main` is dead code there and a
                // workspace lint under `-D warnings` fails on it.
                #[cfg(not(target_os = "zkvm"))]
                let _ = super::ZKVM_ENTRY;
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
