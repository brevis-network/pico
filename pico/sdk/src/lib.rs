//! SDK APIs for the Pico zkVM.
//!
//! Documentation for these syscalls can be found in the zkVM entrypoint
//! `pico_sdk::riscv_ecalls` module.

use pico_vm::machine::logger::setup_logger;

extern crate alloc;

pub mod client;
pub mod client_vk;
pub mod command;
pub mod heap;
pub mod io;
#[cfg(all(target_os = "zkvm", feature = "libm"))]
mod libm;
pub mod poseidon2_hash;
pub mod riscv_ecalls;

#[cfg(all(target_os = "zkvm", feature = "libm"))]
mod libm;

/// The number of 32 bit words that the public values digest is composed of.
pub const PV_DIGEST_NUM_WORDS: usize = 8;
pub const POSEIDON_NUM_WORDS: usize = 8;

#[cfg(target_os = "zkvm")]
mod zkvm {
    use crate::riscv_ecalls::syscall_halt;
    use sha2::{Digest, Sha256};

    #[allow(static_mut_refs)]
    pub static mut PUBLIC_VALUES_HASHER: Option<Sha256> = None;

    #[allow(static_mut_refs)]
    pub static mut COPROCESSOR_OUTPUT_VALUES_HASHER: Option<Sha256> = None;

    #[no_mangle]
    unsafe extern "C" fn __start() {
        {
            PUBLIC_VALUES_HASHER = Some(Sha256::new());

            COPROCESSOR_OUTPUT_VALUES_HASHER = Some(Sha256::new());

            extern "C" {
                fn main();
            }
            main()
        }

        syscall_halt(0);
    }

    static STACK_TOP: u32 = 0x0020_0400;

    core::arch::global_asm!(include_str!("memset.s"));
    core::arch::global_asm!(include_str!("memcpy.s"));

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
        lw sp, 0(sp)
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
                super::ZKVM_ENTRY()
            }
        }
    };
}

pub fn init_logger() {
    setup_logger();
}
