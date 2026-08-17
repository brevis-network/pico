//! SDK APIs for the Pico zkVM.
//!
//! Documentation for these syscalls can be found in the zkVM entrypoint
//! `pico_sdk::riscv_ecalls` module.

use pico_vm::machine::logger::setup_logger;

pub use pico_vm::machine::keys::HashableKey;

extern crate alloc;

pub mod client;
pub mod command;
pub mod heap;
pub mod io;
pub mod m31_client;

#[cfg(all(target_os = "zkvm", feature = "libm"))]
mod libm;
#[deprecated(
    note = "the poseidon2 precompile is shelved: its proving chip is out of the machine and the \
            syscall is unregistered, so a guest that hashes with this stops at UnsupportedSyscall. \
            See instances/chiptype/riscv_chiptype.rs in pico-vm for what has to be finished before \
            it returns."
)]
pub mod poseidon2_hash;
pub mod riscv_ecalls;

#[cfg(all(target_os = "zkvm", feature = "libm"))]
mod libm;

pub mod verify;

/// The number of 32 bit words that the public values digest is composed of.
pub const PV_DIGEST_NUM_WORDS: usize = 8;
pub const POSEIDON_NUM_WORDS: usize = 8;

// The coprocessor integration is shelved along with the poseidon2 precompile it depends on: the
// zkCoprocessor input commitment is a Poseidon2 Merkle root computed through
// `syscall_poseidon2_permute`, and that syscall is no longer served. The feature is kept declared
// but empty so the `#[cfg(feature = "coprocessor")]` blocks below stay valid source rather than
// becoming unexpected-cfg warnings; turning it on lands here instead of failing on a missing crate.
#[cfg(feature = "coprocessor")]
compile_error!(
    "the `coprocessor` feature is shelved -- it needs the poseidon2 precompile, whose chip is out \
     of the machine and whose syscall is unregistered. Restore the coprocessor-sdk dependency and \
     the original feature definition in Cargo.toml, and re-enable the precompile, to bring it back."
);

#[cfg(all(feature = "bb", any(feature = "kb", feature = "m31")))]
compile_error!("Select exactly one of: --features bb | kb | m31");
#[cfg(all(feature = "kb", feature = "m31"))]
compile_error!("Select exactly one of: --features bb | kb | m31");
#[cfg(not(any(feature = "bb", feature = "kb", feature = "m31")))]
compile_error!("Select one of: --features bb | kb | m31");

#[cfg(feature = "bb")]
pub type ZkField = p3_baby_bear::BabyBear;
#[cfg(feature = "kb")]
pub type ZkField = p3_koala_bear::KoalaBear;
#[cfg(feature = "m31")]
pub type ZkField = p3_mersenne_31::Mersenne31;

#[cfg(target_os = "zkvm")]
mod zkvm {
    use super::ZkField as F;
    use crate::riscv_ecalls::syscall_halt;
    use p3_field::FieldAlgebra;
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

/// Loads an ELF file from the specified path.
pub fn load_elf(path: &str) -> Vec<u8> {
    use std::fs;
    fs::read(path).unwrap_or_else(|err| {
        panic!("Failed to load ELF file from {}: {}", path, err);
    })
}
