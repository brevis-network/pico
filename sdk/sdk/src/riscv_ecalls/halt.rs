/// The reason tags the runtime passes in `a1` to `HALT`, read only with a non-zero exit code.
/// Anything else in `a1` reads as a plain exit; the prefix keeps an older runtime's leftover
/// value from being taken for a tag.
pub mod halt_reason {
    const PREFIX: u64 = 0x7069_636f << 32; // "pico"
    pub const EXIT: u64 = 0;
    pub const PANIC: u64 = PREFIX | 1;
    pub const ABORT: u64 = PREFIX | 2;
    pub const OUT_OF_MEMORY: u64 = PREFIX | 3;
}

/// The exit codes the runtime halts with for its own failures.
pub mod exit_code {
    /// A Rust panic, as a panicking Rust process exits.
    pub const PANIC: u32 = 101;
    /// `abort()` and an exhausted heap: 128 + SIGABRT.
    pub const ABORT: u32 = 134;
}

// The host's own values, checked in the host tests: a guest does not compile `pico-vm`.
#[cfg(all(test, not(target_os = "zkvm")))]
const _: () = {
    use pico_vm::emulator::riscv::emulator::error as host;
    assert!(
        halt_reason::EXIT == host::halt_reason::EXIT
            && halt_reason::PANIC == host::halt_reason::PANIC
            && halt_reason::ABORT == host::halt_reason::ABORT
            && halt_reason::OUT_OF_MEMORY == host::halt_reason::OUT_OF_MEMORY
            && exit_code::PANIC == host::exit_code::PANIC
            && exit_code::ABORT == host::exit_code::ABORT
    );
};

cfg_if::cfg_if! {
    if #[cfg(target_os = "zkvm")] {
        use core::arch::asm;
        use sha2::Digest;
        use crate::zkvm;
        use crate::{PV_DIGEST_NUM_WORDS, POSEIDON_NUM_WORDS};
        use p3_field::PrimeField32;
    }
}

/// Halts the program with the given exit code: zero is success, anything else ends the run
/// abnormally, and no proof of it verifies.
///
/// Before halting, the syscall will commit to the public values.
pub extern "C" fn syscall_halt(exit_code: u32) -> ! {
    halt_with_reason(exit_code, halt_reason::EXIT)
}

/// [`syscall_halt`] for a failure of the runtime's own, with the reason the host reports for it
/// (`halt_reason`, passed in `a1`; read only when `exit_code` is non-zero).
#[allow(unused_variables)]
pub fn halt_with_reason(exit_code: u32, reason: u64) -> ! {
    #[cfg(target_os = "zkvm")]
    unsafe {
        #[cfg(feature = "coprocessor")]
        {
            // Commit the coprocessor output values to the public values stream.
            let coprocessor_output_digest_bytes = core::mem::take(&mut *core::ptr::addr_of_mut!(
                zkvm::COPROCESSOR_OUTPUT_VALUES_HASHER
            ))
            .unwrap()
            .finalize();
            println!(
                "coprocessor_output_digest_bytes: {:?}",
                coprocessor_output_digest_bytes
            );

            // write the coprocessor output digest to the public values stream fd
            for chunk in coprocessor_output_digest_bytes.chunks_exact(4) {
                let word = chunk.to_vec();
                asm!(
                    "ecall",
                    in("t0") crate::riscv_ecalls::WRITE,
                    in("a0") 3,
                    in("a1") word.as_ptr(),
                    in("a2") 4,
                );
            }

            // append the coprocessor output digest to the public values hasher
            zkvm::PUBLIC_VALUES_HASHER
                .as_mut()
                .unwrap()
                .update(&coprocessor_output_digest_bytes);
        }
        // When we halt, we retrieve the public values finalized digest.  This is the hash of all
        // the bytes written to the public values fd.
        let pv_digest_bytes =
            core::mem::take(&mut *core::ptr::addr_of_mut!(zkvm::PUBLIC_VALUES_HASHER))
                .unwrap()
                .finalize();

        // For each digest word, call COMMIT ecall.  In the runtime, this will store the digest
        // words into the runtime's execution record's public values digest.  In the AIR, it
        // will be used to verify that the provided public values digest matches the one
        // computed by the program.
        for i in 0..PV_DIGEST_NUM_WORDS {
            let word = u32::from_le_bytes(pv_digest_bytes[i * 4..(i + 1) * 4].try_into().unwrap());
            asm!("ecall", in("t0") crate::riscv_ecalls::COMMIT, in("a0") i, in("a1") word);
        }

        let deferred_proofs_digest = zkvm::DEFERRED_PROOFS_DIGEST.as_mut().unwrap();

        for i in 0..POSEIDON_NUM_WORDS {
            let word = deferred_proofs_digest[i].as_canonical_u32();
            asm!("ecall", in("t0") crate::riscv_ecalls::COMMIT_DEFERRED_PROOFS, in("a0") i, in("a1") word);
        }

        asm!(
            "ecall",
            in("t0") crate::riscv_ecalls::HALT,
            in("a0") exit_code,
            in("a1") reason,
        );
        unreachable!()
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}
