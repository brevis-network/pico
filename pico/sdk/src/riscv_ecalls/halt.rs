cfg_if::cfg_if! {
    if #[cfg(target_os = "zkvm")] {
        use core::arch::asm;
        use sha2::Digest;
        use crate::zkvm;
        use crate::{PV_DIGEST_NUM_WORDS, POSEIDON_NUM_WORDS};
    }
}

/// Halts the program with the given exit code.
///
/// Before halting, the syscall will commit to the public values.
#[allow(unused_variables)]
pub extern "C" fn syscall_halt(exit_code: u8) -> ! {
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

        for i in 0..POSEIDON_NUM_WORDS {
            asm!("ecall", in("t0") crate::riscv_ecalls::COMMIT_DEFERRED_PROOFS, in("a0") i, in("a1") 0);
        }

        asm!(
            "ecall",
            in("t0") crate::riscv_ecalls::HALT,
            in("a0") exit_code
        );
        unreachable!()
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}
