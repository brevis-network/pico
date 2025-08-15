#[cfg(target_os = "zkvm")]
use core::arch::asm;

cfg_if::cfg_if! {
    if #[cfg(target_os = "zkvm")] {
        use crate::zkvm::DEFERRED_PROOFS_DIGEST;
        use crate::ZkField as F;
        use crate::riscv_ecalls::VERIFY_PICO_PROOF;
        use p3_field::FieldAlgebra;
        use pico_vm::primitives::hash_deferred_proof;
    }
}

#[no_mangle]
#[allow(unused_variables)]
pub fn syscall_verify_pico_proof(vk_digest: &[u32; 8], pv_digest: &[u8; 32]) {
    #[cfg(target_os = "zkvm")]
    {
        // Call syscall to verify the next pico proof
        unsafe {
            asm!(
            "ecall",
            in("t0") VERIFY_PICO_PROOF,
            in("a0") vk_digest.as_ptr(),
            in("a1") pv_digest.as_ptr(),
            );
        }

        let deferred_proofs_digest;
        // SAFETY: we have sole access because zkvm is single threaded.
        unsafe {
            deferred_proofs_digest = DEFERRED_PROOFS_DIGEST.as_mut().unwrap();
        }

        // println!(
        //     "deferred_proofs_digest before syscall: {:?}",
        //     deferred_proofs_digest
        // );

        let vk_digest: [F; 8] = core::array::from_fn(|i| F::from_canonical_u32(vk_digest[i]));
        let pv_digest: [F; 32] =
            core::array::from_fn(|i| F::from_canonical_u32(pv_digest[i] as u32));

        *deferred_proofs_digest =
            hash_deferred_proof::<F>(deferred_proofs_digest, &vk_digest, &pv_digest);

        // println!(
        //     "deferred_proofs_digest after syscall: {:?}",
        //     deferred_proofs_digest
        // );
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}
