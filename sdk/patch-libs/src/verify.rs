use crate::syscall_verify_pico_proof;

/// Verifies the next proof in the proof input stream given a verification key digest and public
/// values digest. If the proof is invalid, the function will panic.
pub fn verify_pico_proof(vk_digest: &[u32; 8], pv_digest: &[u8; 32]) {
    unsafe {
        syscall_verify_pico_proof(vk_digest, pv_digest);
    }
}
