use super::super::riscv_emulator::RiscvEmulator;
use crate::chips::gadgets::curves::k256::{Invert, RecoveryId, Signature, VerifyingKey};

pub fn ecrecover(_: &RiscvEmulator, buf: &[u8]) -> Vec<Vec<u8>> {
    assert_eq!(
        buf.len(),
        65 + 32,
        "ecrecover input should have length 65 + 32"
    );
    let (sig, msg_hash) = buf.split_at(65);
    let sig: &[u8; 65] = sig.try_into().unwrap();
    let msg_hash: &[u8; 32] = msg_hash.try_into().unwrap();

    let mut recovery_id = sig[64];
    let mut sig = Signature::from_slice(&sig[..64]).unwrap();

    if let Some(sig_normalized) = sig.normalize_s() {
        sig = sig_normalized;
        recovery_id ^= 1;
    };
    let recid = RecoveryId::from_byte(recovery_id).expect("Computed recovery ID is invalid!");

    let recovered_key = VerifyingKey::recover_from_prehash(&msg_hash[..], &sig, recid).unwrap();
    let bytes = recovered_key.to_sec1_bytes();

    let (_, s) = sig.split_scalars();
    let s_inverse = s.invert();

    vec![bytes.to_vec(), s_inverse.to_bytes().to_vec()]
}
