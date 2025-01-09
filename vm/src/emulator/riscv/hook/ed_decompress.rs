use curve25519_dalek::edwards::CompressedEdwardsY;

use crate::{
    chips::gadgets::curves::edwards::ed25519::decompress,
    emulator::riscv::riscv_emulator::RiscvEmulator,
};

#[must_use]
pub fn ed_decompress(_: &RiscvEmulator, buf: &[u8]) -> Vec<Vec<u8>> {
    let Ok(point) = CompressedEdwardsY::from_slice(buf) else {
        return vec![vec![0]];
    };

    if decompress(&point).is_some() {
        vec![vec![1]]
    } else {
        vec![vec![0]]
    }
}
