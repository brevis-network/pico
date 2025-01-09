mod ecrecover;
mod ed_decompress;

use super::riscv_emulator::RiscvEmulator;
use hashbrown::HashMap;

pub type Hook = fn(&RiscvEmulator, &[u8]) -> Vec<Vec<u8>>;

const SECP256K1_ECRECOVER: u32 = 5;
/// The file descriptor through which to access `hook_ed_decompress`.
pub const FD_EDDECOMPRESS: u32 = 8;

pub fn default_hook_map() -> HashMap<u32, Hook> {
    let hooks: [(u32, Hook); _] = [
        (SECP256K1_ECRECOVER, ecrecover::ecrecover),
        (FD_EDDECOMPRESS, ed_decompress::ed_decompress),
    ];
    HashMap::from_iter(hooks)
}
