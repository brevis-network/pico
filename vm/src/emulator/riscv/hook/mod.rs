mod ecrecover;

use super::riscv_emulator::RiscvEmulator;
use hashbrown::HashMap;

pub type Hook = fn(&RiscvEmulator, &[u8]) -> Vec<Vec<u8>>;

const SECP256K1_ECRECOVER: u32 = 5;

pub fn default_hook_map() -> HashMap<u32, Hook> {
    let hooks: [(u32, Hook); _] = [(SECP256K1_ECRECOVER, ecrecover::ecrecover)];
    HashMap::from_iter(hooks)
}
