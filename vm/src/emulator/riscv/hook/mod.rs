mod bls;
mod ecrecover;
mod ed_decompress;
mod fp;

pub use ecrecover::ecrecover_bytes;

use super::riscv_emulator::RiscvEmulator;
use hashbrown::HashMap;

pub type Hook = fn(&RiscvEmulator, &[u8]) -> Vec<Vec<u8>>;

const SECP256K1_ECRECOVER: u32 = 5;
/// The file descriptor through which to access `hook_ed_decompress`.
pub const FD_EDDECOMPRESS: u32 = 8;

/// The file descriptor through which to access `hook_fp_sqrt`.
pub const FD_FP_SQRT: u32 = 10;

/// The file descriptor through which to access `hook_fp_inverse`.
pub const FD_FP_INV: u32 = 11;

/// The file descriptor through which to access `hook_bls12_381_sqrt`.
pub const FD_BLS12_381_SQRT: u32 = 12;

/// The file descriptor through which to access `hook_bls12_381_inverse`.
pub const FD_BLS12_381_INVERSE: u32 = 13;

pub fn default_hook_map() -> HashMap<u32, Hook> {
    let hooks: [(u32, Hook); _] = [
        (SECP256K1_ECRECOVER, ecrecover::ecrecover),
        (FD_EDDECOMPRESS, ed_decompress::ed_decompress),
        (FD_FP_SQRT, fp::hook_fp_sqrt),
        (FD_FP_INV, fp::hook_fp_inverse),
        (FD_BLS12_381_SQRT, bls::hook_bls12_381_sqrt),
        (FD_BLS12_381_INVERSE, bls::hook_bls12_381_inverse),
    ];
    HashMap::from_iter(hooks)
}
