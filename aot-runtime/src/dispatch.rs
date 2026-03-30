use std::sync::OnceLock;

use crate::BlockFn;

static LOOKUP_BLOCK_FN: OnceLock<fn(u64) -> Option<BlockFn>> = OnceLock::new();

pub fn set_lookup_block_fn(func: fn(u64) -> Option<BlockFn>) {
    let _ = LOOKUP_BLOCK_FN.set(func);
}

pub fn lookup_block_fn(pc: u64) -> Option<BlockFn> {
    match LOOKUP_BLOCK_FN.get() {
        Some(func) => func(pc),
        None => None,
    }
}
