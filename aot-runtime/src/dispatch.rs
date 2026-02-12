use std::sync::OnceLock;

use crate::BlockFn;

static LOOKUP_BLOCK_FN: OnceLock<fn(u32) -> Option<BlockFn>> = OnceLock::new();

pub fn set_lookup_block_fn(func: fn(u32) -> Option<BlockFn>) {
    let _ = LOOKUP_BLOCK_FN.set(func);
}

pub fn lookup_block_fn(pc: u32) -> Option<BlockFn> {
    match LOOKUP_BLOCK_FN.get() {
        Some(func) => func(pc),
        None => None,
    }
}
