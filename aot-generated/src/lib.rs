pub use pico_aot_runtime::AotEmulatorCore;
use pico_aot_runtime::{set_lookup_block_fn, BlockFn, NextStep};
pub fn run_aot(emu: &mut AotEmulatorCore) -> Result<(), String> {
    set_lookup_block_fn(lookup_block);
    let mut next = if emu.pc == 0 {
        NextStep::Halt
    } else if let Some(func) = lookup_block(emu.pc) {
        NextStep::Direct(func)
    } else {
        NextStep::Dynamic(emu.pc)
    };
    loop {
        if emu.should_yield() {
            break;
        }
        match next {
            NextStep::Direct(func) => {
                next = func(emu)?;
            }
            NextStep::Dynamic(pc) => {
                emu.pc = pc;
                if emu.pc == 0 {
                    next = NextStep::Halt;
                } else if let Some(func) = lookup_block(pc) {
                    next = NextStep::Direct(func);
                } else {
                    next = emu.interpret_from_current_pc()?;
                }
            }
            NextStep::Halt => break,
        }
    }
    Ok(())
}
type ChunkLookupFn = fn(u64) -> Option<BlockFn>;
#[repr(C)]
struct ChunkDesc {
    pc_min: u64,
    pc_max: u64,
    lookup: ChunkLookupFn,
}
const CHUNKS: &[ChunkDesc] = &[
    ChunkDesc {
        pc_min: 2099200u64,
        pc_max: 2102452u64,
        lookup: pico_aot_chunk_000::lookup,
    },
    ChunkDesc {
        pc_min: 2102468u64,
        pc_max: 2105828u64,
        lookup: pico_aot_chunk_001::lookup,
    },
    ChunkDesc {
        pc_min: 2105840u64,
        pc_max: 2125272u64,
        lookup: pico_aot_chunk_002::lookup,
    },
    ChunkDesc {
        pc_min: 2125276u64,
        pc_max: 2127208u64,
        lookup: pico_aot_chunk_003::lookup,
    },
    ChunkDesc {
        pc_min: 2127252u64,
        pc_max: 2129304u64,
        lookup: pico_aot_chunk_004::lookup,
    },
    ChunkDesc {
        pc_min: 2129308u64,
        pc_max: 2131676u64,
        lookup: pico_aot_chunk_005::lookup,
    },
    ChunkDesc {
        pc_min: 2131692u64,
        pc_max: 2134080u64,
        lookup: pico_aot_chunk_006::lookup,
    },
    ChunkDesc {
        pc_min: 2134136u64,
        pc_max: 2136284u64,
        lookup: pico_aot_chunk_007::lookup,
    },
    ChunkDesc {
        pc_min: 2136300u64,
        pc_max: 2139900u64,
        lookup: pico_aot_chunk_008::lookup,
    },
    ChunkDesc {
        pc_min: 2139952u64,
        pc_max: 2141608u64,
        lookup: pico_aot_chunk_009::lookup,
    },
    ChunkDesc {
        pc_min: 2141612u64,
        pc_max: 2143548u64,
        lookup: pico_aot_chunk_010::lookup,
    },
    ChunkDesc {
        pc_min: 2143576u64,
        pc_max: 2145344u64,
        lookup: pico_aot_chunk_011::lookup,
    },
    ChunkDesc {
        pc_min: 2145352u64,
        pc_max: 2147924u64,
        lookup: pico_aot_chunk_012::lookup,
    },
    ChunkDesc {
        pc_min: 2147932u64,
        pc_max: 2149020u64,
        lookup: pico_aot_chunk_013::lookup,
    },
];
const GLOBAL_PC_MIN: u64 = 2099200u64;
const PAGE_SHIFT: u32 = 12u32;
const PAGE_HINT: [u16; 13usize] = [
    0u16, 1u16, 2u16, 2u16, 2u16, 2u16, 2u16, 4u16, 6u16, 7u16, 9u16, 11u16, 13u16,
];
fn lookup_block(pc: u64) -> Option<BlockFn> {
    if CHUNKS.is_empty() {
        return None;
    }
    if pc < GLOBAL_PC_MIN {
        return None;
    }
    let off = pc - GLOBAL_PC_MIN;
    let page = (off >> PAGE_SHIFT) as usize;
    let mut idx = if page < PAGE_HINT.len() {
        PAGE_HINT[page] as usize
    } else {
        CHUNKS.len().saturating_sub(1)
    };
    while idx < CHUNKS.len() && pc > CHUNKS[idx].pc_max {
        idx += 1;
    }
    if idx == CHUNKS.len() {
        return None;
    }
    let c = &CHUNKS[idx];
    if pc < c.pc_min {
        return None;
    }
    (c.lookup)(pc)
}
