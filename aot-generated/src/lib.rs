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
type ChunkLookupFn = fn(u32) -> Option<BlockFn>;
#[repr(C)]
struct ChunkDesc {
    pc_min: u32,
    pc_max: u32,
    lookup: ChunkLookupFn,
}
const CHUNKS: &[ChunkDesc] = &[
    ChunkDesc {
        pc_min: 2099200u32,
        pc_max: 2101256u32,
        lookup: pico_aot_chunk_000::lookup,
    },
    ChunkDesc {
        pc_min: 2101308u32,
        pc_max: 2104708u32,
        lookup: pico_aot_chunk_001::lookup,
    },
    ChunkDesc {
        pc_min: 2104724u32,
        pc_max: 2123224u32,
        lookup: pico_aot_chunk_002::lookup,
    },
    ChunkDesc {
        pc_min: 2123236u32,
        pc_max: 2125464u32,
        lookup: pico_aot_chunk_003::lookup,
    },
    ChunkDesc {
        pc_min: 2125512u32,
        pc_max: 2127796u32,
        lookup: pico_aot_chunk_004::lookup,
    },
    ChunkDesc {
        pc_min: 2127852u32,
        pc_max: 2129976u32,
        lookup: pico_aot_chunk_005::lookup,
    },
    ChunkDesc {
        pc_min: 2130000u32,
        pc_max: 2132336u32,
        lookup: pico_aot_chunk_006::lookup,
    },
    ChunkDesc {
        pc_min: 2132352u32,
        pc_max: 2134384u32,
        lookup: pico_aot_chunk_007::lookup,
    },
    ChunkDesc {
        pc_min: 2134420u32,
        pc_max: 2136948u32,
        lookup: pico_aot_chunk_008::lookup,
    },
    ChunkDesc {
        pc_min: 2136956u32,
        pc_max: 2139552u32,
        lookup: pico_aot_chunk_009::lookup,
    },
    ChunkDesc {
        pc_min: 2139580u32,
        pc_max: 2142296u32,
        lookup: pico_aot_chunk_010::lookup,
    },
    ChunkDesc {
        pc_min: 2142332u32,
        pc_max: 2144560u32,
        lookup: pico_aot_chunk_011::lookup,
    },
    ChunkDesc {
        pc_min: 2144568u32,
        pc_max: 2146396u32,
        lookup: pico_aot_chunk_012::lookup,
    },
    ChunkDesc {
        pc_min: 2146420u32,
        pc_max: 2146636u32,
        lookup: pico_aot_chunk_013::lookup,
    },
];
const GLOBAL_PC_MIN: u32 = 2099200u32;
const PAGE_SHIFT: u32 = 12u32;
const PAGE_HINT: [u16; 12usize] = [
    0u16, 1u16, 2u16, 2u16, 2u16, 2u16, 3u16, 5u16, 6u16, 8u16, 10u16, 11u16,
];
fn lookup_block(pc: u32) -> Option<BlockFn> {
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
