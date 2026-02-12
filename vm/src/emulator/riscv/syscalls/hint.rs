use super::{Syscall, SyscallCode, SyscallContext};
use crate::{
    chips::chips::riscv_memory::event::MemoryRecord,
    emulator::riscv::riscv_emulator::RiscvEmulatorMode,
};

pub(crate) struct HintLenSyscall;

impl Syscall for HintLenSyscall {
    fn emulate(
        &self,
        ctx: &mut SyscallContext,
        _: SyscallCode,
        _arg1: u32,
        _arg2: u32,
    ) -> Option<u32> {
        if ctx.rt.state.input_stream_ptr >= ctx.rt.state.input_stream.len() {
            panic!(
                "failed reading stdin due to insufficient input data: input_stream_ptr={}, input_stream_len={}",
                ctx.rt.state.input_stream_ptr,
                ctx.rt.state.input_stream.len()
            );
        }
        Some(ctx.rt.state.input_stream[ctx.rt.state.input_stream_ptr].len() as u32)
    }
}

pub(crate) struct HintReadSyscall;

impl Syscall for HintReadSyscall {
    fn emulate(&self, ctx: &mut SyscallContext, _: SyscallCode, ptr: u32, len: u32) -> Option<u32> {
        let stream_ptr = ctx.rt.state.input_stream_ptr;
        // Check input stream bounds
        if stream_ptr >= ctx.rt.state.input_stream.len() {
            panic!(
                "failed reading stdin due to insufficient input data: input_stream_ptr={}, input_stream_len={}",
                stream_ptr,
                ctx.rt.state.input_stream.len()
            );
        }

        // Scope the immutable borrow of input_stream for validation
        {
            let vec = &ctx.rt.state.input_stream[stream_ptr];
            assert_eq!(
                vec.len() as u32,
                len,
                "hint input stream read length mismatch"
            );
            assert_eq!(ptr % 4, 0, "hint read address not aligned to 4 bytes");
        }

        // Iterate through the vec in 4-byte chunks, avoid holding the borrow
        for i in (0..len).step_by(4) {
            // Scope the immutable borrow to read the word
            let word = {
                let vec = &ctx.rt.state.input_stream[stream_ptr];
                let b1 = vec[i as usize];
                // In case the vec is not a multiple of 4, right-pad with 0s. This is fine because we
                // are assuming the word is uninitialized, so filling it with 0s makes sense.
                let b2 = vec.get(i as usize + 1).copied().unwrap_or(0);
                let b3 = vec.get(i as usize + 2).copied().unwrap_or(0);
                let b4 = vec.get(i as usize + 3).copied().unwrap_or(0);
                u32::from_le_bytes([b1, b2, b3, b4])
            };

            // Write hint data directly to memory with (value, chunk=0, timestamp=0).
            // This indicates it was initialized but not yet accessed by emulation.
            let addr = ptr + i;
            // TODO: use hashmap for uninitialized_memory to prevent some double-zero writing issues
            let existing = ctx.rt.state.uninitialized_memory.get(addr).copied();
            if let Some(old) = existing.filter(|&v| v != 0) {
                let is_trace = matches!(ctx.rt.mode, RiscvEmulatorMode::Trace);
                if is_trace && (old == word) {
                } else {
                    panic!(
                        "hint read address is initialized already (uninitialized_memory)\n\
                         addr=0x{addr:08x} ptr=0x{ptr:08x} i={i} len={len} stream_ptr={stream_ptr}\n\
                         old_uninit_word=0x{old:08x} new_word=0x{word:08x}",
                    );
                }
            }
            ctx.rt.state.uninitialized_memory.insert(addr, word);

            // Capture snapshot for this address (should be 0) before modifying it
            // Now we can mutably borrow ctx.rt
            ctx.rt.capture_snapshot_for_hint(addr);

            let prev_record = ctx.rt.state.memory.insert(
                addr,
                MemoryRecord {
                    value: word,
                    chunk: 0,
                    timestamp: 0,
                },
            );

            if prev_record.value != 0 || prev_record.chunk != 0 || prev_record.timestamp != 0 {
                panic!(
                    "hint read address is initialized already (memory)\n\
                     addr=0x{addr:08x} ptr=0x{ptr:08x} i={i} len={len} stream_ptr={stream_ptr}\n\
                     prev_record={prev_record:?}\n\
                     new_record={{ value: 0x{word:08x}, chunk: 0, timestamp: 0 }}\n\
                     existing_uninit_word={:?}",
                    existing.map(|x| format!("0x{x:08x}")),
                );
            }
        }

        // Advance pointer after successful processing
        ctx.rt.state.input_stream_ptr += 1;
        None
    }
}
