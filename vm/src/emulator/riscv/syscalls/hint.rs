use super::{Syscall, SyscallCode, SyscallContext};
use crate::{
    chips::chips::riscv_memory::event::MemoryRecord,
    emulator::riscv::{
        emulator::util::align_u64, event_types::RvValue, riscv_emulator::RiscvEmulatorMode,
    },
};

pub(crate) struct HintLenSyscall;

impl Syscall for HintLenSyscall {
    fn emulate(
        &self,
        ctx: &mut SyscallContext,
        _: SyscallCode,
        _arg1: RvValue,
        _arg2: RvValue,
    ) -> Option<RvValue> {
        if ctx.rt.state.input_stream_ptr >= ctx.rt.state.input_stream.len() {
            panic!(
                "failed reading stdin due to insufficient input data: input_stream_ptr={}, input_stream_len={}",
                ctx.rt.state.input_stream_ptr,
                ctx.rt.state.input_stream.len()
            );
        }
        Some(ctx.rt.state.input_stream[ctx.rt.state.input_stream_ptr].len() as RvValue)
    }
}

pub(crate) struct HintReadSyscall;

impl Syscall for HintReadSyscall {
    fn emulate(
        &self,
        ctx: &mut SyscallContext,
        _: SyscallCode,
        arg1: RvValue,
        arg2: RvValue,
    ) -> Option<RvValue> {
        let ptr = arg1;
        let len =
            usize::try_from(arg2).unwrap_or_else(|_| panic!("hint_read len overflow: {arg2}"));
        let stream_ptr = ctx.rt.state.input_stream_ptr;

        if stream_ptr >= ctx.rt.state.input_stream.len() {
            panic!(
                "failed reading stdin due to insufficient input data: input_stream_ptr={}, input_stream_len={}",
                stream_ptr,
                ctx.rt.state.input_stream.len()
            );
        }

        {
            let vec = &ctx.rt.state.input_stream[stream_ptr];
            assert_eq!(vec.len(), len, "hint input stream read length mismatch");
            assert_eq!(ptr % 8, 0, "hint read address not aligned to 8 bytes");
        }

        let chunk_count = {
            let vec = &ctx.rt.state.input_stream[stream_ptr];
            vec.len().div_ceil(8)
        };

        for chunk_idx in 0..chunk_count {
            let mut padded = [0u8; 8];
            {
                let vec = &ctx.rt.state.input_stream[stream_ptr];
                let start = chunk_idx * 8;
                let end = core::cmp::min(start + 8, vec.len());
                let chunk = &vec[start..end];
                padded[..chunk.len()].copy_from_slice(chunk);
            }
            let word = u64::from_le_bytes(padded);
            let addr = ptr.checked_add((chunk_idx as u64) * 8).unwrap_or_else(|| {
                panic!("hint_read address overflow: ptr=0x{ptr:016x} chunk_idx={chunk_idx}")
            });

            let existing = ctx.rt.state.uninitialized_memory.get(addr).copied();
            if let Some(old) = existing.filter(|&v| v != 0) {
                let is_trace = matches!(ctx.rt.mode, RiscvEmulatorMode::Trace);
                if !(is_trace && old == word) {
                    panic!(
                        "hint read address is initialized already (uninitialized_memory)\n\
                         addr=0x{addr:016x} ptr=0x{ptr:016x} chunk_idx={chunk_idx} len={len} stream_ptr={stream_ptr}\n\
                         old_uninit_dword=0x{old:016x} new_dword=0x{word:016x}",
                    );
                }
            }
            ctx.rt.state.uninitialized_memory.insert(addr, word);

            let aligned = align_u64(addr);
            debug_assert_eq!(
                aligned, addr,
                "hint_read must operate on aligned dword keys"
            );
            ctx.rt.capture_snapshot_for_hint(aligned);

            let prev_record = ctx.rt.state.memory.insert(
                aligned,
                MemoryRecord {
                    value: word,
                    chunk: 0,
                    timestamp: 0,
                },
            );

            if prev_record.value != 0 || prev_record.chunk != 0 || prev_record.timestamp != 0 {
                panic!(
                    "hint read address is initialized already (memory)\n\
                     addr=0x{addr:016x} ptr=0x{ptr:016x} chunk_idx={chunk_idx} len={len} stream_ptr={stream_ptr}\n\
                     prev_record={prev_record:?}\n\
                     new_record={{ value: 0x{word:016x}, chunk: 0, timestamp: 0 }}\n\
                     existing_uninit_word={:?}",
                    existing.map(|x| format!("0x{x:016x}")),
                );
            }
        }

        ctx.rt.state.input_stream_ptr += 1;
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        compiler::riscv::program::Program,
        emulator::{opts::EmulatorOpts, riscv::riscv_emulator::RiscvEmulator},
    };
    use p3_baby_bear::BabyBear;
    use std::{
        collections::BTreeMap,
        sync::{Arc, Mutex, MutexGuard, OnceLock},
    };

    fn hint_test_guard() -> MutexGuard<'static, ()> {
        static GUARD: OnceLock<Mutex<()>> = OnceLock::new();
        GUARD
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|err| err.into_inner())
    }

    fn test_program() -> Arc<Program> {
        let mut program = Program::new(Vec::new(), 0x1000, 0x1000);
        program.memory_image = Arc::new(BTreeMap::new());
        Arc::new(program)
    }

    fn test_emulator(input_stream: Vec<Vec<u8>>) -> RiscvEmulator {
        RiscvEmulator::new_single::<BabyBear>(test_program(), EmulatorOpts::default(), None)
            .tap_mut(|emu| {
                emu.state.input_stream = input_stream;
            })
    }

    trait TapMut: Sized {
        fn tap_mut(self, f: impl FnOnce(&mut Self)) -> Self;
    }

    impl<T> TapMut for T {
        fn tap_mut(mut self, f: impl FnOnce(&mut Self)) -> Self {
            f(&mut self);
            self
        }
    }

    #[test]
    fn hint_read_writes_exact_dword_for_eight_byte_input() {
        let _guard = hint_test_guard();
        let mut emulator = test_emulator(vec![vec![1, 2, 3, 4, 5, 6, 7, 8]]);
        let mut ctx = SyscallContext::new(&mut emulator);

        HintReadSyscall.emulate(&mut ctx, SyscallCode::HINT_READ, 0x100, 8);

        assert_eq!(
            ctx.rt.state.uninitialized_memory.get(0x100).copied(),
            Some(0x0807_0605_0403_0201)
        );
        assert_eq!(ctx.rt.state.memory.peek_dword(0x100), 0x0807_0605_0403_0201);
        assert_eq!(ctx.rt.state.input_stream_ptr, 1);
        let accessed: Vec<_> = ctx.rt.state.memory.accessed_keys().collect();
        assert_eq!(accessed, vec![0x100]);
    }

    #[test]
    fn hint_read_zero_pads_short_tail() {
        let _guard = hint_test_guard();
        let mut emulator = test_emulator(vec![vec![1, 2, 3]]);
        let mut ctx = SyscallContext::new(&mut emulator);

        HintReadSyscall.emulate(&mut ctx, SyscallCode::HINT_READ, 0x100, 3);

        assert_eq!(
            ctx.rt.state.uninitialized_memory.get(0x100).copied(),
            Some(0x0000_0000_0003_0201)
        );
        assert_eq!(ctx.rt.state.memory.peek_dword(0x100), 0x0000_0000_0003_0201);
    }

    #[test]
    fn hint_read_writes_full_dwords_plus_single_padded_tail() {
        let _guard = hint_test_guard();
        let mut emulator = test_emulator(vec![vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10]]);
        let mut ctx = SyscallContext::new(&mut emulator);

        HintReadSyscall.emulate(&mut ctx, SyscallCode::HINT_READ, 0x100, 10);

        assert_eq!(
            ctx.rt.state.uninitialized_memory.get(0x100).copied(),
            Some(0x0807_0605_0403_0201)
        );
        assert_eq!(
            ctx.rt.state.uninitialized_memory.get(0x108).copied(),
            Some(0x0000_0000_0000_0A09)
        );
        assert_eq!(ctx.rt.state.memory.peek_dword(0x100), 0x0807_0605_0403_0201);
        assert_eq!(ctx.rt.state.memory.peek_dword(0x108), 0x0000_0000_0000_0A09);
        let accessed: Vec<_> = ctx.rt.state.memory.accessed_keys().collect();
        assert_eq!(accessed, vec![0x100, 0x108]);
    }

    #[test]
    #[should_panic(expected = "hint read address not aligned to 8 bytes")]
    fn hint_read_rejects_unaligned_pointer() {
        let _guard = hint_test_guard();
        let mut emulator = test_emulator(vec![vec![1, 2, 3, 4]]);
        let mut ctx = SyscallContext::new(&mut emulator);

        HintReadSyscall.emulate(&mut ctx, SyscallCode::HINT_READ, 0x104, 4);
    }

    #[test]
    #[should_panic(expected = "hint read address is initialized already (uninitialized_memory)")]
    fn hint_read_rejects_duplicate_initialization_per_dword() {
        let _guard = hint_test_guard();
        let mut emulator = test_emulator(vec![vec![1, 2, 3, 4], vec![5, 6, 7, 8]]);

        {
            let mut ctx = SyscallContext::new(&mut emulator);
            HintReadSyscall.emulate(&mut ctx, SyscallCode::HINT_READ, 0x100, 4);
        }

        let mut ctx = SyscallContext::new(&mut emulator);
        HintReadSyscall.emulate(&mut ctx, SyscallCode::HINT_READ, 0x100, 4);
    }
}
