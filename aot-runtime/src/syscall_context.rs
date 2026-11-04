//! The AOT core as a precompile's [`SyscallHost`], so a precompile the AOT core runs writes the
//! events the interpreter's run of it writes: it is the interpreter's own implementation, run here.
//!
//! Only while the core writes records. With the sink off nothing reads an event, and
//! `execute_syscall` keeps running the compute-only copies in `precompiles/`.
//!
//! Each recorded access is the core's own syscall access at the syscall's clock, so the split
//! accounting, the batch snapshot and the cell's metadata move exactly as they do for those copies.
//! The record the interpreter's `mr`/`mw` return is built from the cell as it stood just before the
//! access, which is what the core's access captures and does not hand back. An unrecorded read
//! still snapshots its cell, as the interpreter's `dword` does.

use hashbrown::HashMap;
use p3_koala_bear::KoalaBear;
use pico_vm::{
    chips::{
        chips::riscv_memory::event::{
            MemoryLocalEvent, MemoryReadRecord, MemoryRecord, MemoryWriteRecord,
        },
        gadgets::{
            curves::{
                edwards::ed25519::{Ed25519, Ed25519Parameters},
                weierstrass::{Bls12381, Bn254, Secp256k1, Secp256r1},
            },
            field::{
                bls381::Bls381BaseField, bn254::Bn254BaseField, field_op::FieldOperation,
                secp256k1::Secp256k1BaseField,
            },
        },
    },
    emulator::riscv::{
        event_types::{RvAddr, RvChunk, RvClk, RvTimestamp, RvValue},
        record::EmulationRecord,
        riscv_emulator::MIN_MAIN_MEMORY_ADDR,
        syscalls::{
            host::{Precompile, SyscallHost},
            precompiles::{
                edwards::{add::EdwardsAddAssignSyscall, decompress::EdwardsDecompressSyscall},
                fptower::{fp::FpSyscall, fp2_addsub::Fp2AddSubSyscall, fp2_mul::Fp2MulSyscall},
                keccak256::permute::Keccak256PermuteSyscall,
                poseidon2::permute::Poseidon2PermuteSyscall,
                sha256::{compress::Sha256CompressSyscall, extend::Sha256ExtendSyscall},
                uint256::syscall::Uint256MulSyscall,
                weierstrass::{
                    add::WeierstrassAddAssignSyscall, decompress::WeierstrassDecompressSyscall,
                    double::WeierstrassDoubleAssignSyscall,
                },
            },
            SyscallCode, SyscallEvent,
        },
    },
    mle::ledger,
};
use std::marker::PhantomData;

use crate::emulator::AotEmulatorCore;

/// A precompile's view of the AOT core for one syscall, as `SyscallContext` is the interpreter's.
pub(crate) struct AotSyscallContext<'a> {
    core: &'a mut AotEmulatorCore,
    clk: RvClk,
    /// The syscall's own first and last access to each dword it touched.
    local_memory_access: HashMap<u64, MemoryLocalEvent>,
}

impl<'a> AotSyscallContext<'a> {
    fn new(core: &'a mut AotEmulatorCore) -> Self {
        let clk = RvClk::from(core.clk);
        Self {
            core,
            clk,
            local_memory_access: HashMap::new(),
        }
    }

    fn timestamp(&self) -> RvTimestamp {
        u32::try_from(self.clk).unwrap_or_else(|_| {
            panic!(
                "syscall-local timestamp {} exceeds u32::MAX; increase timestamp width or reduce chunk budget",
                self.clk
            )
        })
    }

    fn validate_main_memory_addr(addr: RvAddr) {
        assert!(
            addr >= MIN_MAIN_MEMORY_ADDR,
            "syscall memory access below floor 0x{MIN_MAIN_MEMORY_ADDR:08x}: 0x{addr:08x}"
        );
    }

    /// The access's own window: the first access to `addr` in this syscall opens it at the cell it
    /// found, every later one moves its end.
    fn local_event(&mut self, addr: u64, prev: MemoryRecord, now: MemoryRecord) {
        self.local_memory_access
            .entry(addr)
            .and_modify(|event| event.final_mem_access = now)
            .or_insert(MemoryLocalEvent {
                addr,
                initial_mem_access: prev,
                final_mem_access: now,
            });
    }
}

impl SyscallHost for AotSyscallContext<'_> {
    fn current_chunk(&self) -> RvChunk {
        self.core.current_chunk
    }

    fn clk(&self) -> RvClk {
        self.clk
    }

    fn advance_clk(&mut self, cycles: RvClk) {
        self.clk += cycles;
    }

    fn mr_dword(&mut self, addr: RvAddr) -> (MemoryReadRecord, RvValue) {
        Self::validate_main_memory_addr(addr);
        debug_assert_eq!(addr & 7, 0, "mr_dword requires 8-byte-aligned address");
        let prev = self.core.memory.get(addr);
        let (chunk, timestamp) = (self.core.current_chunk, self.timestamp());
        let mut value = [0];
        self.core
            .read_mem_dword_span_at_clk(addr, &mut value, timestamp);
        let [value] = value;
        self.local_event(
            addr,
            prev,
            MemoryRecord {
                value,
                chunk,
                timestamp,
            },
        );
        let record = MemoryReadRecord::new(value, chunk, timestamp, prev.chunk, prev.timestamp);
        (record, value)
    }

    fn mw_dword(&mut self, addr: RvAddr, value: RvValue) -> MemoryWriteRecord {
        Self::validate_main_memory_addr(addr);
        debug_assert_eq!(addr & 7, 0, "mw_dword requires 8-byte-aligned address");
        let prev = self.core.memory.get(addr);
        let (chunk, timestamp) = (self.core.current_chunk, self.timestamp());
        self.core
            .write_mem_dword_span_at_clk(addr, &[value], timestamp);
        self.local_event(
            addr,
            prev,
            MemoryRecord {
                value,
                chunk,
                timestamp,
            },
        );
        MemoryWriteRecord::new(
            value,
            chunk,
            timestamp,
            prev.value,
            prev.chunk,
            prev.timestamp,
        )
    }

    fn dword_slice_unsafe(&mut self, addr: RvAddr, len: usize) -> Vec<RvValue> {
        Self::validate_main_memory_addr(addr);
        debug_assert_eq!(
            addr & 7,
            0,
            "dword_slice_unsafe requires 8-byte-aligned address"
        );
        let mut values = vec![0; len];
        self.core.read_mem_dword_span_snapshot(addr, &mut values);
        values
    }

    fn add_syscall_memory_events(&mut self, count: usize) {
        self.core.chunk_split_state.add_syscall_memory_events(count);
    }

    fn record_mut(&mut self) -> &mut EmulationRecord {
        self.core
            .emitting_record_mut()
            .expect("a precompile runs on the AOT core only while it writes records")
    }

    fn postprocess(&mut self) -> Vec<MemoryLocalEvent> {
        let mut syscall_local_mem_events = Vec::new();
        if !self.core.is_unconstrained_mode() {
            for (_, event) in self.local_memory_access.drain() {
                syscall_local_mem_events.push(event);
            }
            // The CPU-window branch alone is timed, once per call over every word it touched: the
            // precompile's own windows, collected above in the same order, are not part of it.
            let start = ledger::timer_start();
            for event in &syscall_local_mem_events {
                if let Some(cpu_window) = self.core.take_cpu_window(event.addr) {
                    self.core
                        .emitting_record_mut()
                        .expect("a precompile runs on the AOT core only while it writes records")
                        .cpu_local_memory_access
                        .push(cpu_window);
                }
            }
            ledger::drain_cpu_window(start, self.core.role, syscall_local_mem_events.len());
        }
        syscall_local_mem_events
    }

    fn syscall_event(
        &self,
        clk: RvClk,
        syscall_id: u32,
        arg1: RvValue,
        arg2: RvValue,
    ) -> SyscallEvent {
        SyscallEvent {
            chunk: self.core.current_chunk,
            clk,
            syscall_id,
            arg1,
            arg2,
        }
    }
}

/// One precompile, run on a syscall's context.
type Run = for<'a, 'b> fn(&'b mut AotSyscallContext<'a>, SyscallCode, u64, u64) -> Option<RvValue>;

/// The precompile `default_syscall_map` registers for `code`, as it constructs it; `None` for a
/// code that is not one.
fn vm_precompile(code: SyscallCode) -> Option<Run> {
    use FieldOperation::{Add, Mul, Sub};
    use SyscallCode as C;
    let run: Run = match code {
        C::SHA_EXTEND => |ctx, code, a, b| Sha256ExtendSyscall.emulate(ctx, code, a, b),
        C::SHA_COMPRESS => |ctx, code, a, b| Sha256CompressSyscall.emulate(ctx, code, a, b),
        C::KECCAK_PERMUTE => |ctx, code, a, b| Keccak256PermuteSyscall.emulate(ctx, code, a, b),
        C::POSEIDON2_PERMUTE => |ctx, code, a, b| {
            Poseidon2PermuteSyscall::<KoalaBear>(PhantomData).emulate(ctx, code, a, b)
        },
        C::UINT256_MUL => |ctx, code, a, b| Uint256MulSyscall.emulate(ctx, code, a, b),
        C::ED_ADD => {
            |ctx, code, a, b| EdwardsAddAssignSyscall::<Ed25519>::new().emulate(ctx, code, a, b)
        }
        C::ED_DECOMPRESS => |ctx, code, a, b| {
            EdwardsDecompressSyscall::<Ed25519Parameters>::new().emulate(ctx, code, a, b)
        },
        C::SECP256K1_ADD => |ctx, code, a, b| {
            WeierstrassAddAssignSyscall::<Secp256k1>::new().emulate(ctx, code, a, b)
        },
        C::SECP256R1_ADD => |ctx, code, a, b| {
            WeierstrassAddAssignSyscall::<Secp256r1>::new().emulate(ctx, code, a, b)
        },
        C::BN254_ADD => {
            |ctx, code, a, b| WeierstrassAddAssignSyscall::<Bn254>::new().emulate(ctx, code, a, b)
        }
        C::BLS12381_ADD => |ctx, code, a, b| {
            WeierstrassAddAssignSyscall::<Bls12381>::new().emulate(ctx, code, a, b)
        },
        C::SECP256K1_DOUBLE => |ctx, code, a, b| {
            WeierstrassDoubleAssignSyscall::<Secp256k1>::new().emulate(ctx, code, a, b)
        },
        C::SECP256R1_DOUBLE => |ctx, code, a, b| {
            WeierstrassDoubleAssignSyscall::<Secp256r1>::new().emulate(ctx, code, a, b)
        },
        C::BN254_DOUBLE => |ctx, code, a, b| {
            WeierstrassDoubleAssignSyscall::<Bn254>::new().emulate(ctx, code, a, b)
        },
        C::BLS12381_DOUBLE => |ctx, code, a, b| {
            WeierstrassDoubleAssignSyscall::<Bls12381>::new().emulate(ctx, code, a, b)
        },
        C::SECP256K1_DECOMPRESS => |ctx, code, a, b| {
            WeierstrassDecompressSyscall::<Secp256k1>::new().emulate(ctx, code, a, b)
        },
        C::SECP256R1_DECOMPRESS => |ctx, code, a, b| {
            WeierstrassDecompressSyscall::<Secp256r1>::new().emulate(ctx, code, a, b)
        },
        C::BLS12381_DECOMPRESS => |ctx, code, a, b| {
            WeierstrassDecompressSyscall::<Bls12381>::new().emulate(ctx, code, a, b)
        },
        C::BLS12381_FP_ADD => {
            |ctx, code, a, b| FpSyscall::<Bls381BaseField>::new(Add).emulate(ctx, code, a, b)
        }
        C::BLS12381_FP_SUB => {
            |ctx, code, a, b| FpSyscall::<Bls381BaseField>::new(Sub).emulate(ctx, code, a, b)
        }
        C::BLS12381_FP_MUL => {
            |ctx, code, a, b| FpSyscall::<Bls381BaseField>::new(Mul).emulate(ctx, code, a, b)
        }
        C::BLS12381_FP2_ADD => {
            |ctx, code, a, b| Fp2AddSubSyscall::<Bls381BaseField>::new(Add).emulate(ctx, code, a, b)
        }
        C::BLS12381_FP2_SUB => {
            |ctx, code, a, b| Fp2AddSubSyscall::<Bls381BaseField>::new(Sub).emulate(ctx, code, a, b)
        }
        C::BLS12381_FP2_MUL => {
            |ctx, code, a, b| Fp2MulSyscall::<Bls381BaseField>::new().emulate(ctx, code, a, b)
        }
        C::BN254_FP_ADD => {
            |ctx, code, a, b| FpSyscall::<Bn254BaseField>::new(Add).emulate(ctx, code, a, b)
        }
        C::BN254_FP_SUB => {
            |ctx, code, a, b| FpSyscall::<Bn254BaseField>::new(Sub).emulate(ctx, code, a, b)
        }
        C::BN254_FP_MUL => {
            |ctx, code, a, b| FpSyscall::<Bn254BaseField>::new(Mul).emulate(ctx, code, a, b)
        }
        C::BN254_FP2_ADD => {
            |ctx, code, a, b| Fp2AddSubSyscall::<Bn254BaseField>::new(Add).emulate(ctx, code, a, b)
        }
        C::BN254_FP2_SUB => {
            |ctx, code, a, b| Fp2AddSubSyscall::<Bn254BaseField>::new(Sub).emulate(ctx, code, a, b)
        }
        C::BN254_FP2_MUL => {
            |ctx, code, a, b| Fp2MulSyscall::<Bn254BaseField>::new().emulate(ctx, code, a, b)
        }
        C::SECP256K1_FP_ADD => {
            |ctx, code, a, b| FpSyscall::<Secp256k1BaseField>::new(Add).emulate(ctx, code, a, b)
        }
        C::SECP256K1_FP_SUB => {
            |ctx, code, a, b| FpSyscall::<Secp256k1BaseField>::new(Sub).emulate(ctx, code, a, b)
        }
        C::SECP256K1_FP_MUL => {
            |ctx, code, a, b| FpSyscall::<Secp256k1BaseField>::new(Mul).emulate(ctx, code, a, b)
        }
        _ => return None,
    };
    Some(run)
}

impl AotEmulatorCore {
    /// Runs `code`'s precompile as the interpreter does, writing its events into the chunk's
    /// record, and returns what it returns; `None` when `code` is not a precompile.
    pub(crate) fn emulate_vm_precompile(
        &mut self,
        code: SyscallCode,
        arg1: u64,
        arg2: u64,
    ) -> Option<Option<RvValue>> {
        let run = vm_precompile(code)?;
        Some(run(&mut AotSyscallContext::new(self), code, arg1, arg2))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use pico_vm::emulator::riscv::syscalls::{default_syscall_map, SyscallCode};

    use super::{vm_precompile, KoalaBear};

    /// The interpreter registers a syscall chip row for exactly the precompiles; a code the AOT
    /// core cannot hand to the interpreter's implementation would emit no precompile event.
    #[test]
    fn every_precompile_the_interpreter_registers_runs_here_too() {
        let precompiles: BTreeSet<SyscallCode> = default_syscall_map::<KoalaBear>()
            .into_keys()
            .filter(|code| code.should_send() != 0)
            .collect();
        let here: BTreeSet<SyscallCode> = precompiles
            .iter()
            .copied()
            .filter(|&code| vm_precompile(code).is_some())
            .collect();
        assert_eq!(here, precompiles);
        for code in default_syscall_map::<KoalaBear>().into_keys() {
            if code.should_send() == 0 {
                assert!(vm_precompile(code).is_none(), "{code} is not a precompile");
            }
        }
    }
}
