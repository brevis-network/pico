//! Syscall Handling for AOT Emulation
//!
//! This module provides syscall execution support tailored to the AOT runtime.

use super::emulator::AotEmulatorCore;
use crate::precompiles;
use p3_koala_bear::KoalaBear;
use pico_vm::{
    chips::{
        chips::riscv_memory::event::MemoryRecord,
        gadgets::{
            curves::{
                edwards::ed25519::{Ed25519, Ed25519Parameters},
                weierstrass::{bls381::Bls12381, secp256k1::Secp256k1, secp256r1::Secp256r1},
            },
            field::{
                bls381::Bls381BaseField, bn254::Bn254BaseField, field_op::FieldOperation,
                secp256k1::Secp256k1BaseField,
            },
        },
    },
    compiler::riscv::register::Register,
    emulator::riscv::syscalls::SyscallCode,
};

// ============================================================
// Precomputed Syscall Metadata Tables
// ============================================================

/// Precomputed extra cycles indexed by syscall_id (byte 0)
const SYSCALL_EXTRA_CYCLES: [u32; 256] = build_extra_cycles_table();

const fn build_extra_cycles_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    // These values come from byte 2 of the syscall encoding
    table[0x05] = 0x30; // SHA_EXTEND
    table[0x06] = 0x01; // SHA_COMPRESS
    table[0x07] = 0x01; // ED_ADD
    table[0x08] = 0x00; // ED_DECOMPRESS
    table[0x09] = 0x01; // KECCAK_PERMUTE
    table[0x0A] = 0x01; // SECP256K1_ADD
    table[0x0B] = 0x00; // SECP256K1_DOUBLE
    table[0x0C] = 0x00; // SECP256K1_DECOMPRESS
    table[0x0E] = 0x01; // BN254_ADD
    table[0x0F] = 0x00; // BN254_DOUBLE
    table[0x1D] = 0x01; // UINT256_MUL
    table[0x1E] = 0x01; // BLS12381_ADD
    table[0x1F] = 0x00; // BLS12381_DOUBLE
    table[0x1C] = 0x00; // BLS12381_DECOMPRESS
    table[0x20] = 0x01; // BLS12381_FP_ADD
    table[0x21] = 0x01; // BLS12381_FP_SUB
    table[0x22] = 0x01; // BLS12381_FP_MUL
    table[0x23] = 0x01; // BLS12381_FP2_ADD
    table[0x24] = 0x01; // BLS12381_FP2_SUB
    table[0x25] = 0x01; // BLS12381_FP2_MUL
    table[0x26] = 0x01; // BN254_FP_ADD
    table[0x27] = 0x01; // BN254_FP_SUB
    table[0x28] = 0x01; // BN254_FP_MUL
    table[0x29] = 0x01; // BN254_FP2_ADD
    table[0x2A] = 0x01; // BN254_FP2_SUB
    table[0x2B] = 0x01; // BN254_FP2_MUL
    table[0x2C] = 0x01; // SECP256K1_FP_ADD
    table[0x2D] = 0x01; // SECP256K1_FP_SUB
    table[0x2E] = 0x01; // SECP256K1_FP_MUL
    table[0x2F] = 0x01; // POSEIDON2_PERMUTE
    table[0x30] = 0x01; // SECP256R1_ADD
    table[0x31] = 0x00; // SECP256R1_DOUBLE
    table[0x32] = 0x00; // SECP256R1_DECOMPRESS
    table
}

pub(crate) const fn max_syscall_extra_cycles() -> u32 {
    let mut idx = 0;
    let mut max = 0;
    while idx < 256 {
        let value = SYSCALL_EXTRA_CYCLES[idx];
        if value > max {
            max = value;
        }
        idx += 1;
    }
    max
}

struct SyscallGuard(*mut AotEmulatorCore);

impl SyscallGuard {
    #[inline(always)]
    fn new(emu: &mut AotEmulatorCore) -> Self {
        emu.enter_syscall();
        Self(emu)
    }
}

impl Drop for SyscallGuard {
    fn drop(&mut self) {
        // SAFETY: SyscallGuard is scoped to execute_syscall and never outlives the emulator.
        unsafe { (*self.0).exit_syscall() };
    }
}

// Note: SYSCALL_SHOULD_SEND table (byte 1 of syscall encoding) is not needed
// in AOT runtime. The should_send flag is used by the CPU table during proof
// generation to determine syscall interaction lookup, but AOT focuses on
// execution only. If needed for future trace/proof features, it can be added.

impl AotEmulatorCore {
    fn handle_write(&mut self, fd: u32, write_buf: u32) {
        let nbytes = self.read_reg_snapshot(Register::X12 as usize);

        // Pre-allocate buffer with exact capacity
        let mut bytes = Vec::with_capacity(nbytes as usize);

        // Read 4 bytes at a time, snapshotting one word at a time
        let mut i = 0;
        while i < nbytes {
            let addr = write_buf + i;
            let word_addr = addr & !3;
            let byte_offset = addr & 3;

            // Read word once and snapshot once
            let word = self.read_mem_snapshot(word_addr);

            // Extract bytes from this word until we run out or reach next word
            let bytes_in_word = 4 - byte_offset;
            let bytes_to_extract = bytes_in_word.min(nbytes - i);

            for j in 0..bytes_to_extract {
                let shift = (byte_offset + j) * 8;
                bytes.push(((word >> shift) & 0xff) as u8);
            }

            i += bytes_to_extract;
        }

        let slice = bytes.as_slice();

        if fd == 1 || fd == 2 {
            let s = core::str::from_utf8(slice).unwrap();
            process_output(fd, self, s);
            return;
        }

        if fd == 3 {
            self.public_values_stream.extend_from_slice(slice);
            return;
        }

        if fd == 4 {
            self.input_stream.push(slice.to_vec());
            return;
        }

        let hook = self.hook_map.get(&fd).copied();
        if let Some(hook) = hook {
            let result = hook(self, slice);
            let ptr = self.input_stream_ptr;
            self.input_stream.splice(ptr..ptr, result);
        } else {
            log::warn!("tried to write to unknown file descriptor {fd}");
        }
    }

    #[inline(always)]
    fn handle_hint_len(&mut self) -> u32 {
        if self.input_stream_ptr >= self.input_stream.len() {
            panic!(
                "failed reading stdin due to insufficient input data: input_stream_ptr={}, input_stream_len={}",
                self.input_stream_ptr,
                self.input_stream.len()
            );
        }
        self.input_stream[self.input_stream_ptr].len() as u32
    }

    fn handle_hint_read(&mut self, ptr: u32, len: u32) {
        let stream_ptr = self.input_stream_ptr;
        if stream_ptr >= self.input_stream.len() {
            panic!(
                "failed reading stdin due to insufficient input data: input_stream_ptr={}, input_stream_len={}",
                stream_ptr,
                self.input_stream.len()
            );
        }

        {
            let vec = &self.input_stream[stream_ptr];
            assert_eq!(
                vec.len() as u32,
                len,
                "hint input stream read length mismatch"
            );
            assert_eq!(ptr % 4, 0, "hint read address not aligned to 4 bytes");
        }

        for i in (0..len).step_by(4) {
            let word = {
                let vec = &self.input_stream[stream_ptr];
                let b1 = vec[i as usize];
                let b2 = vec.get(i as usize + 1).copied().unwrap_or(0);
                let b3 = vec.get(i as usize + 2).copied().unwrap_or(0);
                let b4 = vec.get(i as usize + 3).copied().unwrap_or(0);
                u32::from_le_bytes([b1, b2, b3, b4])
            };

            let addr = ptr + i;
            let existing = self.uninitialized_memory.get(addr).copied();
            if let Some(old) = existing.filter(|&v| v != 0) {
                panic!(
                    "hint read address is initialized already (uninitialized_memory)\n\
                     addr=0x{addr:08x} ptr=0x{ptr:08x} i={i} len={len} stream_ptr={stream_ptr}\n\
                     old_uninit_word=0x{old:08x} new_word=0x{word:08x}",
                );
            }
            self.uninitialized_memory.insert(addr, word);

            self.capture_snapshot_for_hint(addr);

            let prev_record = self.memory.insert(
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

        self.input_stream_ptr += 1;
    }

    #[inline(always)]
    fn handle_commit(&mut self, word_idx: u32, word: u32) {
        let idx = word_idx as usize;
        self.committed_value_digest[idx] = word;
    }

    #[inline(always)]
    fn handle_commit_deferred(&mut self, word_idx: u32, word: u32) {
        let idx = word_idx as usize;
        self.deferred_proofs_digest[idx] = word;
    }

    /// Execute a syscall using the AOT syscall system.
    ///
    /// Returns (return_value, next_pc, extra_cycles, should_halt)
    pub fn execute_syscall(
        &mut self,
        syscall_id: u32,
        arg1: u32,
        arg2: u32,
    ) -> Result<(u32, u32, u32, bool), String> {
        let syscall_code = SyscallCode::from_u32(syscall_id);
        if syscall_code.should_send() != 0 {
            self.chunk_split_state.num_syscall_events += 1;
        }
        let _guard = SyscallGuard::new(self);

        if self.is_unconstrained_mode()
            && syscall_id != SyscallCode::EXIT_UNCONSTRAINED as u32
            && syscall_id != SyscallCode::WRITE as u32
        {
            return Err(format!(
                "Syscall {:?} is not allowed in unconstrained mode",
                syscall_code
            ));
        }

        let id_byte = (syscall_id & 0xff) as usize;
        let extra_cycles = SYSCALL_EXTRA_CYCLES[id_byte];

        let next_pc = self.pc.wrapping_add(4);

        match syscall_id {
            id if id == SyscallCode::SHA_EXTEND as u32 => {
                precompiles::sha256::sha256_extend(self, arg1);
                Ok((syscall_id, next_pc, extra_cycles, false))
            }
            id if id == SyscallCode::SHA_COMPRESS as u32 => {
                precompiles::sha256::sha256_compress(self, arg1, arg2);
                Ok((syscall_id, next_pc, extra_cycles, false))
            }
            id if id == SyscallCode::KECCAK_PERMUTE as u32 => {
                precompiles::keccak256::keccak_permute(self, arg1);
                Ok((syscall_id, next_pc, extra_cycles, false))
            }
            id if id == SyscallCode::POSEIDON2_PERMUTE as u32 => {
                precompiles::poseidon2::poseidon2_permute::<KoalaBear>(self, arg1, arg2);
                Ok((syscall_id, next_pc, extra_cycles, false))
            }
            id if id == SyscallCode::UINT256_MUL as u32 => {
                precompiles::uint256::uint256_mul(self, arg1, arg2);
                Ok((syscall_id, next_pc, extra_cycles, false))
            }
            id if id == SyscallCode::ED_ADD as u32 => {
                precompiles::ec::edwards_add::<Ed25519>(self, arg1, arg2);
                Ok((syscall_id, next_pc, extra_cycles, false))
            }
            id if id == SyscallCode::ED_DECOMPRESS as u32 => {
                precompiles::ec::edwards_decompress::<Ed25519Parameters>(self, arg1, arg2);
                Ok((syscall_id, next_pc, extra_cycles, false))
            }
            id if id == SyscallCode::SECP256K1_ADD as u32 => {
                precompiles::ec::secp256k1_add_optimized(self, arg1, arg2);
                Ok((syscall_id, next_pc, extra_cycles, false))
            }
            id if id == SyscallCode::SECP256K1_DOUBLE as u32 => {
                precompiles::ec::secp256k1_double_optimized(self, arg1);
                Ok((syscall_id, next_pc, extra_cycles, false))
            }
            id if id == SyscallCode::SECP256K1_DECOMPRESS as u32 => {
                precompiles::ec::weierstrass_decompress::<Secp256k1>(self, arg1, arg2);
                Ok((syscall_id, next_pc, extra_cycles, false))
            }
            id if id == SyscallCode::SECP256R1_ADD as u32 => {
                precompiles::ec::secp256r1_add_optimized(self, arg1, arg2);
                Ok((syscall_id, next_pc, extra_cycles, false))
            }
            id if id == SyscallCode::SECP256R1_DOUBLE as u32 => {
                precompiles::ec::secp256r1_double_optimized(self, arg1);
                Ok((syscall_id, next_pc, extra_cycles, false))
            }
            id if id == SyscallCode::SECP256R1_DECOMPRESS as u32 => {
                precompiles::ec::weierstrass_decompress::<Secp256r1>(self, arg1, arg2);
                Ok((syscall_id, next_pc, extra_cycles, false))
            }
            id if id == SyscallCode::BN254_ADD as u32 => {
                precompiles::ec::bn254_add_optimized(self, arg1, arg2);
                Ok((syscall_id, next_pc, extra_cycles, false))
            }
            id if id == SyscallCode::BN254_DOUBLE as u32 => {
                precompiles::ec::bn254_double_optimized(self, arg1);
                Ok((syscall_id, next_pc, extra_cycles, false))
            }
            id if id == SyscallCode::BLS12381_ADD as u32 => {
                precompiles::ec::bls12381_add_optimized(self, arg1, arg2);
                Ok((syscall_id, next_pc, extra_cycles, false))
            }
            id if id == SyscallCode::BLS12381_DOUBLE as u32 => {
                precompiles::ec::bls12381_double_optimized(self, arg1);
                Ok((syscall_id, next_pc, extra_cycles, false))
            }
            id if id == SyscallCode::BLS12381_DECOMPRESS as u32 => {
                precompiles::ec::weierstrass_decompress::<Bls12381>(self, arg1, arg2);
                Ok((syscall_id, next_pc, extra_cycles, false))
            }
            id if id == SyscallCode::BLS12381_FP_ADD as u32 => {
                precompiles::fptower::fp_op::<Bls381BaseField>(
                    self,
                    FieldOperation::Add,
                    arg1,
                    arg2,
                );
                Ok((syscall_id, next_pc, extra_cycles, false))
            }
            id if id == SyscallCode::BLS12381_FP_SUB as u32 => {
                precompiles::fptower::fp_op::<Bls381BaseField>(
                    self,
                    FieldOperation::Sub,
                    arg1,
                    arg2,
                );
                Ok((syscall_id, next_pc, extra_cycles, false))
            }
            id if id == SyscallCode::BLS12381_FP_MUL as u32 => {
                precompiles::fptower::fp_op::<Bls381BaseField>(
                    self,
                    FieldOperation::Mul,
                    arg1,
                    arg2,
                );
                Ok((syscall_id, next_pc, extra_cycles, false))
            }
            id if id == SyscallCode::BLS12381_FP2_ADD as u32 => {
                precompiles::fptower::fp2_addsub::<Bls381BaseField>(
                    self,
                    FieldOperation::Add,
                    arg1,
                    arg2,
                );
                Ok((syscall_id, next_pc, extra_cycles, false))
            }
            id if id == SyscallCode::BLS12381_FP2_SUB as u32 => {
                precompiles::fptower::fp2_addsub::<Bls381BaseField>(
                    self,
                    FieldOperation::Sub,
                    arg1,
                    arg2,
                );
                Ok((syscall_id, next_pc, extra_cycles, false))
            }
            id if id == SyscallCode::BLS12381_FP2_MUL as u32 => {
                precompiles::fptower::fp2_mul::<Bls381BaseField>(self, arg1, arg2);
                Ok((syscall_id, next_pc, extra_cycles, false))
            }
            id if id == SyscallCode::BN254_FP_ADD as u32 => {
                precompiles::fptower::fp_op::<Bn254BaseField>(
                    self,
                    FieldOperation::Add,
                    arg1,
                    arg2,
                );
                Ok((syscall_id, next_pc, extra_cycles, false))
            }
            id if id == SyscallCode::BN254_FP_SUB as u32 => {
                precompiles::fptower::fp_op::<Bn254BaseField>(
                    self,
                    FieldOperation::Sub,
                    arg1,
                    arg2,
                );
                Ok((syscall_id, next_pc, extra_cycles, false))
            }
            id if id == SyscallCode::BN254_FP_MUL as u32 => {
                precompiles::fptower::fp_op::<Bn254BaseField>(
                    self,
                    FieldOperation::Mul,
                    arg1,
                    arg2,
                );
                Ok((syscall_id, next_pc, extra_cycles, false))
            }
            id if id == SyscallCode::BN254_FP2_ADD as u32 => {
                precompiles::fptower::fp2_addsub::<Bn254BaseField>(
                    self,
                    FieldOperation::Add,
                    arg1,
                    arg2,
                );
                Ok((syscall_id, next_pc, extra_cycles, false))
            }
            id if id == SyscallCode::BN254_FP2_SUB as u32 => {
                precompiles::fptower::fp2_addsub::<Bn254BaseField>(
                    self,
                    FieldOperation::Sub,
                    arg1,
                    arg2,
                );
                Ok((syscall_id, next_pc, extra_cycles, false))
            }
            id if id == SyscallCode::BN254_FP2_MUL as u32 => {
                precompiles::fptower::fp2_mul::<Bn254BaseField>(self, arg1, arg2);
                Ok((syscall_id, next_pc, extra_cycles, false))
            }
            id if id == SyscallCode::SECP256K1_FP_ADD as u32 => {
                precompiles::fptower::fp_op::<Secp256k1BaseField>(
                    self,
                    FieldOperation::Add,
                    arg1,
                    arg2,
                );
                Ok((syscall_id, next_pc, extra_cycles, false))
            }
            id if id == SyscallCode::SECP256K1_FP_SUB as u32 => {
                precompiles::fptower::fp_op::<Secp256k1BaseField>(
                    self,
                    FieldOperation::Sub,
                    arg1,
                    arg2,
                );
                Ok((syscall_id, next_pc, extra_cycles, false))
            }
            id if id == SyscallCode::SECP256K1_FP_MUL as u32 => {
                precompiles::fptower::fp_op::<Secp256k1BaseField>(
                    self,
                    FieldOperation::Mul,
                    arg1,
                    arg2,
                );
                Ok((syscall_id, next_pc, extra_cycles, false))
            }
            id if id == SyscallCode::WRITE as u32 => {
                self.handle_write(arg1, arg2);
                Ok((syscall_id, next_pc, extra_cycles, false))
            }
            id if id == SyscallCode::HINT_LEN as u32 => {
                Ok((self.handle_hint_len(), next_pc, extra_cycles, false))
            }
            id if id == SyscallCode::HINT_READ as u32 => {
                self.handle_hint_read(arg1, arg2);
                Ok((syscall_id, next_pc, extra_cycles, false))
            }
            id if id == SyscallCode::COMMIT as u32 => {
                self.handle_commit(arg1, arg2);
                Ok((syscall_id, next_pc, extra_cycles, false))
            }
            id if id == SyscallCode::COMMIT_DEFERRED_PROOFS as u32 => {
                self.handle_commit_deferred(arg1, arg2);
                Ok((syscall_id, next_pc, extra_cycles, false))
            }
            id if id == SyscallCode::VERIFY_PICO_PROOF as u32 => {
                Ok((syscall_id, next_pc, extra_cycles, false))
            }
            id if id == SyscallCode::ENTER_UNCONSTRAINED as u32 => {
                self.enter_unconstrained_mode();
                Ok((1, next_pc, extra_cycles, false))
            }
            id if id == SyscallCode::EXIT_UNCONSTRAINED as u32 => {
                let restored_pc = self.exit_unconstrained_mode();
                let next_pc = restored_pc.unwrap_or(next_pc);
                Ok((0, next_pc, extra_cycles, false))
            }
            id if id == SyscallCode::HALT as u32 => {
                let exit_code = arg1;
                if exit_code != 0 {
                    return Err(format!("HALT with non-zero exit code: {}", exit_code));
                }
                Ok((syscall_id, 0, extra_cycles, true))
            }
            _ => {
                let syscall_code = SyscallCode::from_u32(syscall_id);
                Err(format!(
                    "Unimplemented syscall {:#x} (code: {:?}) at PC {:#x}",
                    syscall_id, syscall_code, self.pc
                ))
            }
        }
    }
}

fn process_output(fd: u32, rt: &mut AotEmulatorCore, s: &str) {
    let (prefix, mut buffer) = match fd {
        1 => ("stdout", core::mem::take(&mut rt.stdout)),
        2 => ("stderr", core::mem::take(&mut rt.stderr)),
        _ => unreachable!(),
    };

    buffer.push_str(s);
    let mut remaining = buffer.as_str();
    while let Some((l, r)) = remaining.split_once('\n') {
        log::info!("{}> {}", prefix, l);
        remaining = r;
    }
    let remaining = remaining.to_owned();

    match fd {
        1 => core::mem::replace(&mut rt.stdout, remaining),
        2 => core::mem::replace(&mut rt.stderr, remaining),
        _ => unreachable!(),
    };
}
