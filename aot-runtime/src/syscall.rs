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
    #[inline(always)]
    fn syscall_leaf_u32(value: u64, context: &str) -> Result<u32, String> {
        u32::try_from(value).map_err(|_| format!("{context} overflow: {value}"))
    }

    #[inline(always)]
    fn decode_syscall_id_u32(value: u64) -> Result<u32, String> {
        let low_byte = value as u8;
        let sign_ext_byte = (low_byte as i8 as i64) as u64;
        if value == sign_ext_byte {
            return Ok(u32::from(low_byte));
        }

        let low = value as u32;
        let zero_ext = u64::from(low);
        let sign_ext = (low as i32 as i64) as u64;

        if value == zero_ext || value == sign_ext {
            return Ok(low);
        }

        Err(format!(
            "invalid rv64 syscall number encoding: 0x{value:016x}"
        ))
    }

    #[inline(always)]
    fn decode_u32_abi_word(value: u64, context: &str) -> Result<u32, String> {
        let low = value as u32;
        let zero_ext = u64::from(low);
        let sign_ext = (low as i32 as i64) as u64;

        if value == zero_ext || value == sign_ext {
            Ok(low)
        } else {
            Err(format!(
                "{context} invalid 32-bit ABI encoding: 0x{value:016x}"
            ))
        }
    }

    #[inline(always)]
    fn decode_u32_abi_index(value: u64, bound: usize, context: &str) -> Result<usize, String> {
        let low = value as u32;
        let zero_ext = u64::from(low);
        if value != zero_ext {
            return Err(format!(
                "{context} invalid unsigned index encoding: 0x{value:016x}"
            ));
        }

        let index =
            usize::try_from(low).map_err(|_| format!("{context} index overflow: {value}"))?;
        if index >= bound {
            return Err(format!("{context} index out of range: {index} >= {bound}"));
        }
        Ok(index)
    }

    #[inline(always)]
    fn digest_leaf_word_u32(value: u64, context: &str) -> Result<u32, String> {
        Self::decode_u32_abi_word(value, context)
    }

    fn handle_write(&mut self, fd: u64, write_buf: u64) -> Result<(), String> {
        let fd = Self::syscall_leaf_u32(fd, "write fd")?;
        let nbytes = usize::try_from(self.read_reg_snapshot(Register::X12 as usize))
            .map_err(|_| "write syscall byte count does not fit usize".to_string())?;

        // Pre-allocate buffer with exact capacity
        let mut bytes = Vec::with_capacity(nbytes);

        let mut i = 0usize;
        while i < nbytes {
            let addr = write_buf
                .checked_add(i as u64)
                .ok_or_else(|| "write syscall address overflow".to_string())?;
            let word_addr = addr & !7;
            let word = self.read_mem_dword_snapshot(word_addr);
            bytes.push(Self::read_u8_from_word(word, addr));
            i += 1;
        }

        let slice = bytes.as_slice();

        if fd == 1 || fd == 2 {
            let s = core::str::from_utf8(slice)
                .map_err(|err| format!("write syscall emitted invalid UTF-8: {err}"))?;
            process_output(fd, self, s);
            return Ok(());
        }

        if fd == 3 {
            self.public_values_stream.extend_from_slice(slice);
            return Ok(());
        }

        if fd == 4 {
            self.input_stream.push(slice.to_vec());
            return Ok(());
        }

        let hook = self.hook_map.get(&fd).copied();
        if let Some(hook) = hook {
            let result = hook(self, slice);
            let ptr = self.input_stream_ptr;
            self.input_stream.splice(ptr..ptr, result);
            Ok(())
        } else {
            Err(format!("tried to write to unknown file descriptor {fd}"))
        }
    }

    #[inline(always)]
    fn handle_hint_len(&mut self, _syscall_id: u64) -> Result<u64, String> {
        if self.input_stream_ptr >= self.input_stream.len() {
            return Err(format!(
                "failed reading stdin due to insufficient input data: input_stream_ptr={}, input_stream_len={}",
                self.input_stream_ptr,
                self.input_stream.len()
            ));
        }
        Ok(self.input_stream[self.input_stream_ptr].len() as u64)
    }

    fn handle_hint_read(&mut self, _syscall_id: u64, ptr: u64, len: u64) -> Result<(), String> {
        let len = usize::try_from(len).map_err(|_| format!("hint_read len overflow: {len}"))?;
        let stream_ptr = self.input_stream_ptr;
        if stream_ptr >= self.input_stream.len() {
            return Err(format!(
                "failed reading stdin due to insufficient input data: input_stream_ptr={}, input_stream_len={}",
                stream_ptr,
                self.input_stream.len()
            ));
        }

        {
            let vec = &self.input_stream[stream_ptr];
            if vec.len() != len {
                return Err(format!(
                    "hint input stream read length mismatch: expected {len}, got {}",
                    vec.len()
                ));
            }
            if !ptr.is_multiple_of(8) {
                return Err(format!(
                    "hint read address not aligned to 8 bytes: 0x{ptr:016x}"
                ));
            }
        }

        let chunk_count = self.input_stream[stream_ptr].len().div_ceil(8);

        for chunk_idx in 0..chunk_count {
            let word = {
                let vec = &self.input_stream[stream_ptr];
                let start = chunk_idx * 8;
                let end = core::cmp::min(start + 8, vec.len());
                let mut padded = [0u8; 8];
                let chunk = &vec[start..end];
                padded[..chunk.len()].copy_from_slice(chunk);
                u64::from_le_bytes(padded)
            };

            let addr = ptr.checked_add((chunk_idx as u64) * 8).ok_or_else(|| {
                format!("hint_read address overflow: ptr=0x{ptr:016x} chunk_idx={chunk_idx}")
            })?;
            let existing = self.uninitialized_memory.get(addr).copied();
            if let Some(old) = existing.filter(|&v| v != 0) {
                return Err(format!(
                    "hint read address is initialized already (uninitialized_memory)\n\
                     addr=0x{addr:016x} ptr=0x{ptr:016x} chunk_idx={chunk_idx} len={len} stream_ptr={stream_ptr}\n\
                     old_uninit_dword=0x{old:016x} new_dword=0x{word:016x}",
                ));
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
                return Err(format!(
                    "hint read address is initialized already (memory)\n\
                     addr=0x{addr:016x} ptr=0x{ptr:016x} chunk_idx={chunk_idx} len={len} stream_ptr={stream_ptr}\n\
                     prev_record={prev_record:?}\n\
                     new_record={{ value: 0x{word:016x}, chunk: 0, timestamp: 0 }}\n\
                     existing_uninit_word={:?}",
                    existing.map(|x| format!("0x{x:016x}")),
                ));
            }
        }

        self.input_stream_ptr += 1;
        Ok(())
    }

    #[inline(always)]
    fn handle_commit(&mut self, word_idx: u64, word: u64) -> Result<(), String> {
        let idx = Self::decode_u32_abi_index(
            word_idx,
            self.committed_value_digest.len(),
            "commit word_idx",
        )?;
        let slot = &mut self.committed_value_digest[idx];
        *slot = Self::digest_leaf_word_u32(word, "commit digest word")?;
        Ok(())
    }

    #[inline(always)]
    fn handle_commit_deferred(&mut self, word_idx: u64, word: u64) -> Result<(), String> {
        let idx = Self::decode_u32_abi_index(
            word_idx,
            self.deferred_proofs_digest.len(),
            "deferred word_idx",
        )?;
        let slot = &mut self.deferred_proofs_digest[idx];
        *slot = Self::digest_leaf_word_u32(word, "deferred digest word")?;
        Ok(())
    }

    /// Execute a syscall using the AOT syscall system.
    ///
    /// Returns (return_value, next_pc, extra_cycles, should_halt)
    pub fn execute_syscall(
        &mut self,
        syscall_id: u64,
        arg1: u64,
        arg2: u64,
    ) -> Result<(u64, u64, u32, bool), String> {
        let syscall_id_u32 = Self::decode_syscall_id_u32(syscall_id)?;
        let syscall_code = SyscallCode::from_u32(syscall_id_u32);
        if syscall_code.should_send() != 0 {
            self.chunk_split_state.record_syscall_event();
        }
        let _guard = SyscallGuard::new(self);

        if self.is_unconstrained_mode()
            && syscall_id_u32 != SyscallCode::EXIT_UNCONSTRAINED as u32
            && syscall_id_u32 != SyscallCode::WRITE as u32
        {
            return Err(format!(
                "Syscall {:?} is not allowed in unconstrained mode",
                syscall_code
            ));
        }

        let id_byte = (syscall_id_u32 & 0xff) as usize;
        let extra_cycles = SYSCALL_EXTRA_CYCLES[id_byte];
        let syscall_return = u64::from(syscall_id_u32);

        let next_pc = self.pc.wrapping_add(4);

        match syscall_id_u32 {
            id if id == SyscallCode::SHA_EXTEND as u32 => {
                precompiles::sha256::sha256_extend(self, arg1);
                Ok((syscall_return, next_pc, extra_cycles, false))
            }
            id if id == SyscallCode::SHA_COMPRESS as u32 => {
                precompiles::sha256::sha256_compress(self, arg1, arg2);
                Ok((syscall_return, next_pc, extra_cycles, false))
            }
            id if id == SyscallCode::KECCAK_PERMUTE as u32 => {
                precompiles::keccak256::keccak_permute(self, arg1);
                Ok((syscall_return, next_pc, extra_cycles, false))
            }
            id if id == SyscallCode::POSEIDON2_PERMUTE as u32 => {
                precompiles::poseidon2::poseidon2_permute::<KoalaBear>(
                    self,
                    Self::syscall_leaf_u32(arg1, "poseidon input_ptr")?,
                    Self::syscall_leaf_u32(arg2, "poseidon output_ptr")?,
                );
                Ok((syscall_return, next_pc, extra_cycles, false))
            }
            id if id == SyscallCode::UINT256_MUL as u32 => {
                precompiles::uint256::uint256_mul(self, arg1, arg2);
                Ok((syscall_return, next_pc, extra_cycles, false))
            }
            id if id == SyscallCode::ED_ADD as u32 => {
                precompiles::ec::edwards_add::<Ed25519>(self, arg1, arg2);
                Ok((syscall_return, next_pc, extra_cycles, false))
            }
            id if id == SyscallCode::ED_DECOMPRESS as u32 => {
                precompiles::ec::edwards_decompress::<Ed25519Parameters>(
                    self,
                    arg1,
                    Self::syscall_leaf_u32(arg2, "ed decompress sign")?,
                );
                Ok((syscall_return, next_pc, extra_cycles, false))
            }
            id if id == SyscallCode::SECP256K1_ADD as u32 => {
                precompiles::ec::secp256k1_add_optimized(self, arg1, arg2);
                Ok((syscall_return, next_pc, extra_cycles, false))
            }
            id if id == SyscallCode::SECP256K1_DOUBLE as u32 => {
                precompiles::ec::secp256k1_double_optimized(self, arg1);
                Ok((syscall_return, next_pc, extra_cycles, false))
            }
            id if id == SyscallCode::SECP256K1_DECOMPRESS as u32 => {
                precompiles::ec::weierstrass_decompress::<Secp256k1>(
                    self,
                    arg1,
                    Self::syscall_leaf_u32(arg2, "secp256k1 decompress sign")?,
                );
                Ok((syscall_return, next_pc, extra_cycles, false))
            }
            id if id == SyscallCode::SECP256R1_ADD as u32 => {
                precompiles::ec::secp256r1_add_optimized(self, arg1, arg2);
                Ok((syscall_return, next_pc, extra_cycles, false))
            }
            id if id == SyscallCode::SECP256R1_DOUBLE as u32 => {
                precompiles::ec::secp256r1_double_optimized(self, arg1);
                Ok((syscall_return, next_pc, extra_cycles, false))
            }
            id if id == SyscallCode::SECP256R1_DECOMPRESS as u32 => {
                precompiles::ec::weierstrass_decompress::<Secp256r1>(
                    self,
                    arg1,
                    Self::syscall_leaf_u32(arg2, "secp256r1 decompress sign")?,
                );
                Ok((syscall_return, next_pc, extra_cycles, false))
            }
            id if id == SyscallCode::BN254_ADD as u32 => {
                precompiles::ec::bn254_add_optimized(self, arg1, arg2);
                Ok((syscall_return, next_pc, extra_cycles, false))
            }
            id if id == SyscallCode::BN254_DOUBLE as u32 => {
                precompiles::ec::bn254_double_optimized(self, arg1);
                Ok((syscall_return, next_pc, extra_cycles, false))
            }
            id if id == SyscallCode::BLS12381_ADD as u32 => {
                precompiles::ec::bls12381_add_optimized(self, arg1, arg2);
                Ok((syscall_return, next_pc, extra_cycles, false))
            }
            id if id == SyscallCode::BLS12381_DOUBLE as u32 => {
                precompiles::ec::bls12381_double_optimized(self, arg1);
                Ok((syscall_return, next_pc, extra_cycles, false))
            }
            id if id == SyscallCode::BLS12381_DECOMPRESS as u32 => {
                precompiles::ec::weierstrass_decompress::<Bls12381>(
                    self,
                    arg1,
                    Self::syscall_leaf_u32(arg2, "bls12381 decompress sign")?,
                );
                Ok((syscall_return, next_pc, extra_cycles, false))
            }
            id if id == SyscallCode::BLS12381_FP_ADD as u32 => {
                precompiles::fptower::fp_op::<Bls381BaseField>(
                    self,
                    FieldOperation::Add,
                    arg1,
                    arg2,
                );
                Ok((syscall_return, next_pc, extra_cycles, false))
            }
            id if id == SyscallCode::BLS12381_FP_SUB as u32 => {
                precompiles::fptower::fp_op::<Bls381BaseField>(
                    self,
                    FieldOperation::Sub,
                    arg1,
                    arg2,
                );
                Ok((syscall_return, next_pc, extra_cycles, false))
            }
            id if id == SyscallCode::BLS12381_FP_MUL as u32 => {
                precompiles::fptower::fp_op::<Bls381BaseField>(
                    self,
                    FieldOperation::Mul,
                    arg1,
                    arg2,
                );
                Ok((syscall_return, next_pc, extra_cycles, false))
            }
            id if id == SyscallCode::BLS12381_FP2_ADD as u32 => {
                precompiles::fptower::fp2_addsub::<Bls381BaseField>(
                    self,
                    FieldOperation::Add,
                    arg1,
                    arg2,
                );
                Ok((syscall_return, next_pc, extra_cycles, false))
            }
            id if id == SyscallCode::BLS12381_FP2_SUB as u32 => {
                precompiles::fptower::fp2_addsub::<Bls381BaseField>(
                    self,
                    FieldOperation::Sub,
                    arg1,
                    arg2,
                );
                Ok((syscall_return, next_pc, extra_cycles, false))
            }
            id if id == SyscallCode::BLS12381_FP2_MUL as u32 => {
                precompiles::fptower::fp2_mul::<Bls381BaseField>(self, arg1, arg2);
                Ok((syscall_return, next_pc, extra_cycles, false))
            }
            id if id == SyscallCode::BN254_FP_ADD as u32 => {
                precompiles::fptower::fp_op::<Bn254BaseField>(
                    self,
                    FieldOperation::Add,
                    arg1,
                    arg2,
                );
                Ok((syscall_return, next_pc, extra_cycles, false))
            }
            id if id == SyscallCode::BN254_FP_SUB as u32 => {
                precompiles::fptower::fp_op::<Bn254BaseField>(
                    self,
                    FieldOperation::Sub,
                    arg1,
                    arg2,
                );
                Ok((syscall_return, next_pc, extra_cycles, false))
            }
            id if id == SyscallCode::BN254_FP_MUL as u32 => {
                precompiles::fptower::fp_op::<Bn254BaseField>(
                    self,
                    FieldOperation::Mul,
                    arg1,
                    arg2,
                );
                Ok((syscall_return, next_pc, extra_cycles, false))
            }
            id if id == SyscallCode::BN254_FP2_ADD as u32 => {
                precompiles::fptower::fp2_addsub::<Bn254BaseField>(
                    self,
                    FieldOperation::Add,
                    arg1,
                    arg2,
                );
                Ok((syscall_return, next_pc, extra_cycles, false))
            }
            id if id == SyscallCode::BN254_FP2_SUB as u32 => {
                precompiles::fptower::fp2_addsub::<Bn254BaseField>(
                    self,
                    FieldOperation::Sub,
                    arg1,
                    arg2,
                );
                Ok((syscall_return, next_pc, extra_cycles, false))
            }
            id if id == SyscallCode::BN254_FP2_MUL as u32 => {
                precompiles::fptower::fp2_mul::<Bn254BaseField>(self, arg1, arg2);
                Ok((syscall_return, next_pc, extra_cycles, false))
            }
            id if id == SyscallCode::SECP256K1_FP_ADD as u32 => {
                precompiles::fptower::fp_op::<Secp256k1BaseField>(
                    self,
                    FieldOperation::Add,
                    arg1,
                    arg2,
                );
                Ok((syscall_return, next_pc, extra_cycles, false))
            }
            id if id == SyscallCode::SECP256K1_FP_SUB as u32 => {
                precompiles::fptower::fp_op::<Secp256k1BaseField>(
                    self,
                    FieldOperation::Sub,
                    arg1,
                    arg2,
                );
                Ok((syscall_return, next_pc, extra_cycles, false))
            }
            id if id == SyscallCode::SECP256K1_FP_MUL as u32 => {
                precompiles::fptower::fp_op::<Secp256k1BaseField>(
                    self,
                    FieldOperation::Mul,
                    arg1,
                    arg2,
                );
                Ok((syscall_return, next_pc, extra_cycles, false))
            }
            id if id == SyscallCode::WRITE as u32 => {
                self.handle_write(arg1, arg2)?;
                Ok((syscall_return, next_pc, extra_cycles, false))
            }
            id if id == SyscallCode::HINT_LEN as u32 => Ok((
                self.handle_hint_len(syscall_id)?,
                next_pc,
                extra_cycles,
                false,
            )),
            id if id == SyscallCode::HINT_READ as u32 => {
                self.handle_hint_read(syscall_id, arg1, arg2)?;
                Ok((syscall_return, next_pc, extra_cycles, false))
            }
            id if id == SyscallCode::COMMIT as u32 => {
                self.handle_commit(arg1, arg2)?;
                Ok((syscall_return, next_pc, extra_cycles, false))
            }
            id if id == SyscallCode::COMMIT_DEFERRED_PROOFS as u32 => {
                self.handle_commit_deferred(arg1, arg2)?;
                Ok((syscall_return, next_pc, extra_cycles, false))
            }
            id if id == SyscallCode::VERIFY_PICO_PROOF as u32 => {
                Ok((syscall_return, next_pc, extra_cycles, false))
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
                let exit_code = Self::decode_u32_abi_word(arg1, "halt exit_code")?;
                if exit_code != 0 {
                    return Err(format!("HALT with non-zero exit code: {}", exit_code));
                }
                Ok((syscall_return, 0, extra_cycles, true))
            }
            _ => {
                let syscall_code = SyscallCode::from_u32(syscall_id_u32);
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

#[cfg(test)]
mod tests {
    use super::AotEmulatorCore;
    use crate::hook::Hook;
    use pico_vm::{compiler::riscv::program::Program, emulator::riscv::syscalls::SyscallCode};
    use std::{collections::BTreeMap, sync::Arc};

    const TEST_HOOK_FD: u32 = 123;

    fn test_program() -> Arc<Program> {
        let mut program = Program::new(Vec::new(), 0x1000, 0x1000);
        program.memory_image = Arc::new(BTreeMap::new());
        Arc::new(program)
    }

    fn install_write_bytes(emu: &mut AotEmulatorCore, addr: u64, bytes: &[u8]) {
        for (word_idx, chunk) in bytes.chunks(4).enumerate() {
            let mut word_bytes = [0u8; 4];
            word_bytes[..chunk.len()].copy_from_slice(chunk);
            emu.write_mem_word(
                addr + (word_idx as u64) * 4,
                u64::from(u32::from_le_bytes(word_bytes)),
            );
        }
    }

    fn test_hook(_: &AotEmulatorCore, _: &[u8]) -> Vec<Vec<u8>> {
        vec![vec![0x11, 0x22], vec![0x33]]
    }

    #[test]
    fn phase5_hint_read_writes_exact_dword_for_eight_byte_input() {
        let mut emu = AotEmulatorCore::new(test_program(), vec![vec![1, 2, 3, 4, 5, 6, 7, 8]]);

        emu.handle_hint_read(SyscallCode::HINT_READ as u64, 0x100, 8)
            .expect("hint read should succeed");

        assert_eq!(
            emu.uninitialized_memory.get(0x100),
            Some(&0x0807_0605_0403_0201)
        );
        assert_eq!(emu.memory.get(0x100).value, 0x0807_0605_0403_0201);
    }

    #[test]
    fn phase5_hint_read_zero_pads_short_tail() {
        let mut emu = AotEmulatorCore::new(test_program(), vec![vec![9, 8, 7]]);

        emu.handle_hint_read(SyscallCode::HINT_READ as u64, 0x100, 3)
            .expect("hint read should succeed");

        assert_eq!(
            emu.uninitialized_memory.get(0x100),
            Some(&0x0000_0000_0007_0809)
        );
        assert_eq!(emu.memory.get(0x100).value, 0x0000_0000_0007_0809);
        assert_eq!(emu.input_stream_ptr, 1);
    }

    #[test]
    fn phase5_hint_read_writes_full_dwords_plus_single_padded_tail() {
        let mut emu =
            AotEmulatorCore::new(test_program(), vec![vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10]]);

        emu.handle_hint_read(SyscallCode::HINT_READ as u64, 0x100, 10)
            .expect("hint read should succeed");

        assert_eq!(
            emu.uninitialized_memory.get(0x100),
            Some(&0x0807_0605_0403_0201)
        );
        assert_eq!(
            emu.uninitialized_memory.get(0x108),
            Some(&0x0000_0000_0000_0A09)
        );
        assert_eq!(emu.memory.get(0x100).value, 0x0807_0605_0403_0201);
        assert_eq!(emu.memory.get(0x108).value, 0x0000_0000_0000_0A09);
    }

    #[test]
    fn phase5_hint_read_rejects_unaligned_pointer() {
        let mut emu = AotEmulatorCore::new(test_program(), vec![vec![1, 2, 3, 4]]);

        let err = emu
            .handle_hint_read(SyscallCode::HINT_READ as u64, 0x104, 4)
            .expect_err("unaligned hint read should fail");
        assert!(err.contains("hint read address not aligned to 8 bytes"));
    }

    #[test]
    fn phase5_hint_read_rejects_duplicate_initialization_per_dword() {
        let mut emu =
            AotEmulatorCore::new(test_program(), vec![vec![1, 2, 3, 4], vec![5, 6, 7, 8]]);

        emu.handle_hint_read(SyscallCode::HINT_READ as u64, 0x100, 4)
            .expect("first hint read should succeed");

        let err = emu
            .handle_hint_read(SyscallCode::HINT_READ as u64, 0x100, 4)
            .expect_err("duplicate initialization should fail");
        assert!(err.contains("hint read address is initialized already (uninitialized_memory)"));
    }

    #[test]
    fn phase5_write_fd4_replenishes_input_before_next_hint_cycle() {
        let mut emu = AotEmulatorCore::new(test_program(), vec![vec![1, 2, 3, 4]]);
        install_write_bytes(&mut emu, 0x200, &[9, 8, 7]);

        emu.handle_hint_len(SyscallCode::HINT_LEN as u64)
            .expect("hint len should succeed");
        emu.handle_hint_read(SyscallCode::HINT_READ as u64, 0x100, 4)
            .expect("hint read should succeed");
        assert_eq!(emu.input_stream_ptr, 1);
        assert_eq!(emu.input_stream.len(), 1);

        emu.write_reg(12, 3);
        emu.handle_write(4, 0x200)
            .expect("write to fd 4 should succeed");

        assert_eq!(emu.input_stream_ptr, 1);
        assert_eq!(emu.input_stream.len(), 2);
        assert_eq!(
            emu.handle_hint_len(SyscallCode::HINT_LEN as u64)
                .expect("hint len should succeed"),
            3
        );
        emu.handle_hint_read(SyscallCode::HINT_READ as u64, 0x108, 3)
            .expect("hint read should succeed");
        assert_eq!(emu.input_stream_ptr, 2);
        assert_eq!(emu.memory.get(0x100).value, 0x0000_0000_0403_0201);
        assert_eq!(emu.memory.get(0x108).value, 0x0000_0000_0007_0809);
    }

    #[test]
    fn phase5_write_hook_splices_results_at_current_input_cursor() {
        let mut emu = AotEmulatorCore::new(test_program(), vec![vec![0xaa], vec![0xbb]]);
        install_write_bytes(&mut emu, 0x200, &[0xde, 0xad, 0xbe, 0xef]);
        emu.input_stream_ptr = 1;
        emu.hook_map.insert(TEST_HOOK_FD, test_hook as Hook);

        emu.write_reg(12, 4);
        emu.handle_write(TEST_HOOK_FD as u64, 0x200)
            .expect("hook write should succeed");

        assert_eq!(
            emu.input_stream,
            vec![vec![0xaa], vec![0x11, 0x22], vec![0x33], vec![0xbb]]
        );
        assert_eq!(emu.input_stream_ptr, 1);
        assert_eq!(
            emu.handle_hint_len(SyscallCode::HINT_LEN as u64)
                .expect("hint len should succeed"),
            2
        );
        emu.handle_hint_read(SyscallCode::HINT_READ as u64, 0x100, 2)
            .expect("hint read should succeed");
        assert_eq!(emu.input_stream_ptr, 2);
        assert_eq!(
            emu.handle_hint_len(SyscallCode::HINT_LEN as u64)
                .expect("hint len should succeed"),
            1
        );
    }

    #[test]
    fn phase5_second_hint_len_errors_without_replenished_input() {
        let mut emu = AotEmulatorCore::new(test_program(), vec![vec![1, 2, 3, 4]]);

        assert_eq!(
            emu.handle_hint_len(SyscallCode::HINT_LEN as u64)
                .expect("hint len should succeed"),
            4
        );
        emu.handle_hint_read(SyscallCode::HINT_READ as u64, 0x100, 4)
            .expect("hint read should succeed");

        let err = emu
            .handle_hint_len(SyscallCode::HINT_LEN as u64)
            .expect_err("second hint len should fail");
        assert!(err.contains("failed reading stdin due to insufficient input data"));
    }

    #[test]
    fn phase5_commit_digest_word_accepts_sign_extended_payload() {
        assert_eq!(
            AotEmulatorCore::digest_leaf_word_u32(0xffff_ffff_ffff_ffff, "digest").unwrap(),
            u32::MAX
        );
        assert_eq!(
            AotEmulatorCore::digest_leaf_word_u32(0x0000_0000_8000_0001, "digest").unwrap(),
            0x8000_0001
        );
    }

    #[test]
    fn phase5_execute_syscall_accepts_sign_extended_hint_ids() {
        let mut emu = AotEmulatorCore::new(test_program(), vec![vec![1, 2, 3, 4]]);

        let (hint_len, _, _, _) = emu
            .execute_syscall(0xffff_ffff_ffff_fff0, 0, 0)
            .expect("sign-extended HINT_LEN should decode");
        assert_eq!(hint_len, 4);

        emu.execute_syscall(0xffff_ffff_ffff_fff1, 0x100, 4)
            .expect("sign-extended HINT_READ should decode");
        assert_eq!(emu.memory.get(0x100).value, 0x0000_0000_0403_0201);
    }
}
