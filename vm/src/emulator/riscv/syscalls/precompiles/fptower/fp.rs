use crate::chips::gadgets::utils::field_params::{FieldType, FpOpField, NumWords};
use hybrid_array::typenum::Unsigned;
use num::BigUint;
use std::marker::PhantomData;

use crate::{
    chips::gadgets::field::field_op::FieldOperation,
    emulator::riscv::{
        event_types::RvValue,
        syscalls::{
            precompiles::{FpEvent, PrecompileEvent},
            Syscall, SyscallCode, SyscallContext,
        },
    },
};

pub struct FpSyscall<P> {
    op: FieldOperation,
    _marker: PhantomData<fn(P) -> P>,
}

impl<P> FpSyscall<P> {
    pub const fn new(op: FieldOperation) -> Self {
        Self {
            op,
            _marker: PhantomData,
        }
    }
}

impl<P: FpOpField> Syscall for FpSyscall<P> {
    fn emulate(
        &self,
        rt: &mut SyscallContext,
        syscall_code: SyscallCode,
        arg1: RvValue,
        arg2: RvValue,
    ) -> Option<RvValue> {
        let x_ptr = arg1;
        let y_ptr = arg2;
        let clk = rt.clk;
        assert!(x_ptr.is_multiple_of(4), "x_ptr is unaligned");
        assert!(y_ptr.is_multiple_of(4), "y_ptr is unaligned");

        // WordsFieldElement is now the u64 dword count.
        let num_u64_words = <P as NumWords>::WordsFieldElement::USIZE;
        let num_memory_words = match P::FIELD_TYPE {
            FieldType::Secp256k1 => {
                SyscallContext::assert_dword_aligned_precompile(x_ptr, "fp x_ptr");
                SyscallContext::assert_dword_aligned_precompile(y_ptr, "fp y_ptr");
                num_u64_words
            }
            // BN/BLS field elements use packed 64-bit dwords in guest memory.
            FieldType::Bn254 | FieldType::Bls381 => {
                SyscallContext::assert_dword_aligned_precompile(x_ptr, "fp x_ptr");
                SyscallContext::assert_dword_aligned_precompile(y_ptr, "fp y_ptr");
                num_u64_words
            }
        };

        let x_vals = match P::FIELD_TYPE {
            FieldType::Secp256k1 => rt.dword_slice_unsafe(x_ptr, num_u64_words),
            FieldType::Bn254 | FieldType::Bls381 => rt.dword_slice_unsafe(x_ptr, num_memory_words),
        };
        let (a, b, y_vals, y_memory_records) = match P::FIELD_TYPE {
            FieldType::Secp256k1 => {
                let (y_memory_records, y_vals) = rt.mr_dword_slice(y_ptr, num_u64_words);
                let a = BigUint::from_bytes_le(
                    &x_vals
                        .iter()
                        .flat_map(|word| word.to_le_bytes())
                        .collect::<Vec<u8>>(),
                );
                let b = BigUint::from_bytes_le(
                    &y_vals
                        .iter()
                        .flat_map(|word| word.to_le_bytes())
                        .collect::<Vec<u8>>(),
                );
                (a, b, y_vals, y_memory_records)
            }
            FieldType::Bn254 | FieldType::Bls381 => {
                let (y_memory_records, y_vals) = rt.mr_dword_slice(y_ptr, num_memory_words);
                let a = BigUint::from_bytes_le(
                    &x_vals
                        .iter()
                        .flat_map(|word| word.to_le_bytes())
                        .collect::<Vec<u8>>(),
                );
                let b = BigUint::from_bytes_le(
                    &y_vals
                        .iter()
                        .flat_map(|word| word.to_le_bytes())
                        .collect::<Vec<u8>>(),
                );
                (a, b, y_vals, y_memory_records)
            }
        };

        let modulus = &BigUint::from_bytes_le(P::MODULUS);
        let a = a % modulus;
        let b = b % modulus;

        let result = match self.op {
            FieldOperation::Add => (a + b) % modulus,
            FieldOperation::Sub => ((a + modulus) - b) % modulus,
            FieldOperation::Mul => (a * b) % modulus,
            _ => panic!("Unsupported operation"),
        };
        let x_memory_records = match P::FIELD_TYPE {
            FieldType::Secp256k1 => {
                let mut result_u64 = result.to_u64_digits();
                result_u64.resize(num_u64_words, 0);
                rt.clk += 1;
                rt.mw_dword_slice(x_ptr, &result_u64)
            }
            FieldType::Bn254 | FieldType::Bls381 => {
                let mut result = result.to_u64_digits();
                result.resize(num_memory_words, 0);
                rt.clk += 1;
                rt.mw_dword_slice(x_ptr, &result)
            }
        };

        let chunk = rt.current_chunk();
        let x = x_vals.into_boxed_slice();
        let y = y_vals.into_boxed_slice();
        let x_memory_records = x_memory_records.into_boxed_slice();
        let y_memory_records = y_memory_records.into_boxed_slice();
        let op = self.op;
        let event = FpEvent {
            chunk,
            clk,
            x_ptr,
            x,
            y_ptr,
            y,
            op,
            x_memory_records,
            y_memory_records,
            local_mem_access: rt.postprocess(),
        };

        // Group all of the events for a specific curve into the same syscall code key.
        match P::FIELD_TYPE {
            FieldType::Bn254 => {
                let syscall_code_key = match syscall_code {
                    SyscallCode::BN254_FP_ADD
                    | SyscallCode::BN254_FP_SUB
                    | SyscallCode::BN254_FP_MUL => SyscallCode::BN254_FP_ADD,
                    _ => unreachable!(),
                };

                let syscall_event = rt
                    .rt
                    .syscall_event(clk, syscall_code.syscall_id(), arg1, arg2);
                rt.record_mut().add_precompile_event(
                    syscall_code_key,
                    syscall_event,
                    PrecompileEvent::Bn254Fp(event),
                );
            }

            FieldType::Bls381 => {
                let syscall_code_key = match syscall_code {
                    SyscallCode::BLS12381_FP_ADD
                    | SyscallCode::BLS12381_FP_SUB
                    | SyscallCode::BLS12381_FP_MUL => SyscallCode::BLS12381_FP_ADD,
                    _ => unreachable!(),
                };

                let syscall_event = rt
                    .rt
                    .syscall_event(clk, syscall_code.syscall_id(), arg1, arg2);
                rt.record_mut().add_precompile_event(
                    syscall_code_key,
                    syscall_event,
                    PrecompileEvent::Bls12381Fp(event),
                );
            }

            FieldType::Secp256k1 => {
                let syscall_code_key = match syscall_code {
                    SyscallCode::SECP256K1_FP_ADD
                    | SyscallCode::SECP256K1_FP_SUB
                    | SyscallCode::SECP256K1_FP_MUL => SyscallCode::SECP256K1_FP_ADD,
                    _ => unreachable!(),
                };

                let syscall_event = rt
                    .rt
                    .syscall_event(clk, syscall_code.syscall_id(), arg1, arg2);
                rt.record_mut().add_precompile_event(
                    syscall_code_key,
                    syscall_event,
                    PrecompileEvent::Secp256k1Fp(event),
                );
            }
        }

        None
    }

    fn num_extra_cycles(&self) -> u32 {
        1
    }
}
