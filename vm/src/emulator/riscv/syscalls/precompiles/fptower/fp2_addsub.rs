use crate::chips::gadgets::utils::field_params::{FieldType, FpOpField, NumWords};
use hybrid_array::typenum::Unsigned;
use num::BigUint;
use std::marker::PhantomData;

use crate::{
    chips::gadgets::field::field_op::FieldOperation,
    emulator::riscv::{
        event_types::RvValue,
        syscalls::{
            precompiles::{Fp2AddSubEvent, PrecompileEvent},
            Syscall, SyscallCode, SyscallContext,
        },
    },
};

pub struct Fp2AddSubSyscall<P> {
    op: FieldOperation,
    _marker: PhantomData<fn(P) -> P>,
}

impl<P> Fp2AddSubSyscall<P> {
    pub const fn new(op: FieldOperation) -> Self {
        Self {
            op,
            _marker: PhantomData,
        }
    }
}

impl<P: FpOpField> Syscall for Fp2AddSubSyscall<P> {
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
        SyscallContext::assert_dword_aligned_precompile(x_ptr, "fp2 addsub x_ptr");
        SyscallContext::assert_dword_aligned_precompile(y_ptr, "fp2 addsub y_ptr");

        let num_words = <P as NumWords>::WordsCurvePoint::USIZE;
        // WordsCurvePoint is now the u64 dword count directly.
        let num_memory_words = num_words;

        let x_vals = rt.dword_slice_unsafe(x_ptr, num_memory_words);
        let (y_memory_records, y_vals) = rt.mr_dword_slice(y_ptr, num_memory_words);
        rt.clk += 1;

        let x_bytes = x_vals
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect::<Vec<u8>>();
        let y_bytes = y_vals
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect::<Vec<u8>>();
        let (ac0, ac1) = x_bytes.split_at(x_bytes.len() / 2);
        let (bc0, bc1) = y_bytes.split_at(y_bytes.len() / 2);

        let ac0 = BigUint::from_bytes_le(ac0);
        let ac1 = BigUint::from_bytes_le(ac1);
        let bc0 = BigUint::from_bytes_le(bc0);
        let bc1 = BigUint::from_bytes_le(bc1);
        let modulus = &BigUint::from_bytes_le(P::MODULUS);

        let (c0, c1) = match self.op {
            FieldOperation::Add => ((ac0 + bc0) % modulus, (ac1 + bc1) % modulus),
            FieldOperation::Sub => (
                (ac0 + modulus - bc0) % modulus,
                (ac1 + modulus - bc1) % modulus,
            ),
            _ => panic!("Invalid operation"),
        };

        // The first half of the dword buffer is c0 and the second half is c1, matching the guest
        // memory layout read above.
        let mut result = c0.to_u64_digits();
        result.resize(num_memory_words / 2, 0);
        result.append(&mut c1.to_u64_digits());
        result.resize(num_memory_words, 0);
        let x_memory_records = rt.mw_dword_slice(x_ptr, &result);

        let chunk = rt.current_chunk();
        let x = x_vals.into_boxed_slice();
        let y = y_vals.into_boxed_slice();
        let x_memory_records = x_memory_records.into_boxed_slice();
        let y_memory_records = y_memory_records.into_boxed_slice();
        let op = self.op;

        let event = Fp2AddSubEvent {
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

        match P::FIELD_TYPE {
            // All the fp2 add and sub events for a given curve are coalesced to the curve's fp2 add operation. Only check for
            // that operation.
            FieldType::Bn254 => {
                let syscall_code_key = match syscall_code {
                    SyscallCode::BN254_FP2_ADD | SyscallCode::BN254_FP2_SUB => {
                        SyscallCode::BN254_FP2_ADD
                    }
                    _ => unreachable!(),
                };

                let syscall_event = rt
                    .rt
                    .syscall_event(clk, syscall_code.syscall_id(), arg1, arg2);
                rt.record_mut().add_precompile_event(
                    syscall_code_key,
                    syscall_event,
                    PrecompileEvent::Bn254Fp2AddSub(event),
                );
            }
            FieldType::Bls381 => {
                let syscall_code_key = match syscall_code {
                    SyscallCode::BLS12381_FP2_ADD | SyscallCode::BLS12381_FP2_SUB => {
                        SyscallCode::BLS12381_FP2_ADD
                    }
                    _ => unreachable!(),
                };

                let syscall_event = rt
                    .rt
                    .syscall_event(clk, syscall_code.syscall_id(), arg1, arg2);
                rt.record_mut().add_precompile_event(
                    syscall_code_key,
                    syscall_event,
                    PrecompileEvent::Bls12381Fp2AddSub(event),
                );
            }
            _ => unimplemented!("fp2 available only for Bn254 and Bls12381"),
        }

        None
    }

    fn num_extra_cycles(&self) -> u32 {
        1
    }
}
