use crate::chips::gadgets::utils::field_params::{FieldType, FpOpField, NumWords};
use hybrid_array::typenum::Unsigned;
use num::BigUint;
use std::marker::PhantomData;

use crate::{
    chips::gadgets::field::field_op::FieldOperation,
    emulator::riscv::syscalls::{
        precompiles::fptower::event::FpEvent, Syscall, SyscallCode, SyscallContext,
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
        _syscall_code: SyscallCode,
        x_ptr: u32,
        y_ptr: u32,
    ) -> Option<u32> {
        let clk = rt.clk;
        assert!(x_ptr % 4 == 0, "x_ptr is unaligned");
        assert!(y_ptr % 4 == 0, "y_ptr is unaligned");

        let num_words = <P as NumWords>::WordsFieldElement::USIZE;

        let x = rt.slice_unsafe(x_ptr, num_words);
        let (y_memory_records, y) = rt.mr_slice(y_ptr, num_words);

        let modulus = &BigUint::from_bytes_le(P::MODULUS);
        let a = BigUint::from_slice(&x) % modulus;
        let b = BigUint::from_slice(&y) % modulus;

        let result = match self.op {
            FieldOperation::Add => (a + b) % modulus,
            FieldOperation::Sub => ((a + modulus) - b) % modulus,
            FieldOperation::Mul => (a * b) % modulus,
            _ => panic!("Unsupported operation"),
        };
        let mut result = result.to_u32_digits();
        result.resize(num_words, 0);

        rt.clk += 1;
        let x_memory_records = rt.mw_slice(x_ptr, &result);

        let lookup_id = rt.syscall_lookup_id;
        let chunk = rt.current_chunk();
        let x = x.into_boxed_slice();
        let y = y.into_boxed_slice();
        let x_memory_records = x_memory_records.into_boxed_slice();
        let y_memory_records = y_memory_records.into_boxed_slice();
        let op = self.op;
        match P::FIELD_TYPE {
            FieldType::Bn254 => &mut rt.record_mut().fp_bn254_events,
            FieldType::Bls381 => &mut rt.record_mut().fp_bls381_events,
        }
        .push(FpEvent {
            lookup_id,
            chunk,
            clk,
            x_ptr,
            x,
            y_ptr,
            y,
            op,
            x_memory_records,
            y_memory_records,
        });

        None
    }

    fn num_extra_cycles(&self) -> u32 {
        1
    }
}
