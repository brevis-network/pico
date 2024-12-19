use crate::chips::gadgets::utils::field_params::{FieldType, FpOpField, NumWords};
use hybrid_array::typenum::Unsigned;
use num::BigUint;
use std::marker::PhantomData;

use crate::{
    chips::gadgets::field::field_op::FieldOperation,
    emulator::riscv::syscalls::{
        precompiles::fptower::event::Fp2AddSubEvent, Syscall, SyscallCode, SyscallContext,
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
        _syscall_code: SyscallCode,
        x_ptr: u32,
        y_ptr: u32,
    ) -> Option<u32> {
        let clk = rt.clk;
        assert!(x_ptr % 4 == 0, "x_ptr is unaligned");
        assert!(y_ptr % 4 == 0, "y_ptr is unaligned");

        let num_words = <P as NumWords>::WordsCurvePoint::USIZE;

        let x = rt.slice_unsafe(x_ptr, num_words);
        let (y_memory_records, y) = rt.mr_slice(y_ptr, num_words);
        rt.clk += 1;

        let (ac0, ac1) = x.split_at(x.len() / 2);
        let (bc0, bc1) = y.split_at(y.len() / 2);

        let ac0 = BigUint::from_slice(ac0);
        let ac1 = BigUint::from_slice(ac1);
        let bc0 = BigUint::from_slice(bc0);
        let bc1 = BigUint::from_slice(bc1);
        let modulus = &BigUint::from_bytes_le(P::MODULUS);

        let (c0, c1) = match self.op {
            FieldOperation::Add => ((ac0 + bc0) % modulus, (ac1 + bc1) % modulus),
            FieldOperation::Sub => (
                (ac0 + modulus - bc0) % modulus,
                (ac1 + modulus - bc1) % modulus,
            ),
            _ => panic!("Invalid operation"),
        };

        let mut result = c0
            .to_u32_digits()
            .into_iter()
            .chain(c1.to_u32_digits())
            .collect::<Vec<u32>>();

        result.resize(num_words, 0);
        let x_memory_records = rt.mw_slice(x_ptr, &result);

        let lookup_id = rt.syscall_lookup_id;
        let chunk = rt.current_chunk();
        let x = x.into_boxed_slice();
        let y = y.into_boxed_slice();
        let x_memory_records = x_memory_records.into_boxed_slice();
        let y_memory_records = y_memory_records.into_boxed_slice();
        let op = self.op;
        match P::FIELD_TYPE {
            FieldType::Bn254 => &mut rt.record_mut().fp2_bn254_addsub_events,
            FieldType::Bls381 => &mut rt.record_mut().fp2_bls381_addsub_events,
        }
        .push(Fp2AddSubEvent {
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
