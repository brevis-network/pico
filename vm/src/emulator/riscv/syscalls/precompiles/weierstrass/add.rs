use crate::{
    chips::gadgets::curves::{CurveType, EllipticCurve},
    emulator::riscv::syscalls::{
        precompiles::edwards::event::create_ec_add_event, syscall_context::SyscallContext, Syscall,
        SyscallCode,
    },
};
use std::marker::PhantomData;

pub(crate) struct WeierstrassAddAssignSyscall<E: EllipticCurve> {
    _phantom: PhantomData<E>,
}

impl<E: EllipticCurve> WeierstrassAddAssignSyscall<E> {
    /// Create a new instance of the [`WeierstrassAddAssignSyscall`].
    pub const fn new() -> Self {
        Self {
            _phantom: PhantomData,
        }
    }
}

impl<E: EllipticCurve> Syscall for WeierstrassAddAssignSyscall<E> {
    fn emulate(
        &self,
        rt: &mut SyscallContext,
        _syscall_code: SyscallCode,
        arg1: u32,
        arg2: u32,
    ) -> Option<u32> {
        let event = create_ec_add_event::<E>(rt, arg1, arg2);
        match E::CURVE_TYPE {
            CurveType::Secp256k1 => rt.record_mut().secp256k1_add_events.push(event),
            CurveType::Bn254 => rt.record_mut().bn254_add_events.push(event),
            CurveType::Bls12381 => rt.record_mut().bls12381_add_events.push(event),
            _ => panic!("Unsupported curve: {}", E::CURVE_TYPE),
        }
        None
    }

    fn num_extra_cycles(&self) -> u32 {
        1
    }
}
