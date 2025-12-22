use crate::{
    chips::gadgets::curves::{CurveType, EllipticCurve},
    emulator::riscv::syscalls::{
        precompiles::{edwards::event::create_ec_add_event, PrecompileEvent},
        syscall_context::SyscallContext,
        Syscall, SyscallCode,
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
        syscall_code: SyscallCode,
        arg1: u32,
        arg2: u32,
    ) -> Option<u32> {
        let event = create_ec_add_event::<E>(rt, arg1, arg2);

        let syscall_event = rt
            .rt
            .syscall_event(event.clk, syscall_code.syscall_id(), arg1, arg2);
        match E::CURVE_TYPE {
            CurveType::Secp256k1 => rt.record_mut().add_precompile_event(
                syscall_code,
                syscall_event,
                PrecompileEvent::Secp256k1Add(event),
            ),
            CurveType::Secp256r1 => rt.record_mut().add_precompile_event(
                syscall_code,
                syscall_event,
                PrecompileEvent::Secp256r1Add(event),
            ),
            CurveType::Bn254 => {
                rt.record_mut().add_precompile_event(
                    syscall_code,
                    syscall_event,
                    PrecompileEvent::Bn254Add(event),
                );
            }
            CurveType::Bls12381 => rt.record_mut().add_precompile_event(
                syscall_code,
                syscall_event,
                PrecompileEvent::Bls12381Add(event),
            ),
            _ => panic!("Unsupported curve"),
        }

        None
    }

    fn num_extra_cycles(&self) -> u32 {
        1
    }
}
