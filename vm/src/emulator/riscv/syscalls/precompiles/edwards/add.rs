use std::marker::PhantomData;

use crate::{
    chips::gadgets::curves::{edwards::EdwardsParameters, EllipticCurve},
    emulator::riscv::syscalls::{
        precompiles::{edwards::event::create_ec_add_event, PrecompileEvent},
        syscall_context::SyscallContext,
        Syscall, SyscallCode,
    },
};

pub(crate) struct EdwardsAddAssignSyscall<E: EllipticCurve + EdwardsParameters> {
    _phantom: PhantomData<E>,
}

impl<E: EllipticCurve + EdwardsParameters> EdwardsAddAssignSyscall<E> {
    /// Create a new instance of the [`EdwardsAddAssignSyscall`].
    pub const fn new() -> Self {
        Self {
            _phantom: PhantomData,
        }
    }
}

impl<E: EllipticCurve + EdwardsParameters> Syscall for EdwardsAddAssignSyscall<E> {
    fn num_extra_cycles(&self) -> u32 {
        1
    }

    fn emulate(
        &self,
        ctx: &mut SyscallContext,
        syscall_code: SyscallCode,
        arg1: u32,
        arg2: u32,
    ) -> Option<u32> {
        let event = create_ec_add_event::<E>(ctx, arg1, arg2);
        let syscall_event = ctx.rt.syscall_event(
            event.clk,
            syscall_code.syscall_id(),
            arg1,
            arg2,
            event.lookup_id,
        );
        ctx.record_mut().add_precompile_event(
            syscall_code,
            syscall_event,
            PrecompileEvent::EdAdd(event),
        );
        None
    }
}
