use crate::{
    chips::gadgets::curves::{CurveType, EllipticCurve},
    emulator::riscv::{
        event_types::RvValue,
        syscalls::{
            host::{Precompile, SyscallHost},
            precompiles::{ec::event::create_ec_decompress_event, PrecompileEvent},
            SyscallCode,
        },
    },
};
use std::marker::PhantomData;

pub struct WeierstrassDecompressSyscall<E: EllipticCurve> {
    _phantom: PhantomData<E>,
}

impl<E: EllipticCurve> WeierstrassDecompressSyscall<E> {
    /// Create a new instance of the [`WeierstrassDecompressSyscall`].
    #[allow(clippy::new_without_default)]
    pub const fn new() -> Self {
        Self {
            _phantom: PhantomData,
        }
    }
}

impl<E: EllipticCurve> Precompile for WeierstrassDecompressSyscall<E> {
    fn emulate<H: SyscallHost>(
        &self,
        rt: &mut H,
        syscall_code: SyscallCode,
        arg1: RvValue,
        arg2: RvValue,
    ) -> Option<RvValue> {
        let event = create_ec_decompress_event::<E, _>(rt, arg1, arg2);

        let syscall_event = rt.syscall_event(event.clk, syscall_code.syscall_id(), arg1, arg2);
        match E::CURVE_TYPE {
            CurveType::Secp256k1 => rt.record_mut().add_precompile_event(
                syscall_code,
                syscall_event,
                PrecompileEvent::Secp256k1Decompress(event),
            ),
            CurveType::Secp256r1 => rt.record_mut().add_precompile_event(
                syscall_code,
                syscall_event,
                PrecompileEvent::Secp256r1Decompress(event),
            ),
            CurveType::Bls12381 => rt.record_mut().add_precompile_event(
                syscall_code,
                syscall_event,
                PrecompileEvent::Bls12381Decompress(event),
            ),
            _ => panic!("Unsupported curve"),
        }
        None
    }

    fn num_extra_cycles(&self) -> u32 {
        0
    }
}
