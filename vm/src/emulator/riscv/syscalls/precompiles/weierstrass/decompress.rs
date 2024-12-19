use crate::{
    chips::gadgets::curves::{CurveType, EllipticCurve},
    emulator::riscv::syscalls::{
        precompiles::ec::event::create_ec_decompress_event, syscall_context::SyscallContext,
        Syscall, SyscallCode,
    },
};
use std::marker::PhantomData;

pub(crate) struct WeierstrassDecompressSyscall<E: EllipticCurve> {
    _phantom: PhantomData<E>,
}

impl<E: EllipticCurve> WeierstrassDecompressSyscall<E> {
    /// Create a new instance of the [`WeierstrassDecompressSyscall`].
    pub const fn new() -> Self {
        Self {
            _phantom: PhantomData,
        }
    }
}

impl<E: EllipticCurve> Syscall for WeierstrassDecompressSyscall<E> {
    fn emulate(
        &self,
        rt: &mut SyscallContext,
        _syscall_code: SyscallCode,
        arg1: u32,
        arg2: u32,
    ) -> Option<u32> {
        let event = create_ec_decompress_event::<E>(rt, arg1, arg2);
        match E::CURVE_TYPE {
            CurveType::Secp256k1 => rt.record_mut().k256_decompress_events.push(event),
            CurveType::Bls12381 => rt.record_mut().bls12381_decompress_events.push(event),
            _ => panic!("Unsupported curve: {}", E::CURVE_TYPE),
        }
        None
    }

    fn num_extra_cycles(&self) -> u32 {
        0
    }
}
