use std::marker::PhantomData;

use crate::{
    chips::gadgets::{
        curves::{edwards::EdwardsParameters, AffinePoint, EllipticCurve},
        utils::field_params::FieldParameters,
    },
    emulator::riscv::{
        event_types::RvValue,
        syscalls::{
            precompiles::{edwards::event::create_ec_add_event, PrecompileEvent},
            syscall_context::SyscallContext,
            Syscall, SyscallCode,
        },
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
        arg1: RvValue,
        arg2: RvValue,
    ) -> Option<RvValue> {
        let event = create_ec_add_event::<E>(ctx, arg1, arg2);
        assert_canonical::<E>(&event.p, "p");
        assert_canonical::<E>(&event.q, "q");
        let syscall_event = ctx
            .rt
            .syscall_event(event.clk, syscall_code.syscall_id(), arg1, arg2);
        ctx.record_mut().add_precompile_event(
            syscall_code,
            syscall_event,
            PrecompileEvent::EdAdd(event),
        );
        None
    }
}

/// Both coordinates of `point` must already be canonical field elements.
///
/// `AffinePoint::from_dwords_le` reduces nothing: the chip reads the same bytes back out of the
/// memory cells and feeds them to `FieldInnerProductCols`/`FieldOpCols`, whose witness bounds
/// assume operands below the modulus. Without this the guest emulates fine and then has no
/// provable trace, which surfaces as an unsatisfied constraint in the prover rather than as
/// anything pointing back at the guest. Same reasoning as the alignment assertions in
/// `create_ec_add_event`: make the side that knows why fail first.
///
/// Edwards-local on purpose. `create_ec_add_event` is shared with the Weierstrass add syscall,
/// which has never checked this; tightening that path is a separate change with its own
/// re-testing of the curve benchmarks.
fn assert_canonical<E: EllipticCurve + EdwardsParameters>(point: &[u64], which: &str) {
    let modulus = E::BaseField::modulus();
    let decoded = AffinePoint::<E>::from_dwords_le(point);
    for (name, coord) in [("x", &decoded.x), ("y", &decoded.y)] {
        assert!(
            *coord < modulus,
            "edwards add: {which}.{name} is not a canonical field element (>= {modulus}); \
             the curve arithmetic operates on field elements, so the guest must reduce first"
        );
    }
}
