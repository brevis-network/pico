//! Where a guest's loads and stores may land. Both emulators ask [`access_fault`] before an
//! instruction touches memory, and the syscall hosts before a syscall's access counts, so every
//! path ends the run at the same access with the same reason.

use core::ops::Range;

use super::TerminationReason;
use crate::{
    compiler::riscv::opcode::Opcode,
    primitives::layout::{HEAP_END, MEMORY_SIZE, MIN_SEGMENT_ADDR, STACK_BOTTOM},
};

/// Why a guest access of `width` bytes at `addr` may not happen, or `None` if it may. `store` says
/// whether it writes, and `code` is the program's code, `[pc_base, pc_base + 4 * instructions)`.
/// The access starts at `addr` and must not touch a forbidden byte anywhere in its `width`:
///
/// - below `MIN_SEGMENT_ADDR`: a null access, where no segment loads and no access is provable;
/// - at or past the top of memory: an invalid access;
/// - in the stack guard, `[HEAP_END, STACK_BOTTOM)`: a stack overflow, or a heap run past its end;
/// - for a store, in the code.
#[inline(always)]
pub fn access_fault(
    opcode: Opcode,
    addr: u64,
    width: u64,
    store: bool,
    code: &Range<u64>,
) -> Option<TerminationReason> {
    let end = addr.wrapping_add(width);
    if addr < MIN_SEGMENT_ADDR {
        Some(TerminationReason::NullAccess { opcode, addr })
    } else if end > MEMORY_SIZE || end < addr {
        Some(TerminationReason::InvalidMemoryAccess { opcode, addr })
    } else if addr < STACK_BOTTOM && end > HEAP_END {
        Some(TerminationReason::StackOverflow { opcode, addr })
    } else if store && addr < code.end && end > code.start {
        Some(TerminationReason::StoreToCode { opcode, addr })
    } else {
        None
    }
}

/// The width of a load or store, in bytes.
#[inline(always)]
pub const fn access_width(opcode: Opcode) -> u64 {
    match opcode {
        Opcode::LB | Opcode::LBU | Opcode::SB => 1,
        Opcode::LH | Opcode::LHU | Opcode::SH => 2,
        Opcode::LW | Opcode::LWU | Opcode::SW => 4,
        _ => 8,
    }
}

#[cfg(test)]
mod tests {
    use super::{access_fault, access_width};
    use crate::{
        compiler::riscv::opcode::Opcode,
        emulator::riscv::emulator::TerminationReason,
        primitives::layout::{HEAP_END, MEMORY_SIZE, MIN_SEGMENT_ADDR, STACK_BOTTOM, TEXT_START},
    };

    const CODE: core::ops::Range<u64> = TEXT_START..TEXT_START + 0x1000;

    fn fault(opcode: Opcode, addr: u64) -> Option<TerminationReason> {
        let store = matches!(opcode, Opcode::SB | Opcode::SH | Opcode::SW | Opcode::SD);
        access_fault(opcode, addr, access_width(opcode), store, &CODE)
    }

    /// Each region's first and last byte, for an access that starts in it and for one that runs
    /// into it from the byte before.
    #[test]
    fn each_region_ends_where_the_layout_says() {
        use Opcode::*;
        use TerminationReason::*;
        let null = |opcode, addr| Some(NullAccess { opcode, addr });
        let guard = |opcode, addr| Some(StackOverflow { opcode, addr });
        let past = |opcode, addr| Some(InvalidMemoryAccess { opcode, addr });
        let code = |opcode, addr| Some(StoreToCode { opcode, addr });

        assert_eq!(fault(LD, 0), null(LD, 0));
        assert_eq!(
            fault(LB, MIN_SEGMENT_ADDR - 1),
            null(LB, MIN_SEGMENT_ADDR - 1)
        );
        assert_eq!(
            fault(LW, MIN_SEGMENT_ADDR - 2),
            null(LW, MIN_SEGMENT_ADDR - 2)
        );
        assert_eq!(fault(LB, MIN_SEGMENT_ADDR), None);

        assert_eq!(fault(SD, HEAP_END - 8), None);
        assert_eq!(fault(SD, HEAP_END - 7), guard(SD, HEAP_END - 7));
        assert_eq!(fault(LB, HEAP_END), guard(LB, HEAP_END));
        assert_eq!(fault(LB, STACK_BOTTOM - 1), guard(LB, STACK_BOTTOM - 1));
        assert_eq!(fault(LB, STACK_BOTTOM), None);

        assert_eq!(fault(LD, MEMORY_SIZE - 8), None);
        assert_eq!(fault(LD, MEMORY_SIZE - 7), past(LD, MEMORY_SIZE - 7));
        assert_eq!(fault(LB, MEMORY_SIZE), past(LB, MEMORY_SIZE));
        assert_eq!(fault(LD, u64::MAX - 3), past(LD, u64::MAX - 3));

        assert_eq!(fault(SW, CODE.start - 4), None);
        assert_eq!(fault(SW, CODE.start - 3), code(SW, CODE.start - 3));
        assert_eq!(fault(SB, CODE.end - 1), code(SB, CODE.end - 1));
        assert_eq!(fault(SB, CODE.end), None);
        assert_eq!(fault(LW, CODE.start), None, "the code is readable");
    }
}
