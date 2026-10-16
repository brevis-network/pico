//! The precompiles this machine cannot prove, pinned.
//!
//! Two tables decide it: a syscall with no handler in the syscall map stops a guest at emulation,
//! and a chip with no AIR in the MLE RISC-V air list is refused at proving time. Both sets are
//! empty, so the patch-testing harness (`vm/examples/patch-testing/common`) fails any case the
//! machine refuses. A precompile leaving either table would turn its patch case red; this test goes
//! red first, until the pinned sets below change in the same commit, so the change is reviewed.

use std::collections::BTreeSet;

use pico_vm::{
    emulator::riscv::syscalls::{default_syscall_map, SyscallCode},
    instances::chiptype::riscv_chiptype::RiscvChipType,
    machine::chip::ChipBehavior,
    mle::machine::riscv::{air_id_for, Kb},
};
use strum::IntoEnumIterator;

/// Chips in the machine's chip list with no AIR in the MLE air list. Their syscalls are
/// registered, so a guest calling one emulates and is then rejected by the prover.
const CHIPS_WITHOUT_AIR: &[&str] = &[];

/// Syscall codes with no handler in the syscall map.
const UNREGISTERED_SYSCALLS: &[SyscallCode] = &[];

#[test]
fn chips_without_an_mle_air_match_the_pinned_set() {
    let actual: BTreeSet<String> = RiscvChipType::<Kb>::all_chip_variants()
        .iter()
        .map(|chip| chip.name())
        .filter(|name| air_id_for(name).is_none())
        .collect();
    let pinned: BTreeSet<String> = CHIPS_WITHOUT_AIR.iter().map(|s| s.to_string()).collect();
    assert_eq!(
        actual, pinned,
        "the chips outside the MLE air table changed; update CHIPS_WITHOUT_AIR with the change"
    );
}

#[test]
fn unregistered_syscalls_match_the_pinned_set() {
    let map = default_syscall_map::<Kb>();
    let actual: BTreeSet<SyscallCode> = SyscallCode::iter()
        .filter(|code| !map.contains_key(code))
        .collect();
    let pinned: BTreeSet<SyscallCode> = UNREGISTERED_SYSCALLS.iter().copied().collect();
    assert_eq!(
        actual, pinned,
        "the syscalls without a handler changed; update UNREGISTERED_SYSCALLS with the change"
    );
}
