use std::ops::{Deref, DerefMut};

use pico_vm::emulator::riscv::state::RuntimeRegisterRecord;

/// A register as the core keeps it, the interpreter's own record, so the snapshot takes the
/// register file as it stands. A register never accessed is the zero record; an access stamps a
/// timestamp of at least 1 (the clock plus the operand's slot), so a nonzero record is present.
pub type RegisterRecord = RuntimeRegisterRecord;

/// The 32 registers' records, 64-byte aligned so no 16-byte record straddles a cache line.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
#[repr(C, align(64))]
pub struct RegisterFile(pub [RegisterRecord; 32]);

const _: () = assert!(
    std::mem::align_of::<RegisterFile>() == 64 && 64 % std::mem::size_of::<RegisterRecord>() == 0
);

impl Deref for RegisterFile {
    type Target = [RegisterRecord; 32];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for RegisterFile {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

/// Whether some access has touched the register, by the interpreter's `postprocess` test.
#[inline(always)]
pub(crate) fn is_present(record: &RegisterRecord) -> bool {
    *record != RegisterRecord::default()
}
