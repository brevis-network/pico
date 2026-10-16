//! The program a generated `pico-aot-dispatch` crate exports, and why registering one can fail.
//!
//! A generated dispatch crate exports one [`AotProgram`] as `pub static AOT`: the SHA-256 of the
//! ELF its code was generated from, and that code's entry point. The digest is the program's
//! identity — [`register`](crate::register) keys on it, and a host can hold it against the ELF it
//! proves. A function pointer is no identity: rustc may merge two functions into one address or
//! give one function two (`unpredictable_function_pointer_comparisons`).
//!
//! The committed `aot-generated/` bootstrap stub exports [`AotProgram::STUB`] instead, so code that
//! names `pico_aot_dispatch::AOT` builds before any code is generated, and is refused at
//! registration rather than silently interpreting under an AOT banner.

use std::fmt;

use crate::AotEmulatorCore;

/// One guest's AOT-compiled code: what a generated `pico-aot-dispatch` crate exports as `AOT`.
#[derive(Clone, Copy, Debug)]
pub struct AotProgram {
    pub(crate) elf_sha256: [u8; 32],
    pub(crate) run: fn(&mut AotEmulatorCore) -> Result<(), String>,
}

impl AotProgram {
    /// The bootstrap stub's program. It has no compiled code and interprets every block, and
    /// [`register`](crate::register) refuses it.
    pub const STUB: AotProgram = AotProgram {
        elf_sha256: [0; 32],
        run: interpret_every_block,
    };

    /// `elf_sha256` is the SHA-256 of the ELF `run`'s code was generated from. The all-zero digest
    /// is [`Self::STUB`]'s, and no ELF has it.
    pub const fn new(
        elf_sha256: [u8; 32],
        run: fn(&mut AotEmulatorCore) -> Result<(), String>,
    ) -> Self {
        Self { elf_sha256, run }
    }

    /// The SHA-256 of the ELF this program's code was generated from.
    pub const fn elf_sha256(&self) -> [u8; 32] {
        self.elf_sha256
    }

    pub fn is_stub(&self) -> bool {
        self.elf_sha256 == Self::STUB.elf_sha256
    }

    /// Runs from `emu.pc` until the batch yields or the guest halts.
    pub fn run(&self, emu: &mut AotEmulatorCore) -> Result<(), String> {
        (self.run)(emu)
    }
}

fn interpret_every_block(emu: &mut AotEmulatorCore) -> Result<(), String> {
    emu.run_blocks(|_| None)
}

/// Why [`register`](crate::register) refused a program.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum AotError {
    /// The program is [`AotProgram::STUB`]: no code was generated from the guest's ELF.
    Stub,
    /// The process already holds a different program, and the VM holds one per process.
    Conflict {
        registered: [u8; 32],
        requested: [u8; 32],
    },
    /// An AOT factory was installed through `pico_vm::emulator::aot::register_aot_factory`
    /// directly, so which program the process runs is unknown.
    ForeignFactory,
}

impl fmt::Display for AotError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Stub => write!(
                f,
                "the AOT program is the bootstrap stub, which has no compiled code; generate it \
                 from the guest's ELF with `cargo pico aot`"
            ),
            Self::Conflict {
                registered,
                requested,
            } => write!(
                f,
                "this process already registered the AOT program for ELF {}, so it cannot \
                 register the one for ELF {}: the VM holds one AOT program per process",
                Sha256Hex(registered),
                Sha256Hex(requested)
            ),
            Self::ForeignFactory => write!(
                f,
                "an AOT factory was installed without `pico_aot_runtime::register`, so the program \
                 this process runs is unknown"
            ),
        }
    }
}

impl std::error::Error for AotError {}

pub(crate) struct Sha256Hex<'a>(pub(crate) &'a [u8; 32]);

impl fmt::Display for Sha256Hex<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.iter().try_for_each(|byte| write!(f, "{byte:02x}"))
    }
}
