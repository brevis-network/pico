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
//!
//! A program also carries the codegen stamp of the code it runs. Generated code calls into this
//! runtime, and what the runtime expects of it changes: code that inlines an instruction must write
//! that instruction's events where the runtime's own helpers would. Code generated against another
//! contract still builds and still runs the guest, with events missing, so
//! [`register`](crate::register) refuses a stamp that is not [`AotProgram::CODEGEN_STAMP`] rather
//! than let it run.

use std::fmt;

use crate::AotEmulatorCore;

/// One guest's AOT-compiled code: what a generated `pico-aot-dispatch` crate exports as `AOT`.
#[derive(Clone, Copy, Debug)]
pub struct AotProgram {
    pub(crate) elf_sha256: [u8; 32],
    pub(crate) codegen_stamp: u32,
    pub(crate) run: fn(&mut AotEmulatorCore) -> Result<(), String>,
}

impl AotProgram {
    /// The contract between generated code and this runtime, as [`register`] accepts it:
    /// [`pico_vm::AOT_CODEGEN_STAMP`], which the code generator writes too.
    ///
    /// [`register`]: crate::register
    pub const CODEGEN_STAMP: u32 = pico_vm::AOT_CODEGEN_STAMP;

    /// The bootstrap stub's program. It has no compiled code and interprets every block, and
    /// [`register`](crate::register) refuses it.
    pub const STUB: AotProgram = AotProgram {
        elf_sha256: [0; 32],
        codegen_stamp: Self::CODEGEN_STAMP,
        run: interpret_every_block,
    };

    /// A program with no codegen stamp, which [`register`](crate::register) refuses: what a crate
    /// generated before the stamp existed builds. [`Self::stamped`] is the constructor to use.
    ///
    /// Kept so such a crate still builds and is refused with a message that says to regenerate
    /// it; deprecated so a hand-written caller hears it at build time rather than at `register`.
    #[deprecated(note = "no codegen stamp, so `register` refuses it; use `AotProgram::stamped`")]
    pub const fn new(
        elf_sha256: [u8; 32],
        run: fn(&mut AotEmulatorCore) -> Result<(), String>,
    ) -> Self {
        Self::stamped(elf_sha256, 0, run)
    }

    /// `elf_sha256` is the SHA-256 of the ELF `run`'s code was generated from, and `codegen_stamp`
    /// the [`Self::CODEGEN_STAMP`] it was generated against. The all-zero digest is
    /// [`Self::STUB`]'s, and no ELF has it.
    ///
    /// A program whose `run` is written by hand carries the stamp of the code it ends up running:
    /// this runtime's own when it interprets, the generated program's when it wraps one.
    pub const fn stamped(
        elf_sha256: [u8; 32],
        codegen_stamp: u32,
        run: fn(&mut AotEmulatorCore) -> Result<(), String>,
    ) -> Self {
        Self {
            elf_sha256,
            codegen_stamp,
            run,
        }
    }

    /// The SHA-256 of the ELF this program's code was generated from.
    pub const fn elf_sha256(&self) -> [u8; 32] {
        self.elf_sha256
    }

    /// The codegen stamp this program's code was generated against; 0 for none.
    pub const fn codegen_stamp(&self) -> u32 {
        self.codegen_stamp
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
    /// The program's code was generated against another codegen stamp than this runtime's
    /// [`AotProgram::CODEGEN_STAMP`], or before stamps existed (`found` is 0): it would run the
    /// guest without writing every event this runtime's records need.
    CodegenStamp { found: u32, expected: u32 },
    /// The process already holds a different program, and the VM holds one per process.
    Conflict {
        registered: [u8; 32],
        requested: [u8; 32],
    },
    /// An AOT factory was installed through `pico_vm::emulator::aot::register_aot_factory`
    /// directly, so which program the process runs is unknown.
    ForeignFactory,
}

impl AotError {
    const STUB_DIGEST: [u8; 32] = AotProgram::STUB.elf_sha256;
}

impl fmt::Display for AotError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Stub => write!(
                f,
                "the AOT program is the bootstrap stub, which has no compiled code; generate it \
                 from the guest's ELF with `cargo pico aot`"
            ),
            Self::CodegenStamp { found: 0, expected } => write!(
                f,
                "the AOT program carries no codegen stamp, so it was generated before stamp \
                 {expected}, the one this runtime runs; regenerate it from the guest's ELF with \
                 `cargo pico aot`"
            ),
            Self::CodegenStamp { found, expected } => write!(
                f,
                "the AOT program was generated with codegen stamp {found}, and this runtime runs \
                 stamp {expected}; regenerate it from the guest's ELF with `cargo pico aot`"
            ),
            Self::Conflict {
                registered,
                requested,
            } => {
                let name = |digest: &[u8; 32]| {
                    if *digest == Self::STUB_DIGEST {
                        "the interpreted AOT runtime (no compiled code)".to_string()
                    } else {
                        format!("the AOT program for ELF {}", Sha256Hex(digest))
                    }
                };
                write!(
                    f,
                    "this process already registered {}, so it cannot register {}: the VM \
                     holds one AOT program per process",
                    name(registered),
                    name(requested)
                )
            }
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
