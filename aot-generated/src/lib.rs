//! Bootstrap stub for `pico-aot-dispatch`, replaced wholesale when the AOT code is generated from
//! a guest's ELF (`cargo pico aot`, or `generate_crates <elf> aot-generated`).
//!
//! It exports what a generated crate exports, so dependents build before any code is generated.
//! Its [`AOT`] is [`AotProgram::STUB`], which has no compiled code and which
//! `pico_aot_runtime::register` refuses.

pub use pico_aot_runtime::AotEmulatorCore;
use pico_aot_runtime::AotProgram;

pub static AOT: AotProgram = AotProgram::STUB;

/// Interprets every block: the stub has no compiled code.
pub fn run_aot(emu: &mut AotEmulatorCore) -> Result<(), String> {
    AOT.run(emu)
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_stub_exports_the_stub_program() {
        assert!(super::AOT.is_stub());
    }
}
