// Bootstrap stub - will be replaced by generate_crates
pub use pico_aot_runtime::AotEmulatorCore;
use pico_aot_runtime::NextStep;

pub fn run_aot(emu: &mut AotEmulatorCore) -> Result<(), String> {
    let mut next = if emu.pc == 0 {
        NextStep::Halt
    } else {
        NextStep::Dynamic(emu.pc)
    };

    loop {
        if emu.should_yield() {
            break;
        }
        match next {
            NextStep::Direct(func) => {
                next = func(emu)?;
            }
            NextStep::Dynamic(pc) => {
                emu.pc = pc;
                next = emu.interpret_from_current_pc()?;
            }
            NextStep::Halt => break,
        }
    }

    Ok(())
}
