use std::sync::OnceLock;

use crate::{AotEmulatorCore, BlockFn, NextStep};

static LOOKUP_BLOCK_FN: OnceLock<fn(u64) -> Option<BlockFn>> = OnceLock::new();

pub fn set_lookup_block_fn(func: fn(u64) -> Option<BlockFn>) {
    let _ = LOOKUP_BLOCK_FN.set(func);
}

pub fn lookup_block_fn(pc: u64) -> Option<BlockFn> {
    match LOOKUP_BLOCK_FN.get() {
        Some(func) => func(pc),
        None => None,
    }
}

impl AotEmulatorCore {
    /// Runs from `self.pc` until the batch yields or the guest halts: through the compiled block
    /// `lookup` finds for a pc, and through the interpreter where it finds none.
    ///
    /// Generic and always inlined so a generated crate's `lookup` is called directly inside its
    /// own copy of the loop.
    #[inline(always)]
    pub fn run_blocks(&mut self, lookup: impl Fn(u64) -> Option<BlockFn>) -> Result<(), String> {
        let mut next = if self.pc == 0 {
            NextStep::Halt
        } else if let Some(func) = lookup(self.pc) {
            NextStep::Direct(func)
        } else {
            NextStep::Dynamic(self.pc)
        };

        loop {
            if self.should_yield() {
                break;
            }
            match next {
                NextStep::Direct(func) => {
                    self.compiled_block_dispatches += 1;
                    next = func(self)?;
                }
                NextStep::Dynamic(pc) => {
                    self.pc = pc;
                    if pc == 0 {
                        next = NextStep::Halt;
                    } else if let Some(func) = lookup(pc) {
                        next = NextStep::Direct(func);
                    } else {
                        next = self.interpret_from_current_pc()?;
                    }
                }
                NextStep::Halt => break,
            }
        }
        Ok(())
    }

    /// How many times [`Self::run_blocks`] has entered a compiled block.
    pub fn compiled_block_dispatches(&self) -> u64 {
        self.compiled_block_dispatches
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use pico_vm::compiler::riscv::{instruction::Instruction, opcode::Opcode, program::Program};

    use crate::{AotEmulatorCore, AotProgram, BlockFn, NextStep};

    /// Two `ADD`s, then a `JALR` to pc 0, which halts.
    fn program() -> Arc<Program> {
        Arc::new(Program::new(
            vec![
                Instruction::new(Opcode::ADD, 1, 0, 0, false, false),
                Instruction::new(Opcode::ADD, 2, 0, 0, false, false),
                Instruction::new(Opcode::JALR, 0, 0, 0, false, true),
            ],
            0x1000,
            0x1000,
        ))
    }

    /// Stands in for the generated block at the entry: hands the rest to the interpreter.
    fn compiled_entry_block(emu: &mut AotEmulatorCore) -> Result<NextStep, String> {
        emu.pc = 0x1004;
        Ok(NextStep::Dynamic(0x1004))
    }

    #[test]
    fn only_a_compiled_block_counts_as_a_dispatch() {
        let mut compiled = AotEmulatorCore::new(program(), Vec::new());
        compiled
            .run_blocks(|pc| (pc == 0x1000).then_some(compiled_entry_block as BlockFn))
            .unwrap();
        assert_eq!(compiled.pc, 0, "the guest ran to its halt");
        assert_eq!(compiled.compiled_block_dispatches(), 1);

        let mut stub = AotEmulatorCore::new(program(), Vec::new());
        AotProgram::STUB.run(&mut stub).unwrap();
        assert_eq!(stub.pc, 0, "the guest ran to its halt");
        assert_eq!(stub.insn_count, 3, "every instruction was interpreted");
        assert_eq!(stub.compiled_block_dispatches(), 0);
    }
}
