use crate::{
    compiler::program::Program,
    emulator::{opts::EmulatorOpts, riscv::riscv_emulator::RiscvEmulator, stdin::EmulatorStdin},
};

pub enum EmulatorType {
    Riscv,
}

pub enum Emulatable {
    Riscv(RiscvEmulator),
}

impl Emulatable {
    pub fn run(&mut self, stdin: EmulatorStdin) {
        match self {
            Self::Riscv(emulator) => emulator.run_with_stdin(stdin).unwrap(),
        }
    }
}

pub struct Emulator {
    pub emulator_type: EmulatorType,
    pub emulator: Emulatable,
}

impl Emulator {
    pub fn new(emulator_type: EmulatorType, program: Program, opts: EmulatorOpts) -> Self {
        // create a new emulator based on the emulator type
        let emulator = match emulator_type {
            EmulatorType::Riscv => Emulatable::Riscv(RiscvEmulator::new(program, opts)),
        };

        Self {
            emulator_type,
            emulator,
        }
    }

    pub fn run(&mut self, stdin: EmulatorStdin) {
        self.emulator.run(stdin);
    }
}
