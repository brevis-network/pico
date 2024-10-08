use crate::{
    compiler::program::Program,
    emulator::{opts::PicoCoreOpts, riscv::riscv_emulator::RiscvEmulator, stdin::PicoStdin},
};

pub enum EmulatorType {
    Riscv,
}

pub enum Emulatable {
    Riscv(RiscvEmulator),
}

impl Emulatable {
    pub fn run(&mut self, stdin: PicoStdin) {
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
    pub fn new(emulator_type: EmulatorType, program: Program, opts: PicoCoreOpts) -> Self {
        // create a new emulator based on the emulator type
        let emulator = match emulator_type {
            EmulatorType::Riscv => Emulatable::Riscv(RiscvEmulator::new(program, opts)),
        };

        Self {
            emulator_type,
            emulator,
        }
    }

    pub fn run(&mut self, stdin: PicoStdin) {
        self.emulator.run(stdin);
    }
}
