use crate::{
    compiler::program::ProgramBehavior,
    emulator::{context::EmulatorContext, opts::EmulatorOpts, stdin::EmulatorStdin},
    machine::chip::ChipBehavior,
};
use p3_field::Field;

pub struct ProvingWitness<F, C>
where
    F: Field,
    C: ChipBehavior<F>,
{
    pub program: C::Program,

    pub stdin: EmulatorStdin,

    pub opts: EmulatorOpts,

    pub context: EmulatorContext,

    pub records: Vec<C::Record>,
}

// implement Witness
impl<F, C> ProvingWitness<F, C>
where
    F: Field,
    C: ChipBehavior<F>,
{
    pub fn new_with_program(
        program: C::Program,
        stdin: EmulatorStdin,
        opts: EmulatorOpts,
        context: EmulatorContext,
    ) -> Self {
        Self {
            program,
            stdin,
            opts,
            context,
            records: vec![],
        }
    }

    pub fn new_with_records(records: Vec<C::Record>) -> Self {
        Self {
            program: C::Program::default(),
            stdin: EmulatorStdin::default(),
            opts: EmulatorOpts::default(),
            context: EmulatorContext::default(),
            records,
        }
    }

    pub fn records(&self) -> &[C::Record] {
        &self.records
    }
}
