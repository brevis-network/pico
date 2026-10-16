use crate::{
    configs::config::{StarkGenericConfig, Val},
    emulator::{opts::EmulatorOpts, stdin::EmulatorStdin},
    machine::chip::ChipBehavior,
    primitives::consts::DIGEST_SIZE,
};
use alloc::sync::Arc;

/// What the emulators need to run a program: the program, its stdin and the emulator options,
/// plus the records they produce. The FRI proving/verifying keys and proofs that used to ride
/// along were removed with the FRI path (see tag `legacy-fri-last`); the MLE backend keys itself.
#[derive(Default)]
pub struct ProvingWitness<SC, C, I>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<Val<SC>>,
{
    pub program: Option<Arc<C::Program>>,

    pub vk_root: Option<[Val<SC>; DIGEST_SIZE]>,

    pub stdin: Option<EmulatorStdin<C::Program, I>>,

    pub flag_empty_stdin: bool,

    pub config: Option<Arc<SC>>,

    pub opts: Option<EmulatorOpts>,

    pub records: Vec<C::Record>,
}

impl<SC, C, I> ProvingWitness<SC, C, I>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<Val<SC>>,
{
    pub fn setup_with_records(records: Vec<C::Record>) -> Self {
        Self {
            program: None,
            vk_root: None,
            stdin: None,
            flag_empty_stdin: false,
            config: None,
            opts: None,
            records,
        }
    }

    pub fn records(&self) -> &[C::Record] {
        &self.records
    }
}

// implement Witness for riscv machine
impl<SC, C> ProvingWitness<SC, C, Vec<u8>>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<Val<SC>>,
{
    /// Keyless witness for the MLE single-node path: drives emulation only (reads
    /// `program`/`stdin`/`opts`). The MLE backend proves with its own key.
    pub fn setup_for_mle_riscv(
        program: Arc<C::Program>,
        stdin: EmulatorStdin<C::Program, Vec<u8>>,
        opts: EmulatorOpts,
    ) -> Self {
        Self {
            program: Some(program),
            vk_root: None,
            stdin: Some(stdin),
            flag_empty_stdin: false,
            opts: Some(opts),
            config: None,
            records: vec![],
        }
    }
}
