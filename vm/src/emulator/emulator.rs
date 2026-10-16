#[cfg(feature = "aot-emulator")]
use crate::emulator::{aot::create_aot_emulator, riscv::public_values::RecordFinalPvsState};
use crate::{
    compiler::riscv::program::Program,
    configs::config::{StarkGenericConfig, Val},
    emulator::{
        riscv::{
            emulator::{ParOptions, SharedDeferredState},
            record::EmulationRecord,
            riscv_emulator::{EmulationError, RiscvEmulator},
            state::RiscvEmulationState,
        },
        snapshot::SnapshotEmulator,
        stdin::EmulatorStdin,
    },
    machine::{
        chip::ChipBehavior, field::FieldSpecificPoseidon2Config, report::EmulationReport,
        witness::ProvingWitness,
    },
};
use p3_field::PrimeField32;
use std::marker::PhantomData;
#[cfg(feature = "aot-emulator")]
use std::sync::Arc;

// Meta emulator that encapsulates multiple emulators
// SC and C for configs in the emulated machine
// P and I for the native program and input types
// E for the emulator type
pub struct MetaEmulator<SC, C, P, I, E>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<Val<SC>>,
{
    pub stdin: EmulatorStdin<P, I>,
    pub emulator: Option<E>,
    pub batch_size: u32, // max parallelism
    pub _sc_and_chip: PhantomData<(SC, C)>,
}

// MetaEmulator for riscv
impl<SC, C> MetaEmulator<SC, C, Program, Vec<u8>, RiscvEmulator>
where
    SC: StarkGenericConfig,
    SC::Val: PrimeField32 + FieldSpecificPoseidon2Config,
    C: ChipBehavior<Val<SC>, Program = Program, Record = EmulationRecord>,
{
    pub fn setup_riscv(
        proving_witness: &ProvingWitness<SC, C, Vec<u8>>,
        par_opts: Option<ParOptions>,
    ) -> Self {
        // create a new emulator based on the emulator type
        let opts = proving_witness.opts.unwrap();
        let mut emulator = RiscvEmulator::new_single::<SC::Val>(
            proving_witness.program.clone().unwrap(),
            opts,
            par_opts,
        );
        emulator.write_stdin(proving_witness.stdin.as_ref().unwrap());

        Self {
            stdin: proving_witness.stdin.clone().unwrap(),
            emulator: Some(emulator),
            batch_size: opts.chunk_batch_size,
            _sc_and_chip: PhantomData,
        }
    }

    pub fn recover_riscv(
        witness: &ProvingWitness<SC, C, Vec<u8>>,
        state: RiscvEmulationState,
        par_opts: Option<ParOptions>,
        shared_ds: SharedDeferredState,
        target_clk: u64,
        final_segment: bool,
    ) -> Self {
        let mut me = MetaEmulator::setup_riscv(witness, par_opts);
        let opts = me.emulator.as_ref().unwrap().opts;
        let prog = me.emulator.as_ref().unwrap().program.clone();
        me.emulator = Some(RiscvEmulator::recover::<SC::Val>(
            prog,
            state,
            opts,
            shared_ds,
            target_clk,
            final_segment,
        ));
        me
    }

    pub fn next_record_batch<F>(&mut self, record_callback: &mut F) -> EmulationReport
    where
        F: FnMut(EmulationRecord),
    {
        self.try_next_record_batch(record_callback).unwrap()
    }

    /// [`Self::next_record_batch`], with the emulator's failure returned rather than unwrapped.
    pub fn try_next_record_batch<F>(
        &mut self,
        record_callback: &mut F,
    ) -> Result<EmulationReport, EmulationError>
    where
        F: FnMut(EmulationRecord),
    {
        let emulator = self.emulator.as_mut().unwrap();
        emulator.emulate_batch(record_callback)
    }

    pub fn set_cost_estimator(&mut self, enabled: bool) {
        if let Some(e) = &mut self.emulator {
            e.opts.cost_estimator = enabled;
        }
    }

    pub fn next_state_batch<F>(
        &mut self,
        emit_events: bool,
        record_cb: &mut F,
    ) -> Result<(RiscvEmulationState, EmulationReport), EmulationError>
    where
        F: FnMut(EmulationRecord),
    {
        let emu = self.emulator.as_mut().unwrap();
        emu.emulate_state(emit_events, record_cb)
    }

    pub fn cycles(&self) -> u64 {
        self.emulator.as_ref().unwrap().state.global_clk
    }

    pub fn get_pv_stream_with_dryrun(&mut self) -> Vec<u8> {
        loop {
            let report = self.next_record_batch(&mut |_| {});
            if report.done {
                break;
            }
        }
        self.emulator
            .as_ref()
            .unwrap()
            .state
            .public_values_stream
            .clone()
    }

    pub fn get_pv_stream(&mut self) -> Vec<u8> {
        self.emulator
            .as_ref()
            .unwrap()
            .state
            .public_values_stream
            .clone()
    }
}

#[cfg(feature = "aot-emulator")]
pub struct AotMetaEmulator<SC, C>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<Val<SC>>,
{
    emulator: Box<dyn crate::emulator::aot::AotSnapshotEmulator>,
    _sc_and_chip: PhantomData<(SC, C)>,
}

#[cfg(feature = "aot-emulator")]
impl<SC, C> AotMetaEmulator<SC, C>
where
    SC: StarkGenericConfig,
    SC::Val: PrimeField32 + FieldSpecificPoseidon2Config,
    C: ChipBehavior<Val<SC>, Program = Program, Record = EmulationRecord>,
{
    pub fn setup_riscv(proving_witness: &ProvingWitness<SC, C, Vec<u8>>) -> Self {
        let opts = proving_witness.opts.as_ref().expect("witness.opts not set");
        let program = proving_witness
            .program
            .as_ref()
            .expect("witness.program not set")
            .clone();
        let input_stream = proving_witness
            .stdin
            .as_ref()
            .expect("witness.stdin not set")
            .inputs
            .to_vec();
        // The factory takes the shared final-pvs cell the AOT runtime writes its last record's
        // digests into. Nothing on this branch reads it back, so there is no shared cell to pass
        // and one is made here.
        let final_pvs_state = Arc::new(RecordFinalPvsState::default());
        let emulator = create_aot_emulator(program, input_stream, *opts, final_pvs_state)
            .expect("AOT emulator factory not registered");
        Self {
            emulator,
            _sc_and_chip: PhantomData,
        }
    }

    pub fn next_state_batch(
        &mut self,
    ) -> Result<(RiscvEmulationState, EmulationReport), EmulationError> {
        self.emulator.next_state_batch()
    }

    /// See [`crate::emulator::aot::AotSnapshotEmulator::next_state_batch_segments`].
    pub fn next_state_batch_segments(
        &mut self,
    ) -> Result<(Vec<(RiscvEmulationState, u64)>, EmulationReport), EmulationError> {
        self.emulator.next_state_batch_segments()
    }

    pub fn cycles(&self) -> u64 {
        self.emulator.cycles()
    }

    pub fn get_pv_stream(&mut self) -> Vec<u8> {
        self.emulator.get_pv_stream()
    }
}

impl<SC, C> SnapshotEmulator for MetaEmulator<SC, C, Program, Vec<u8>, RiscvEmulator>
where
    SC: StarkGenericConfig,
    SC::Val: PrimeField32 + FieldSpecificPoseidon2Config,
    C: ChipBehavior<Val<SC>, Program = Program, Record = EmulationRecord>,
{
    fn next_state_batch(
        &mut self,
    ) -> Result<(RiscvEmulationState, EmulationReport), EmulationError> {
        MetaEmulator::next_state_batch(self, true, &mut |_| {})
    }

    fn cycles(&self) -> u64 {
        MetaEmulator::cycles(self)
    }

    fn get_pv_stream(&mut self) -> Vec<u8> {
        MetaEmulator::get_pv_stream(self)
    }
}

#[cfg(feature = "aot-emulator")]
impl<SC, C> SnapshotEmulator for AotMetaEmulator<SC, C>
where
    SC: StarkGenericConfig,
    SC::Val: PrimeField32 + FieldSpecificPoseidon2Config,
    C: ChipBehavior<Val<SC>, Program = Program, Record = EmulationRecord>,
{
    fn next_state_batch(
        &mut self,
    ) -> Result<(RiscvEmulationState, EmulationReport), EmulationError> {
        AotMetaEmulator::next_state_batch(self)
    }

    fn next_state_batch_segments(
        &mut self,
    ) -> Result<(Vec<(RiscvEmulationState, u64)>, EmulationReport), EmulationError> {
        AotMetaEmulator::next_state_batch_segments(self)
    }

    fn cycles(&self) -> u64 {
        AotMetaEmulator::cycles(self)
    }

    fn get_pv_stream(&mut self) -> Vec<u8> {
        AotMetaEmulator::get_pv_stream(self)
    }
}
