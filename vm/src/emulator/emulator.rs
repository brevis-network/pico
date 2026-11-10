#[cfg(feature = "aot-emulator")]
use crate::emulator::aot::{create_aot_emulator, create_aot_replay_emulator, AotReplayEmulator};
use crate::{
    compiler::riscv::program::Program,
    configs::config::{StarkGenericConfig, Val},
    emulator::{
        riscv::{
            emulator::SharedDeferredState,
            memory::ContiguousRiscvMemory,
            public_values::RecordFinalPvsState,
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
use alloc::sync::Arc;
use p3_field::PrimeField32;
use std::marker::PhantomData;

// Meta emulator that encapsulates multiple emulators
// SC and C for configs in the emulated machine
// E for the emulator type
pub struct MetaEmulator<SC, C, E>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<Val<SC>>,
{
    pub stdin: EmulatorStdin,
    pub emulator: Option<E>,
    pub _sc_and_chip: PhantomData<(SC, C)>,
}

// MetaEmulator for riscv
impl<SC, C> MetaEmulator<SC, C, RiscvEmulator>
where
    SC: StarkGenericConfig,
    SC::Val: PrimeField32 + FieldSpecificPoseidon2Config,
    C: ChipBehavior<Val<SC>, Program = Program, Record = EmulationRecord>,
{
    pub fn setup_riscv(
        proving_witness: &ProvingWitness<SC, C>,
        final_pvs_state: Arc<RecordFinalPvsState>,
    ) -> Self {
        // create a new emulator based on the emulator type
        let opts = proving_witness.opts.unwrap();
        let mut emulator = RiscvEmulator::new_single::<SC::Val>(
            proving_witness.program.clone().unwrap(),
            final_pvs_state,
            opts,
        );
        emulator.write_stdin(proving_witness.stdin.as_ref().unwrap());

        Self {
            stdin: proving_witness.stdin.clone().unwrap(),
            emulator: Some(emulator),
            _sc_and_chip: PhantomData,
        }
    }

    pub fn recover_riscv(
        witness: &ProvingWitness<SC, C>,
        state: RiscvEmulationState,
        shared_ds: SharedDeferredState,
        target_clk: u64,
        final_segment: bool,
    ) -> Self {
        // Build the snapshot-worker emulator directly from the witness. The previous
        // implementation called `setup_riscv`, which constructed a *full* RiscvEmulator
        // (syscall/hook maps, contiguous memory, an EmulationRecord, a throwaway deferred
        // state, plus a `write_stdin` copy of the entire input stream) only to read `opts`
        // and `program` back off it and immediately discard it when `recover` rebuilt a
        // second emulator. `opts`/`program` come straight from the witness, and the
        // recovered emulator uses `shared_ds` directly, so the `setup_riscv` emulator —
        // and the `shared_ds.lock()`/`final_pvs_state.clone()` that only fed its deferred
        // state — are pure redundant work (heavy under concurrent per-worker allocation).
        let opts = witness.opts.unwrap();
        let prog = witness.program.clone().unwrap();
        let emulator = RiscvEmulator::recover::<SC::Val>(
            prog,
            state,
            opts,
            shared_ds,
            target_clk,
            final_segment,
        );
        Self {
            stdin: witness.stdin.clone().unwrap(),
            emulator: Some(emulator),
            _sc_and_chip: PhantomData,
        }
    }

    /// [`RiscvEmulator::recover_in_place`]: returns the previous state's memory.
    #[must_use]
    pub fn recover_riscv_in_place(
        &mut self,
        state: RiscvEmulationState,
        shared_ds: SharedDeferredState,
        target_clk: u64,
        final_segment: bool,
    ) -> ContiguousRiscvMemory {
        let emulator = self.emulator.as_mut().expect("emulator missing");
        emulator.recover_in_place(state, shared_ds, target_clk, final_segment)
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

    pub fn disable_cost_estimator_for_snapshot(&mut self) {
        if let Some(e) = &mut self.emulator {
            e.opts.cost_estimator = false;
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

    /// The interpreter snapshot pass does not split a chunk, so a batch is always one segment.
    pub fn next_state_batch_segments<F>(
        &mut self,
        emit_events: bool,
        record_cb: &mut F,
    ) -> Result<(Vec<(RiscvEmulationState, u64)>, EmulationReport), EmulationError>
    where
        F: FnMut(EmulationRecord),
    {
        let (state, report) = self.next_state_batch(emit_events, record_cb)?;
        let target = report.current_cycle;
        Ok((vec![(state, target)], report))
    }

    pub fn cycles(&self) -> u64 {
        self.emulator.as_ref().unwrap().state.global_clk
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
    pub fn setup_riscv(
        proving_witness: &ProvingWitness<SC, C>,
        final_pvs_state: Arc<RecordFinalPvsState>,
    ) -> Self {
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
        let emulator = create_aot_emulator(program, input_stream, *opts, final_pvs_state)
            .expect("AOT emulator factory not registered");
        Self {
            emulator,
            _sc_and_chip: PhantomData,
        }
    }

    pub fn disable_cost_estimator_for_snapshot(&mut self) {
        // The AOT snapshot path does not build or use the interpreter cost estimator.
    }

    pub fn next_state_batch<F>(
        &mut self,
        _emit_events: bool,
        _record_cb: &mut F,
    ) -> Result<(RiscvEmulationState, EmulationReport), EmulationError>
    where
        F: FnMut(EmulationRecord),
    {
        let _ = _emit_events;
        let _ = _record_cb;
        self.emulator.next_state_batch()
    }

    /// See [`AotSnapshotEmulator::next_state_batch_segments`].
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

    pub fn counters(&self) -> crate::emulator::snapshot::SnapshotCounters {
        self.emulator.counters()
    }
}

/// A replay worker running the AOT-compiled guest's recording blocks:
/// [`MetaEmulator::recover_riscv`] and [`MetaEmulator::try_next_record_batch`] with the AOT core in
/// the interpreter's place. Its records take the interpreter worker's road, through the same
/// deferral and callback, so nothing downstream learns which engine replayed them.
#[cfg(feature = "aot-emulator")]
pub struct AotReplayMetaEmulator<SC, C>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<Val<SC>>,
{
    emulator: Box<dyn AotReplayEmulator>,
    program: Arc<Program>,
    shared_ds: SharedDeferredState,
    _sc_and_chip: PhantomData<(SC, C)>,
}

#[cfg(feature = "aot-emulator")]
impl<SC, C> AotReplayMetaEmulator<SC, C>
where
    SC: StarkGenericConfig,
    SC::Val: PrimeField32 + FieldSpecificPoseidon2Config,
    C: ChipBehavior<Val<SC>, Program = Program, Record = EmulationRecord>,
{
    /// A worker's first replay, of `state` up to `target_clk`.
    ///
    /// # Panics
    ///
    /// If no AOT replay factory is registered, which only a program with a recording entry point
    /// installs.
    pub fn recover_riscv(
        witness: &ProvingWitness<SC, C>,
        state: RiscvEmulationState,
        shared_ds: SharedDeferredState,
        target_clk: u64,
        final_segment: bool,
    ) -> Self {
        let program = witness
            .program
            .as_ref()
            .expect("witness.program not set")
            .clone();
        let emulator =
            create_aot_replay_emulator(program.clone(), state, target_clk, final_segment)
                .expect("no AOT program with a recording entry point is registered");
        Self {
            emulator,
            program,
            shared_ds,
            _sc_and_chip: PhantomData,
        }
    }

    /// [`Self::recover_riscv`] on a worker that has replayed before, reusing it. Returns the
    /// previous state's memory, which only the caller knows whether to give back to the pool.
    #[must_use]
    pub fn recover_riscv_in_place(
        &mut self,
        state: RiscvEmulationState,
        shared_ds: SharedDeferredState,
        target_clk: u64,
        final_segment: bool,
    ) -> crate::emulator::riscv::memory::ContiguousRiscvMemory {
        self.shared_ds = shared_ds;
        self.emulator
            .recover_in_place(state, target_clk, final_segment)
    }

    /// Replays to the target, deferring the record into the shared pool and handing it to
    /// `record_callback` as the interpreter's worker does. A replay that ends the run defers the
    /// memory initialize and finalize events after it.
    pub fn try_next_record_batch<F>(
        &mut self,
        record_callback: &mut F,
    ) -> Result<EmulationReport, EmulationError>
    where
        F: FnMut(EmulationRecord),
    {
        let (record, report) = self.emulator.replay()?;
        // A worker's record is traced and only deferred: the sequencer stamps its public values.
        self.shared_ds.lock().complete_and_return_record(
            report.done,
            record,
            true,
            true,
            record_callback,
        );
        if report.done {
            let mut memory_events = EmulationRecord::new(self.program.clone());
            self.emulator.postprocess(&mut memory_events);
            self.shared_ds.lock().defer_record(&mut memory_events);
        }
        Ok(report)
    }

    /// Compiled blocks entered, over every replay this worker ran.
    pub fn compiled_block_dispatches(&self) -> u64 {
        self.emulator.compiled_block_dispatches()
    }

    /// Instructions the fallback interpreter ran, over every replay this worker ran.
    pub fn fallback_insns(&self) -> u64 {
        self.emulator.fallback_insns()
    }

    /// See [`AotReplayEmulator::recorder_body_dispatches`].
    pub fn recorder_body_dispatches(&self) -> u64 {
        self.emulator.recorder_body_dispatches()
    }

    /// See [`AotReplayEmulator::recorder_body_insns`].
    pub fn recorder_body_insns(&self) -> u64 {
        self.emulator.recorder_body_insns()
    }

    /// See [`AotReplayEmulator::recorder_direct_insns`].
    pub fn recorder_direct_insns(&self) -> u64 {
        self.emulator.recorder_direct_insns()
    }
}

#[cfg(feature = "aot-emulator")]
impl<SC, C> AotReplayMetaEmulator<SC, C>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<Val<SC>>,
{
    /// See [`AotReplayEmulator::replace_memory`].
    pub fn replace_memory(
        &mut self,
        memory: crate::emulator::riscv::memory::ContiguousRiscvMemory,
    ) -> crate::emulator::riscv::memory::ContiguousRiscvMemory {
        self.emulator.replace_memory(memory)
    }

    /// The memory the last replay ran on, for the caller to give back.
    pub fn into_memory(self) -> crate::emulator::riscv::memory::ContiguousRiscvMemory {
        self.emulator.into_memory()
    }
}

impl<SC, C> SnapshotEmulator for MetaEmulator<SC, C, RiscvEmulator>
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
        AotMetaEmulator::next_state_batch(self, true, &mut |_| {})
    }

    fn cycles(&self) -> u64 {
        AotMetaEmulator::cycles(self)
    }

    fn get_pv_stream(&mut self) -> Vec<u8> {
        AotMetaEmulator::get_pv_stream(self)
    }

    fn counters(&self) -> crate::emulator::snapshot::SnapshotCounters {
        AotMetaEmulator::counters(self)
    }
}
