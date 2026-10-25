#[cfg(feature = "aot-emulator")]
use crate::emulator::aot::create_aot_emulator;
use crate::{
    compiler::riscv::program::Program,
    configs::config::{StarkGenericConfig, Val},
    emulator::{
        riscv::{
            emulator::{ParOptions, SharedDeferredState},
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
        final_pvs_state: Arc<RecordFinalPvsState>,
        par_opts: Option<ParOptions>,
    ) -> Self {
        // Ensure the CUDA pinned-memory event pools are initialised.
        // They are required by CpuEventBuffer / AluEventBuffer which
        // back EmulationRecord. The pools are process-global singletons,
        // so the guarded init is a cheap no-op after the first call.
        {
            use crate::emulator::riscv::{
                alu_event_pool::{init_alu_event_buffer_pool, is_alu_pool_initialized},
                cpu_event_pool::{init_cpu_event_buffer_pool, is_pool_initialized},
            };
            use cudart::memory::CudaHostAllocFlags;
            if !is_pool_initialized() {
                init_cpu_event_buffer_pool(50, CudaHostAllocFlags::DEFAULT);
            }
            if !is_alu_pool_initialized() {
                init_alu_event_buffer_pool(50, CudaHostAllocFlags::DEFAULT);
            }
        }

        // create a new emulator based on the emulator type
        let opts = proving_witness.opts.unwrap();
        let mut emulator = RiscvEmulator::new_single::<SC::Val>(
            proving_witness.program.clone().unwrap(),
            final_pvs_state,
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
            par_opts,
            shared_ds,
            target_clk,
            final_segment,
        );
        Self {
            stdin: witness.stdin.clone().unwrap(),
            emulator: Some(emulator),
            batch_size: opts.chunk_batch_size,
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
    pub fn setup_riscv(
        proving_witness: &ProvingWitness<SC, C, Vec<u8>>,
        final_pvs_state: Arc<RecordFinalPvsState>,
        _par_opts: Option<ParOptions>,
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
        AotMetaEmulator::next_state_batch(self, true, &mut |_| {})
    }

    fn cycles(&self) -> u64 {
        AotMetaEmulator::cycles(self)
    }

    fn get_pv_stream(&mut self) -> Vec<u8> {
        AotMetaEmulator::get_pv_stream(self)
    }
}
