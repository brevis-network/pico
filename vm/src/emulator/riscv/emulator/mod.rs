pub mod error;
pub mod instruction;
pub mod instruction_simple;
pub mod mode;
mod postprocess;
pub mod unconstrained;
pub mod util;

use crate::{
    chips::chips::events::{
        MemoryAccessPosition, MemoryLocalEvent, MemoryReadRecord, MemoryRecord, MemoryWriteRecord,
    },
    compiler::{
        addr::fits_pc,
        riscv::{instruction::Instruction, program::Program, register::Register},
    },
    emulator::{
        opts::EmulatorOpts,
        record::RecordBehavior,
        riscv::{
            chunk_split::{self, ChunkSplitConfig, ChunkSplitState},
            event_types::{RvAddr, RvChunk, RvClk, RvTimestamp, RvValue},
            hook::{default_hook_map, Hook},
            public_values::{PublicValues, RecordFinalPvsState},
            public_values_compat::{
                encode_public_value_chunk_counter, encode_public_value_pc_limbs,
            },
            record::EmulationRecord,
            sink::{ChunkBoundary, ExecutionSink, HistorySink, Sink},
            state::{RiscvEmulationState, RuntimeRegisterRecord},
            syscalls::{default_syscall_map, Syscall, SyscallCode},
        },
    },
    machine::{
        estimator::{CycleEstimator, EventSizeCapture},
        field::{same_field, FieldSpecificPoseidon2Config},
        report::EmulationReport,
    },
    primitives::consts::CHUNK_CLK_START,
};
use alloc::sync::Arc;
use hashbrown::HashMap;
use p3_field::PrimeField32;
use p3_koala_bear::KoalaBear;
use parking_lot::Mutex as ParkingMutex;
use serde::{Deserialize, Serialize};
use std::time::Instant;
use tracing::{debug, error, instrument};

use crate::emulator::riscv::memory::ContiguousRiscvMemory;
pub use error::{AbnormalTermination, EmulationError, TerminationReason};
pub use mode::RiscvEmulatorMode;
pub use postprocess::{postprocess, FinalState};
pub use unconstrained::UnconstrainedState;
pub use util::align_u64;

pub const MIN_MAIN_MEMORY_ADDR: u64 = 0x100;

pub type SharedDeferredState = Arc<ParkingMutex<EmulationDeferredState>>;

/// `CHUNK_SPLIT_DEBUG=1`: the chunk counter a tail record ends up proving under.
///
/// The probe in `EmulationRecord::split` cannot print this — it sees the records before their
/// public values exist. The records reach here in the order that probe listed them.
fn maybe_debug_tail_chunk_pv(record: &EmulationRecord) {
    if !record.is_cpu_chunk && chunk_split::split_debug() {
        tracing::info!(
            "[chunk-split] tail-chunk pvs.chunk={}",
            record.public_values.chunk
        );
    }
}

/// The pc a deferred record, a precompile or memory chunk split off the deferred pool with no CPU
/// event of its own, states as both its start and its next pc: where the run stands once the CPU
/// chunks before the split are in.
///
/// The serial path splits at the end of a batch, which ends on its last cut, so the emulator's pc
/// is that chunk's next pc. The sequencer holds no emulator, and takes the next pc of the last CPU
/// chunk it handed on. The two differ only for public values that took none of the run's CPU
/// chunks, as the snapshot thread's do, so each caller names its own.
#[derive(Clone, Copy, Debug)]
pub enum DeferredChunkPc {
    /// The pc the emulator stands at.
    At(RvAddr),
    /// The next pc of the last CPU chunk these public values took.
    LastCpuChunk,
}

/// The state for saving deferred information
pub struct EmulationDeferredState {
    flag_active: bool,
    deferred: EmulationRecord,
    pvs: PublicValues<u32, u32>,
    pub final_pvs_state: Arc<RecordFinalPvsState>,
}

impl EmulationDeferredState {
    pub fn new(program: Arc<Program>, final_pvs_state: Arc<RecordFinalPvsState>) -> Self {
        let flag_active = true;
        let deferred = EmulationRecord::new(program);
        let pvs = PublicValues::<u32, u32>::default();

        Self {
            flag_active,
            deferred,
            pvs,
            final_pvs_state,
        }
    }

    /// [`Self::new`] behind the lock the pipeline's emulators share it through, for a caller
    /// outside this crate, which cannot name that lock.
    pub fn shared(
        program: Arc<Program>,
        final_pvs_state: Arc<RecordFinalPvsState>,
    ) -> SharedDeferredState {
        Arc::new(ParkingMutex::new(Self::new(program, final_pvs_state)))
    }

    /// Only defer the record: the run's memory initialize and finalize events, at its end. A
    /// chunk's record is deferred by [`Self::complete_and_return_record`], and timed apart.
    pub(crate) fn defer_record(&mut self, new_record: &mut EmulationRecord) {
        let start = crate::mle::ledger::timer_start();
        self.deferred.append(&mut new_record.defer());
        crate::mle::ledger::deferred_memory_extend(start);
    }

    /// Update the public values, defer and return the record.
    pub(crate) fn complete_and_return_record<F>(
        &mut self,
        emulation_done: bool,
        mut new_record: EmulationRecord,
        is_trace: bool,
        defer_only: bool,
        callback: &mut F,
    ) where
        F: FnMut(EmulationRecord),
    {
        let start = crate::mle::ledger::timer_start();
        self.deferred.append(&mut new_record.defer());
        crate::mle::ledger::deferred_extend(start);

        if !defer_only {
            // A cut record is a CPU chunk, which states the pcs its cut stamped.
            assert!(new_record.is_cpu_chunk, "a cut record is not a CPU chunk");
            self.update_public_values(
                emulation_done,
                &mut new_record,
                DeferredChunkPc::LastCpuChunk,
            );
        }

        // in trace mode
        if is_trace {
            callback(new_record);
        }
    }

    /// Update the public values, split and return the deferred records.
    ///
    /// # Arguments
    /// * `committed_batch_idx` - The current batch_idx that sequencer has processed.
    ///   Use `u32::MAX` to disable filtering (legacy behavior).
    pub fn split_and_return_deferred_records<F>(
        &mut self,
        emulation_done: bool,
        is_trace: bool,
        callback: &mut F,
        pc: u64,
        committed_batch_idx: u32,
    ) where
        F: FnMut(EmulationRecord),
    {
        // Get the deferred records.
        let mut records = self.deferred.split(emulation_done, committed_batch_idx);
        debug!("split-chunks len: {:?}", records.len());

        if emulation_done {
            if let Some(last) = records.last_mut() {
                last.is_last = true;
            }
        }

        records.into_iter().for_each(|mut r| {
            self.update_public_values(emulation_done, &mut r, DeferredChunkPc::At(pc));

            if is_trace {
                callback(r);
            }
        });
    }

    pub fn take_split_records(
        &mut self,
        emulation_done: bool,
        committed_batch_idx: u32,
    ) -> Vec<EmulationRecord> {
        let mut records = self.deferred.split(emulation_done, committed_batch_idx);
        debug!("split-chunks len: {:?}", records.len());
        if emulation_done {
            if let Some(last) = records.last_mut() {
                last.is_last = true;
            }
        }
        records
    }

    /// Takes `record` into the run's public values, in order, and writes them into it: the one
    /// reader of every record's public values, on the serial path and in the sequencer.
    ///
    /// Every record moves the chunk counter on. A CPU chunk counts an execution chunk, and states
    /// the pcs the cut stamped into its record, in Simple Mode as in Trace Mode, and the digest
    /// words its COMMITs wrote. A deferred record closes the run of execution chunks unless the run
    /// is done, states `deferred_pc`, and keeps its own memory initialize and finalize address
    /// ranges. In Simple Mode only `chunk`, `execution_chunk` and `flag_active` need to keep
    /// counting; the rest is overwritten correctly in trace mode.
    pub fn update_public_values(
        &mut self,
        emulation_done: bool,
        record: &mut EmulationRecord,
        deferred_pc: DeferredChunkPc,
    ) {
        self.pvs.chunk = encode_public_value_chunk_counter(self.pvs.chunk + 1);
        if record.is_cpu_chunk {
            if !self.flag_active {
                self.flag_active = true;
            } else {
                self.pvs.execution_chunk =
                    encode_public_value_chunk_counter(self.pvs.execution_chunk + 1);
            }
            self.adopt_stamped_pcs(record.public_values.start_pc, record.public_values.next_pc);
            // digest guard (fix): committed_value_digest / deferred_proofs_digest are MONOTONIC —
            // zero until the guest's COMMIT ecall, then held for every later chunk. Adopt an
            // incoming NON-ZERO digest, but never let a post-commit chunk whose standalone record
            // carries 0 clobber the accumulated value back to 0. Without this, a block with CPU
            // chunk(s) after the commit chunk emits a `...,V,0,...` stream that the reference
            // verifier and the recursion combine circuit correctly reject (e.g. block 24006128).
            if record
                .public_values
                .committed_value_digest
                .iter()
                .any(|&w| w != 0)
            {
                self.pvs.committed_value_digest = record.public_values.committed_value_digest;
            }
            if record
                .public_values
                .deferred_proofs_digest
                .iter()
                .any(|&w| w != 0)
            {
                self.pvs.deferred_proofs_digest = record.public_values.deferred_proofs_digest;
            }
        } else {
            // Make execution chunk consistent.
            if self.flag_active && !emulation_done {
                self.pvs.execution_chunk =
                    encode_public_value_chunk_counter(self.pvs.execution_chunk + 1);
                self.flag_active = false;
            }

            let pc = match deferred_pc {
                DeferredChunkPc::At(pc) => encode_public_value_pc_limbs(pc),
                DeferredChunkPc::LastCpuChunk => self.pvs.next_pc,
            };
            self.pvs.start_pc = pc;
            self.pvs.next_pc = pc;
            self.pvs.previous_init_addr_limbs = record.public_values.previous_init_addr_limbs;
            self.pvs.last_init_addr_limbs = record.public_values.last_init_addr_limbs;
            self.pvs.previous_finalize_addr_limbs =
                record.public_values.previous_finalize_addr_limbs;
            self.pvs.last_finalize_addr_limbs = record.public_values.last_finalize_addr_limbs;
        }

        record.public_values = self.pvs;
        maybe_debug_tail_chunk_pv(record);
        debug!(
            "riscv record index: {:?}, record.public_values.deferred_proofs_digest: {:?}",
            record.chunk_index(),
            record.public_values.deferred_proofs_digest
        );
    }

    /// Takes a CPU chunk's pcs from the [`ChunkBoundary`] its cut wrote into its record, so a
    /// record that carries no CPU events still has them; the out-of-order sequencer passes the
    /// ones it saved. Its exit code is 0, written here alone: a HALT with any other code is an
    /// error in both modes, so no chunk is cut on one, and the recursion pins every chunk's exit
    /// code to 0.
    fn adopt_stamped_pcs(&mut self, start_pc: [u32; 3], next_pc: [u32; 3]) {
        self.pvs.start_pc = start_pc;
        self.pvs.next_pc = next_pc;
        self.pvs.exit_code = 0;
    }

    /// Accumulate PV state without modifying a record.
    /// Used by OOO sequencer: records already emitted with standalone PVs,
    /// but deferred state still needs sequential accumulation for splits.
    pub fn accumulate_pvs_only(
        &mut self,
        is_cpu_chunk: bool,
        start_pc: [u32; 3],
        next_pc: [u32; 3],
        committed_value_digest: [u32; 8],
        deferred_proofs_digest: [u32; 8],
    ) {
        self.pvs.chunk = encode_public_value_chunk_counter(self.pvs.chunk + 1);
        if is_cpu_chunk {
            if !self.flag_active {
                self.flag_active = true;
            } else {
                self.pvs.execution_chunk =
                    encode_public_value_chunk_counter(self.pvs.execution_chunk + 1);
            }
            self.adopt_stamped_pcs(start_pc, next_pc);
            // digest guard (fix): see update_public_values — monotonic digest, adopt non-zero only.
            if committed_value_digest.iter().any(|&w| w != 0) {
                self.pvs.committed_value_digest = committed_value_digest;
            }
            if deferred_proofs_digest.iter().any(|&w| w != 0) {
                self.pvs.deferred_proofs_digest = deferred_proofs_digest;
            }
        } else {
            if self.flag_active {
                self.pvs.execution_chunk =
                    encode_public_value_chunk_counter(self.pvs.execution_chunk + 1);
                self.flag_active = false;
            }
            self.pvs.start_pc = self.pvs.next_pc;
        }
    }
}

type EmuFn = fn(&mut RiscvEmulator, &Instruction) -> Result<(), EmulationError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChunkBoundaryMode {
    ReplayToTarget,
    ChunkSplit,
}

/// An emulator for the Pico RISC-V zkVM.
///
/// The executor is responsible for executing a user program and tracing important events which
/// occur during emulation (i.e., memory reads, alu operations, etc).
pub struct RiscvEmulator {
    /// The current running mode of RiscV emulator.
    pub mode: RiscvEmulatorMode,

    /// The program.
    pub program: Arc<Program>,

    /// The options for the emulator.
    pub opts: EmulatorOpts,

    /// The state of the emulation.
    pub state: RiscvEmulationState,

    /// Memory addresses that were touched in this batch of chunks. Used to minimize the size of snapshots.
    pub memory_snapshot: ContiguousRiscvMemory,

    /// Previous register records touched in this batch of chunks.
    pub register_snapshot: [RuntimeRegisterRecord; 32],

    /// Bitmap of registers (0-31) that were snapshotted.
    pub register_snapshot_bitmap: u32,

    /// Where the emulation's events are written.
    pub sink: Sink,

    /// The mapping between syscall codes and their implementations.
    pub syscall_map: HashMap<SyscallCode, Arc<dyn Syscall>>,

    /// The mapping between hook fds and their implementation
    pub hook_map: HashMap<u32, Hook>,

    /// The maximum number of cycles for a syscall.
    pub max_syscall_cycles: RvClk,

    /// Shared event-based chunk splitting thresholds for the current execution mode.
    pub chunk_split_config: ChunkSplitConfig,

    /// Shared event-based counters for the current chunk.
    pub chunk_split_state: ChunkSplitState,

    /// Set when a snapshot worker reaches its target, to end the batch loop.
    ///
    /// The loop otherwise ends on the chunk counter moving, and a segment that is not the last
    /// one deliberately leaves that counter alone — without its own signal it would replay
    /// straight past its target.
    pub segment_complete: bool,
    /// Whether this replay ends the chunk, rather than one of its segments.
    ///
    /// A chunk's replay can be split across threads; only the segment that reaches the chunk's
    /// own boundary may advance the chunk counters. A middle segment that reset `clk` would
    /// restart the chunk-local clock inside the chunk, and every event after the seam would
    /// carry the wrong one.
    pub final_segment: bool,

    /// Stdout buffer
    pub stdout: String,

    /// Stderr buffer
    pub stderr: String,

    /// Tracked cycles
    pub cycle_tracker: HashMap<String, Vec<u64>>,

    /// Cycle tracker requests "cycle-tracker-start: "
    pub cycle_tracker_requests: HashMap<String, u64>,

    /// Snapshot workers stop exactly at this global clock when set.
    pub target_global_clk: Option<u64>,

    /// The state for saving the deferred information
    deferred_state: SharedDeferredState,

    defer_only: bool,

    /// whether or not to log syscalls
    log_syscalls: bool,

    /// emulate_instruction, emulate_instruction_simple
    emu_fn: EmuFn,

    /// keep track of the field name
    field: &'static str,

    /// The pc the current record started at: the program's start, the pc a replay was recovered
    /// at, or the pc of the last cut. The cut owes it to the record's public values, which do not
    /// depend on the record holding its CPU events.
    chunk_start_pc: RvAddr,
}

/// The different modes the emulator can run in.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EmulatorMode {
    /// Run the emulation with no tracing or checkpointing.
    #[default]
    Simple,
    /// Run the emulation with full tracing of events.
    Trace,
}

/// A batch's snapshot, whose memory is a block of the global pool, held while the batch runs. The
/// pool creates its blocks once, so a batch that fails or unwinds puts its block back rather than
/// dropping it; one that succeeds claims the snapshot.
struct PooledSnapshot(Option<RiscvEmulationState>);

impl PooledSnapshot {
    fn claim(mut self) -> RiscvEmulationState {
        self.0.take().expect("a pooled snapshot is claimed once")
    }
}

impl Drop for PooledSnapshot {
    fn drop(&mut self) {
        if let Some(snapshot) = self.0.take() {
            let _ = crate::emulator::riscv::memory::GLOBAL_MEMORY_RECYCLER
                .send((snapshot.memory, true));
        }
    }
}

#[inline(always)]
fn register_event_addr_u32(register: Register) -> u32 {
    // Register-memory events still use the retained u32 register-address schema; make the narrow
    // boundary explicit rather than leaving it as a migration-era compat shim.
    register as u32
}

impl RiscvEmulator {
    /// Whether this emulator replays a snapshot: `target_global_clk` is set on no other.
    #[inline(always)]
    fn is_snapshot_worker(&self) -> bool {
        self.target_global_clk.is_some()
    }

    /// Saves `record`, the state `addr` held before the batch first touched it, into the snapshot
    /// tracker. Only the snapshot thread's [`Self::emulate_state`] reads the tracker, and only it
    /// clears it, so a snapshot worker, re-armed for batch after batch, writes nothing: its
    /// tracker would otherwise come to hold every page the run touched.
    #[inline(always)]
    fn snapshot_memory_if_needed(&mut self, addr: RvAddr, record: &MemoryRecord) {
        if self.is_snapshot_worker() {
            return;
        }
        if !self.memory_snapshot.has_accessed(addr) {
            self.memory_snapshot.insert_u64(addr, *record);
        }
    }

    #[inline(always)]
    fn chunk_boundary_mode(&self) -> ChunkBoundaryMode {
        if self.is_snapshot_worker() {
            ChunkBoundaryMode::ReplayToTarget
        } else {
            ChunkBoundaryMode::ChunkSplit
        }
    }

    #[inline(always)]
    fn max_syscall_cycles_u32(&self) -> u32 {
        u32::try_from(self.max_syscall_cycles)
            .expect("syscall cycle budget exceeds u32 during chunk split setup")
    }

    #[inline(always)]
    fn chunk_clk_u32(&self) -> u32 {
        u32::try_from(self.state.clk)
            .expect("chunk-local clock exceeds u32 during chunk split evaluation")
    }

    /// Log why the current chunk closed (silent unless `CHUNK_SPLIT_DEBUG=1`).
    #[inline(always)]
    fn maybe_debug_split_snapshot(&self) {
        chunk_split::maybe_debug_split_snapshot(
            self.state.current_chunk,
            self.chunk_clk_u32(),
            self.max_syscall_cycles_u32(),
            self.state.global_clk,
            &self.chunk_split_state,
            &self.chunk_split_config,
        );
    }

    #[inline(always)]
    fn refresh_chunk_split_config(&mut self) {
        self.chunk_split_config =
            ChunkSplitConfig::for_chunk_size(self.opts.chunk_size, self.max_syscall_cycles_u32());
    }

    /// Capture a snapshot for a hint address (which should be uninitialized/zero).
    pub fn capture_snapshot_for_hint(&mut self, addr: u64) {
        self.validate_main_memory_addr(addr);
        let zero_record = MemoryRecord {
            value: 0,
            chunk: 0,
            timestamp: 0,
        };
        self.snapshot_memory_if_needed(addr, &zero_record);
    }

    /// Convenience: build a single-thread emulator with its own shared_ds.
    #[must_use]
    pub fn new_single<F>(
        program: Arc<Program>,
        final_pvs_state: Arc<RecordFinalPvsState>,
        opts: EmulatorOpts,
    ) -> Self
    where
        F: PrimeField32 + FieldSpecificPoseidon2Config,
    {
        let deferred_state = Arc::new(ParkingMutex::new(EmulationDeferredState::new(
            program.clone(),
            final_pvs_state,
        )));
        Self::new::<F>(program, opts, deferred_state, false, None)
    }

    /// The emulator, writing through `sink`.
    ///
    /// # Panics
    ///
    /// If `sink`'s record is not for this emulator's program, whose memory image `postprocess`
    /// reads off it, or if the emulator has run, since the replaced sink holds what it wrote.
    #[must_use]
    pub fn with_sink(mut self, sink: Sink) -> Self {
        assert!(
            Arc::ptr_eq(&sink.record().program, &self.program),
            "the sink's record is for another program"
        );
        assert_eq!(self.state.global_clk, 0, "the emulator has already run");
        self.sink = sink;
        self
    }

    /// Convenience: build a snapshot-worker emulator.
    ///
    /// `recovered_state`, when `Some`, is installed directly as the emulator state instead of
    /// allocating a fresh one — the snapshot-recover path overwrites the state immediately, so
    /// the default `RiscvEmulationState::new` (a ~5GB contiguous-memory mmap plus a ~31 MB
    /// accessed-bitmap zeroing) would otherwise be built and then dropped on every worker's
    /// first batch.
    #[must_use]
    pub fn new_snapshot_worker<F>(
        program: Arc<Program>,
        opts: EmulatorOpts,
        shared_ds: SharedDeferredState,
        recovered_state: Option<RiscvEmulationState>,
    ) -> Self
    where
        F: PrimeField32 + FieldSpecificPoseidon2Config,
    {
        Self::new::<F>(program, opts, shared_ds, true, recovered_state)
    }

    #[must_use]
    pub fn new<F>(
        program: Arc<Program>,
        opts: EmulatorOpts,
        deferred_state: SharedDeferredState,
        defer_only: bool,
        recovered_state: Option<RiscvEmulationState>,
    ) -> Self
    where
        F: PrimeField32 + FieldSpecificPoseidon2Config,
    {
        let record = EmulationRecord::new(program.clone());

        // Determine the maximum number of cycles for any syscall.
        let syscall_map = default_syscall_map::<F>();
        let max_syscall_cycles = syscall_map
            .values()
            .map(|syscall| syscall.num_extra_cycles())
            .map(u64::from)
            .max()
            .unwrap_or_default();

        let hook_map = default_hook_map();

        let log_syscalls = std::env::var_os("LOG_SYSCALLS").is_some();
        let pc_start = program.pc_start;
        // A replay can resume mid-chunk, so its first record starts where the state stands.
        let state = recovered_state.unwrap_or_else(|| RiscvEmulationState::new(pc_start));
        let chunk_start_pc = state.pc;

        let mut emu = Self {
            syscall_map,
            hook_map,
            sink: Sink::History(HistorySink::new(record)),
            state,
            // FIX(pool-leak deadlock): do NOT source the worker's snapshot tracker from
            // GLOBAL_MEMORY_POOL. Workers are rebuilt per block and their memory_snapshot is
            // plain-dropped at teardown (never recycled back), so each block permanently
            // drained ~NUM_THREADS pool entries; once the bounded pool (MEMORY_POOL_SIZE)
            // ran out, RiscvEmulationState::clone_without_memory's blocking recv() deadlocked
            // the snapshot emulator (workers only return memories when given a next batch).
            // Observed: two-machine multi-block runs froze deterministically at block
            // ~pool_size/12 (140 -> block 10, 280 -> block 22). Allocating fresh here
            // costs ~10ms per worker per block and restores pool balance.
            memory_snapshot: ContiguousRiscvMemory::new(),
            register_snapshot: [RuntimeRegisterRecord::default(); 32],
            register_snapshot_bitmap: 0,
            program,
            opts,
            max_syscall_cycles,
            chunk_split_config: ChunkSplitConfig::disabled(
                u32::try_from(max_syscall_cycles).expect("syscall cycle budget exceeds u32"),
            ),
            chunk_split_state: Default::default(),
            segment_complete: false,
            final_segment: true,
            mode: RiscvEmulatorMode::Trace,
            stdout: Default::default(),
            stderr: Default::default(),
            cycle_tracker: Default::default(),
            cycle_tracker_requests: Default::default(),
            target_global_clk: None,
            deferred_state,
            defer_only,
            log_syscalls,
            emu_fn: RiscvEmulator::emulate_instruction,
            field: if same_field::<F, KoalaBear, 4>() {
                "KoalaBear"
            } else {
                panic!("Unsupported field type");
            },
            chunk_start_pc,
        };

        emu.update_mode_deps();
        emu
    }

    /// If it's the first cycle, initialize the program.
    /// Pairs adjacent 4-byte entries from memory_image into 8-byte dwords.
    #[inline(always)]
    fn initialize_if_needed(&mut self) {
        if self.state.global_clk == 0 {
            self.state.clk = u64::from(CHUNK_CLK_START);
            debug!("loading memory image");
            // Write-only bulk load: the `prev` record `insert` returns is discarded here, and
            // the metadata it would write (chunk=0, timestamp=0) already holds in the freshly
            // zeroed backing — so `load_memory_image` skips both the reads and the redundant
            // metadata stores, writing only the value dword + the accessed bit. State identical.
            self.state
                .memory
                .load_memory_image(self.program.memory_image.iter());
        }
    }

    #[inline(always)]
    pub fn update_mode_deps(&mut self) {
        self.emu_fn = match self.mode {
            RiscvEmulatorMode::Simple => Self::emulate_instruction_simple,
            _ => Self::emulate_instruction,
        };
    }

    #[inline(always)]
    fn flush(&mut self) {
        if !self.stdout.is_empty() {
            log::info!("stdout (remaining)> {}", self.stdout);
            self.stdout.clear();
        }
        if !self.stderr.is_empty() {
            log::info!("stderr (remaining)> {}", self.stderr);
            self.stderr.clear();
        }
    }

    fn generate_report(
        &mut self,
        estimators: Option<Vec<CycleEstimator>>,
        done: bool,
        start_chunk: u32,
    ) -> EmulationReport {
        EmulationReport {
            current_cycle: self.state.global_clk,
            done,
            start_chunk,
            cycle_tracker: self
                .opts
                .cycle_tracker
                .then_some(core::mem::take(&mut self.cycle_tracker)),
            host_cycle_estimator: estimators,
        }
    }

    /// Emulates one cycle of the program, returning whether the program has finished.
    #[inline]
    fn emulate_cycle<F>(
        &mut self,
        record_callback: F,
        last_record_time: &mut Instant,
    ) -> Result<bool, EmulationError>
    where
        F: FnMut(bool, EmulationRecord),
    {
        // Fetch the instruction at the current program counter.
        let instruction = self.program.fetch(self.state.pc);

        // Emulate the instruction.
        (self.emu_fn)(self, &instruction)?;

        // Increment the clock.
        self.state.global_clk += 1;

        if let Some(max_cycles) = self.opts.max_cycles {
            let current_cycles = self.state.global_clk;
            if current_cycles >= max_cycles {
                return Err(EmulationError::ExceededCycleLimit(current_cycles));
            }
        }

        let done = self.state.pc == 0
            || self.state.pc.wrapping_sub(self.program.pc_base)
                >= (self.program.instructions.len() * 4) as u64;
        if done && self.is_unconstrained() {
            error!(
                "program ended in unconstrained mode at clk {}",
                self.state.global_clk,
            );
            return Err(EmulationError::UnconstrainedEnd);
        }
        if done && !fits_pc(self.state.pc) {
            return Err(EmulationError::EndPcBeyondProofAddress(self.state.pc));
        }

        if !self.is_unconstrained() {
            match self.chunk_boundary_mode() {
                ChunkBoundaryMode::ReplayToTarget => {
                    if let Some(target_global_clk) = self.target_global_clk {
                        if self.state.global_clk >= target_global_clk {
                            debug_assert_eq!(
                                self.state.global_clk, target_global_clk,
                                "snapshot worker overshot target_global_clk"
                            );
                            // Only the segment that ends the chunk closes it out; a middle one
                            // just hands its record over and leaves the chunk running.
                            if self.final_segment {
                                self.chunk_split_state.clear();
                                self.state.current_chunk += 1;
                                self.state.clk = u64::from(CHUNK_CLK_START);
                            }
                            self.segment_complete = true;

                            let elapsed = last_record_time.elapsed();

                            debug!(
                                "Record[{}] generated in {:.3} ms",
                                self.state.current_chunk,
                                elapsed.as_secs_f64() * 1000.0
                            );
                            *last_record_time = Instant::now(); // reset timer

                            self.bump_record(done, record_callback);
                        }
                    }
                }
                ChunkBoundaryMode::ChunkSplit
                    if self.chunk_split_state.should_split(
                        self.chunk_clk_u32(),
                        self.max_syscall_cycles_u32(),
                        &self.chunk_split_config,
                    ) =>
                {
                    self.maybe_debug_split_snapshot();
                    // Check if there's enough cycles or move to the next chunk.
                    self.chunk_split_state.clear();
                    self.state.current_chunk += 1;
                    self.state.clk = u64::from(CHUNK_CLK_START);

                    let elapsed = last_record_time.elapsed();

                    debug!(
                        "Record[{}] generated in {:.3} ms",
                        self.state.current_chunk,
                        elapsed.as_secs_f64() * 1000.0
                    );
                    *last_record_time = Instant::now(); // reset timer

                    self.bump_record(done, record_callback);
                }
                ChunkBoundaryMode::ChunkSplit => {
                    // No boundary crossed.
                }
            }
        }

        Ok(done)
    }

    #[doc(hidden)]
    pub fn debug_step_simple(&mut self) -> Result<bool, EmulationError> {
        self.initialize_if_needed();
        self.refresh_chunk_split_config();
        self.mode = RiscvEmulatorMode::Simple;
        self.update_mode_deps();

        let instruction = self.program.fetch(self.state.pc);
        Self::emulate_instruction_simple(self, &instruction)?;
        self.state.global_clk += 1;

        if let Some(max_cycles) = self.opts.max_cycles {
            let current_cycles = self.state.global_clk;
            if current_cycles >= max_cycles {
                return Err(EmulationError::ExceededCycleLimit(current_cycles));
            }
        }

        let done = self.state.pc == 0
            || self.state.pc.wrapping_sub(self.program.pc_base)
                >= (self.program.instructions.len() * 4) as u64;
        if done && self.is_unconstrained() {
            return Err(EmulationError::UnconstrainedEnd);
        }
        if done && !fits_pc(self.state.pc) {
            return Err(EmulationError::EndPcBeyondProofAddress(self.state.pc));
        }

        if !self.is_unconstrained() {
            match self.chunk_boundary_mode() {
                ChunkBoundaryMode::ReplayToTarget => {
                    if let Some(target_global_clk) = self.target_global_clk {
                        if self.state.global_clk >= target_global_clk && self.final_segment {
                            debug_assert_eq!(self.state.global_clk, target_global_clk);
                            self.chunk_split_state.clear();
                            self.state.current_chunk += 1;
                            self.state.clk = u64::from(CHUNK_CLK_START);
                        }
                    }
                }
                ChunkBoundaryMode::ChunkSplit
                    if self.chunk_split_state.should_split(
                        self.chunk_clk_u32(),
                        self.max_syscall_cycles_u32(),
                        &self.chunk_split_config,
                    ) =>
                {
                    self.maybe_debug_split_snapshot();
                    self.chunk_split_state.clear();
                    self.state.current_chunk += 1;
                    self.state.clk = u64::from(CHUNK_CLK_START);
                }
                ChunkBoundaryMode::ChunkSplit => {}
            }
        }

        Ok(done)
    }

    /// Emulate chunk_batch_size cycles and bump to self.batch_records.
    /// `record_callback` is used to return the EmulationRecord in function or closure.
    /// Return the emulation complete flag if success.
    #[instrument(name = "emulate_batch_records", level = "debug", skip_all)]
    pub fn emulate_batch<F>(
        &mut self,
        record_callback: &mut F,
    ) -> Result<EmulationReport, EmulationError>
    where
        F: FnMut(EmulationRecord),
    {
        self.initialize_if_needed();
        self.refresh_chunk_split_config();

        // Temporarily take out the deferred state during emulation.
        // Will set it back before finishing this function.
        // And since self cannot be invoked in a closure created by self.
        let deferred_state = Arc::clone(&self.deferred_state);
        let defer_only = self.defer_only;

        let mut estimators = self.opts.cost_estimator.then_some(Vec::new());
        let start_chunk = self.state.current_chunk;

        // create the real callback that will be used, maybe making additions
        // to the cycle estimator
        let mut real_callback = |record| {
            if let Some(ref mut estimators) = &mut estimators {
                estimators.push(EventSizeCapture::snapshot(&record, self.field).estimate());
            }
            record_callback(record)
        };

        let mut done = false;
        let mut num_chunks_emulated = 0;
        let mut current_chunk = self.state.current_chunk;
        debug!(
            "emulate - current chunk {}, batch size {}",
            current_chunk, self.opts.chunk_batch_size,
        );

        let is_snapshot_worker = self.is_snapshot_worker();
        if !is_snapshot_worker {
            self.update_mode_deps();
        }

        let mut last_record_time = Instant::now();

        let is_trace_mode = self.mode.is_recording();

        // Loop until we've emulated CHUNK_BATCH_SIZE chunks.
        loop {
            if self.emulate_cycle(
                |done, new_record| {
                    deferred_state.lock().complete_and_return_record(
                        done,
                        new_record,
                        is_trace_mode,
                        defer_only,
                        &mut real_callback,
                    );
                },
                &mut last_record_time,
            )? {
                done = true;
                break;
            }

            // A snapshot worker is done when it reaches its target. The chunk-counter test below
            // cannot see that for a middle segment, which leaves the counter where it was.
            //
            // This also takes over from that test for an unsplit worker, which used to leave the
            // loop one iteration later, through it. Nothing downstream misses the difference:
            // what the test does besides breaking is advance `num_chunks_emulated` (read only by
            // its own break condition) and re-read `current_chunk` into a local.
            if is_snapshot_worker && self.segment_complete {
                self.segment_complete = false;
                break;
            }

            if self.opts.chunk_batch_size > 0 && current_chunk != self.state.current_chunk {
                num_chunks_emulated += 1;
                current_chunk = self.state.current_chunk;

                if num_chunks_emulated == self.opts.chunk_batch_size {
                    break;
                }
            }
        }
        debug!("emulate - global clk {}", self.state.global_clk);

        let is_trace = self.mode.is_recording();
        if self.sink.holds_steps() {
            self.bump_record(done, |done, new_record| {
                deferred_state.lock().complete_and_return_record(
                    done,
                    new_record,
                    is_trace,
                    defer_only,
                    &mut real_callback,
                );
            });
        }

        if done {
            if is_trace {
                self.postprocess();

                // Push the remaining emulation record with memory initialize & finalize events.
                self.bump_record(done, |_done, mut new_record| {
                    // Unnecessary to prove this record, since it's an empty record after deferring the memory events.
                    deferred_state.lock().defer_record(&mut new_record);
                });
            }

            // output any remaining information
            self.flush();
        } else {
            self.state.current_batch += 1;
        }

        if !defer_only {
            deferred_state.lock().split_and_return_deferred_records(
                done,
                is_trace,
                &mut real_callback,
                self.state.pc,
                u32::MAX, // disable committed_batch_idx filtering (single-machine)
            );
        }

        Ok(self.generate_report(estimators, done, start_chunk))
    }

    // TODO: may remove all the deferred_events in snapshot_main mode
    #[instrument(name = "emulate_batch_snapshot_main", level = "debug", skip_all)]
    pub fn emulate_batch_snapshot_main<F>(
        &mut self,
        record_callback: &mut F,
    ) -> Result<EmulationReport, EmulationError>
    where
        F: FnMut(EmulationRecord),
    {
        self.initialize_if_needed();
        self.refresh_chunk_split_config();

        let mut estimators = self.opts.cost_estimator.then_some(Vec::new());
        let start_chunk = self.state.current_chunk;

        // create the real callback that will be used, maybe making additions
        // to the cycle estimator
        let mut real_callback = |record| {
            if let Some(ref mut estimators) = &mut estimators {
                estimators.push(EventSizeCapture::snapshot(&record, self.field).estimate());
            }
            record_callback(record)
        };

        // Temporarily take out the deferred state during emulation.
        // Will set it back before finishing this function.
        // And since self cannot be invoked in a closure created by self.
        let deferred_state = Arc::clone(&self.deferred_state);
        // TODO: just drop all precompile events
        let defer_only = true;

        let mut done = false;
        let mut num_chunks_emulated = 0;
        let mut current_chunk = self.state.current_chunk;
        debug!(
            "emulate - current chunk {}, batch size {}",
            current_chunk, self.opts.chunk_batch_size,
        );

        let mut last_record_time = Instant::now();

        // Loop until we've emulated CHUNK_BATCH_SIZE chunks.
        loop {
            if self.emulate_cycle(
                |done, new_record| {
                    deferred_state.lock().complete_and_return_record(
                        done,
                        new_record,
                        false,
                        defer_only,
                        &mut real_callback,
                    );
                },
                &mut last_record_time,
            )? {
                done = true;
                break;
            }

            if self.opts.chunk_batch_size > 0 && current_chunk != self.state.current_chunk {
                num_chunks_emulated += 1;
                current_chunk = self.state.current_chunk;

                if num_chunks_emulated == self.opts.chunk_batch_size {
                    break;
                }
            }
        }
        debug!("emulate - global clk {}", self.state.global_clk);

        if self.sink.holds_steps() {
            self.bump_record(done, |done, new_record| {
                deferred_state.lock().complete_and_return_record(
                    done,
                    new_record,
                    false,
                    defer_only,
                    &mut real_callback,
                );
            });
        }

        if done {
            self.flush();

            // we must get the real traces if cost_estimator = true
            if self.opts.cost_estimator {
                self.postprocess();

                // Push the remaining emulation record with memory initialize & finalize events.
                self.bump_record(done, |_done, mut new_record| {
                    // Unnecessary to prove this record, since it's an empty record after deferring the memory events.
                    deferred_state.lock().defer_record(&mut new_record);
                });
                if !self.defer_only {
                    deferred_state.lock().split_and_return_deferred_records(
                        done,
                        self.mode.is_recording(),
                        &mut real_callback,
                        self.state.pc,
                        u32::MAX, // disable committed_batch_idx filtering (single-machine)
                    );
                }
            }
        } else {
            self.state.current_batch += 1;
        }

        Ok(self.generate_report(estimators, done, start_chunk))
    }

    pub fn emulate_state<F>(
        &mut self,
        _emit_global_memory_events: bool,
        record_callback: &mut F,
    ) -> Result<(RiscvEmulationState, EmulationReport), EmulationError>
    // ) -> Result<(RiscvEmulationState, PublicValues<u32, u32>, bool), EmulationError>
    where
        F: FnMut(EmulationRecord),
    {
        let t_clone = Instant::now();
        self.mode = RiscvEmulatorMode::Simple;
        self.update_mode_deps();
        // TODO: add flag to choose whether emit global_memory_events in postprocess()
        // TODO: clone, then emulate_batch
        // self.emit_global_memory_events = emit_global_memory_events;

        // Fast clone: uses vec![0; size] for memory instead of copying 12GB
        let pooled = PooledSnapshot(Some(self.state.clone_without_memory()));

        debug!(
            "state clone duration: {:?}ms",
            t_clone.elapsed().as_secs_f64() * 1000.0
        );

        let t_emu_snapshot = Instant::now();
        let report = self.emulate_batch_snapshot_main(record_callback)?;
        let mut snapshot = pooled.claim();
        debug!(
            "t_emu_snapshot: {:?}ms",
            t_emu_snapshot.elapsed().as_secs_f64() * 1000.0
        );

        let t_rollback = Instant::now();

        // Use mem::take to avoid allocating a new 12GB memory
        // self.memory_snapshot will be Default (zeroed) after take
        // The reset logic is handled here as well.
        let mut mem_snap = std::mem::take(&mut self.memory_snapshot);
        let register_snapshot_bitmap = self.register_snapshot_bitmap;
        let register_snapshot = self.register_snapshot;

        // if done && !self.emit_global_memory_events {
        // trick: no need to rollback the bitmap in snapshot.memory
        if report.done {
            // Use swap instead of clone_from to avoid copying 12GB
            // After swap:
            //   - snapshot.memory = the final (live) state memory
            //   - self.state.memory = the zeroed snapshot memory (fine since done=true)
            std::mem::swap(&mut snapshot.memory, &mut self.state.memory);
            std::mem::swap(
                &mut snapshot.uninitialized_memory,
                &mut self.state.uninitialized_memory,
            );

            // Restore from snapshot: apply pre-batch values to rollback addresses.
            // Main memory is restored from memory_snapshot.
            snapshot.memory.par_restore_from(&mem_snap);

            // Recycle dirty mem_snap with reset=true
            let _ = crate::emulator::riscv::memory::GLOBAL_MEMORY_RECYCLER.send((mem_snap, true));
        } else {
            // Reconstruct partial memory from snapshot
            // snapshot.memory was zeroed from clone_without_memory().

            // Use mem_snap directly as snapshot.memory.
            // After swap:
            //   - snapshot.memory = mem_snap (The snapshot state)
            //   - mem_snap = zeroed pooled memory (to be recycled)
            std::mem::swap(&mut snapshot.memory, &mut mem_snap);

            // No restore_from call here.

            // ELSE case: mem_snap is implicitly ZEROED (it came from snapshot.memory which was new/pooled).
            // Recycle it.
            let _ = crate::emulator::riscv::memory::GLOBAL_MEMORY_RECYCLER.send((mem_snap, false));
        }
        // Restore touched registers from register snapshot.
        for reg_idx in 0..32 {
            if (register_snapshot_bitmap & (1 << reg_idx)) != 0 {
                snapshot.registers[reg_idx as usize] = register_snapshot[reg_idx as usize];
            }
        }
        self.register_snapshot_bitmap = 0;
        self.register_snapshot = [RuntimeRegisterRecord::default(); 32];

        debug!(
            "state mem rollback duration: {:?}ms",
            t_rollback.elapsed().as_secs_f64() * 1000.0
        );
        // TODO: handle public values properly (COMMIT syscall across chunks )

        Ok((snapshot, report))
    }

    #[inline]
    pub fn mr(
        &mut self,
        addr: RvAddr,
        chunk: RvChunk,
        timestamp: RvTimestamp,
        local_memory_access: Option<&mut HashMap<u64, MemoryLocalEvent>>,
    ) -> MemoryReadRecord {
        self.validate_main_memory_addr(addr);
        self.chunk_split_state.track_address(addr);
        if self.chunk_split_state.in_syscall() {
            self.chunk_split_state.add_syscall_memory_events(1);
        }

        let is_unconstrained = self.is_unconstrained();

        let (value, prev_chunk, prev_timestamp) = if is_unconstrained {
            self.state
                .memory
                .read_and_update_metadata_no_mark(addr, chunk, timestamp)
        } else {
            self.state
                .memory
                .read_and_update_metadata(addr, chunk, timestamp)
        };
        let prev_record = MemoryRecord {
            value,
            chunk: prev_chunk,
            timestamp: prev_timestamp,
        };

        self.snapshot_memory_if_needed(addr, &prev_record);
        self.mode
            .add_unconstrained_memory_record(addr, Some(&prev_record));

        let final_record = MemoryRecord {
            value,
            chunk,
            timestamp,
        };

        let local_access = local_memory_access.unwrap_or(self.sink.local_memory_access_mut());
        self.mode
            .add_memory_local_event(addr, final_record, prev_record, local_access);

        MemoryReadRecord::new(value, chunk, timestamp, prev_chunk, prev_timestamp)
    }

    /// Read a dword from memory and create an access record.
    pub fn mr_simple(
        &mut self,
        addr: RvAddr,
        chunk: RvChunk,
        timestamp: RvTimestamp,
        _local_memory_access: Option<&mut HashMap<u64, MemoryLocalEvent>>,
    ) -> MemoryReadRecord {
        self.validate_main_memory_addr(addr);
        self.chunk_split_state.track_address(addr);
        if self.chunk_split_state.in_syscall() {
            self.chunk_split_state.add_syscall_memory_events(1);
        }

        let (value, prev_chunk, prev_timestamp) = self
            .state
            .memory
            .read_and_update_metadata(addr, chunk, timestamp);
        let prev_record = MemoryRecord {
            value,
            chunk: prev_chunk,
            timestamp: prev_timestamp,
        };
        self.snapshot_memory_if_needed(addr, &prev_record);

        MemoryReadRecord::new(value, chunk, timestamp, prev_chunk, prev_timestamp)
    }

    /// Write a dword to memory and create an access record.
    #[inline]
    pub fn mw(
        &mut self,
        addr: RvAddr,
        value: RvValue,
        chunk: RvChunk,
        timestamp: RvTimestamp,
        local_memory_access: Option<&mut HashMap<u64, MemoryLocalEvent>>,
    ) -> MemoryWriteRecord {
        self.validate_main_memory_addr(addr);
        self.chunk_split_state.track_address(addr);
        if self.chunk_split_state.in_syscall() {
            self.chunk_split_state.add_syscall_memory_events(1);
        } else {
            self.chunk_split_state.add_memory_rw_events(1);
        }

        let is_unconstrained = self.is_unconstrained();

        let (prev_value, prev_chunk, prev_timestamp) = if is_unconstrained {
            self.state
                .memory
                .write_and_capture_prev_no_mark(addr, value, chunk, timestamp)
        } else {
            self.state
                .memory
                .write_and_capture_prev(addr, value, chunk, timestamp)
        };

        let prev_record = MemoryRecord {
            value: prev_value,
            chunk: prev_chunk,
            timestamp: prev_timestamp,
        };

        self.snapshot_memory_if_needed(addr, &prev_record);
        self.mode
            .add_unconstrained_memory_record(addr, Some(&prev_record));

        let final_record = MemoryRecord {
            value,
            chunk,
            timestamp,
        };

        let local_access = local_memory_access.unwrap_or(self.sink.local_memory_access_mut());
        self.mode
            .add_memory_local_event(addr, final_record, prev_record, local_access);

        MemoryWriteRecord::new(
            value,
            chunk,
            timestamp,
            prev_value,
            prev_chunk,
            prev_timestamp,
        )
    }

    /// Write a dword to memory
    pub fn mw_simple(
        &mut self,
        addr: RvAddr,
        value: RvValue,
        chunk: RvChunk,
        timestamp: RvTimestamp,
        _local_memory_access: Option<&mut HashMap<u64, MemoryLocalEvent>>,
    ) {
        self.validate_main_memory_addr(addr);
        self.chunk_split_state.track_address(addr);
        if self.chunk_split_state.in_syscall() {
            self.chunk_split_state.add_syscall_memory_events(1);
        } else {
            self.chunk_split_state.add_memory_rw_events(1);
        }

        let (prev_value, prev_chunk, prev_timestamp) = self
            .state
            .memory
            .write_and_capture_prev(addr, value, chunk, timestamp);

        let prev_record = MemoryRecord {
            value: prev_value,
            chunk: prev_chunk,
            timestamp: prev_timestamp,
        };

        self.snapshot_memory_if_needed(addr, &prev_record);
    }

    /// Read from memory, assuming that all addresses are aligned.
    #[inline]
    pub fn mr_cpu(&mut self, addr: RvAddr, position: MemoryAccessPosition) -> RvValue {
        // Read the address from memory and create a memory read record.
        let record = self.mr(addr, self.chunk(), self.timestamp(&position), None);

        // If we're not in unconstrained mode, record the access for the current cycle.
        self.mode
            .set_memory_access(position, record.into(), &mut self.sink);

        record.value
    }

    /// Read from memory, assuming that all addresses are aligned.
    pub fn mr_cpu_simple(&mut self, addr: RvAddr, position: MemoryAccessPosition) -> RvValue {
        // Read the address from memory and create a memory read record.
        // TODO: may reduce record assembly
        let record = self.mr_simple(addr, self.chunk(), self.timestamp(&position), None);

        record.value
    }

    /// Write to memory.
    ///
    /// # Panics
    ///
    /// This function will panic if the address is not aligned or if the memory accesses are already
    /// initialized.
    #[inline]
    pub fn mw_cpu(&mut self, addr: RvAddr, value: RvValue, position: MemoryAccessPosition) {
        // Read the address from memory and create a memory read record.
        let record = self.mw(addr, value, self.chunk(), self.timestamp(&position), None);

        // If we're not in unconstrained mode, record the access for the current cycle.
        self.mode
            .set_memory_access(position, record.into(), &mut self.sink);
    }

    pub fn mw_cpu_simple(&mut self, addr: RvAddr, value: RvValue, position: MemoryAccessPosition) {
        // Read the address from memory and create a memory read record.
        self.mw_simple(addr, value, self.chunk(), self.timestamp(&position), None);
    }

    /// [`Self::snapshot_memory_if_needed`] for a register; tested after the register's bit, so the
    /// snapshot thread only pays for it on a register's first touch in the batch.
    #[inline(always)]
    fn snapshot_register_if_needed(&mut self, reg_idx: u32, prev_record: &RuntimeRegisterRecord) {
        let mask = 1u32 << reg_idx;
        if (self.register_snapshot_bitmap & mask) == 0 && !self.is_snapshot_worker() {
            self.register_snapshot[reg_idx as usize] = *prev_record;
            self.register_snapshot_bitmap |= mask;
        }
    }

    /// Record a per-chunk *register* local-memory event in the sink's dense register array
    /// (addr 0..32) instead of its hashbrown map. Registers are touched ~3x/instruction, so this
    /// O(1) array update replaces the single hottest emulator cost (the hashbrown entry op).
    /// Mirrors `add_memory_local_event`'s mode gate; drained at each chunk cut.
    #[inline]
    fn add_register_local_event(
        &mut self,
        reg_idx: u32,
        final_record: MemoryRecord,
        prev_record: MemoryRecord,
    ) {
        if matches!(
            self.mode,
            RiscvEmulatorMode::Trace | RiscvEmulatorMode::Simple
        ) {
            let slot = &mut self.sink.register_local_access_mut()[reg_idx as usize];
            match slot {
                Some(ev) => ev.final_mem_access = final_record,
                None => {
                    *slot = Some(MemoryLocalEvent {
                        addr: u64::from(reg_idx),
                        initial_mem_access: prev_record,
                        final_mem_access: final_record,
                    });
                }
            }
        }
    }

    #[inline(always)]
    fn read_register_common(
        &mut self,
        reg_idx: u32,
        position: MemoryAccessPosition,
        record_memory_access: bool,
        emit_local_event: bool,
        add_unconstrained_record: bool,
    ) -> u64 {
        let chunk = self.chunk();
        let timestamp = self.timestamp(&position);
        let prev_record = self.state.registers[reg_idx as usize];
        let value = prev_record.value;
        self.state.registers[reg_idx as usize] = RuntimeRegisterRecord {
            value,
            chunk,
            timestamp,
        };

        self.snapshot_register_if_needed(reg_idx, &prev_record);
        if add_unconstrained_record {
            let reg_idx_u8 =
                u8::try_from(reg_idx).expect("register index does not fit u8 during read rollback");
            let prev_register_record = prev_record;
            self.mode
                .add_unconstrained_register_record(reg_idx_u8, Some(&prev_register_record));
        }
        if emit_local_event {
            let final_record = MemoryRecord {
                value,
                chunk,
                timestamp,
            };
            let prev_record = MemoryRecord {
                value: prev_record.value,
                chunk: prev_record.chunk,
                timestamp: prev_record.timestamp,
            };
            self.add_register_local_event(reg_idx, final_record, prev_record);
        }
        if record_memory_access {
            let final_record = MemoryRecord {
                value,
                chunk,
                timestamp,
            };
            let prev_record = MemoryRecord {
                value: prev_record.value,
                chunk: prev_record.chunk,
                timestamp: prev_record.timestamp,
            };
            let record = MemoryReadRecord::new(
                final_record.value,
                final_record.chunk,
                final_record.timestamp,
                prev_record.chunk,
                prev_record.timestamp,
            );
            self.mode
                .set_memory_access(position, record.into(), &mut self.sink);
        }
        value
    }

    #[inline(always)]
    fn write_register_common(
        &mut self,
        reg_idx: u32,
        value: u64,
        position: MemoryAccessPosition,
        record_memory_access: bool,
        emit_local_event: bool,
        add_unconstrained_record: bool,
    ) {
        self.chunk_split_state.track_address(u64::from(reg_idx));
        if !self.is_unconstrained() {
            self.chunk_split_state.add_memory_rw_events(1);
        }

        let chunk = self.chunk();
        let timestamp = self.timestamp(&position);
        let prev_record = self.state.registers[reg_idx as usize];
        self.state.registers[reg_idx as usize] = RuntimeRegisterRecord {
            value,
            chunk,
            timestamp,
        };

        self.snapshot_register_if_needed(reg_idx, &prev_record);
        if add_unconstrained_record {
            let reg_idx_u8 = u8::try_from(reg_idx)
                .expect("register index does not fit u8 during write rollback");
            let prev_register_record = prev_record;
            self.mode
                .add_unconstrained_register_record(reg_idx_u8, Some(&prev_register_record));
        }
        if emit_local_event {
            let final_record = MemoryRecord {
                value,
                chunk,
                timestamp,
            };
            let prev_record = MemoryRecord {
                value: prev_record.value,
                chunk: prev_record.chunk,
                timestamp: prev_record.timestamp,
            };
            self.add_register_local_event(reg_idx, final_record, prev_record);
        }
        if record_memory_access {
            let prev_record = MemoryRecord {
                value: prev_record.value,
                chunk: prev_record.chunk,
                timestamp: prev_record.timestamp,
            };
            let record = MemoryWriteRecord::new(
                value,
                chunk,
                timestamp,
                prev_record.value,
                prev_record.chunk,
                prev_record.timestamp,
            );
            self.mode
                .set_memory_access(position, record.into(), &mut self.sink);
        }
    }

    /// Read from a register.
    #[inline]
    pub fn rr(&mut self, register: Register, position: MemoryAccessPosition) -> RvValue {
        self.read_register_common(
            register_event_addr_u32(register),
            position,
            true,
            true,
            true,
        )
    }

    /// Write to a register.
    #[inline]
    pub fn rw(&mut self, register: Register, value: RvValue) {
        // The only time we are writing to a register is when it is in operand A.
        // Register %x0 should always be 0. See 2.6 Load and Store Instruction on
        // P.18 of the RISC-V spec. We always write 0 to %x0.
        let reg_idx = register_event_addr_u32(register);
        let value = if register == Register::X0 { 0 } else { value };
        self.write_register_common(reg_idx, value, MemoryAccessPosition::A, true, true, true);
    }

    pub fn rw_simple(&mut self, register: Register, value: RvValue) {
        // The only time we are writing to a register is when it is in operand A.
        // Register %x0 should always be 0. See 2.6 Load and Store Instruction on
        // P.18 of the RISC-V spec. We always write 0 to %x0.
        let reg_idx = register_event_addr_u32(register);
        let value = if register == Register::X0 { 0 } else { value };
        self.write_register_common(reg_idx, value, MemoryAccessPosition::A, false, false, false);
    }

    // This fn is only used for ENTER_UNCONSTRAINED syscall in simple mode
    pub fn rw_unconstrained(&mut self, register: Register, value: u64) {
        let addr = register_event_addr_u32(register);
        let chunk = self.chunk();
        let timestamp = self.timestamp(&MemoryAccessPosition::A);
        let prev = self.state.registers[addr as usize];
        self.state.registers[addr as usize] = RuntimeRegisterRecord {
            value,
            chunk,
            timestamp,
        };

        // Reconstruct previous record for snapshotting/tracking
        self.snapshot_register_if_needed(addr, &prev);

        // TODO: no conditional check here
        let prev_register_record = prev;
        self.mode.add_unconstrained_register_record(
            u8::try_from(addr).expect("register address does not fit u8 in unconstrained mode"),
            Some(&prev_register_record),
        );
    }

    /// Fetch the destination register and input operand values for an ALU instruction.
    #[inline]
    fn alu_rr_u64(&mut self, instruction: &Instruction) -> (Register, u64, u64) {
        if !instruction.imm_c {
            let (rd, rs1, rs2) = instruction.r_type();

            let c = self.rr(rs2, MemoryAccessPosition::C);
            let b = self.rr(rs1, MemoryAccessPosition::B);

            (rd, b, c)
        } else if !instruction.imm_b && instruction.imm_c {
            let (rd, rs1, imm) = instruction.i_type();
            let (rd, b, c) = (rd, self.rr(rs1, MemoryAccessPosition::B), imm);

            (rd, b, c)
        } else {
            assert!(instruction.imm_b && instruction.imm_c);
            let (rd, b, c) = (
                Register::from_u8(instruction.op_a),
                instruction.op_b,
                instruction.op_c,
            );
            (rd, b, c)
        }
    }

    /// Fetch the destination register and input operand values for an ALU instruction.
    fn alu_rr_simple_u64(&mut self, instruction: &Instruction) -> (Register, u64, u64) {
        if !instruction.imm_c {
            let (rd, rs1, rs2) = instruction.r_type();

            let c = self.rr_simple(rs2, MemoryAccessPosition::C);
            let b = self.rr_simple(rs1, MemoryAccessPosition::B);

            (rd, b, c)
        } else if !instruction.imm_b && instruction.imm_c {
            let (rd, rs1, imm) = instruction.i_type();
            let (rd, b, c) = (rd, self.rr_simple(rs1, MemoryAccessPosition::B), imm);

            (rd, b, c)
        } else {
            assert!(instruction.imm_b && instruction.imm_c);
            let (rd, b, c) = (
                Register::from_u8(instruction.op_a),
                instruction.op_b,
                instruction.op_c,
            );
            (rd, b, c)
        }
    }

    /// Fetch the destination register and input operand values for an ALU instruction.
    #[inline]
    fn alu_rr(&mut self, instruction: &Instruction) -> (Register, u64, u64) {
        self.alu_rr_u64(instruction)
    }

    /// Fetch the destination register and input operand values for an ALU instruction.
    fn alu_rr_simple(&mut self, instruction: &Instruction) -> (Register, u64, u64) {
        self.alu_rr_simple_u64(instruction)
    }

    /// Read a register.
    #[inline]
    pub fn rr_simple(&mut self, register: Register, position: MemoryAccessPosition) -> RvValue {
        self.read_register_common(
            register_event_addr_u32(register),
            position,
            false,
            false,
            false,
        )
    }

    /// Set the destination register with the result and emit an ALU event.
    #[inline]
    fn alu_rw(&mut self, rd: Register, a: u64) {
        self.rw(rd, a);
    }

    /// Set the destination register with the result and emit an ALU event.
    #[inline]
    fn alu_rw_simple(&mut self, rd: Register, a: u64) {
        self.rw_simple(rd, a);
    }

    /// Fetch the input operand values for a load instruction.
    #[inline]
    fn load_rr(&mut self, instruction: &Instruction) -> (Register, u64, u64, u64, u64) {
        let (rd, rs1, imm) = instruction.i_type();
        let (b, c) = (self.rr(rs1, MemoryAccessPosition::B), imm);
        let addr = b.wrapping_add(c);
        let memory_value = self.mr_cpu(align_u64(addr), MemoryAccessPosition::Memory);
        (rd, b, c, addr, memory_value)
    }

    /// Fetch the input operand values for a load instruction.
    fn load_rr_simple(&mut self, instruction: &Instruction) -> (Register, u64, u64, u64, u64) {
        let (rd, rs1, imm) = instruction.i_type();
        let (b, c) = (self.rr_simple(rs1, MemoryAccessPosition::B), imm);
        let addr = b.wrapping_add(c);
        let memory_value = self.mr_cpu_simple(align_u64(addr), MemoryAccessPosition::Memory);
        (rd, b, c, addr, memory_value)
    }

    /// Fetch the input operand values for a store instruction.
    /// Returns (a, b, c, addr, existing_dword) where existing_dword is the current 8-byte value.
    #[inline]
    fn store_rr(&mut self, instruction: &Instruction) -> (u64, u64, u64, u64, u64) {
        let (rs1, rs2, imm) = instruction.s_type();
        let c = imm;
        let b = self.rr(rs2, MemoryAccessPosition::B);
        let a = self.rr(rs1, MemoryAccessPosition::A);
        let addr = b.wrapping_add(c);
        let memory_value = self.dword(align_u64(addr));
        (a, b, c, addr, memory_value)
    }

    /// Fetch the input operand values for a store instruction.
    fn store_rr_simple(&mut self, instruction: &Instruction) -> (u64, u64, u64, u64, u64) {
        let (rs1, rs2, imm) = instruction.s_type();
        let c = imm;
        let b = self.rr_simple(rs2, MemoryAccessPosition::B);
        let a = self.rr_simple(rs1, MemoryAccessPosition::A);
        let addr = b.wrapping_add(c);
        let memory_value = self.dword(align_u64(addr));
        (a, b, c, addr, memory_value)
    }

    /// Fetch the input operand values for a branch instruction.
    #[inline]
    fn branch_rr(&mut self, instruction: &Instruction) -> (u64, u64, u64) {
        let (rs1, rs2, imm) = instruction.b_type();
        let c = imm;
        let b = self.rr(rs2, MemoryAccessPosition::B);
        let a = self.rr(rs1, MemoryAccessPosition::A);
        (a, b, c)
    }

    /// Fetch the input operand values for a branch instruction.
    fn branch_rr_simple(&mut self, instruction: &Instruction) -> (u64, u64, u64) {
        let (rs1, rs2, imm) = instruction.b_type();
        let c = imm;
        let b = self.rr_simple(rs2, MemoryAccessPosition::B);
        let a = self.rr_simple(rs1, MemoryAccessPosition::A);
        (a, b, c)
    }

    /// Recover emulator state from a program and existing emulation state for replay.
    #[must_use]
    pub fn recover<F>(
        program: Arc<Program>,
        state: RiscvEmulationState,
        opts: EmulatorOpts,
        shared_ds: SharedDeferredState,
        target_global_clk: u64,
        final_segment: bool,
    ) -> Self
    where
        F: PrimeField32 + FieldSpecificPoseidon2Config,
    {
        // Pass the recovered state straight into construction so the snapshot-worker emulator
        // is not built with a throwaway `RiscvEmulationState::new` (a ~5GB mmap + ~31 MB bitmap
        // zeroing) that the previous `runtime.state = state` would immediately overwrite.
        let mut runtime = Self::new_snapshot_worker::<F>(program, opts, shared_ds, Some(state));
        runtime.target_global_clk = Some(target_global_clk);
        runtime.final_segment = final_segment;
        runtime.sink = Sink::History(HistorySink::new(EmulationRecord::new(
            runtime.program.clone(),
        )));
        runtime
    }

    /// Recover snapshot worker state in place without reallocating the emulator shell. Returns
    /// the previous state's memory, which only the caller knows whether to give back to the pool.
    ///
    /// Every field a replay mutates must be reset here; [`Self::new`] is the reference. The
    /// snapshot tracker, `memory_snapshot` and `register_snapshot`, needs nothing: a worker never
    /// writes it ([`Self::snapshot_memory_if_needed`]), so it stays as [`Self::new`] built it.
    #[must_use]
    pub fn recover_in_place(
        &mut self,
        state: RiscvEmulationState,
        shared_ds: SharedDeferredState,
        target_global_clk: u64,
        final_segment: bool,
    ) -> ContiguousRiscvMemory {
        let previous = std::mem::replace(&mut self.state, state).memory;

        self.deferred_state = shared_ds;
        self.target_global_clk = Some(target_global_clk);
        self.final_segment = final_segment;
        // Still raised by a replay whose target was the program's last cycle.
        self.segment_complete = false;
        self.mode = RiscvEmulatorMode::Trace;
        self.update_mode_deps();
        self.chunk_start_pc = self.state.pc;

        self.sink.restart(self.program.clone());
        self.stdout.clear();
        self.stderr.clear();
        self.cycle_tracker.clear();
        self.cycle_tracker_requests.clear();
        // host-opt cycle host-2026-06-10-005: reset the chunk-split tracker in place via its
        // existing cheap clear() (madvise MADV_DONTNEED on the retained ~30 MB mmap + scalar
        // reset) instead of `= Default::default()`, which dropped (munmap) and re-mapped the
        // whole anonymous mapping every batch on all 12 workers. clear() resets all scalars
        // (incl. syscall_depth) and the bitset, so it is identical to Default for a fresh
        // batch; it is already the per-chunk-split reset used inside emulate().
        self.chunk_split_state.clear();
        previous
    }

    /// Get the current values of the registers.
    #[allow(clippy::single_match_else)]
    #[must_use]
    pub fn registers(&mut self) -> [RvValue; 32] {
        let mut registers = [0; 32];
        for i in 0..32 {
            let addr = register_event_addr_u32(Register::from_u8(i as u8));
            let record = self.state.registers[addr as usize];
            self.snapshot_register_if_needed(addr, &record);
            registers[i] = record.value;
        }
        registers
    }

    /// Get the current value of a register.
    #[must_use]
    pub fn register(&mut self, register: Register) -> RvValue {
        let addr = register_event_addr_u32(register);
        let record = self.state.registers[addr as usize];
        self.snapshot_register_if_needed(addr, &record);
        record.value
    }

    /// Get the current value of a dword (8 bytes) at an 8-byte-aligned address.
    #[must_use]
    pub fn dword(&mut self, addr: RvAddr) -> RvValue {
        self.validate_main_memory_addr(addr);

        let value = self.state.memory.peek_dword(addr);
        let (chunk, timestamp) = self.state.memory.peek_metadata(addr);
        let record = MemoryRecord {
            value,
            chunk,
            timestamp,
        };
        self.snapshot_memory_if_needed(addr, &record);
        record.value
    }

    /// Get the current value of a word (4 bytes). Returns as u64 with upper 32 bits zero.
    /// Kept for compatibility — internally reads the containing dword and extracts the half.
    #[must_use]
    pub fn word(&mut self, addr: RvAddr) -> RvValue {
        let dword = self.dword(align_u64(addr));
        let half = util::dword_half(addr);
        if half == 0 {
            dword & 0xFFFF_FFFF
        } else {
            dword >> 32
        }
    }

    #[inline(always)]
    fn validate_main_memory_addr(&self, addr: RvAddr) {
        assert!(
            addr >= MIN_MAIN_MEMORY_ADDR,
            "memory access below floor 0x{MIN_MAIN_MEMORY_ADDR:08x}: 0x{addr:08x}"
        );
    }

    /// Bump the record.
    pub fn bump_record<F>(&mut self, emulation_done: bool, record_callback: F)
    where
        F: FnOnce(bool, EmulationRecord),
    {
        assert!(
            !self.is_unconstrained(),
            "a chunk is cut inside an unconstrained block"
        );
        // Every cut follows a completed instruction, which leaves the pc at its next pc.
        let boundary = ChunkBoundary {
            start_pc: self.chunk_start_pc,
            next_pc: self.state.pc,
        };
        // Only a Trace-mode chunk has every step of its span written. A Simple-mode record can
        // still hold the one an unconstrained block's closing ecall writes, which is neither end.
        if matches!(self.mode, RiscvEmulatorMode::Trace) {
            if let Some(written) = self.sink.written_boundary() {
                assert_eq!(
                    written, boundary,
                    "the chunk boundary disagrees with the first and last step the sink wrote"
                );
            }
        }
        let removed_record = self.sink.cut_chunk(self.program.clone(), boundary);
        self.chunk_start_pc = self.state.pc;

        // Return the record.
        record_callback(emulation_done, removed_record);
    }

    fn postprocess(&mut self) {
        let state = &self.state;
        postprocess(
            FinalState {
                registers: &state.registers,
                uninitialized_memory: &state.uninitialized_memory,
                memory: &state.memory,
                input_stream_ptr: state.input_stream_ptr,
                input_stream_len: state.input_stream.len(),
            },
            self.sink.record_mut(),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::{
        encode_public_value_pc_limbs, DeferredChunkPc, EmulationDeferredState, EmulationRecord,
        ParkingMutex, Program, RiscvEmulationState, RiscvEmulator, CHUNK_CLK_START,
    };
    use crate::{
        compiler::{
            addr::Pc,
            riscv::{
                compiler::{Compiler, SourceType},
                instruction::Instruction,
                opcode::Opcode,
                register::Register,
            },
        },
        configs::stark_config::KoalaBearPoseidon2,
        emulator::{
            opts::EmulatorOpts,
            riscv::{
                emulator::UnconstrainedState,
                history::ExecutionHistory,
                public_values::RecordFinalPvsState,
                sink::{ChunkBoundary, CountingSink, ExecutionSink, HistorySink, Sink},
                state::RuntimeRegisterRecord,
                syscalls::SyscallCode,
            },
            stdin::EmulatorStdin,
        },
    };
    use alloc::sync::Arc;
    use p3_koala_bear::KoalaBear;
    use std::{collections::BTreeMap, time::Instant};

    #[allow(dead_code)]
    const FIBONACCI_ELF: &[u8] =
        include_bytes!("../../../compiler/test_elf/riscv32im-pico-fibonacci-elf");

    #[allow(dead_code)]
    const KECCAK_ELF: &[u8] =
        include_bytes!("../../../compiler/test_elf/riscv32im-pico-keccak-elf");

    pub fn simple_fibo_program() -> Arc<Program> {
        let compiler =
            Compiler::new(SourceType::RISCV, FIBONACCI_ELF).expect("failed to parse FIBONACCI_ELF");

        compiler.compile()
    }

    pub fn simple_keccak_program() -> Arc<Program> {
        let compiler =
            Compiler::new(SourceType::RISCV, KECCAK_ELF).expect("failed to parse KECCAK_ELF");

        compiler.compile()
    }

    fn take_history(emulator: &mut RiscvEmulator) -> ExecutionHistory {
        emulator
            .sink
            .cut_chunk(
                emulator.program.clone(),
                ChunkBoundary {
                    start_pc: emulator.chunk_start_pc,
                    next_pc: emulator.state.pc,
                },
            )
            .history
            .expect("a CPU chunk's history")
    }

    fn tiny_program() -> Arc<Program> {
        let mut program = Program::new(
            vec![
                Instruction::new(Opcode::ADD, 1, 0, 0, false, false),
                Instruction::new(Opcode::ADD, 2, 0, 0, false, false),
            ],
            0x1000,
            0x1000,
        );
        program.memory_image = Arc::new(BTreeMap::new());
        Arc::new(program)
    }

    const MAX_FIBONACCI_NUM_IN_ONE_CHUNK: u32 = 836789u32;

    #[test]
    #[should_panic(expected = "the sink's record is for another program")]
    fn with_sink_refuses_a_record_for_another_program() {
        let emulator = RiscvEmulator::new_single::<KoalaBear>(
            tiny_program(),
            Arc::new(RecordFinalPvsState::default()),
            EmulatorOpts::default(),
        );
        let _ = emulator.with_sink(Sink::Counting(
            CountingSink::new(EmulationRecord::default()),
        ));
    }

    #[test]
    #[should_panic(expected = "the emulator has already run")]
    fn with_sink_refuses_an_emulator_that_has_run() {
        let program = tiny_program();
        let mut emulator = RiscvEmulator::new_single::<KoalaBear>(
            program.clone(),
            Arc::new(RecordFinalPvsState::default()),
            EmulatorOpts::default(),
        );
        emulator.initialize_if_needed();
        emulator.refresh_chunk_split_config();
        emulator
            .emulate_cycle(|_, _| {}, &mut Instant::now())
            .expect("emulate_cycle failed");
        let _ = emulator.with_sink(Sink::Counting(CountingSink::new(EmulationRecord::new(
            program,
        ))));
    }

    /// Only the segment that ends the chunk may close it. A middle one that advanced the chunk
    /// counter and reset `clk` would restart the chunk-local clock inside the chunk, and every
    /// event after the seam would carry the wrong one — which a whole-run proof does not catch,
    /// because each segment replays from its own snapshot and never sees the others' state.
    #[test]
    fn only_the_final_segment_closes_the_chunk() {
        let opts = EmulatorOpts {
            chunk_size: 4,
            chunk_batch_size: 1,
            max_cycles: Some(32),
            ..EmulatorOpts::default()
        };
        let mut middle = RiscvEmulator::new_single::<KoalaBear>(
            tiny_program(),
            Arc::new(RecordFinalPvsState::default()),
            opts,
        );
        middle.initialize_if_needed();
        middle.final_segment = false;
        middle.target_global_clk = Some(middle.state.global_clk + 1);
        let chunk_before = middle.state.current_chunk;
        middle
            .emulate_cycle(|_, _| {}, &mut Instant::now())
            .expect("emulate_cycle failed");
        assert_eq!(
            middle.state.current_chunk, chunk_before,
            "a middle segment leaves the chunk running"
        );

        let mut last = RiscvEmulator::new_single::<KoalaBear>(
            tiny_program(),
            Arc::new(RecordFinalPvsState::default()),
            opts,
        );
        last.initialize_if_needed();
        last.target_global_clk = Some(last.state.global_clk + 1);
        let chunk_before = last.state.current_chunk;
        last.emulate_cycle(|_, _| {}, &mut Instant::now())
            .expect("emulate_cycle failed");
        assert_eq!(
            last.state.current_chunk,
            chunk_before + 1,
            "the segment that ends the chunk closes it"
        );
        assert_eq!(last.state.clk, u64::from(CHUNK_CLK_START));
    }

    #[test]
    fn cycle_only_chunk_rollover_exact_fit_in_baseline() {
        let opts = EmulatorOpts {
            chunk_size: 4,
            chunk_batch_size: 1,
            max_cycles: Some(32),
            ..EmulatorOpts::default()
        };
        let mut emulator = RiscvEmulator::new_single::<KoalaBear>(
            tiny_program(),
            Arc::new(RecordFinalPvsState::default()),
            opts,
        );
        emulator.initialize_if_needed();
        emulator.state.clk = 12;
        emulator.max_syscall_cycles = 4;

        emulator.refresh_chunk_split_config();

        let done = emulator
            .emulate_cycle(|_, _| {}, &mut Instant::now())
            .expect("emulate_cycle failed");

        assert!(!done);
        assert_eq!(emulator.state.current_chunk, 2);
        assert_eq!(emulator.state.clk, u64::from(CHUNK_CLK_START));
    }

    #[test]
    fn cycle_only_chunk_rollover_stays_suppressed_in_unconstrained_mode() {
        let opts = EmulatorOpts {
            chunk_size: 4,
            chunk_batch_size: 1,
            max_cycles: Some(32),
            ..EmulatorOpts::default()
        };
        let mut emulator = RiscvEmulator::new_single::<KoalaBear>(
            tiny_program(),
            Arc::new(RecordFinalPvsState::default()),
            opts,
        );
        emulator.initialize_if_needed();
        emulator.state.clk = 12;
        emulator.max_syscall_cycles = 4;
        emulator.mode = super::RiscvEmulatorMode::Simple;
        emulator.update_mode_deps();
        emulator.mode =
            super::RiscvEmulatorMode::Unconstrained(UnconstrainedState::new(&mut emulator));

        emulator.refresh_chunk_split_config();

        let done = emulator
            .emulate_cycle(|_, _| {}, &mut Instant::now())
            .expect("emulate_cycle failed");

        assert!(!done);
        assert_eq!(emulator.state.current_chunk, 1);
        assert_eq!(emulator.state.clk, 16);
    }

    #[test]
    fn snapshot_worker_stops_at_target_global_clk_before_cycle_rollover() {
        let opts = EmulatorOpts {
            chunk_size: 16,
            chunk_batch_size: 1,
            max_cycles: Some(64),
            ..EmulatorOpts::default()
        };
        let mut emulator = RiscvEmulator::new_single::<KoalaBear>(
            tiny_program(),
            Arc::new(RecordFinalPvsState::default()),
            opts,
        );
        emulator.target_global_clk = Some(1);

        let mut records = 0usize;
        let report = emulator
            .emulate_batch(&mut |_| {
                records += 1;
            })
            .expect("snapshot worker batch should stop at target_global_clk");

        assert!(!report.done);
        assert_eq!(report.current_cycle, 1);
        assert_eq!(emulator.state.global_clk, 1);
        assert_eq!(emulator.state.current_chunk, 2);
        assert_eq!(emulator.state.clk, u64::from(CHUNK_CLK_START));
        assert_eq!(emulator.state.pc, 0x1004);
        assert_eq!(records, 1);
    }

    #[test]
    fn snapshot_worker_replay_ignores_event_split_when_target_global_clk_is_set() {
        let opts = EmulatorOpts {
            chunk_size: 16,
            chunk_batch_size: 1,
            max_cycles: Some(64),
            ..EmulatorOpts::default()
        };
        let mut emulator = RiscvEmulator::new_single::<KoalaBear>(
            tiny_program(),
            Arc::new(RecordFinalPvsState::default()),
            opts,
        );
        emulator.target_global_clk = Some(2);
        emulator.chunk_split_state.num_memory_read_write_events = 8;
        emulator.chunk_split_state.num_global_lookup_base = 5;

        let mut records = 0usize;
        let report = emulator
            .emulate_batch(&mut |_| {
                records += 1;
            })
            .expect("snapshot replay batch should stop at target_global_clk");

        assert!(report.done);
        assert_eq!(report.current_cycle, 2);
        assert_eq!(emulator.state.global_clk, 2);
        assert_eq!(emulator.state.current_chunk, 2);
        assert_eq!(emulator.state.clk, u64::from(CHUNK_CLK_START));
        assert_eq!(emulator.state.pc, 0x1008);
        assert!(records >= 1);
    }

    #[test]
    fn interpreter_splits_on_event_threshold_in_boundary_authoritative_mode() {
        let opts = EmulatorOpts {
            chunk_size: 16,
            chunk_batch_size: 1,
            max_cycles: Some(64),
            ..EmulatorOpts::default()
        };
        let mut emulator = RiscvEmulator::new_single::<KoalaBear>(
            tiny_program(),
            Arc::new(RecordFinalPvsState::default()),
            opts,
        );
        emulator.chunk_split_state.num_memory_read_write_events = 7;
        emulator.chunk_split_state.num_global_lookup_base = 5;

        let mut records = 0usize;
        let report = emulator
            .emulate_batch(&mut |_| {
                records += 1;
            })
            .expect("event-heavy batch should split");

        assert!(!report.done);
        assert_eq!(report.current_cycle, 1);
        assert_eq!(emulator.state.global_clk, 1);
        assert_eq!(emulator.state.current_chunk, 2);
        assert_eq!(emulator.state.clk, u64::from(CHUNK_CLK_START));
        assert_eq!(emulator.state.pc, 0x1004);
        assert_eq!(records, 1);
        assert_eq!(emulator.chunk_split_state.num_memory_read_write_events, 0);
        assert_eq!(emulator.chunk_split_state.num_global_lookup_base, 0);
    }

    fn jal(rd: Register, imm: i64) -> Instruction {
        Instruction::new(Opcode::JAL, rd as u8, imm as u64, 0, true, true)
    }

    fn beq(rs1: Register, rs2: Register, imm: i64) -> Instruction {
        Instruction::new(Opcode::BEQ, rs1 as u8, rs2 as u64, imm as u64, false, true)
    }

    fn ecall() -> Instruction {
        Instruction::new(
            Opcode::ECALL,
            Register::X5 as u8,
            Register::X10 as u64,
            Register::X11 as u64,
            false,
            false,
        )
    }

    /// A loop whose chunks start and end at different pcs, one of them after a taken branch.
    fn looping_program() -> Arc<Program> {
        Arc::new(Program::new(
            vec![
                i_type(Opcode::ADD, Register::X1, Register::X0, 1), // 0x1000
                beq(Register::X0, Register::X0, 8),                 // 0x1004 -> 0x100c
                i_type(Opcode::ADD, Register::X2, Register::X0, 2), // 0x1008, skipped
                i_type(Opcode::ADD, Register::X3, Register::X0, 3), // 0x100c
                jal(Register::X0, -16),                             // 0x1010 -> 0x1000
            ],
            0x1000,
            0x1000,
        ))
    }

    fn replay_opts() -> EmulatorOpts {
        EmulatorOpts {
            chunk_size: 16,
            chunk_batch_size: 1,
            max_cycles: Some(1000),
            ..EmulatorOpts::default()
        }
    }

    /// Runs until the next chunk is cut, and returns it as the cut left it: the callback sees the
    /// record before the deferred state stamps its public values.
    fn run_to_cut(emulator: &mut RiscvEmulator) -> EmulationRecord {
        let mut cut = None;
        while cut.is_none() {
            emulator
                .emulate_cycle(|_, record| cut = Some(record), &mut Instant::now())
                .expect("emulate_cycle failed");
        }
        cut.unwrap()
    }

    fn assert_stamped(record: &EmulationRecord, start_pc: u64, next_pc: u64) {
        let pvs = &record.public_values;
        assert_eq!(
            pvs.start_pc,
            encode_public_value_pc_limbs(start_pc),
            "start_pc"
        );
        assert_eq!(
            pvs.next_pc,
            encode_public_value_pc_limbs(next_pc),
            "next_pc"
        );
        assert_eq!(pvs.exit_code, 0, "exit_code");
    }

    /// Cuts the loop after global clocks 3, 6 and 8: a chunk that opens on a taken branch's
    /// target, one that ends on a taken branch, and one that ends on a jump.
    fn assert_chunks_carry_their_pcs(mode: super::RiscvEmulatorMode) {
        let mut emulator = RiscvEmulator::new_single::<KoalaBear>(
            looping_program(),
            Arc::new(RecordFinalPvsState::default()),
            replay_opts(),
        );
        emulator.initialize_if_needed();
        emulator.mode = mode;
        emulator.update_mode_deps();

        for (target, start_pc, next_pc) in [
            (3, 0x1000, 0x1010),
            (6, 0x1010, 0x100c),
            (8, 0x100c, 0x1000),
        ] {
            emulator.target_global_clk = Some(target);
            let record = run_to_cut(&mut emulator);
            assert_stamped(&record, start_pc, next_pc);
            let steps = record.cpu_steps();
            if let Some(last) = steps.len().checked_sub(1) {
                assert_eq!(
                    (steps.get(0).pc, steps.get(last).next_pc),
                    (start_pc, next_pc)
                );
            }
        }
    }

    #[test]
    fn a_trace_chunk_is_stamped_with_its_first_pc_and_its_last_next_pc() {
        assert_chunks_carry_their_pcs(super::RiscvEmulatorMode::Trace);
    }

    #[test]
    fn a_simple_chunk_is_stamped_with_the_same_pcs() {
        assert_chunks_carry_their_pcs(super::RiscvEmulatorMode::Simple);
    }

    /// The loop, tracing into a history alone, set to cut its first chunk after global clock 3.
    fn history_only_emulator() -> RiscvEmulator {
        let program = looping_program();
        let mut emulator = RiscvEmulator::new_single::<KoalaBear>(
            program.clone(),
            Arc::new(RecordFinalPvsState::default()),
            replay_opts(),
        )
        .with_sink(Sink::History(HistorySink::new(EmulationRecord::new(
            program,
        ))));
        emulator.initialize_if_needed();
        emulator.mode = super::RiscvEmulatorMode::Trace;
        emulator.update_mode_deps();
        emulator.target_global_clk = Some(3);
        emulator
    }

    /// The cut's boundary is checked against the history's steps.
    #[test]
    fn a_history_only_chunk_is_cut_at_its_first_pc_and_its_last_next_pc() {
        let record = run_to_cut(&mut history_only_emulator());
        assert_stamped(&record, 0x1000, 0x1010);
        let steps = &record.history.as_ref().expect("a history").steps;
        let (first, last) = (steps.first().unwrap(), steps.last().unwrap());
        assert_eq!((first.pc, last.next_pc), (0x1000, 0x1010));
    }

    #[test]
    #[should_panic(expected = "the chunk boundary disagrees with the first and last step")]
    fn a_history_only_chunk_cut_at_a_wrong_start_pc_panics() {
        let mut emulator = history_only_emulator();
        emulator.chunk_start_pc = 0x1004;
        run_to_cut(&mut emulator);
    }

    /// A replay that resumes inside a chunk never executes the instruction at the chunk clock's
    /// origin, so its start can only come from the state it was recovered from.
    #[test]
    fn a_replay_resumed_mid_chunk_starts_at_the_recovered_pc() {
        let program = looping_program();
        let mut state = RiscvEmulationState::new(0x1004);
        state.global_clk = 5;
        state.clk = u64::from(CHUNK_CLK_START) + 20;
        let shared_ds = Arc::new(ParkingMutex::new(EmulationDeferredState::new(
            program.clone(),
            Arc::new(RecordFinalPvsState::default()),
        )));
        let mut emulator =
            RiscvEmulator::recover::<KoalaBear>(program, state, replay_opts(), shared_ds, 6, false);

        let record = run_to_cut(&mut emulator);

        assert_stamped(&record, 0x1004, 0x100c);
        assert_eq!(record.cpu_steps().len(), 1);
    }

    /// A block entered at 0x1004 whose jump lands at 0x1018; the run resumes at 0x1008.
    fn unconstrained_program() -> Arc<Program> {
        Arc::new(Program::new(
            vec![
                i_type(
                    Opcode::ADD,
                    Register::X5,
                    Register::X0,
                    SyscallCode::ENTER_UNCONSTRAINED as i32,
                ), // 0x1000
                ecall(), // 0x1004, enters; resumes here after the exit
                beq(Register::X5, Register::X0, 0x18), // 0x1008, taken once the block has run
                jal(Register::X0, 0xc), // 0x100c, in the block -> 0x1018
                i_type(Opcode::ADD, Register::X0, Register::X0, 0), // 0x1010
                i_type(Opcode::ADD, Register::X0, Register::X0, 0), // 0x1014
                i_type(
                    Opcode::ADD,
                    Register::X5,
                    Register::X0,
                    SyscallCode::EXIT_UNCONSTRAINED as i32,
                ), // 0x1018
                ecall(), // 0x101c, exits
                i_type(Opcode::ADD, Register::X6, Register::X0, 6), // 0x1020
            ],
            0x1000,
            0x1000,
        ))
    }

    /// An unconstrained block executes instructions whose events are thrown away, and the closing
    /// ecall puts the pc back at the opening one. What the chunk ends at is that ecall's next pc,
    /// and the block's own jump must not be what the cut finds.
    #[test]
    fn an_unconstrained_block_leaves_the_pcs_of_the_ecall_that_closes_it() {
        let mut emulator = RiscvEmulator::new_single::<KoalaBear>(
            unconstrained_program(),
            Arc::new(RecordFinalPvsState::default()),
            replay_opts(),
        );
        emulator.initialize_if_needed();

        emulator.target_global_clk = Some(1);
        let before = run_to_cut(&mut emulator);
        assert_stamped(&before, 0x1000, 0x1004);

        // The block's clocks are rolled back when it closes, so this chunk ends at clock 2, and
        // opens on the ecall that enters the block.
        emulator.target_global_clk = Some(2);
        let block = run_to_cut(&mut emulator);
        assert_stamped(&block, 0x1004, 0x1008);
        let steps = block.cpu_steps();
        assert_eq!(steps.len(), 1);
        assert_eq!((steps.get(0).pc, steps.get(0).next_pc), (0x1004, 0x1008));
    }

    /// In Simple mode the closing ecall still writes its CPU event, so the record holds one event
    /// that is neither the chunk's first instruction nor a trace of it. The cut and the reader
    /// take the boundary, not that event.
    #[test]
    fn a_simple_chunk_holding_an_unconstrained_block_goes_through_the_reader() {
        let program = unconstrained_program();
        let mut emulator = RiscvEmulator::new_single::<KoalaBear>(
            program.clone(),
            Arc::new(RecordFinalPvsState::default()),
            replay_opts(),
        );
        emulator.initialize_if_needed();
        emulator.mode = super::RiscvEmulatorMode::Simple;
        emulator.update_mode_deps();
        let mut deferred =
            EmulationDeferredState::new(program, Arc::new(RecordFinalPvsState::default()));

        emulator.target_global_clk = Some(2);
        let mut record = run_to_cut(&mut emulator);
        deferred.update_public_values(false, &mut record, DeferredChunkPc::LastCpuChunk);

        assert_stamped(&record, 0x1000, 0x1008);
    }

    /// A chunk replayed in two segments folds to the chunk the unsplit replay cuts: the start
    /// from the middle segment, which never reaches the chunk clock's origin, and the end from the
    /// final one.
    #[test]
    fn a_chunk_replayed_in_segments_folds_to_the_unsplit_boundary() {
        let program = looping_program();
        let mut resumed_at = RiscvEmulationState::new(0x1004);
        resumed_at.global_clk = 5;
        resumed_at.clk = u64::from(CHUNK_CLK_START) + 20;
        let replay = |state: RiscvEmulationState, target: u64, final_segment: bool| {
            let shared_ds = Arc::new(ParkingMutex::new(EmulationDeferredState::new(
                program.clone(),
                Arc::new(RecordFinalPvsState::default()),
            )));
            RiscvEmulator::recover::<KoalaBear>(
                program.clone(),
                state,
                replay_opts(),
                shared_ds,
                target,
                final_segment,
            )
        };

        let unsplit = run_to_cut(&mut replay(resumed_at.clone(), 8, true));

        let mut middle = replay(resumed_at, 6, false);
        let head = run_to_cut(&mut middle);
        assert_stamped(&head, 0x1004, 0x100c);
        let tail = run_to_cut(&mut replay(middle.state.clone(), 8, true));
        assert_stamped(&tail, 0x100c, 0x1000);
        let merged = crate::emulator::riscv::record_merge::merge_segments(vec![head, tail]);

        assert_stamped(&unsplit, 0x1004, 0x1000);
        assert_eq!(
            merged.public_values.start_pc,
            unsplit.public_values.start_pc
        );
        assert_eq!(merged.public_values.next_pc, unsplit.public_values.next_pc);
        assert_eq!(
            merged.public_values.exit_code,
            unsplit.public_values.exit_code
        );
        let pcs = |record: &EmulationRecord| -> Vec<(u64, u64)> {
            record
                .cpu_steps()
                .iter()
                .map(|event| (event.pc, event.next_pc))
                .collect()
        };
        assert_eq!(pcs(&merged), pcs(&unsplit));
    }

    /// Commits one digest word, then adds, with nothing after: a replay can end on the program's
    /// last cycle, holding a record whose public values carry the word.
    fn committing_program() -> Arc<Program> {
        Arc::new(Program::new(
            vec![
                i_type(
                    Opcode::ADD,
                    Register::X5,
                    Register::X0,
                    SyscallCode::COMMIT as i32,
                ), // 0x1000
                i_type(Opcode::ADD, Register::X10, Register::X0, 0), // 0x1004, the word's index
                i_type(Opcode::ADD, Register::X11, Register::X0, 7), // 0x1008, its value
                ecall(),                                             // 0x100c
                i_type(Opcode::ADD, Register::X6, Register::X6, 1),  // 0x1010
                i_type(Opcode::ADD, Register::X6, Register::X6, 2),  // 0x1014
                i_type(Opcode::ADD, Register::X6, Register::X6, 3),  // 0x1018
                i_type(Opcode::ADD, Register::X6, Register::X6, 4),  // 0x101c
            ],
            0x1000,
            0x1000,
        ))
    }

    /// A worker recovered in place replays a segment as a freshly recovered one does, after a
    /// replay that ended the program. That replay leaves `segment_complete` raised, which would
    /// stop a middle segment after its first instruction, and leaves the open record holding the
    /// committed word, which the next segment's record would carry.
    #[test]
    fn an_emulator_recovered_in_place_replays_as_a_fresh_one_does() {
        let program = committing_program();
        let shared_ds = || {
            Arc::new(ParkingMutex::new(EmulationDeferredState::new(
                program.clone(),
                Arc::new(RecordFinalPvsState::default()),
            )))
        };
        let replay = |emulator: &mut RiscvEmulator| {
            let mut records = Vec::new();
            emulator
                .emulate_batch(&mut |record| records.push(record))
                .expect("the replay runs");
            records
                .iter()
                .map(crate::emulator::riscv::record_digest::field_digests)
                .collect::<Vec<_>>()
        };
        let middle = || {
            let mut state = RiscvEmulationState::new(0x1010);
            state.global_clk = 4;
            state.clk = u64::from(CHUNK_CLK_START) + 16;
            state
        };

        let mut reused = RiscvEmulator::recover::<KoalaBear>(
            program.clone(),
            RiscvEmulationState::new(0x1000),
            replay_opts(),
            shared_ds(),
            8,
            true,
        );
        replay(&mut reused);
        assert!(
            reused.segment_complete,
            "a replay to the program's end no longer leaves the flag raised"
        );
        assert_eq!(
            reused.sink.record().public_values.committed_value_digest[0],
            7,
            "the open record no longer carries the committed word"
        );
        drop(reused.recover_in_place(middle(), shared_ds(), 7, false));
        let mut fresh = RiscvEmulator::recover::<KoalaBear>(
            program.clone(),
            middle(),
            replay_opts(),
            shared_ds(),
            7,
            false,
        );

        let (reused_records, fresh_records) = (replay(&mut reused), replay(&mut fresh));
        assert_eq!(reused.state.global_clk, fresh.state.global_clk);
        assert_eq!(reused_records, fresh_records);
    }

    /// Stores a dword at 0x200 and loads it back, then runs off the program's end.
    fn storing_program() -> Arc<Program> {
        Arc::new(Program::new(
            vec![
                i_type(Opcode::ADD, Register::X1, Register::X0, 0x200), // 0x1000
                s_type(Opcode::SD, Register::X1, Register::X1, 0),      // 0x1004
                i_type(Opcode::LD, Register::X2, Register::X1, 0),      // 0x1008
            ],
            0x1000,
            0x1000,
        ))
    }

    /// Only the snapshot thread reads the snapshot tracker. A worker is re-armed for batch after
    /// batch and never clears it, so one that wrote it would come to hold every page the run
    /// touched. The same run outside a worker shows the program touches what the tracker holds.
    #[test]
    fn a_replay_worker_leaves_its_snapshot_tracker_untouched() {
        let program = storing_program();
        let shared_ds = || {
            Arc::new(ParkingMutex::new(EmulationDeferredState::new(
                program.clone(),
                Arc::new(RecordFinalPvsState::default()),
            )))
        };
        let tracked = |emulator: &RiscvEmulator| {
            (
                emulator.memory_snapshot.accessed_keys().collect::<Vec<_>>(),
                emulator.register_snapshot_bitmap,
            )
        };

        let mut serial = RiscvEmulator::new_single::<KoalaBear>(
            program.clone(),
            Arc::new(RecordFinalPvsState::default()),
            replay_opts(),
        );
        serial.emulate_batch(&mut |_| {}).expect("the run");
        let (addrs, registers) = tracked(&serial);
        assert_eq!(addrs, [0x200]);
        assert_ne!(registers, 0);

        let mut worker = RiscvEmulator::recover::<KoalaBear>(
            program.clone(),
            RiscvEmulationState::new(0x1000),
            replay_opts(),
            shared_ds(),
            3,
            true,
        );
        worker.emulate_batch(&mut |_| {}).expect("the replay");
        assert_eq!(tracked(&worker), (vec![], 0));
        drop(worker.recover_in_place(RiscvEmulationState::new(0x1000), shared_ds(), 3, true));
        worker
            .emulate_batch(&mut |_| {})
            .expect("the second replay");
        assert_eq!(tracked(&worker), (vec![], 0));
    }

    /// Jumps to `(1 << shift) + offset`, which ends the run there, on its third clock.
    fn jump_to(shift: i32, offset: i32) -> Arc<Program> {
        Arc::new(Program::new(
            vec![
                i_type(Opcode::ADD, Register::X1, Register::X0, 1), // 0x1000
                i_type(Opcode::SLL, Register::X1, Register::X1, shift), // 0x1004
                i_type(Opcode::JALR, Register::X0, Register::X1, offset), // 0x1008
            ],
            0x1000,
            0x1000,
        ))
    }

    /// Runs `program` in `mode` until it ends or fails, with the cut and the end on the same
    /// clock, and returns how it ended and the records it cut.
    fn run_to_end(
        program: Arc<Program>,
        mode: super::RiscvEmulatorMode,
    ) -> (Result<bool, super::EmulationError>, Vec<EmulationRecord>) {
        let mut emulator = RiscvEmulator::new_single::<KoalaBear>(
            program,
            Arc::new(RecordFinalPvsState::default()),
            replay_opts(),
        );
        emulator.initialize_if_needed();
        emulator.mode = mode;
        emulator.update_mode_deps();
        emulator.target_global_clk = Some(3);

        let mut records = Vec::new();
        let ended = loop {
            match emulator.emulate_cycle(|_, record| records.push(record), &mut Instant::now()) {
                Ok(false) => continue,
                ended => break ended,
            }
        };
        (ended, records)
    }

    fn modes() -> [super::RiscvEmulatorMode; 2] {
        [
            super::RiscvEmulatorMode::Trace,
            super::RiscvEmulatorMode::Simple,
        ]
    }

    /// A run that ends on a jump to a pc the CPU trace cannot hold has a final `next_pc` no proof
    /// can state. Both modes report it as an error where the run ends, before a cut tries to
    /// encode it.
    #[test]
    fn a_run_ending_beyond_the_proof_address_range_is_an_error() {
        for shift in [32, 48] {
            for mode in modes() {
                let (ended, _) = run_to_end(jump_to(shift, 0), mode);
                assert!(
                    matches!(
                        ended,
                        Err(super::EmulationError::EndPcBeyondProofAddress(pc)) if pc == 1 << shift
                    ),
                    "{ended:?}"
                );
            }
        }
    }

    /// The last pc the CPU trace can hold ends a run as any pc past the program does.
    #[test]
    fn a_run_ending_at_the_last_proof_pc_is_no_error() {
        let end_pc = (1u64 << 32) - 4;
        for mode in modes() {
            let trace = mode == super::RiscvEmulatorMode::Trace;
            let (ended, records) = run_to_end(jump_to(32, -4), mode);
            assert!(matches!(ended, Ok(true)), "{ended:?}");
            if trace {
                let [record] = records.as_slice() else {
                    panic!("{} records", records.len());
                };
                let steps: Vec<_> = record.cpu_steps().iter().collect();
                assert_eq!(steps.last().map(|e| e.next_pc), Some(end_pc));
                for event in &steps {
                    assert!(Pc::<KoalaBear>::try_from(event.pc).is_ok());
                    assert!(Pc::<KoalaBear>::try_from(event.next_pc).is_ok());
                }
            }
        }
    }

    /// A cut record goes through the reader with the pcs the cut stamped, which a Trace-mode cut
    /// checks against the record's first and last event.
    #[test]
    fn a_cut_record_keeps_its_stamped_pcs_through_the_reader() {
        let program = looping_program();
        let mut emulator = RiscvEmulator::new_single::<KoalaBear>(
            program.clone(),
            Arc::new(RecordFinalPvsState::default()),
            replay_opts(),
        );
        emulator.initialize_if_needed();
        let mut deferred =
            EmulationDeferredState::new(program, Arc::new(RecordFinalPvsState::default()));

        emulator.target_global_clk = Some(3);
        let mut first = run_to_cut(&mut emulator);
        deferred.update_public_values(false, &mut first, DeferredChunkPc::LastCpuChunk);
        assert_stamped(&first, 0x1000, 0x1010);

        emulator.target_global_clk = Some(6);
        let mut second = run_to_cut(&mut emulator);
        deferred.update_public_values(false, &mut second, DeferredChunkPc::LastCpuChunk);
        assert_stamped(&second, 0x1010, 0x100c);
    }

    /// An empty history still hands on the stamped pcs. The exit code is the reader's 0, whatever
    /// the record carries: no chunk is cut on any other.
    #[test]
    fn a_record_without_steps_hands_on_its_stamp() {
        let program = looping_program();
        let mut deferred =
            EmulationDeferredState::new(program.clone(), Arc::new(RecordFinalPvsState::default()));
        let mut record = EmulationRecord::new(program);
        record.history = Some(ExecutionHistory::default());
        assert!(record.cpu_steps().is_empty());
        record.public_values.start_pc = encode_public_value_pc_limbs(0x1010);
        record.public_values.next_pc = encode_public_value_pc_limbs(0x100c);
        record.public_values.exit_code = 7;

        deferred.update_public_values(false, &mut record, DeferredChunkPc::LastCpuChunk);

        for pvs in [&record.public_values, &deferred.pvs] {
            assert_eq!(pvs.start_pc, encode_public_value_pc_limbs(0x1010));
            assert_eq!(pvs.next_pc, encode_public_value_pc_limbs(0x100c));
            assert_eq!(pvs.exit_code, 0);
        }
    }

    /// A deferred record states one pc as its start and next pc: the one the serial path passes,
    /// or the next pc of the last CPU chunk, which the sequencer reads. After a CPU chunk the two
    /// write the same public values; before any, only the pc passed is where the run stands, so
    /// each caller says which it means.
    #[test]
    fn a_deferred_record_states_the_pc_the_run_stands_at() {
        let program = looping_program();
        let limbs = encode_public_value_pc_limbs;
        // A deferred record's public values, after a CPU chunk ending at 0x100c when there is one.
        let deferred_record = |after_a_cpu_chunk: bool, deferred_pc: DeferredChunkPc| {
            let mut deferred = EmulationDeferredState::new(
                program.clone(),
                Arc::new(RecordFinalPvsState::default()),
            );
            if after_a_cpu_chunk {
                let mut cpu = EmulationRecord::new(program.clone());
                cpu.public_values.start_pc = limbs(0x1010);
                cpu.public_values.next_pc = limbs(0x100c);
                deferred.update_public_values(false, &mut cpu, DeferredChunkPc::LastCpuChunk);
            }
            let mut split = EmulationRecord::new(program.clone());
            split.is_cpu_chunk = false;
            split.public_values.last_init_addr_limbs = [1, 2, 3];
            deferred.update_public_values(false, &mut split, deferred_pc);
            split.public_values
        };

        let serial = deferred_record(true, DeferredChunkPc::At(0x100c));
        assert_eq!(
            (serial.start_pc, serial.next_pc),
            (limbs(0x100c), limbs(0x100c))
        );
        assert_eq!((serial.chunk, serial.execution_chunk), (2, 2));
        assert_eq!(serial.last_init_addr_limbs, [1, 2, 3]);
        let sequenced = deferred_record(true, DeferredChunkPc::LastCpuChunk);
        assert_eq!(format!("{serial:?}"), format!("{sequenced:?}"));

        let passed = deferred_record(false, DeferredChunkPc::At(0x100c));
        let last_cpu_chunk = deferred_record(false, DeferredChunkPc::LastCpuChunk);
        assert_eq!(passed.start_pc, limbs(0x100c));
        assert_ne!(last_cpu_chunk.start_pc, passed.start_pc);
    }

    #[test]
    #[ignore = "RV32 ELF — not supported under RV64-only emulator"]
    fn test_simple_fib() {
        // just run a simple elf file in the compiler folder(test_elf)
        let program = simple_fibo_program();
        let mut stdin = EmulatorStdin::<Program, Vec<u8>>::new_builder::<KoalaBearPoseidon2>();
        stdin.write(&MAX_FIBONACCI_NUM_IN_ONE_CHUNK);
        let mut emulator = RiscvEmulator::new_single::<KoalaBear>(
            program,
            Arc::new(RecordFinalPvsState::default()),
            EmulatorOpts::default(),
        );
        let stdin = stdin.finalize();
        emulator.run(Some(stdin)).unwrap();
        // println!("{:x?}", emulator.state.public_values_stream)
    }

    #[test]
    #[ignore = "RV32 ELF — not supported under RV64-only emulator"]
    fn test_simple_keccak() {
        let program = simple_keccak_program();
        let n = "a"; // do keccak(b"abcdefg")
        let mut stdin = EmulatorStdin::<Program, Vec<u8>>::new_builder::<KoalaBearPoseidon2>();
        stdin.write(&n);
        let mut emulator = RiscvEmulator::new_single::<KoalaBear>(
            program,
            Arc::new(RecordFinalPvsState::default()),
            EmulatorOpts::default(),
        );
        let stdin = stdin.finalize();
        emulator.run(Some(stdin)).unwrap();
        // println!("{:x?}", emulator.state.public_values_stream)
    }

    #[test]
    fn test_phase2a_register_and_memory_paths_are_explicit() {
        let program = simple_fibo_program();
        let mut emulator = RiscvEmulator::new_single::<KoalaBear>(
            program,
            Arc::new(RecordFinalPvsState::default()),
            EmulatorOpts::default(),
        );

        emulator.rw(Register::X5, 0xCAFE_BABE);
        assert_eq!(emulator.register(Register::X5), 0xCAFE_BABE);

        emulator.mw_cpu(
            0x1000,
            0x1020_3040,
            crate::chips::chips::events::MemoryAccessPosition::Memory,
        );
        assert_eq!(emulator.word(0x1000), 0x1020_3040);
    }

    #[test]
    fn test_guest_addr_to_event_addr_supports_u64() {
        let addr = u64::from(u32::MAX) + 1;
        assert_eq!(addr, u64::from(u32::MAX) + 1);
    }

    #[test]
    fn test_rw_unconstrained_keeps_no_mark_behavior() {
        let program = simple_fibo_program();
        let mut emulator = RiscvEmulator::new_single::<KoalaBear>(
            program,
            Arc::new(RecordFinalPvsState::default()),
            EmulatorOpts::default(),
        );

        let reg_idx = Register::X7 as u32;
        let reg_byte_addr = (reg_idx * 4) as u64;
        assert!(!emulator.state.memory.has_accessed(reg_byte_addr));
        emulator.rw_unconstrained(Register::X7, 0x55AA_55AA);
        assert_eq!(emulator.register(Register::X7), 0x55AA_55AA);
        assert!(!emulator.state.memory.has_accessed(reg_byte_addr));
    }

    #[test]
    fn test_register_access_does_not_mark_state_bitmap() {
        let program = simple_fibo_program();
        let mut emulator = RiscvEmulator::new_single::<KoalaBear>(
            program,
            Arc::new(RecordFinalPvsState::default()),
            EmulatorOpts::default(),
        );

        let reg_idx = Register::X5 as u32;
        let reg_byte_addr = (reg_idx * 4) as u64;
        assert!(!emulator.state.memory.has_accessed(reg_byte_addr));
        emulator.rw(Register::X5, 0xCAFE_BABE);
        assert_eq!(emulator.register(Register::X5), 0xCAFE_BABE);
        assert!(!emulator.state.memory.has_accessed(reg_byte_addr));
    }

    #[test]
    fn test_simple_register_access_does_not_emit_local_memory_events() {
        let program = simple_fibo_program();
        let mut emulator = RiscvEmulator::new_single::<KoalaBear>(
            program,
            Arc::new(RecordFinalPvsState::default()),
            EmulatorOpts::default(),
        );
        emulator.mode = super::RiscvEmulatorMode::Simple;
        emulator.update_mode_deps();

        emulator.rw_simple(Register::X6, 0x1234_5678);
        let _ = emulator.rr_simple(
            Register::X6,
            crate::chips::chips::events::MemoryAccessPosition::B,
        );

        assert!(emulator.sink.local_memory_access_mut().is_empty());
    }

    #[test]
    fn test_register_and_memory_are_isolated() {
        let program = simple_fibo_program();
        let mut emulator = RiscvEmulator::new_single::<KoalaBear>(
            program,
            Arc::new(RecordFinalPvsState::default()),
            EmulatorOpts::default(),
        );

        emulator.rw(Register::X5, 0xABCD_1234);
        emulator.mw_cpu(
            0x100,
            0x5555_AAAA,
            crate::chips::chips::events::MemoryAccessPosition::Memory,
        );

        assert_eq!(emulator.register(Register::X5), 0xABCD_1234);
        assert_eq!(emulator.word(0x100), 0x5555_AAAA);
    }

    #[test]
    fn test_memory_floor_accepts_boundary_address() {
        let program = simple_fibo_program();
        let mut emulator = RiscvEmulator::new_single::<KoalaBear>(
            program,
            Arc::new(RecordFinalPvsState::default()),
            EmulatorOpts::default(),
        );

        emulator.mw_cpu(
            0x100,
            0xA5A5_5A5A,
            crate::chips::chips::events::MemoryAccessPosition::Memory,
        );
        assert_eq!(emulator.word(0x100), 0xA5A5_5A5A);
    }

    #[test]
    #[should_panic(expected = "memory access below floor")]
    fn test_memory_floor_rejects_low_address() {
        let program = simple_fibo_program();
        let mut emulator = RiscvEmulator::new_single::<KoalaBear>(
            program,
            Arc::new(RecordFinalPvsState::default()),
            EmulatorOpts::default(),
        );
        let _ = emulator.word(0xFC);
    }

    #[test]
    fn test_register_snapshot_is_consumed_during_rollback() {
        let program = simple_fibo_program();
        let mut emulator = RiscvEmulator::new_single::<KoalaBear>(
            program,
            Arc::new(RecordFinalPvsState::default()),
            EmulatorOpts::default(),
        );

        // Simulate pre-batch snapshot state.
        let mut snapshot = emulator.state.clone_without_memory();
        snapshot.registers[3] = RuntimeRegisterRecord {
            value: 0xAAAA_BBBB,
            chunk: 1,
            timestamp: 1,
        };

        // Simulate that x3 was touched and snapshotted before mutation.
        emulator.register_snapshot[3] = RuntimeRegisterRecord {
            value: 0x1111_2222,
            chunk: 2,
            timestamp: 2,
        };
        emulator.register_snapshot_bitmap = 1 << 3;

        // Apply the same rollback semantics as emulate_state.
        let register_snapshot_bitmap = emulator.register_snapshot_bitmap;
        let register_snapshot = emulator.register_snapshot;
        for reg_idx in 0..32 {
            if (register_snapshot_bitmap & (1 << reg_idx)) != 0 {
                snapshot.registers[reg_idx as usize] = register_snapshot[reg_idx as usize];
            }
        }

        assert_eq!(snapshot.registers[3].value, 0x1111_2222);
        assert_eq!(snapshot.registers[3].chunk, 2);
        assert_eq!(snapshot.registers[3].timestamp, 2);
    }

    fn r_type(opcode: Opcode, rd: Register, rs1: Register, rs2: Register) -> Instruction {
        Instruction::new(opcode, rd as u8, rs1 as u64, rs2 as u64, false, false)
    }

    fn i_type(opcode: Opcode, rd: Register, rs1: Register, imm: i32) -> Instruction {
        Instruction::new(opcode, rd as u8, rs1 as u64, imm as i64 as u64, false, true)
    }

    fn s_type(opcode: Opcode, rs_value: Register, rs_base: Register, imm: i32) -> Instruction {
        Instruction::new(
            opcode,
            rs_value as u8,
            rs_base as u64,
            imm as i64 as u64,
            false,
            true,
        )
    }

    fn set_reg_raw(emulator: &mut RiscvEmulator, register: Register, value: u64) {
        emulator.state.registers[register as usize] = RuntimeRegisterRecord {
            value,
            chunk: 0,
            timestamp: 0,
        };
    }

    #[test]
    fn test_phase_3r3_w_ops_semantics() {
        let program = simple_fibo_program();
        let mut emulator = RiscvEmulator::new_single::<KoalaBear>(
            program,
            Arc::new(RecordFinalPvsState::default()),
            EmulatorOpts::default(),
        );

        set_reg_raw(&mut emulator, Register::X1, 0xFFFF_FFFF);
        set_reg_raw(&mut emulator, Register::X2, 1);
        emulator
            .emulate_instruction(&r_type(
                Opcode::ADDW,
                Register::X3,
                Register::X1,
                Register::X2,
            ))
            .unwrap();
        assert_eq!(emulator.register(Register::X3), 0);

        set_reg_raw(&mut emulator, Register::X1, 1);
        set_reg_raw(&mut emulator, Register::X2, 2);
        emulator
            .emulate_instruction(&r_type(
                Opcode::SUBW,
                Register::X3,
                Register::X1,
                Register::X2,
            ))
            .unwrap();
        assert_eq!(emulator.register(Register::X3), u64::MAX);

        set_reg_raw(&mut emulator, Register::X1, 0x8000_0001);
        set_reg_raw(&mut emulator, Register::X2, 32);
        emulator
            .emulate_instruction(&r_type(
                Opcode::SLLW,
                Register::X3,
                Register::X1,
                Register::X2,
            ))
            .unwrap();
        assert_eq!(emulator.register(Register::X3), 0xFFFF_FFFF_8000_0001);

        set_reg_raw(&mut emulator, Register::X1, 0x8000_0001);
        set_reg_raw(&mut emulator, Register::X2, 0);
        emulator
            .emulate_instruction(&r_type(
                Opcode::SRLW,
                Register::X3,
                Register::X1,
                Register::X2,
            ))
            .unwrap();
        assert_eq!(emulator.register(Register::X3), 0xFFFF_FFFF_8000_0001);

        set_reg_raw(&mut emulator, Register::X1, 0x8000_0000);
        set_reg_raw(&mut emulator, Register::X2, 1);
        emulator
            .emulate_instruction(&r_type(
                Opcode::SRAW,
                Register::X3,
                Register::X1,
                Register::X2,
            ))
            .unwrap();
        assert_eq!(emulator.register(Register::X3), 0xFFFF_FFFF_C000_0000);

        set_reg_raw(&mut emulator, Register::X1, 0x8000_0000);
        set_reg_raw(&mut emulator, Register::X2, 0xFFFF_FFFF);
        emulator
            .emulate_instruction(&r_type(
                Opcode::DIVW,
                Register::X3,
                Register::X1,
                Register::X2,
            ))
            .unwrap();
        assert_eq!(emulator.register(Register::X3), 0xFFFF_FFFF_8000_0000);

        set_reg_raw(&mut emulator, Register::X1, 0x8000_0001);
        set_reg_raw(&mut emulator, Register::X2, 0);
        emulator
            .emulate_instruction(&r_type(
                Opcode::REMW,
                Register::X3,
                Register::X1,
                Register::X2,
            ))
            .unwrap();
        assert_eq!(emulator.register(Register::X3), 0xFFFF_FFFF_8000_0001);

        set_reg_raw(&mut emulator, Register::X1, 0x8000_0001);
        set_reg_raw(&mut emulator, Register::X2, 0);
        emulator
            .emulate_instruction(&r_type(
                Opcode::DIVUW,
                Register::X3,
                Register::X1,
                Register::X2,
            ))
            .unwrap();
        assert_eq!(emulator.register(Register::X3), u64::MAX);

        set_reg_raw(&mut emulator, Register::X1, 0x8000_0001);
        set_reg_raw(&mut emulator, Register::X2, 0);
        emulator
            .emulate_instruction(&r_type(
                Opcode::REMUW,
                Register::X3,
                Register::X1,
                Register::X2,
            ))
            .unwrap();
        assert_eq!(emulator.register(Register::X3), 0xFFFF_FFFF_8000_0001);
    }

    #[test]
    fn test_phase_3r3_lwu_ld_sd_semantics() {
        let program = simple_fibo_program();
        let mut emulator = RiscvEmulator::new_single::<KoalaBear>(
            program,
            Arc::new(RecordFinalPvsState::default()),
            EmulatorOpts::default(),
        );

        set_reg_raw(&mut emulator, Register::X1, 0x1000);
        set_reg_raw(&mut emulator, Register::X2, 0x1122_3344_5566_7788);
        emulator
            .emulate_instruction(&s_type(Opcode::SD, Register::X2, Register::X1, 0))
            .unwrap();
        assert_eq!(emulator.word(0x1000), 0x5566_7788);
        assert_eq!(emulator.word(0x1004), 0x1122_3344);

        emulator
            .emulate_instruction(&i_type(Opcode::LD, Register::X3, Register::X1, 0))
            .unwrap();
        assert_eq!(emulator.register(Register::X3), 0x1122_3344_5566_7788);

        emulator.state.memory.write_word(0x1008, u32::MAX, 0, 0);
        set_reg_raw(&mut emulator, Register::X1, 0x1008);
        emulator
            .emulate_instruction(&i_type(Opcode::LWU, Register::X4, Register::X1, 0))
            .unwrap();
        assert_eq!(emulator.register(Register::X4), 0x0000_0000_FFFF_FFFF);
    }

    /// The block's own instructions leave nothing in the record: once it closes, the record holds
    /// what it held before and the closing ECALL's CPU row.
    #[test]
    fn an_unconstrained_block_leaves_no_event_in_the_record() {
        let mut emulator = RiscvEmulator::new_single::<KoalaBear>(
            simple_fibo_program(),
            Arc::new(RecordFinalPvsState::default()),
            EmulatorOpts::default(),
        );
        let ecall = Instruction::new(Opcode::ECALL, 5, 10, 11, false, false);
        let add = r_type(Opcode::ADD, Register::X3, Register::X1, Register::X2);
        set_reg_raw(&mut emulator, Register::X1, 1);
        set_reg_raw(&mut emulator, Register::X2, 2);
        emulator.emulate_instruction(&add).unwrap();

        set_reg_raw(
            &mut emulator,
            Register::X5,
            SyscallCode::ENTER_UNCONSTRAINED as u64,
        );
        emulator.emulate_instruction(&ecall).unwrap();
        assert!(emulator.is_unconstrained());
        emulator.emulate_instruction(&add).unwrap();
        set_reg_raw(
            &mut emulator,
            Register::X5,
            SyscallCode::EXIT_UNCONSTRAINED as u64,
        );
        emulator.emulate_instruction(&ecall).unwrap();
        assert!(!emulator.is_unconstrained());

        let history = take_history(&mut emulator);
        assert_eq!(history.steps.len(), 2);
        assert_eq!(history.chip_steps.add, [0]);
        assert_eq!(history.chip_steps.ecall, [1]);
    }

    #[test]
    fn test_phase_3r5_cpu_event_payload_preserves_rv64_ld_sd_values() {
        let program = simple_fibo_program();
        let mut emulator = RiscvEmulator::new_single::<KoalaBear>(
            program,
            Arc::new(RecordFinalPvsState::default()),
            EmulatorOpts::default(),
        );

        set_reg_raw(&mut emulator, Register::X1, 0x1000);
        set_reg_raw(&mut emulator, Register::X2, 0xCAFE_BABE_DEAD_BEEF);

        let sd = s_type(Opcode::SD, Register::X2, Register::X1, 0);
        emulator.emulate_instruction(&sd).unwrap();
        let history = take_history(&mut emulator);
        assert_eq!(history.operands(0, &sd).0, 0xCAFE_BABE_DEAD_BEEF);
        assert_eq!(history.chip_steps.memory, [0]);
        assert_eq!(
            history.accesses_of(0, &sd).last().unwrap().1.value,
            0xCAFE_BABE_DEAD_BEEF
        );

        let ld = i_type(Opcode::LD, Register::X3, Register::X1, 0);
        emulator.emulate_instruction(&ld).unwrap();
        let history = take_history(&mut emulator);
        assert_eq!(history.operands(0, &ld).0, 0xCAFE_BABE_DEAD_BEEF);
        assert_eq!(history.chip_steps.memory, [0]);
        assert_eq!(
            history.accesses_of(0, &ld).last().unwrap().1.value,
            0xCAFE_BABE_DEAD_BEEF
        );
    }

    #[test]
    fn test_phase_3r5_cpu_event_payload_preserves_rv64_w_op_values() {
        let program = simple_fibo_program();
        let mut emulator = RiscvEmulator::new_single::<KoalaBear>(
            program,
            Arc::new(RecordFinalPvsState::default()),
            EmulatorOpts::default(),
        );

        set_reg_raw(&mut emulator, Register::X5, 0xAAAA_BBBB_FFFF_FFFF);
        set_reg_raw(&mut emulator, Register::X6, 1);
        let addw = r_type(Opcode::ADDW, Register::X7, Register::X5, Register::X6);
        emulator.emulate_instruction(&addw).unwrap();
        let history = take_history(&mut emulator);
        assert_eq!(history.chip_steps.add, [0]);
        assert_eq!(
            history.operands(history.steps.len() - 1, &addw),
            (0, 0xAAAA_BBBB_FFFF_FFFF, 1)
        );
    }

    #[test]
    fn test_phase_3r6_alu_event_payload_preserves_rv64_w_op_operands() {
        let program = simple_fibo_program();
        let mut emulator = RiscvEmulator::new_single::<KoalaBear>(
            program,
            Arc::new(RecordFinalPvsState::default()),
            EmulatorOpts::default(),
        );

        set_reg_raw(&mut emulator, Register::X5, 0xAAAA_BBBB_FFFF_FFFF);
        set_reg_raw(&mut emulator, Register::X6, 1);
        let addw = r_type(Opcode::ADDW, Register::X7, Register::X5, Register::X6);
        emulator.emulate_instruction(&addw).unwrap();
        let history = take_history(&mut emulator);
        assert_eq!(history.chip_steps.add, [0]);
        assert_eq!(
            history.operands(history.steps.len() - 1, &addw),
            (0, 0xAAAA_BBBB_FFFF_FFFF, 1)
        );
    }

    #[test]
    fn test_phase_3r6_alu_event_payload_preserves_rv64_w_op_result() {
        let program = simple_fibo_program();
        let mut emulator = RiscvEmulator::new_single::<KoalaBear>(
            program,
            Arc::new(RecordFinalPvsState::default()),
            EmulatorOpts::default(),
        );

        set_reg_raw(&mut emulator, Register::X5, 0xFFFF_FFFF_8000_0001);
        set_reg_raw(&mut emulator, Register::X6, 0);
        let divuw = r_type(Opcode::DIVUW, Register::X7, Register::X5, Register::X6);
        emulator.emulate_instruction(&divuw).unwrap();
        let history = take_history(&mut emulator);
        assert_eq!(history.chip_steps.divrem, [0]);
        assert_eq!(
            history.operands(history.steps.len() - 1, &divuw),
            (u64::MAX, 0xFFFF_FFFF_8000_0001, 0)
        );
    }

    #[test]
    fn test_phase_3r6_alu_event_payload_preserves_rv64_mulw_inputs() {
        let program = simple_fibo_program();
        let mut emulator = RiscvEmulator::new_single::<KoalaBear>(
            program,
            Arc::new(RecordFinalPvsState::default()),
            EmulatorOpts::default(),
        );

        set_reg_raw(&mut emulator, Register::X5, 0x1234_5678_FFFF_FFFE);
        set_reg_raw(&mut emulator, Register::X6, 0xAAAA_BBBB_0000_0002);
        let mulw = r_type(Opcode::MULW, Register::X7, Register::X5, Register::X6);
        emulator.emulate_instruction(&mulw).unwrap();
        let history = take_history(&mut emulator);
        assert_eq!(history.chip_steps.mul, [0]);
        let (_, b, c) = history.operands(history.steps.len() - 1, &mulw);
        assert_eq!((b, c), (0x1234_5678_FFFF_FFFE, 0xAAAA_BBBB_0000_0002));
    }

    #[test]
    fn test_phase_3r3_lwu_ld_sd_alignment_errors() {
        let program = simple_fibo_program();
        let mut emulator = RiscvEmulator::new_single::<KoalaBear>(
            program,
            Arc::new(RecordFinalPvsState::default()),
            EmulatorOpts::default(),
        );

        // Use addresses in different 8-byte dwords to avoid timestamp collisions
        // (failed instructions don't advance the clock but still touch memory metadata).
        set_reg_raw(&mut emulator, Register::X1, 0x1002);
        let err = emulator
            .emulate_instruction(&i_type(Opcode::LWU, Register::X4, Register::X1, 0))
            .unwrap_err();
        assert_eq!(
            err.abnormal_termination().map(|t| t.reason),
            Some(super::TerminationReason::InvalidMemoryAccess {
                opcode: Opcode::LWU,
                addr: 0x1002,
            })
        );

        // Use 0x2004 (different 8-byte dword than 0x1002) to avoid timestamp conflict.
        set_reg_raw(&mut emulator, Register::X1, 0x2004);
        let err = emulator
            .emulate_instruction(&i_type(Opcode::LD, Register::X4, Register::X1, 0))
            .unwrap_err();
        assert_eq!(
            err.abnormal_termination().map(|t| t.reason),
            Some(super::TerminationReason::InvalidMemoryAccess {
                opcode: Opcode::LD,
                addr: 0x2004,
            })
        );

        set_reg_raw(&mut emulator, Register::X1, 0x3004);
        set_reg_raw(&mut emulator, Register::X2, 0xAABB_CCDD_EEFF_0011);
        let err = emulator
            .emulate_instruction(&s_type(Opcode::SD, Register::X2, Register::X1, 0))
            .unwrap_err();
        assert_eq!(
            err.abnormal_termination().map(|t| t.reason),
            Some(super::TerminationReason::InvalidMemoryAccess {
                opcode: Opcode::SD,
                addr: 0x3004,
            })
        );
    }

    #[test]
    fn test_phase_3r3_trace_simple_parity_for_rv64_ops() {
        let program = simple_fibo_program();
        let mut trace_emulator = RiscvEmulator::new_single::<KoalaBear>(
            program.clone(),
            Arc::new(RecordFinalPvsState::default()),
            EmulatorOpts::default(),
        );
        let mut simple_emulator = RiscvEmulator::new_single::<KoalaBear>(
            program,
            Arc::new(RecordFinalPvsState::default()),
            EmulatorOpts::default(),
        );

        trace_emulator.mode = super::RiscvEmulatorMode::Trace;
        trace_emulator.update_mode_deps();
        simple_emulator.mode = super::RiscvEmulatorMode::Simple;
        simple_emulator.update_mode_deps();

        set_reg_raw(&mut trace_emulator, Register::X1, 0x1200);
        set_reg_raw(&mut trace_emulator, Register::X2, 0xCAFE_BABE_DEAD_BEEF);
        set_reg_raw(&mut trace_emulator, Register::X5, 0xFFFF_FFFF);
        set_reg_raw(&mut trace_emulator, Register::X6, 1);

        set_reg_raw(&mut simple_emulator, Register::X1, 0x1200);
        set_reg_raw(&mut simple_emulator, Register::X2, 0xCAFE_BABE_DEAD_BEEF);
        set_reg_raw(&mut simple_emulator, Register::X5, 0xFFFF_FFFF);
        set_reg_raw(&mut simple_emulator, Register::X6, 1);

        let instructions = [
            s_type(Opcode::SD, Register::X2, Register::X1, 0),
            i_type(Opcode::LD, Register::X3, Register::X1, 0),
            r_type(Opcode::ADDW, Register::X4, Register::X5, Register::X6),
            r_type(Opcode::DIVUW, Register::X7, Register::X5, Register::X6),
        ];

        for instruction in instructions {
            trace_emulator.emulate_instruction(&instruction).unwrap();
            simple_emulator
                .emulate_instruction_simple(&instruction)
                .unwrap();
        }

        assert_eq!(trace_emulator.state.pc, simple_emulator.state.pc);
        assert_eq!(trace_emulator.state.clk, simple_emulator.state.clk);
        assert_eq!(
            trace_emulator.state.registers,
            simple_emulator.state.registers
        );
        assert_eq!(trace_emulator.word(0x1200), simple_emulator.word(0x1200));
        assert_eq!(trace_emulator.word(0x1204), simple_emulator.word(0x1204));
    }

    #[test]
    fn test_stage1_postprocess_memory_events_follow_the_ga3_rules() {
        use crate::chips::chips::riscv_memory::event::MemoryRecord;
        // Two image words: one zero-valued and never touched, one the program overwrites.
        let program = {
            let mut program = Program::new(
                vec![
                    Instruction::new(Opcode::ADD, 1, 0, 0, false, false),
                    Instruction::new(Opcode::ADD, 2, 0, 0, false, false),
                ],
                0x1000,
                0x1000,
            );
            program.memory_image = Arc::new(BTreeMap::from([(0x118u64, 0u64), (0x120u64, 7u64)]));
            Arc::new(program)
        };
        let mut emulator = RiscvEmulator::new_single::<KoalaBear>(
            program,
            Arc::new(RecordFinalPvsState::default()),
            EmulatorOpts::default(),
        );
        let rec = |value: u64, chunk: u32, timestamp: u32| MemoryRecord {
            value,
            chunk,
            timestamp,
        };

        // 0x100: hinted, never accessed by the program (record still (0, 0)): no events.
        emulator
            .state
            .uninitialized_memory
            .insert(0x100, 0x0807_0605_0403_0201);
        emulator
            .state
            .memory
            .insert(0x100, rec(0x0807_0605_0403_0201, 0, 0));
        // 0x108: hinted and then accessed: its non-zero initial value needs a MemoryInitialize
        // row, so both events, the init value exact.
        emulator
            .state
            .uninitialized_memory
            .insert(0x108, 0x0000_0000_0000_0A09);
        emulator
            .state
            .memory
            .insert(0x108, rec(0x0000_0000_0000_0A09, 1, 8));
        // 0x110: accessed, started at zero: the first-touch MemoryLocal entry declares the zero
        // initial state, so finalize only.
        emulator.state.memory.insert(0x110, rec(0x42, 1, 12));
        // 0x118 / 0x120: image words (the bulk load leaves the record at (chunk 0, timestamp 0)
        // until the program touches it). Their initial state is sent by the image digest, so
        // finalize only -- whether the word stayed at its image value (even zero) or was
        // overwritten.
        emulator.state.memory.insert(0x118, rec(0, 0, 0));
        emulator.state.memory.insert(0x120, rec(9, 1, 20));

        emulator.postprocess();

        let inits = &emulator.sink.record().memory_initialize_events;
        let finals = &emulator.sink.record().memory_finalize_events;
        assert!(inits.iter().all(|e| e.addr != 0x100));
        assert!(finals.iter().all(|e| e.addr != 0x100));
        let init_108 = inits
            .iter()
            .find(|e| e.addr == 0x108)
            .expect("missing init event for the accessed hinted dword");
        assert_eq!(init_108.value, 0x0000_0000_0000_0A09);
        assert!(finals.iter().any(|e| e.addr == 0x108));
        assert!(inits.iter().all(|e| e.addr != 0x110));
        let final_110 = finals
            .iter()
            .find(|e| e.addr == 0x110)
            .expect("missing finalize event for the zero-initial dword");
        assert_eq!(final_110.value, 0x42);
        for (addr, value) in [(0x118u64, 0u64), (0x120, 9)] {
            assert!(inits.iter().all(|e| e.addr != addr));
            let fin = finals
                .iter()
                .find(|e| e.addr == addr)
                .expect("missing finalize event for the image word");
            assert_eq!(fin.value, value);
        }
        // Registers keep their initialize rows unconditionally (x0 at least).
        assert!(inits.iter().any(|e| e.addr == 0));
    }

    const RV64IM_FIBONACCI_ELF: &[u8] =
        include_bytes!("../../../compiler/test_elf/riscv64im-pico-fibnacci-elf");

    pub fn rv64im_fibonacci_program() -> Arc<Program> {
        Compiler::new(SourceType::RISCV, RV64IM_FIBONACCI_ELF)
            .expect("failed to parse RV64IM_FIBONACCI_ELF")
            .compile()
    }

    #[test]
    fn test_rv64im_fib() {
        crate::machine::logger::setup_logger();

        let program = rv64im_fibonacci_program();
        let mut stdin = EmulatorStdin::<Program, Vec<u8>>::new_builder::<KoalaBearPoseidon2>();
        stdin.write(&10u64);
        let mut emulator = RiscvEmulator::new_single::<KoalaBear>(
            program,
            Arc::new(RecordFinalPvsState::default()),
            EmulatorOpts::default(),
        );
        let stdin = stdin.finalize();
        emulator.run(Some(stdin)).unwrap();
        println!("public_values: {:x?}", emulator.state.public_values_stream);
    }

    fn workspace_root() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("vm/ has a parent")
            .to_path_buf()
    }

    fn load_rv64_reth_program() -> Arc<Program> {
        let elf_path = workspace_root().join("perf/bench_data/rv64/reth-elf");
        let elf_bytes = std::fs::read(&elf_path)
            .unwrap_or_else(|e| panic!("failed to read {}: {e}", elf_path.display()));
        Compiler::new(SourceType::RISCV, &elf_bytes)
            .expect("failed to parse rv64 reth ELF")
            .compile()
    }

    fn run_rv64_reth_block(block: u32) {
        crate::machine::logger::setup_logger();

        let program = load_rv64_reth_program();
        let input_path = workspace_root().join(format!("perf/bench_data/rv64/reth-{block}.bin"));
        let input_bytes = std::fs::read(&input_path)
            .unwrap_or_else(|e| panic!("failed to read {}: {e}", input_path.display()));

        let mut stdin = EmulatorStdin::<Program, Vec<u8>>::new_builder::<KoalaBearPoseidon2>();
        stdin.write_slice(&input_bytes);
        let stdin = stdin.finalize();

        let mut emulator = RiscvEmulator::new_single::<KoalaBear>(
            program,
            Arc::new(RecordFinalPvsState::default()),
            EmulatorOpts::default(),
        );
        emulator.run(Some(stdin)).unwrap();

        println!("block {block}: cycles = {}", emulator.state.global_clk);
    }

    fn run_rv64_reth_block_simple(block: u32) {
        crate::machine::logger::setup_logger();

        let program = load_rv64_reth_program();
        let input_path = workspace_root().join(format!("perf/bench_data/rv64/reth-{block}.bin"));
        let input_bytes = std::fs::read(&input_path)
            .unwrap_or_else(|e| panic!("failed to read {}: {e}", input_path.display()));

        let mut stdin = EmulatorStdin::<Program, Vec<u8>>::new_builder::<KoalaBearPoseidon2>();
        stdin.write_slice(&input_bytes);
        let stdin = stdin.finalize();

        let mut emulator = RiscvEmulator::new_single::<KoalaBear>(
            program,
            Arc::new(RecordFinalPvsState::default()),
            EmulatorOpts::default(),
        );
        emulator.mode = super::RiscvEmulatorMode::Simple;
        emulator.update_mode_deps();
        if let Err(err) = emulator.run(Some(stdin)) {
            panic!(
                "rv64 reth simple block {block} failed: {err:?}\npc=0x{:016x} clk={} global_clk={}\nstdout:\n{}\nstderr:\n{}",
                emulator.state.pc,
                emulator.state.clk,
                emulator.state.global_clk,
                emulator.stdout,
                emulator.stderr,
            );
        }

        println!("block {block}: cycles = {}", emulator.state.global_clk);
    }

    fn single_instruction_program(instruction: Instruction) -> Arc<Program> {
        Arc::new(Program::new(vec![instruction], 0x1000, 0x1000))
    }

    #[test]
    fn jal_to_x0_counts_chunk_split_event() {
        let program =
            single_instruction_program(Instruction::new(Opcode::JAL, 0, 4, 0, false, true));
        let mut emulator = RiscvEmulator::new_single::<KoalaBear>(
            program,
            Arc::new(RecordFinalPvsState::default()),
            EmulatorOpts::default(),
        );
        emulator.run(None).unwrap();

        assert_eq!(emulator.chunk_split_state.num_memory_read_write_events, 1);
    }

    #[test]
    fn jalr_to_x0_counts_chunk_split_event() {
        let program =
            single_instruction_program(Instruction::new(Opcode::JALR, 0, 1, 0, false, true));
        let mut emulator = RiscvEmulator::new_single::<KoalaBear>(
            program,
            Arc::new(RecordFinalPvsState::default()),
            EmulatorOpts::default(),
        );
        emulator.state.registers[1] = RuntimeRegisterRecord {
            value: 0,
            chunk: 0,
            timestamp: 0,
        };
        emulator.run(None).unwrap();

        assert_eq!(emulator.chunk_split_state.num_memory_read_write_events, 1);
    }

    /// Run: cargo test --release -p pico-vm test_rv64_reth_17106222 -- --ignored --nocapture
    #[test]
    #[ignore = "requires rv64 reth ELF + block inputs in perf/bench_data/rv64/"]
    fn test_rv64_reth_17106222() {
        run_rv64_reth_block(17106222);
    }

    /// Run: cargo test --release -p pico-vm test_rv64_reth_18884864 -- --ignored --nocapture
    #[test]
    #[ignore = "requires rv64 reth ELF + block inputs in perf/bench_data/rv64/"]
    fn test_rv64_reth_18884864() {
        run_rv64_reth_block(18884864);
    }

    /// Run: cargo test --release -p pico-vm test_rv64_reth_23993050 -- --ignored --nocapture
    #[test]
    #[ignore = "requires rv64 reth ELF + block inputs in perf/bench_data/rv64/"]
    fn test_rv64_reth_23993050() {
        run_rv64_reth_block(23993050);
    }

    /// Run: cargo test --release -p pico-vm test_rv64_reth_simple_17106222 -- --ignored --nocapture
    #[test]
    #[ignore = "requires rv64 reth ELF + block inputs in perf/bench_data/rv64/"]
    fn test_rv64_reth_simple_17106222() {
        run_rv64_reth_block_simple(17106222);
    }

    /// Run: cargo test --release -p pico-vm test_rv64_reth_simple_18884864 -- --ignored --nocapture
    #[test]
    #[ignore = "requires rv64 reth ELF + block inputs in perf/bench_data/rv64/"]
    fn test_rv64_reth_simple_18884864() {
        run_rv64_reth_block_simple(18884864);
    }

    /// Run: cargo test --release -p pico-vm test_rv64_reth_simple_23993050 -- --ignored --nocapture
    #[test]
    #[ignore = "requires rv64 reth ELF + block inputs in perf/bench_data/rv64/"]
    fn test_rv64_reth_simple_23993050() {
        run_rv64_reth_block_simple(23993050);
    }
}
