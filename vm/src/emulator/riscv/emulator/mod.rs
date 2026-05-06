pub mod error;
pub mod instruction;
pub mod instruction_simple;
pub mod mode;
pub mod unconstrained;
pub mod util;

use crate::{
    chips::chips::events::{
        MemoryAccessPosition, MemoryInitializeFinalizeEvent, MemoryLocalEvent, MemoryReadRecord,
        MemoryRecord, MemoryWriteRecord,
    },
    compiler::riscv::{instruction::Instruction, program::Program, register::Register},
    emulator::{
        opts::{EmulatorOpts, SplitOpts},
        record::RecordBehavior,
        riscv::{
            chunk_split::ChunkSplitConfig,
            event_types::{RvAddr, RvChunk, RvClk, RvTimestamp, RvValue},
            hook::{default_hook_map, Hook},
            public_values::PublicValues,
            public_values_compat::{
                encode_public_value_chunk_counter, encode_public_value_pc_limbs,
            },
            record::{EmulationRecord, MemoryAccessRecord},
            state::{RiscvEmulationState, RuntimeRegisterRecord},
            syscalls::{default_syscall_map, Syscall, SyscallCode},
        },
    },
    machine::{
        estimator::{CycleEstimator, EventSizeCapture},
        field::same_field,
        report::EmulationReport,
    },
    primitives::Poseidon2Init,
};
use alloc::sync::Arc;
use hashbrown::HashMap;
use p3_baby_bear::BabyBear;
use p3_field::PrimeField32;
use p3_koala_bear::KoalaBear;
use p3_mersenne_31::Mersenne31;
use p3_symmetric::Permutation;
use serde::{Deserialize, Serialize};
use std::{sync::Mutex, time::Instant};
use tracing::{debug, error, instrument};

use crate::emulator::riscv::memory::ContiguousRiscvMemory;
pub use error::EmulationError;
pub use mode::RiscvEmulatorMode;
pub use unconstrained::UnconstrainedState;
pub use util::align_u64;

pub const MIN_MAIN_MEMORY_ADDR: u64 = 0x100;

// TODO: try parking_lot
pub type SharedDeferredState = Arc<Mutex<EmulationDeferredState>>;

/// The state for saving deferred information
pub struct EmulationDeferredState {
    flag_active: bool,
    deferred: EmulationRecord,
    pvs: PublicValues<u32, u32>,
}

impl EmulationDeferredState {
    pub(crate) fn new(program: Arc<Program>) -> Self {
        let flag_active = true;
        let deferred = EmulationRecord::new(program);
        let pvs = PublicValues::<u32, u32>::default();

        Self {
            flag_active,
            deferred,
            pvs,
        }
    }

    /// Only defer the record.
    fn defer_record(&mut self, new_record: &mut EmulationRecord) {
        self.deferred.append(&mut new_record.defer());
    }

    /// Update the public values, defer and return the record.
    fn complete_and_return_record<F>(
        &mut self,
        emulation_done: bool,
        mut new_record: EmulationRecord,
        is_trace: bool,
        defer_only: bool,
        callback: &mut F,
    ) where
        F: FnMut(EmulationRecord),
    {
        self.defer_record(&mut new_record);

        if !defer_only {
            self.update_public_values_cpu_chunk(emulation_done, &mut new_record);
        }

        // in trace mode
        if is_trace {
            callback(new_record);
        }
    }

    /// Update the public values, split and return the deferred records.
    pub fn split_and_return_deferred_records<F>(
        &mut self,
        emulation_done: bool,
        opts: SplitOpts,
        is_trace: bool,
        callback: &mut F,
        pc: u64,
    ) where
        F: FnMut(EmulationRecord),
    {
        // Get the deferred records.
        let mut records = self.deferred.split(emulation_done, opts);
        debug!("split-chunks len: {:?}", records.len());

        if emulation_done {
            if let Some(last) = records.last_mut() {
                last.is_last = true;
            }
        }

        records.into_iter().for_each(|mut r| {
            self.update_public_values_non_cpu_chunk(emulation_done, &mut r, pc);

            if is_trace {
                callback(r);
            }
        });
    }

    pub fn take_split_records(
        &mut self,
        emulation_done: bool,
        opts: SplitOpts,
    ) -> Vec<EmulationRecord> {
        let mut records = self.deferred.split(emulation_done, opts);
        debug!("split-chunks len: {:?}", records.len());
        if emulation_done {
            if let Some(last) = records.last_mut() {
                last.is_last = true;
            }
        }
        records
    }

    /// Update both the current state and record public values.
    /// This function was previously a single `update_public_values` method,
    /// but has now been split into two:
    /// - `update_public_values_cpu_chunk`: used when handling CPU chunks (e.g., from `complete_and_return_record`)
    /// - `update_public_values_non_cpu_chunk`: used for non-CPU chunks (e.g., precompile or memory chunks from `split_and_return_deferred_records`)
    ///
    /// In Simple Mode, we only need to maintain `self.pvs.chunk`, `self.pvs.execution_chunk`, and `self.flag_active`.
    /// self.pvs.start_pc and self.pvs.next_pc are maintained by emulator state.
    /// All other fields will later be overwritten correctly when in trace mode
    fn update_public_values_cpu_chunk(
        &mut self,
        _emulation_done: bool,
        record: &mut EmulationRecord,
    ) {
        self.pvs.chunk = encode_public_value_chunk_counter(self.pvs.chunk + 1);
        if !self.flag_active {
            self.flag_active = true;
        } else {
            self.pvs.execution_chunk =
                encode_public_value_chunk_counter(self.pvs.execution_chunk + 1);
        }
        // cpu chunk in Simple Mode has no cpu_events
        if !record.cpu_events.is_empty() {
            self.pvs.start_pc = encode_public_value_pc_limbs(record.cpu_events.first().unwrap().pc);
            self.pvs.next_pc =
                encode_public_value_pc_limbs(record.cpu_events.last().unwrap().next_pc);
            self.pvs.exit_code = record.cpu_events.last().unwrap().exit_code;
            self.pvs.committed_value_digest = record.public_values.committed_value_digest;
            self.pvs.deferred_proofs_digest = record.public_values.deferred_proofs_digest;
        }

        record.public_values = self.pvs;
        debug!(
            "riscv record index: {:?}, record.public_values.deferred_proofs_digest: {:?}",
            record.chunk_index(),
            record.public_values.deferred_proofs_digest
        );
    }

    fn update_public_values_non_cpu_chunk(
        &mut self,
        emulation_done: bool,
        record: &mut EmulationRecord,
        pc: u64,
    ) {
        // Stage 8 keeps the frozen 48-bit proof/public-value PC contract explicit; full-width
        // proof-side PC widening remains deferred outside this tranche.
        let pc_limbs = encode_public_value_pc_limbs(pc);
        self.pvs.chunk = encode_public_value_chunk_counter(self.pvs.chunk + 1);

        // Make execution chunk consistent.
        if self.flag_active && !emulation_done {
            self.pvs.execution_chunk =
                encode_public_value_chunk_counter(self.pvs.execution_chunk + 1);
            self.flag_active = false;
        }

        self.pvs.start_pc = pc_limbs;
        self.pvs.next_pc = pc_limbs;
        self.pvs.previous_init_addr_limbs = record.public_values.previous_init_addr_limbs;
        self.pvs.last_init_addr_limbs = record.public_values.last_init_addr_limbs;
        self.pvs.previous_finalize_addr_limbs = record.public_values.previous_finalize_addr_limbs;
        self.pvs.last_finalize_addr_limbs = record.public_values.last_finalize_addr_limbs;

        record.public_values = self.pvs;
        debug!(
            "riscv record index: {:?}, record.public_values.deferred_proofs_digest: {:?}",
            record.chunk_index(),
            record.public_values.deferred_proofs_digest
        );
    }

    #[allow(dead_code)]
    pub fn update_public_values(&mut self, emulation_done: bool, record: &mut EmulationRecord) {
        self.pvs.chunk = encode_public_value_chunk_counter(self.pvs.chunk + 1);
        if !record.cpu_events.is_empty() {
            if !self.flag_active {
                self.flag_active = true;
            } else {
                self.pvs.execution_chunk =
                    encode_public_value_chunk_counter(self.pvs.execution_chunk + 1);
            }
            self.pvs.start_pc = encode_public_value_pc_limbs(record.cpu_events.first().unwrap().pc);
            self.pvs.next_pc =
                encode_public_value_pc_limbs(record.cpu_events.last().unwrap().next_pc);
            self.pvs.exit_code = record.cpu_events.last().unwrap().exit_code;
            self.pvs.committed_value_digest = record.public_values.committed_value_digest;
            self.pvs.deferred_proofs_digest = record.public_values.deferred_proofs_digest;
        } else {
            // Make execution chunk consistent.
            if self.flag_active && !emulation_done {
                self.pvs.execution_chunk =
                    encode_public_value_chunk_counter(self.pvs.execution_chunk + 1);
                self.flag_active = false;
            }

            self.pvs.start_pc = self.pvs.next_pc;
            self.pvs.previous_init_addr_limbs = record.public_values.previous_init_addr_limbs;
            self.pvs.last_init_addr_limbs = record.public_values.last_init_addr_limbs;
            self.pvs.previous_finalize_addr_limbs =
                record.public_values.previous_finalize_addr_limbs;
            self.pvs.last_finalize_addr_limbs = record.public_values.last_finalize_addr_limbs;
        }

        record.public_values = self.pvs;
        debug!(
            "riscv record index: {:?}, record.public_values.deferred_proofs_digest: {:?}",
            record.chunk_index(),
            record.public_values.deferred_proofs_digest
        );
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

    pub par_opts: Option<ParOptions>,

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

    /// The current trace of the emulation that is being collected.
    pub record: EmulationRecord,

    /// The mapping between syscall codes and their implementations.
    pub syscall_map: HashMap<SyscallCode, Arc<dyn Syscall>>,

    /// The mapping between hook fds and their implementation
    pub hook_map: HashMap<u32, Hook>,

    /// The memory accesses for the current cycle.
    pub memory_accesses: MemoryAccessRecord,

    /// The maximum number of cycles for a syscall.
    pub max_syscall_cycles: RvClk,

    /// Shared event-based chunk splitting thresholds for the current execution mode.
    pub chunk_split_config: ChunkSplitConfig,

    /// Shared event-based counters for the current chunk.
    pub chunk_split_state: crate::emulator::riscv::chunk_split::ChunkSplitState,

    /// Local memory access events.
    pub local_memory_access: HashMap<u64, MemoryLocalEvent>,

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
}

#[derive(Clone, Copy, Default)]
pub struct ParOptions {
    pub num_threads: u32,
    pub thread_id: u32, // 0‥num_threads-1
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

/// Save the old value into memory snapshot once per touched memory address.
#[inline(always)]
fn snapshot_memory_if_needed(
    snapshot: &mut ContiguousRiscvMemory,
    addr: RvAddr,
    current_record: Option<&MemoryRecord>,
) {
    if !snapshot.has_accessed(addr) {
        let rec = current_record.copied().unwrap_or_default();
        snapshot.insert_u64(addr, rec);
    }
}

#[inline(always)]
fn compat_register_addr_u32(register: Register) -> u32 {
    // Register addresses remain an intentional narrow event/public-value boundary in the current
    // non-AOT proof pipeline because architectural registers are indexed 0..31.
    register as u32
}

impl RiscvEmulator {
    #[inline(always)]
    fn chunk_boundary_mode(&self) -> ChunkBoundaryMode {
        if self.target_global_clk.is_some() {
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
        snapshot_memory_if_needed(&mut self.memory_snapshot, addr, Some(&zero_record));
    }

    /// Convenience: build a single-thread emulator with its own shared_ds.
    #[must_use]
    pub fn new_single<F>(
        program: Arc<Program>,
        opts: EmulatorOpts,
        par_opts: Option<ParOptions>,
    ) -> Self
    where
        F: PrimeField32 + Poseidon2Init,
        F::Poseidon2: Permutation<[F; 16]>,
    {
        let deferred_state = Arc::new(Mutex::new(EmulationDeferredState::new(program.clone())));
        Self::new::<F>(program, opts, par_opts, deferred_state, false)
    }

    /// Convenience: build a snapshot-worker emulator
    #[must_use]
    pub fn new_snapshot_worker<F>(
        program: Arc<Program>,
        opts: EmulatorOpts,
        par_opts: Option<ParOptions>,
        shared_ds: SharedDeferredState,
    ) -> Self
    where
        F: PrimeField32 + Poseidon2Init,
        F::Poseidon2: Permutation<[F; 16]>,
    {
        Self::new::<F>(program, opts, par_opts, shared_ds, true)
    }

    #[must_use]
    pub fn new<F>(
        program: Arc<Program>,
        opts: EmulatorOpts,
        par_opts: Option<ParOptions>,
        deferred_state: SharedDeferredState,
        defer_only: bool,
    ) -> Self
    where
        F: PrimeField32 + Poseidon2Init,
        F::Poseidon2: Permutation<[F; 16]>,
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

        let mut emu = Self {
            syscall_map,
            hook_map,
            memory_accesses: Default::default(),
            record,
            state: RiscvEmulationState::new(program.pc_start),
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
            local_memory_access: Default::default(),
            mode: RiscvEmulatorMode::Trace,
            stdout: Default::default(),
            stderr: Default::default(),
            cycle_tracker: Default::default(),
            cycle_tracker_requests: Default::default(),
            target_global_clk: None,
            deferred_state,
            defer_only,
            log_syscalls,
            par_opts,
            emu_fn: RiscvEmulator::emulate_instruction,
            field: if same_field::<F, BabyBear, 4>() {
                "BabyBear"
            } else if same_field::<F, KoalaBear, 4>() {
                "KoalaBear"
            } else if same_field::<F, Mersenne31, 3>() {
                "Mersenne31"
            } else {
                panic!("Unsupported field type");
            },
        };

        emu.update_mode_deps();
        emu
    }

    /// If it's the first cycle, initialize the program.
    /// Pairs adjacent 4-byte entries from memory_image into 8-byte dwords.
    #[inline(always)]
    fn initialize_if_needed(&mut self) {
        if self.state.global_clk == 0 {
            self.state.clk = 0;
            debug!("loading memory image");
            for (addr, value) in self.program.memory_image.iter() {
                self.state.memory.insert(
                    *addr,
                    MemoryRecord {
                        value: *value,
                        chunk: 0,
                        timestamp: 0,
                    },
                );
            }
        }
    }

    /// Set the emulator mode based on current chunk and parallelism config.
    fn set_mode_by_chunk(&mut self, current_chunk: u32) {
        if let Some(par) = self.par_opts {
            let is_my_chunk = (current_chunk % par.num_threads) == par.thread_id;
            self.mode = if is_my_chunk {
                RiscvEmulatorMode::Trace
            } else {
                RiscvEmulatorMode::Simple
            };
            debug!(
                "thread[{}], self.mode in chunk {}: {:?}",
                par.thread_id, current_chunk, self.mode
            );
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
            log::info!("stdout (remaining)> {}", &self.stdout);
            self.stdout.clear();
        }
        if !self.stderr.is_empty() {
            log::info!("stderr (remaining)> {}", &self.stderr);
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

        if !self.is_unconstrained() {
            match self.chunk_boundary_mode() {
                ChunkBoundaryMode::ReplayToTarget => {
                    if let Some(target_global_clk) = self.target_global_clk {
                        if self.state.global_clk >= target_global_clk {
                            debug_assert_eq!(
                                self.state.global_clk, target_global_clk,
                                "snapshot worker overshot target_global_clk"
                            );
                            self.chunk_split_state.clear();
                            self.state.current_chunk += 1;
                            self.state.clk = 0;

                            let elapsed = last_record_time.elapsed();
                            let tid = self.par_opts.unwrap_or_default().thread_id;

                            debug!(
                                "Record[{}] generated in {:.3} ms, thread_id: {}",
                                self.state.current_chunk,
                                elapsed.as_secs_f64() * 1000.0,
                                tid
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
                    // Check if there's enough cycles or move to the next chunk.
                    self.chunk_split_state.clear();
                    self.state.current_chunk += 1;
                    self.state.clk = 0;

                    let elapsed = last_record_time.elapsed();
                    let tid = self.par_opts.unwrap_or_default().thread_id;

                    debug!(
                        "Record[{}] generated in {:.3} ms, thread_id: {}",
                        self.state.current_chunk,
                        elapsed.as_secs_f64() * 1000.0,
                        tid
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

        if !self.is_unconstrained() {
            match self.chunk_boundary_mode() {
                ChunkBoundaryMode::ReplayToTarget => {
                    if let Some(target_global_clk) = self.target_global_clk {
                        if self.state.global_clk >= target_global_clk {
                            debug_assert_eq!(self.state.global_clk, target_global_clk);
                            self.chunk_split_state.clear();
                            self.state.current_chunk += 1;
                            self.state.clk = 0;
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
                    self.chunk_split_state.clear();
                    self.state.current_chunk += 1;
                    self.state.clk = 0;
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

        // Set mode for the first chunk
        self.set_mode_by_chunk(current_chunk);
        self.update_mode_deps();

        let mut last_record_time = Instant::now();

        let mut is_trace_mode = matches!(self.mode, RiscvEmulatorMode::Trace);

        // Loop until we've emulated CHUNK_BATCH_SIZE chunks.
        loop {
            if self.emulate_cycle(
                |done, new_record| {
                    deferred_state.lock().unwrap().complete_and_return_record(
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

            if self.opts.chunk_batch_size > 0 && current_chunk != self.state.current_chunk {
                num_chunks_emulated += 1;
                current_chunk = self.state.current_chunk;
                // Set mode for each chunk
                self.set_mode_by_chunk(current_chunk);
                self.update_mode_deps();
                is_trace_mode = matches!(self.mode, RiscvEmulatorMode::Trace);

                if num_chunks_emulated == self.opts.chunk_batch_size {
                    break;
                }
            }
        }
        debug!("emulate - global clk {}", self.state.global_clk);

        let is_trace = matches!(self.mode, RiscvEmulatorMode::Trace);
        if !self.record.cpu_events.is_empty() {
            self.bump_record(done, |done, new_record| {
                deferred_state.lock().unwrap().complete_and_return_record(
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
                    deferred_state.lock().unwrap().defer_record(&mut new_record);
                });
            }

            // output any remaining information
            self.flush();
        } else {
            self.state.current_batch += 1;
        }

        if !defer_only {
            deferred_state
                .lock()
                .unwrap()
                .split_and_return_deferred_records(
                    done,
                    self.opts.split_opts,
                    is_trace,
                    &mut real_callback,
                    self.state.pc,
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
                    deferred_state.lock().unwrap().complete_and_return_record(
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

        if !self.record.cpu_events.is_empty() {
            self.bump_record(done, |done, new_record| {
                deferred_state.lock().unwrap().complete_and_return_record(
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
                    deferred_state.lock().unwrap().defer_record(&mut new_record);
                });
                if !self.defer_only {
                    deferred_state
                        .lock()
                        .unwrap()
                        .split_and_return_deferred_records(
                            done,
                            self.opts.split_opts,
                            self.mode == RiscvEmulatorMode::Trace,
                            &mut real_callback,
                            self.state.pc,
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
        let mut snapshot = self.state.clone_without_memory();

        println!(
            "state clone duration: {:?}ms",
            t_clone.elapsed().as_secs_f64() * 1000.0
        );

        let t_emu_snapshot = Instant::now();
        let report = self.emulate_batch_snapshot_main(record_callback)?;
        println!(
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

        println!(
            "state mem rollback duration: {:?}ms",
            t_rollback.elapsed().as_secs_f64() * 1000.0
        );
        // TODO: handle public values properly (COMMIT syscall across chunks )

        Ok((snapshot, report))
    }

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
        let local_access = local_memory_access.unwrap_or(&mut self.local_memory_access);

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

        snapshot_memory_if_needed(&mut self.memory_snapshot, addr, Some(&prev_record));
        self.mode
            .add_unconstrained_memory_record(addr, Some(&prev_record));

        let final_record = MemoryRecord {
            value,
            chunk,
            timestamp,
        };

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
        snapshot_memory_if_needed(&mut self.memory_snapshot, addr, Some(&prev_record));

        MemoryReadRecord::new(value, chunk, timestamp, prev_chunk, prev_timestamp)
    }

    /// Write a dword to memory and create an access record.
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
        let local_access = local_memory_access.unwrap_or(&mut self.local_memory_access);

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

        snapshot_memory_if_needed(&mut self.memory_snapshot, addr, Some(&prev_record));
        self.mode
            .add_unconstrained_memory_record(addr, Some(&prev_record));

        let final_record = MemoryRecord {
            value,
            chunk,
            timestamp,
        };

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

        snapshot_memory_if_needed(&mut self.memory_snapshot, addr, Some(&prev_record));
    }

    /// Read from memory, assuming that all addresses are aligned.
    pub fn mr_cpu(&mut self, addr: RvAddr, position: MemoryAccessPosition) -> RvValue {
        // Read the address from memory and create a memory read record.
        let record = self.mr(addr, self.chunk(), self.timestamp(&position), None);

        // If we're not in unconstrained mode, record the access for the current cycle.
        self.mode
            .set_memory_access(position, record.into(), &mut self.memory_accesses);

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
    pub fn mw_cpu(&mut self, addr: RvAddr, value: RvValue, position: MemoryAccessPosition) {
        // Read the address from memory and create a memory read record.
        let record = self.mw(addr, value, self.chunk(), self.timestamp(&position), None);

        // If we're not in unconstrained mode, record the access for the current cycle.
        self.mode
            .set_memory_access(position, record.into(), &mut self.memory_accesses);
    }

    pub fn mw_cpu_simple(&mut self, addr: RvAddr, value: RvValue, position: MemoryAccessPosition) {
        // Read the address from memory and create a memory read record.
        self.mw_simple(addr, value, self.chunk(), self.timestamp(&position), None);
    }

    #[inline(always)]
    fn snapshot_register_if_needed(&mut self, reg_idx: u32, prev_record: &RuntimeRegisterRecord) {
        let mask = 1u32 << reg_idx;
        if (self.register_snapshot_bitmap & mask) == 0 {
            self.register_snapshot[reg_idx as usize] = *prev_record;
            self.register_snapshot_bitmap |= mask;
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
            self.mode.add_memory_local_event(
                u64::from(reg_idx),
                final_record,
                prev_record,
                &mut self.local_memory_access,
            );
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
                .set_memory_access(position, record.into(), &mut self.memory_accesses);
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
            self.mode.add_memory_local_event(
                u64::from(reg_idx),
                final_record,
                prev_record,
                &mut self.local_memory_access,
            );
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
                .set_memory_access(position, record.into(), &mut self.memory_accesses);
        }
    }

    /// Read from a register.
    pub fn rr(&mut self, register: Register, position: MemoryAccessPosition) -> RvValue {
        self.read_register_common(
            compat_register_addr_u32(register),
            position,
            true,
            true,
            true,
        )
    }

    /// Write to a register.
    pub fn rw(&mut self, register: Register, value: RvValue) {
        // The only time we are writing to a register is when it is in operand A.
        // Register %x0 should always be 0. See 2.6 Load and Store Instruction on
        // P.18 of the RISC-V spec. We always write 0 to %x0.
        let reg_idx = compat_register_addr_u32(register);
        let value = if register == Register::X0 { 0 } else { value };
        self.write_register_common(reg_idx, value, MemoryAccessPosition::A, true, true, true);
    }

    pub fn rw_simple(&mut self, register: Register, value: RvValue) {
        // The only time we are writing to a register is when it is in operand A.
        // Register %x0 should always be 0. See 2.6 Load and Store Instruction on
        // P.18 of the RISC-V spec. We always write 0 to %x0.
        let reg_idx = compat_register_addr_u32(register);
        let value = if register == Register::X0 { 0 } else { value };
        self.write_register_common(reg_idx, value, MemoryAccessPosition::A, false, false, false);
    }

    // This fn is only used for ENTER_UNCONSTRAINED syscall in simple mode
    pub fn rw_unconstrained(&mut self, register: Register, value: u64) {
        let addr = compat_register_addr_u32(register);
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
            compat_register_addr_u32(register),
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

    /// Recover emulator state from a program and existing emulation state.
    #[must_use]
    pub fn recover<F>(
        program: Arc<Program>,
        state: RiscvEmulationState,
        opts: EmulatorOpts,
        shared_ds: SharedDeferredState,
        target_global_clk: u64,
    ) -> Self
    where
        F: PrimeField32 + Poseidon2Init,
        F::Poseidon2: Permutation<[F; 16]>,
    {
        let mut runtime = Self::new_snapshot_worker::<F>(program, opts, None, shared_ds);
        runtime.state = state;
        runtime.target_global_clk = Some(target_global_clk);
        runtime
    }

    /// Get the current values of the registers.
    #[allow(clippy::single_match_else)]
    #[must_use]
    pub fn registers(&mut self) -> [RvValue; 32] {
        let mut registers = [0; 32];
        for i in 0..32 {
            let addr = compat_register_addr_u32(Register::from_u8(i as u8));
            let record = self.state.registers[addr as usize];
            self.snapshot_register_if_needed(addr, &record);
            registers[i] = record.value;
        }
        registers
    }

    /// Get the current value of a register.
    #[must_use]
    pub fn register(&mut self, register: Register) -> RvValue {
        let addr = compat_register_addr_u32(register);
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
        snapshot_memory_if_needed(&mut self.memory_snapshot, addr, Some(&record));
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
        // Copy all of the existing local memory accesses to the record's local_memory_access vec.
        self.mode.copy_local_memory_events(
            &mut self.local_memory_access,
            &mut self.record.cpu_local_memory_access,
        );

        let removed_record =
            std::mem::replace(&mut self.record, EmulationRecord::new(self.program.clone()));
        let public_values = removed_record.public_values;
        self.record.public_values = public_values;

        // Return the record.
        record_callback(emulation_done, removed_record);
    }

    fn postprocess(&mut self) {
        // Ensure that all proofs and input bytes were read...
        if self.state.input_stream_ptr != self.state.input_stream.len() {
            tracing::warn!("Not all input bytes were read.");
        }
        // helper
        // For registers, the timestamp cannot be 0
        let is_used =
            |rec: &RuntimeRegisterRecord| rec.value != 0 || rec.timestamp != 0 || rec.chunk != 0;

        let memory_finalize_events = &mut self.record.memory_finalize_events;
        let memory_initialize_events = &mut self.record.memory_initialize_events;

        // We handle x0 separately, as we constrain it to be 0 in the first row
        // of the memory finalize table so it must be first in the array of events.
        let addr_0_record = self.state.registers[0];
        let default_0_rec = RuntimeRegisterRecord {
            value: 0,
            chunk: 0,
            timestamp: 1,
        };

        let (addr_0_final_record, used_0) = if is_used(&addr_0_record) {
            (&addr_0_record, true)
        } else {
            (&default_0_rec, false)
        };

        let addr_0_final_record = MemoryRecord {
            value: addr_0_final_record.value,
            chunk: addr_0_final_record.chunk,
            timestamp: addr_0_final_record.timestamp,
        };
        memory_finalize_events.push(MemoryInitializeFinalizeEvent::finalize_from_record(
            0,
            &addr_0_final_record,
        ));

        let addr_0_initialize_event = MemoryInitializeFinalizeEvent::initialize(0, 0, used_0);
        memory_initialize_events.push(addr_0_initialize_event);

        // Handle x1..x31 registers from dedicated register storage.
        for reg in 1..32 {
            let addr = reg as u64;
            let is_in_image = self.record.program.memory_image.contains_key(&addr);
            debug_assert!(
                !is_in_image,
                "register address unexpectedly in memory_image: 0x{addr:08x}"
            );
            let record = self.state.registers[reg];
            if is_used(&record) {
                if !is_in_image {
                    let initial_value = self.state.uninitialized_memory.get(addr).unwrap_or(&0);
                    memory_initialize_events.push(MemoryInitializeFinalizeEvent::initialize(
                        addr,
                        *initial_value,
                        true,
                    ));
                }
                let record = MemoryRecord {
                    value: record.value,
                    chunk: record.chunk,
                    timestamp: record.timestamp,
                };
                memory_finalize_events.push(MemoryInitializeFinalizeEvent::finalize_from_record(
                    addr, &record,
                ));
            }
        }

        // =========================================================
        // Handle main memory
        // =========================================================
        // accessed_addrs = the union set of (memory_image_addrs, global_accessed_addrs)
        let accessed_addrs: Vec<RvAddr> = self.state.memory.accessed_keys().collect();
        debug!("postprocess: accessed_addrs len: {}", accessed_addrs.len());
        for addr in accessed_addrs {
            if addr < MIN_MAIN_MEMORY_ADDR {
                continue;
            }

            // With 8-byte-aligned addresses, check if either 4-byte half is in the image.
            let lo_in_image = self.record.program.memory_image.contains_key(&addr);
            let hi_in_image = self.record.program.memory_image.contains_key(&(addr + 4));
            let is_in_image = lo_in_image || hi_in_image;
            // Program memory is initialized in the MemoryProgram chip and doesn't require any
            // events, so we only send init events for other memory addresses.
            if !is_in_image {
                let initial_value = self.state.uninitialized_memory.get(addr).unwrap_or(&0);
                memory_initialize_events.push(MemoryInitializeFinalizeEvent::initialize(
                    addr,
                    *initial_value,
                    true,
                ));
            }

            let record = self.state.memory.get(addr);
            memory_finalize_events.push(MemoryInitializeFinalizeEvent::finalize_from_record(
                addr, &record,
            ));
        }

        // =========================================================
        // DEBUG: Print all memory events for comparison
        // Enable with: DEBUG_MEMORY_EVENTS=1
        // =========================================================
        if std::env::var("DEBUG_MEMORY_EVENTS").is_ok() {
            let mut sorted_program_memory: Vec<_> =
                self.record.program.memory_image.iter().collect();
            sorted_program_memory.sort_by_key(|(addr, _)| **addr);
            eprintln!(
                "\n========== PROGRAM MEMORY IMAGE ({}) ==========",
                sorted_program_memory.len()
            );
            for (i, (addr, value)) in sorted_program_memory.iter().enumerate() {
                eprintln!(
                    "[PROG {:4}] addr=0x{:08x} ({:10}), value=0x{:08x}",
                    i, addr, addr, value
                );
            }

            eprintln!(
                "\n========== MEMORY INITIALIZE EVENTS ({}) ==========",
                memory_initialize_events.len()
            );
            for (i, evt) in memory_initialize_events.iter().enumerate() {
                eprintln!(
                    "[INIT {:4}] addr=0x{:08x} ({:10}), value=0x{:08x}, chunk={}, ts={}, used={}",
                    i, evt.addr, evt.addr, evt.value, evt.chunk, evt.timestamp, evt.used
                );
            }

            eprintln!(
                "\n========== MEMORY FINALIZE EVENTS ({}) ==========",
                memory_finalize_events.len()
            );
            for (i, evt) in memory_finalize_events.iter().enumerate() {
                eprintln!(
                    "[FINAL {:4}] addr=0x{:08x} ({:10}), value=0x{:08x}, chunk={}, ts={}, used={}",
                    i, evt.addr, evt.addr, evt.value, evt.chunk, evt.timestamp, evt.used
                );
            }

            eprintln!("\n========== ALIGNMENT CHECK ==========");
            let prog_set: std::collections::HashSet<u64> =
                sorted_program_memory.into_iter().map(|(k, _)| *k).collect();
            let init_set: std::collections::HashSet<u64> =
                memory_initialize_events.iter().map(|e| e.addr).collect();
            let final_set: std::collections::HashSet<u64> =
                memory_finalize_events.iter().map(|e| e.addr).collect();

            let mut all_addrs: Vec<RvAddr> = final_set.iter().cloned().collect();
            all_addrs.extend(prog_set.iter());
            all_addrs.extend(init_set.iter());
            all_addrs.sort();
            all_addrs.dedup();

            for addr in all_addrs {
                let p = prog_set.contains(&addr);
                let i = init_set.contains(&addr);
                let f = final_set.contains(&addr);

                if p && i {
                    eprintln!(
                        "WARN: Addr 0x{:08x} is in BOTH Program Image and Init Events",
                        addr
                    );
                }
                if f && !p && !i {
                    eprintln!(
                        "WARN: Addr 0x{:08x} is in Finalize but NEITHER Program nor Init",
                        addr
                    );
                }
                if i && !f {
                    eprintln!("WARN: Addr 0x{:08x} is in Init but NOT Finalize (might be 0 or unaccessed?)", addr);
                }
                if p && !f {
                    eprintln!("WARN: Addr 0x{:08x} is in Program Image but NOT Finalize (Should imply accessed!)", addr);
                }
            }
            eprintln!("========== END MEMORY EVENTS ==========\n");

            // DEBUG: Compare MemoryLocal initial_mem_access with MemoryInitialize
            if std::env::var("DEBUG_LOCAL_MEMORY").is_ok() {
                eprintln!(
                    "\n========== MEMORY LOCAL EVENTS (checking initial_mem_access) =========="
                );
                let local_events = self.record.cpu_local_memory_access.iter();
                for evt in local_events {
                    let is_in_image = self.record.program.memory_image.contains_key(&evt.addr);
                    let actual_init = (
                        evt.initial_mem_access.chunk,
                        evt.initial_mem_access.timestamp,
                    );

                    // For non-program-memory addresses, MemoryInitialize sends (0,0)
                    // For program-memory addresses, MemoryProgram chip handles it (also sends 0,0)
                    // So initial should ALWAYS be (0,0) for the FIRST access in a chunk
                    if actual_init != (0, 0) {
                        eprintln!(
                            "NON-ZERO INIT: addr=0x{:08x}, initial=({}, {}), value={}, in_image={}",
                            evt.addr,
                            actual_init.0,
                            actual_init.1,
                            evt.initial_mem_access.value,
                            is_in_image
                        );
                    }
                }
                eprintln!("========== END MEMORY LOCAL CHECK ==========\n");
            }
        }
    }

    /// Collect signatures from memory between the given begin and end addresses.
    ///
    /// The guest-facing address surface is RV64, but the signature collection format remains the
    /// retained legacy 32-bit word stream used by the current proverchain harness.
    pub fn collect_signatures(&mut self, begin: RvAddr, end: RvAddr) -> Vec<RvValue> {
        if begin >= end {
            return Vec::new();
        }

        let size = usize::try_from(end - begin).unwrap_or_else(|_| {
            panic!("collect_signatures range too large: begin={begin}, end={end}")
        });
        let mut signatures = Vec::with_capacity(size / 4);

        for offset in (0..size).step_by(4) {
            let addr = begin + offset as u64;
            let word = self.word(addr);
            signatures.push(word);
        }

        signatures
    }
}

#[cfg(test)]
mod tests {
    use super::{Program, RiscvEmulator};
    use crate::{
        compiler::riscv::{
            compiler::{Compiler, SourceType},
            instruction::Instruction,
            opcode::Opcode,
            register::Register,
        },
        configs::stark_config::KoalaBearPoseidon2,
        emulator::{opts::EmulatorOpts, riscv::state::RuntimeRegisterRecord, stdin::EmulatorStdin},
    };
    use alloc::sync::Arc;
    use p3_baby_bear::BabyBear;

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

    fn tiny_program() -> Arc<Program> {
        Arc::new(Program::new(
            vec![
                r_type(Opcode::ADD, Register::X0, Register::X0, Register::X0),
                r_type(Opcode::ADD, Register::X0, Register::X0, Register::X0),
            ],
            0x1000,
            0x1000,
        ))
    }

    const MAX_FIBONACCI_NUM_IN_ONE_CHUNK: u32 = 836789u32;

    #[test]
    fn snapshot_worker_stops_at_target_global_clk_before_cycle_rollover() {
        let opts = EmulatorOpts {
            chunk_size: 16,
            chunk_batch_size: 1,
            max_cycles: Some(64),
            ..EmulatorOpts::default()
        };
        let mut emulator = RiscvEmulator::new_single::<BabyBear>(tiny_program(), opts, None);
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
        assert_eq!(emulator.state.clk, 0);
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
        let mut emulator = RiscvEmulator::new_single::<BabyBear>(tiny_program(), opts, None);
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
        assert_eq!(emulator.state.clk, 0);
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
        let mut emulator = RiscvEmulator::new_single::<BabyBear>(tiny_program(), opts, None);
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
        assert_eq!(emulator.state.clk, 0);
        assert_eq!(emulator.state.pc, 0x1004);
        assert_eq!(records, 1);
        assert_eq!(emulator.chunk_split_state.num_memory_read_write_events, 0);
        assert_eq!(emulator.chunk_split_state.num_global_lookup_base, 0);
    }

    #[test]
    #[ignore = "RV32 ELF — not supported under RV64-only emulator"]
    fn test_simple_fib() {
        // just run a simple elf file in the compiler folder(test_elf)
        let program = simple_fibo_program();
        let mut stdin = EmulatorStdin::<Program, Vec<u8>>::new_builder::<KoalaBearPoseidon2>();
        stdin.write(&MAX_FIBONACCI_NUM_IN_ONE_CHUNK);
        let mut emulator =
            RiscvEmulator::new_single::<BabyBear>(program, EmulatorOpts::default(), None);
        let (stdin, _) = stdin.finalize();
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
        let mut emulator =
            RiscvEmulator::new_single::<BabyBear>(program, EmulatorOpts::default(), None);
        let (stdin, _) = stdin.finalize();
        emulator.run(Some(stdin)).unwrap();
        // println!("{:x?}", emulator.state.public_values_stream)
    }

    #[test]
    fn test_phase2a_register_and_memory_paths_are_explicit() {
        let program = simple_fibo_program();
        let mut emulator =
            RiscvEmulator::new_single::<BabyBear>(program, EmulatorOpts::default(), None);

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
        let mut emulator =
            RiscvEmulator::new_single::<BabyBear>(program, EmulatorOpts::default(), None);

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
        let mut emulator =
            RiscvEmulator::new_single::<BabyBear>(program, EmulatorOpts::default(), None);

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
        let mut emulator =
            RiscvEmulator::new_single::<BabyBear>(program, EmulatorOpts::default(), None);
        emulator.mode = super::RiscvEmulatorMode::Simple;
        emulator.update_mode_deps();

        emulator.rw_simple(Register::X6, 0x1234_5678);
        let _ = emulator.rr_simple(
            Register::X6,
            crate::chips::chips::events::MemoryAccessPosition::B,
        );

        assert!(emulator.local_memory_access.is_empty());
    }

    #[test]
    fn test_register_and_memory_are_isolated() {
        let program = simple_fibo_program();
        let mut emulator =
            RiscvEmulator::new_single::<BabyBear>(program, EmulatorOpts::default(), None);

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
        let mut emulator =
            RiscvEmulator::new_single::<BabyBear>(program, EmulatorOpts::default(), None);

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
        let mut emulator =
            RiscvEmulator::new_single::<BabyBear>(program, EmulatorOpts::default(), None);
        let _ = emulator.word(0xFC);
    }

    #[test]
    fn test_register_snapshot_is_consumed_during_rollback() {
        let program = simple_fibo_program();
        let mut emulator =
            RiscvEmulator::new_single::<BabyBear>(program, EmulatorOpts::default(), None);

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
        let mut emulator =
            RiscvEmulator::new_single::<BabyBear>(program, EmulatorOpts::default(), None);

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
        let mut emulator =
            RiscvEmulator::new_single::<BabyBear>(program, EmulatorOpts::default(), None);

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

    #[test]
    fn test_phase_3r5_cpu_event_payload_preserves_rv64_ld_sd_values() {
        let program = simple_fibo_program();
        let mut emulator =
            RiscvEmulator::new_single::<BabyBear>(program, EmulatorOpts::default(), None);

        set_reg_raw(&mut emulator, Register::X1, 0x1000);
        set_reg_raw(&mut emulator, Register::X2, 0xCAFE_BABE_DEAD_BEEF);

        emulator
            .emulate_instruction(&s_type(Opcode::SD, Register::X2, Register::X1, 0))
            .unwrap();
        let sd_event = emulator.record.cpu_events.last().unwrap();
        assert_eq!(sd_event.a, 0xCAFE_BABE_DEAD_BEEF);
        assert_eq!(sd_event.memory, Some(0xCAFE_BABE_DEAD_BEEF));

        emulator
            .emulate_instruction(&i_type(Opcode::LD, Register::X3, Register::X1, 0))
            .unwrap();
        let ld_event = emulator.record.cpu_events.last().unwrap();
        assert_eq!(ld_event.a, 0xCAFE_BABE_DEAD_BEEF);
        assert_eq!(ld_event.memory, Some(0xCAFE_BABE_DEAD_BEEF));
    }

    #[test]
    fn test_phase_3r5_cpu_event_payload_preserves_rv64_w_op_values() {
        let program = simple_fibo_program();
        let mut emulator =
            RiscvEmulator::new_single::<BabyBear>(program, EmulatorOpts::default(), None);

        set_reg_raw(&mut emulator, Register::X5, 0xAAAA_BBBB_FFFF_FFFF);
        set_reg_raw(&mut emulator, Register::X6, 1);
        emulator
            .emulate_instruction(&r_type(
                Opcode::ADDW,
                Register::X7,
                Register::X5,
                Register::X6,
            ))
            .unwrap();
        let addw_event = emulator.record.cpu_events.last().unwrap();
        assert_eq!(addw_event.a, 0);
        assert_eq!(addw_event.b, 0xAAAA_BBBB_FFFF_FFFF);
        assert_eq!(addw_event.c, 1);
    }

    #[test]
    fn test_phase_3r6_alu_event_payload_preserves_rv64_w_op_operands() {
        let program = simple_fibo_program();
        let mut emulator =
            RiscvEmulator::new_single::<BabyBear>(program, EmulatorOpts::default(), None);

        set_reg_raw(&mut emulator, Register::X5, 0xAAAA_BBBB_FFFF_FFFF);
        set_reg_raw(&mut emulator, Register::X6, 1);
        emulator
            .emulate_instruction(&r_type(
                Opcode::ADDW,
                Register::X7,
                Register::X5,
                Register::X6,
            ))
            .unwrap();
        let addw_event = emulator.record.add_events.last().unwrap();
        assert_eq!(addw_event.a, 0);
        assert_eq!(addw_event.b, 0xAAAA_BBBB_FFFF_FFFF);
        assert_eq!(addw_event.c, 1);
    }

    #[test]
    fn test_phase_3r6_alu_event_payload_preserves_rv64_w_op_result() {
        let program = simple_fibo_program();
        let mut emulator =
            RiscvEmulator::new_single::<BabyBear>(program, EmulatorOpts::default(), None);

        set_reg_raw(&mut emulator, Register::X5, 0xFFFF_FFFF_8000_0001);
        set_reg_raw(&mut emulator, Register::X6, 0);
        emulator
            .emulate_instruction(&r_type(
                Opcode::DIVUW,
                Register::X7,
                Register::X5,
                Register::X6,
            ))
            .unwrap();
        let divuw_event = emulator.record.divrem_events.last().unwrap();
        assert_eq!(divuw_event.a, u64::MAX);
        assert_eq!(divuw_event.b, 0xFFFF_FFFF_8000_0001);
        assert_eq!(divuw_event.c, 0);
    }

    #[test]
    fn test_phase_3r6_alu_event_payload_preserves_rv64_mulw_inputs() {
        let program = simple_fibo_program();
        let mut emulator =
            RiscvEmulator::new_single::<BabyBear>(program, EmulatorOpts::default(), None);

        set_reg_raw(&mut emulator, Register::X5, 0x1234_5678_FFFF_FFFE);
        set_reg_raw(&mut emulator, Register::X6, 0xAAAA_BBBB_0000_0002);
        emulator
            .emulate_instruction(&r_type(
                Opcode::MULW,
                Register::X7,
                Register::X5,
                Register::X6,
            ))
            .unwrap();
        let mulw_event = emulator.record.mul_events.last().unwrap();
        assert_eq!(mulw_event.b, 0x1234_5678_FFFF_FFFE);
        assert_eq!(mulw_event.c, 0xAAAA_BBBB_0000_0002);
    }

    #[test]
    fn test_phase_3r3_lwu_ld_sd_alignment_errors() {
        let program = simple_fibo_program();
        let mut emulator =
            RiscvEmulator::new_single::<BabyBear>(program, EmulatorOpts::default(), None);

        // Use addresses in different 8-byte dwords to avoid timestamp collisions
        // (failed instructions don't advance the clock but still touch memory metadata).
        set_reg_raw(&mut emulator, Register::X1, 0x1002);
        let err = emulator
            .emulate_instruction(&i_type(Opcode::LWU, Register::X4, Register::X1, 0))
            .unwrap_err();
        assert!(matches!(
            err,
            super::EmulationError::InvalidMemoryAccess(Opcode::LWU, 0x1002)
        ));

        // Use 0x2004 (different 8-byte dword than 0x1002) to avoid timestamp conflict.
        set_reg_raw(&mut emulator, Register::X1, 0x2004);
        let err = emulator
            .emulate_instruction(&i_type(Opcode::LD, Register::X4, Register::X1, 0))
            .unwrap_err();
        assert!(matches!(
            err,
            super::EmulationError::InvalidMemoryAccess(Opcode::LD, 0x2004)
        ));

        set_reg_raw(&mut emulator, Register::X1, 0x3004);
        set_reg_raw(&mut emulator, Register::X2, 0xAABB_CCDD_EEFF_0011);
        let err = emulator
            .emulate_instruction(&s_type(Opcode::SD, Register::X2, Register::X1, 0))
            .unwrap_err();
        assert!(matches!(
            err,
            super::EmulationError::InvalidMemoryAccess(Opcode::SD, 0x3004)
        ));
    }

    #[test]
    fn test_phase_3r3_trace_simple_parity_for_rv64_ops() {
        let program = simple_fibo_program();
        let mut trace_emulator =
            RiscvEmulator::new_single::<BabyBear>(program.clone(), EmulatorOpts::default(), None);
        let mut simple_emulator =
            RiscvEmulator::new_single::<BabyBear>(program, EmulatorOpts::default(), None);

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
        let mut emulator =
            RiscvEmulator::new_single::<BabyBear>(program, EmulatorOpts::default(), None);
        let (stdin, _) = stdin.finalize();
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
        let (stdin, _) = stdin.finalize();

        let mut emulator =
            RiscvEmulator::new_single::<BabyBear>(program, EmulatorOpts::default(), None);
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
        let (stdin, _) = stdin.finalize();

        let mut emulator =
            RiscvEmulator::new_single::<BabyBear>(program, EmulatorOpts::default(), None);
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
        let mut emulator =
            RiscvEmulator::new_single::<BabyBear>(program, EmulatorOpts::default(), None);
        emulator.run(None).unwrap();

        assert_eq!(emulator.chunk_split_state.num_memory_read_write_events, 1);
    }

    #[test]
    fn jalr_to_x0_counts_chunk_split_event() {
        let program =
            single_instruction_program(Instruction::new(Opcode::JALR, 0, 1, 0, false, true));
        let mut emulator =
            RiscvEmulator::new_single::<BabyBear>(program, EmulatorOpts::default(), None);
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
