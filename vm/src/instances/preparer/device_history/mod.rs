//! A chunk's execution history on the device, and the program table its kernels read
//! instructions from.
//!
//! [`DeviceProgram`]: one instruction table per program and device, uploaded once and cached under
//! the program's content key, which every fill names. Consumers wait on its upload event, and the
//! cache publishes an entry only once that event is recorded: a wait on an event not yet recorded
//! waits for nothing.
//!
//! [`DeviceHistory`]: one fill per chunk (laid out by `history_fill`, copied by [`plan`]) in a pool
//! allocation made on the owner stream. The upload enqueues, in the order the kernels need:
//! - on the owner stream, the error word's zeroing and the descriptor with the exceptions behind
//!   it, then the descriptor event, which every reader waits on: no kernel may set the error word
//!   before it is zeroed;
//! - each CPU slice on one of two copy streams in turn, each stream first waiting on the
//!   allocation, then that slice's event, which the slice's kernel waits on and nothing later;
//! - on the owner stream, the chip lists and the syscall rows, then a join of both copy streams,
//!   the completion word and the completion event, which every other kernel waits on. The join is
//!   of the slices' copies, not their kernels, so no chip waits behind the CPU chip's kernel.
//!
//! The tables are copied from the history's arena slot when it holds one, and nothing after the
//! join from the host, so such an upload returns once it is enqueued: the trace generator waits
//! for no copy, and each CPU slice's kernel starts as its slice lands. A table on the heap is
//! staged by the driver, which may hold the host until the copy's stream reaches it.
//!
//! A test of the CPU chip's ordering (`riscv_cpu::traces::ordering_edge`, built only with the
//! `drop-ordering-edge` feature) may hold the descriptor back and drop its wait, land the
//! completion word without the join, or let the slot go without its fence; every other build
//! orders the upload as above. The trace oracle's positive control may change one row on the owner
//! stream behind every copy and the completion word ([`DeviceHistory::overwrite_row`]), recording
//! every readiness event again behind it before any reader is made.
//!
//! A kernel reads the fill only through a [`HistoryReader`] made on its stream: making one makes
//! the stream wait for what its [`Readiness`] needs, and dropping it records a mark on the stream.
//! The error word's read-back ([`DeviceHistory::finish`]) and the buffer's free follow every mark
//! and every copy on the owner stream, never a wrapper's return: a wrapper with no host wait has
//! only enqueued its kernels when it returns. The arena slot the fill was copied from is held
//! until those copies have run ([`HistoryTables::hold_slot_until`]); it goes back when its record
//! drops.

pub mod plan;

use std::{
    marker::PhantomData,
    mem::offset_of,
    ops::Deref,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex, PoisonError,
    },
};

use cudart::{
    event::{CudaEvent, CudaEventCreateFlags},
    memory::DeviceAllocation,
    memory_pools::{CudaMemPool, DevicePoolAllocation},
    slice::{CudaSlice, CudaSliceMut},
    stream::{CudaStream, CudaStreamCreateFlags, CudaStreamWaitEventFlags},
};
use cudart_sys::{cudaMemcpyAsync, cudaMemsetAsync, CudaError, CudaMemoryCopyKind};

use crate::{
    chips::chips::riscv_cpu::traces::ordering_edge::{self, Edge},
    compiler::riscv::{instruction::Instruction, program::Program},
    emulator::riscv::{
        history_arena::{DeviceReadsDone, HistoryTables, Table, ROW_SHAPES},
        history_fill::{
            check_exceptions, describe_errors, program_key, program_rows, DerivedRows,
            FillDescriptor, FillIdentity, HistoryArgs, ProgramTable,
        },
    },
    mle::{machine::trace_oracle::poison, spans::device},
};
use plan::{DecodedFill, Piece, PlanError, UploadPlan, CPU_SLICE_STEPS};

#[derive(Debug, thiserror::Error)]
pub enum DeviceHistoryError {
    #[error(transparent)]
    Plan(#[from] PlanError),
    #[error("{what}: {error}")]
    Cuda {
        what: &'static str,
        error: CudaError,
    },
    #[error("the history's kernels found {errors} (error word {word:#x})")]
    Fault { word: u32, errors: String },
    #[error("CPU slice {slice} of a fill with {slices}")]
    NoSuchSlice { slice: usize, slices: usize },
    #[error("two programs share the content key {key:#x}")]
    ProgramKeyCollision { key: u64 },
}

fn cuda(what: &'static str) -> impl FnOnce(CudaError) -> DeviceHistoryError {
    move |error| DeviceHistoryError::Cuda { what, error }
}

fn checked(what: &'static str, code: CudaError) -> Result<(), DeviceHistoryError> {
    if code == CudaError::Success {
        Ok(())
    } else {
        Err(cuda(what)(code))
    }
}

fn event() -> Result<CudaEvent, DeviceHistoryError> {
    CudaEvent::create_with_flags(CudaEventCreateFlags::DISABLE_TIMING)
        .map_err(cuda("creating an event"))
}

/// Fills `bytes` at `fill` with the trace oracle's poison on `stream` when its poisoned mode is
/// armed: every byte of a history buffer that no copy overwrites then reads as poison.
fn poison_history(fill: *mut std::ffi::c_void, bytes: usize, stream: &CudaStream) {
    if poison::history_armed() {
        // SAFETY: `fill` is the start of this fill's allocation of `bytes` bytes, freed on
        // `stream` after every copy and reader, so after the memset too.
        unsafe { poison::fill(fill, bytes, stream) };
    }
}

/// Never 0, and never reused in the process, so never on a device.
fn next_nonce() -> u64 {
    static NONCE: AtomicU64 = AtomicU64::new(1);
    NONCE.fetch_add(1, Ordering::Relaxed)
}

/// A stream mark that may be waited on from any thread.
struct Mark(CudaEvent);

// SAFETY: a CUDA event is a context object that any host thread may record, wait on or destroy.
unsafe impl Send for Mark {}

/// A program's instruction table on one device.
pub struct DeviceProgram {
    device: usize,
    /// The instructions as `history_fill::program_rows` lays them out, every padding byte zero.
    rows: DeviceAllocation<u8>,
    count: usize,
    pc_base: u64,
    key: u64,
    /// The host table it was uploaded from, held so a later ask for the same table is found by
    /// identity without hashing it.
    source: Arc<[Instruction]>,
    uploaded: CudaEvent,
}

// SAFETY: the device table is written once, before the entry is published, and only read after;
// the event is waited on from any thread.
unsafe impl Send for DeviceProgram {}
unsafe impl Sync for DeviceProgram {}

/// Every table uploaded in the process. Never evicted: one table per program and device, and a
/// prover proves a handful of programs.
static PROGRAMS: Mutex<Vec<Arc<DeviceProgram>>> = Mutex::new(Vec::new());

impl DeviceProgram {
    /// `program`'s table on `device_id`, the calling thread's current device, uploaded on `stream`
    /// if no earlier ask did.
    pub fn of(
        device_id: usize,
        program: &Program,
        stream: &CudaStream,
    ) -> Result<Arc<Self>, DeviceHistoryError> {
        let mut programs = PROGRAMS.lock().unwrap_or_else(PoisonError::into_inner);
        let on_device =
            |entry: &&Arc<Self>| entry.device == device_id && entry.pc_base == program.pc_base;
        if let Some(entry) = programs
            .iter()
            .filter(on_device)
            .find(|entry| Arc::ptr_eq(&entry.source, &program.instructions))
        {
            return Ok(Arc::clone(entry));
        }
        let rows = program_rows(program);
        let key = program_key(&rows);
        if let Some(entry) = programs
            .iter()
            .filter(on_device)
            .find(|entry| entry.key == key)
        {
            return if entry.source[..] == program.instructions[..] {
                Ok(Arc::clone(entry))
            } else {
                Err(DeviceHistoryError::ProgramKeyCollision { key })
            };
        }

        let mut device_rows = DeviceAllocation::<u8>::alloc(rows.len().max(1))
            .map_err(cuda("allocating a program table"))?;
        let (source, bytes) = (rows.as_ptr().cast(), rows.len());
        let copy = device::start(stream);
        // SAFETY: the table has room for every row; the pageable source is staged by the driver
        // before the call returns.
        let code = unsafe {
            cudaMemcpyAsync(
                device_rows.as_mut_c_void_ptr(),
                source,
                bytes,
                CudaMemoryCopyKind::HostToDevice,
                stream.into(),
            )
        };
        device::copied(copy, stream, "program", Some((source, bytes)));
        checked("copying a program table", code)?;
        let uploaded = event()?;
        uploaded
            .record(stream)
            .map_err(cuda("recording a program table's upload"))?;
        let entry = Arc::new(Self {
            device: device_id,
            rows: device_rows,
            count: program.instructions.len(),
            pc_base: program.pc_base,
            key,
            source: Arc::clone(&program.instructions),
            uploaded,
        });
        programs.push(Arc::clone(&entry));
        Ok(entry)
    }

    #[must_use]
    pub const fn key(&self) -> u64 {
        self.key
    }

    #[must_use]
    pub fn table(&self) -> ProgramTable {
        ProgramTable {
            instructions: self.rows.as_c_void_ptr(),
            count: self.count as u64,
            pc_base: self.pc_base,
            key: self.key,
        }
    }

    /// Makes `stream` wait for the table to have landed.
    pub fn wait_uploaded(&self, stream: &CudaStream) -> Result<(), DeviceHistoryError> {
        stream
            .wait_event(&self.uploaded, CudaStreamWaitEventFlags::DEFAULT)
            .map_err(cuda("waiting on a program table's upload"))
    }
}

/// What a reader's kernels may read of the fill.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Readiness {
    /// The descriptor and the exceptions, and each CPU slice once [`HistoryReader::wait_slice`]
    /// has waited for it: the CPU chip's slice kernels.
    Descriptor,
    /// The whole fill: every other kernel.
    Complete,
}

/// One chunk's fill on the device.
pub struct DeviceHistory<'a> {
    fill: DevicePoolAllocation<'a, u8>,
    owner: &'a CudaStream,
    program: Arc<DeviceProgram>,
    descriptor: FillDescriptor,
    /// The error word's offset in the allocation, past the fill, and the allocation's length.
    error_at: u64,
    allocation_bytes: u64,
    descriptor_landed: CudaEvent,
    slices_landed: Vec<CudaEvent>,
    complete: CudaEvent,
    /// The readers' marks and the copy streams' last ones: what the free and the read-back follow.
    marks: Mutex<Vec<Mark>>,
}

// SAFETY: the buffer is device memory reached through stream-ordered calls; the host-side state
// that changes after the upload, the marks, is behind a mutex.
unsafe impl Send for DeviceHistory<'_> {}
unsafe impl Sync for DeviceHistory<'_> {}

impl<'a> DeviceHistory<'a> {
    /// Uploads `history`, whose header counts are `counts`, into a fill allocated from `mem_pool`
    /// on `owner`, the CPU chip's slices of `cpu_slice_steps` steps on `copy_streams` in turn.
    ///
    /// # Panics
    ///
    /// If an operand exception is not where the device's lookups search for it
    /// ([`check_exceptions`]), before anything is allocated or copied.
    pub fn upload(
        history: &impl HistoryTables,
        counts: DerivedRows,
        program: Arc<DeviceProgram>,
        mem_pool: &CudaMemPool,
        owner: &'a CudaStream,
        copy_streams: [&CudaStream; 2],
        cpu_slice_steps: u32,
    ) -> Result<Self, DeviceHistoryError> {
        check_exceptions(history.exception_rows(), history.step_rows().len());
        let plan = UploadPlan::new(
            history,
            next_nonce(),
            program.key(),
            counts,
            cpu_slice_steps,
        )?;
        let fill = DevicePoolAllocation::<u8>::alloc_from_pool_async(
            plan.allocation_bytes as usize,
            mem_pool,
            owner,
        )
        .map_err(cuda("allocating a fill"))?;
        let mut device = Self {
            fill,
            owner,
            program,
            descriptor: plan.descriptor,
            error_at: plan.error_at,
            allocation_bytes: plan.allocation_bytes,
            descriptor_landed: event()?,
            slices_landed: Vec::with_capacity(plan.slices.len()),
            complete: event()?,
            marks: Mutex::default(),
        };
        let enqueued = device.enqueue_head_and_slices(&plan, copy_streams);
        let completed_unjoined = (!ordering_edge::kept(Edge::SliceCopyJoin) && enqueued.is_ok())
            .then(|| device.enqueue_completion());
        // Whatever was enqueued is joined to the owner stream before the slot is fenced on it, so
        // neither the slot nor the buffer is let go under a copy.
        let joined = copy_streams.map(|stream| device.join_to_owner(stream));
        device.fence_slot(history);
        enqueued?;
        for join in joined {
            join?;
        }
        match completed_unjoined {
            Some(completed) => completed?,
            None => device.enqueue_completion()?,
        }
        Ok(device)
    }

    fn enqueue_head_and_slices(
        &mut self,
        plan: &UploadPlan,
        copy_streams: [&CudaStream; 2],
    ) -> Result<(), DeviceHistoryError> {
        let owner = self.owner;
        poison_history(self.at(0), self.allocation_bytes as usize, owner);
        let allocated = event()?;
        allocated
            .record(owner)
            .map_err(cuda("recording a fill's allocation"))?;
        let zero = device::start(owner);
        // SAFETY: the error word lies inside the allocation, past the fill.
        let code =
            unsafe { cudaMemsetAsync(self.at(self.error_at), 0, size_of::<u32>(), owner.into()) };
        device::filled(zero, owner);
        checked("zeroing a fill's error word", code)?;
        self.copy(
            owner,
            Piece {
                src: plan.head.as_ptr(),
                len: plan.head.len(),
                dst_at: 0,
                pinned: false,
            },
            "descriptor",
        )?;
        // SAFETY: the head lies at the start of the fill, which is freed on the owner stream after
        // everything enqueued on it.
        unsafe { ordering_edge::withhold(Edge::Descriptor, self.at(0), plan.head.len(), owner) };
        self.descriptor_landed
            .record(owner)
            .map_err(cuda("recording a fill's descriptor"))?;
        for stream in copy_streams {
            stream
                .wait_event(&allocated, CudaStreamWaitEventFlags::DEFAULT)
                .map_err(cuda("ordering a copy stream after a fill's allocation"))?;
        }
        for slice in &plan.slices {
            let stream = copy_streams[slice.index % 2];
            for piece in slice.pieces {
                self.copy(stream, piece, "cpu_slices")?;
            }
            let landed = event()?;
            landed
                .record(stream)
                .map_err(cuda("recording a CPU slice's copy"))?;
            self.slices_landed.push(landed);
        }
        // The rest is the chip lists in `Table::LISTS` order, then the syscall rows.
        let (lists, syscalls) = plan.rest.split_at(Table::LISTS.len().min(plan.rest.len()));
        for &piece in lists {
            self.copy(owner, piece, "lists")?;
        }
        for &piece in syscalls {
            self.copy(owner, piece, "syscalls")?;
        }
        Ok(())
    }

    /// The completion word, after both copy streams' joins: the last copy of the fill. Copied on
    /// the device from the descriptor's nonce, which landed first on this stream, never from the
    /// host: a copy out of pageable memory may hold the host until its stream reaches it, and this
    /// one follows every slice's copy, so the upload would return only once the whole fill had
    /// landed, and no CPU slice kernel could start under the copies of the slices after it.
    fn enqueue_completion(&self) -> Result<(), DeviceHistoryError> {
        let nonce_at =
            (offset_of!(FillDescriptor, identity) + offset_of!(FillIdentity, nonce)) as u64;
        let copy = device::start(self.owner);
        // SAFETY: the descriptor sits at the start of the fill and the completion word where it
        // places it, both inside the allocation; the head copy that lands the descriptor is
        // enqueued earlier on the same stream.
        let code = unsafe {
            cudaMemcpyAsync(
                self.at(self.descriptor.completion_at),
                self.at(nonce_at),
                size_of::<u64>(),
                CudaMemoryCopyKind::DeviceToDevice,
                self.owner.into(),
            )
        };
        device::copied(copy, self.owner, "completion", None);
        checked("copying a fill's completion word", code)?;
        self.complete
            .record(self.owner)
            .map_err(cuda("recording a fill's completion"))
    }

    /// Copies `piece` into the fill on `stream`, a copy of `what` to the device readings. A
    /// pageable source is staged by the driver before the call returns; a pinned one is read later,
    /// which the slot fence covers.
    fn copy(
        &self,
        stream: &CudaStream,
        piece: Piece,
        what: &'static str,
    ) -> Result<(), DeviceHistoryError> {
        if piece.len == 0 {
            return Ok(());
        }
        let copy = device::start(stream);
        // SAFETY: the plan places every piece inside the fill, and its source is `len` bytes of a
        // table of the history being uploaded, or of the plan.
        let code = unsafe {
            cudaMemcpyAsync(
                self.at(piece.dst_at),
                piece.src.cast(),
                piece.len,
                CudaMemoryCopyKind::HostToDevice,
                stream.into(),
            )
        };
        device::copied(copy, stream, what, Some((piece.src.cast(), piece.len)));
        checked("copying a history table", code)
    }

    /// Overwrites row `row` of `table` with `from`'s on the owner stream, which has joined every
    /// copy of the upload, then records the fill's readiness again behind it, so every reader made
    /// from here on reads the new row. For the trace oracle's corrupted-history control
    /// (`trace_oracle::corrupt`), never a prover.
    ///
    /// # Panics
    ///
    /// If `from` holds no such row, or holds it in pinned memory, which the copy would read after
    /// this returns.
    pub fn overwrite_row(
        &self,
        table: Table,
        row: usize,
        from: &impl HistoryTables,
    ) -> Result<(), DeviceHistoryError> {
        let bytes = ROW_SHAPES[table.index()].bytes;
        let source = from.table(table);
        assert!(
            (row + 1) * bytes <= source.len && !source.pinned,
            "row {row} of a pageable {} table of {} rows",
            table.name(),
            source.len / bytes
        );
        let dst_at = self.table_at(table) + (row * bytes) as u64;
        assert!(
            dst_at + bytes as u64 <= self.descriptor.completion_at,
            "a row past the fill's tables"
        );
        self.copy(
            self.owner,
            Piece {
                src: source.ptr.wrapping_add(row * bytes),
                len: bytes,
                dst_at,
                pinned: false,
            },
            "overwrite",
        )?;
        let readiness = [&self.descriptor_landed, &self.complete];
        for landed in readiness.into_iter().chain(&self.slices_landed) {
            landed
                .record(self.owner)
                .map_err(cuda("recording a fill's readiness after an overwrite"))?;
        }
        Ok(())
    }

    /// Where `table` starts in the fill.
    fn table_at(&self, table: Table) -> u64 {
        let descriptor = &self.descriptor;
        match table {
            Table::Steps => descriptor.steps_at,
            Table::Reads => descriptor.reads_at,
            Table::Writes => descriptor.writes_at,
            Table::OperandExceptions => descriptor.exceptions_at,
            Table::Syscalls => descriptor.syscalls_at,
            list => {
                let list = Table::LISTS
                    .iter()
                    .position(|&l| l == list)
                    .unwrap_or_else(|| unreachable!("{} is no chip list", list.name()));
                descriptor.entries_at + u64::from(descriptor.list_start[list]) * 4
            }
        }
    }

    /// The device address `at` bytes into the allocation.
    fn at(&self, at: u64) -> *mut std::ffi::c_void {
        debug_assert!(at < self.allocation_bytes, "an address past the fill");
        self.fill
            .as_c_void_ptr()
            .cast_mut()
            .wrapping_byte_add(at as usize)
    }

    /// Orders the owner stream after everything `stream` has been given. If that cannot be
    /// enqueued, `stream` is waited for on the host instead, so nothing that follows on the owner
    /// stream can overtake it.
    fn join_to_owner(&self, stream: &CudaStream) -> Result<(), DeviceHistoryError> {
        let joined = event().and_then(|mark| {
            mark.record(stream)
                .and_then(|()| {
                    self.owner
                        .wait_event(&mark, CudaStreamWaitEventFlags::DEFAULT)
                })
                .map_err(cuda("joining a copy stream to a fill's owner"))?;
            self.lock_marks().push(Mark(mark));
            Ok(())
        });
        if joined.is_err() {
            stream.synchronize().unwrap_or_else(|e| {
                panic!("a copy stream could neither be joined nor waited for: {e}")
            });
        }
        joined
    }

    /// Holds `history`'s slot until every copy enqueued so far on the owner stream, which has
    /// joined both copy streams, has run.
    fn fence_slot(&self, history: &impl HistoryTables) {
        if !ordering_edge::kept(Edge::SlotFence) {
            return;
        }
        let fenced = event().and_then(|done| {
            done.record(self.owner)
                .map_err(cuda("recording a fill's slot fence"))?;
            Ok(done)
        });
        match fenced {
            Ok(done) => history.hold_slot_until(DeviceReadsDone::new(done)),
            Err(e) => self.owner.synchronize().unwrap_or_else(|sync| {
                panic!("a fill's slot could neither be fenced ({e}) nor waited for: {sync}")
            }),
        }
    }

    fn lock_marks(&self) -> std::sync::MutexGuard<'_, Vec<Mark>> {
        self.marks.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// A reader for kernels on `stream`, which waits from here for the program table, the
    /// descriptor and, for [`Readiness::Complete`], the whole fill.
    pub fn reader<'h>(
        &'h self,
        stream: &'h CudaStream,
        readiness: Readiness,
    ) -> Result<HistoryReader<'h, 'a>, DeviceHistoryError> {
        self.program.wait_uploaded(stream)?;
        if ordering_edge::kept(Edge::Descriptor) {
            stream
                .wait_event(&self.descriptor_landed, CudaStreamWaitEventFlags::DEFAULT)
                .map_err(cuda("waiting on a fill's descriptor"))?;
        }
        if readiness == Readiness::Complete {
            stream
                .wait_event(&self.complete, CudaStreamWaitEventFlags::DEFAULT)
                .map_err(cuda("waiting on a fill's completion"))?;
        }
        Ok(HistoryReader {
            history: self,
            stream,
            readiness,
        })
    }

    #[must_use]
    pub const fn descriptor(&self) -> &FillDescriptor {
        &self.descriptor
    }

    #[must_use]
    pub const fn identity(&self) -> FillIdentity {
        self.descriptor.identity
    }

    /// The CPU chip's slices.
    #[must_use]
    pub fn slices(&self) -> usize {
        self.slices_landed.len()
    }

    /// Orders the owner stream after every reader's kernels and every copy, each mark waited for
    /// on the host instead when its wait cannot be enqueued: on every path, nothing later on the
    /// owner stream, the free included, can overtake them.
    fn join_readers(&self) {
        for Mark(mark) in std::mem::take(&mut *self.lock_marks()) {
            if self
                .owner
                .wait_event(&mark, CudaStreamWaitEventFlags::DEFAULT)
                .is_err()
            {
                mark.synchronize().unwrap_or_else(|e| {
                    panic!("a fill's reader could neither be joined nor waited for: {e}")
                });
            }
        }
    }

    /// The error word once every reader's kernels have run, then the buffer's free. `Err` on any
    /// bit a loader set.
    pub fn finish(self) -> Result<(), DeviceHistoryError> {
        self.join_readers();
        let mut word = 0u32;
        // SAFETY: the error word lies inside the allocation; a copy into pageable memory returns
        // once it has completed, and the synchronisation below orders it in any case.
        let code = unsafe {
            cudaMemcpyAsync(
                (&raw mut word).cast(),
                self.at(self.error_at),
                size_of::<u32>(),
                CudaMemoryCopyKind::DeviceToHost,
                self.owner.into(),
            )
        };
        checked("reading a fill's error word", code)?;
        device::wait(self.owner).map_err(cuda("waiting for a fill's readers"))?;
        if word == 0 {
            Ok(())
        } else {
            Err(DeviceHistoryError::Fault {
                word,
                errors: describe_errors(word),
            })
        }
    }

    /// The whole allocation as the device holds it once every reader's kernels have run, decoded
    /// by table.
    pub fn read_back(&mut self) -> Result<DecodedFill, DeviceHistoryError> {
        self.join_readers();
        let mut bytes = vec![0u8; self.allocation_bytes as usize];
        // SAFETY: `bytes` is the allocation's length; a copy into pageable memory returns once it
        // has completed, and the synchronisation below orders it in any case.
        let code = unsafe {
            cudaMemcpyAsync(
                bytes.as_mut_ptr().cast(),
                self.at(0),
                bytes.len(),
                CudaMemoryCopyKind::DeviceToHost,
                self.owner.into(),
            )
        };
        checked("reading a fill back", code)?;
        device::wait(self.owner).map_err(cuda("waiting for a fill's read-back"))?;
        Ok(DecodedFill::decode(&bytes, &self.descriptor, self.error_at))
    }
}

/// The buffer is freed on the owner stream behind every mark: the field drops after this body.
impl Drop for DeviceHistory<'_> {
    fn drop(&mut self) {
        self.join_readers();
    }
}

/// `history`, run against `program` and counted as `counts`, uploaded for one chunk's trace
/// generation on `device_id`, the calling thread's current device, into a fill owned by `owner`,
/// with the CPU chip's slices of [`CPU_SLICE_STEPS`] copied on two streams of its own.
pub fn upload_chunk<'a>(
    history: &impl HistoryTables,
    program: &Program,
    counts: DerivedRows,
    device_id: usize,
    owner: &'a CudaStream,
) -> Result<DeviceHistory<'a>, DeviceHistoryError> {
    let mem_pool = &crate::cuda_adaptor::get_global_mem_pool(device_id).0;
    let stream = || {
        CudaStream::create_with_flags(CudaStreamCreateFlags::NON_BLOCKING)
            .map_err(cuda("creating a stream"))
    };
    // Dropped once their copies are enqueued: a stream destroyed with work pending finishes it,
    // and the events recorded on it stay valid.
    let copies = [stream()?, stream()?];
    let program = DeviceProgram::of(device_id, program, owner)?;
    DeviceHistory::upload(
        history,
        counts,
        program,
        mem_pool,
        owner,
        [&copies[0], &copies[1]],
        CPU_SLICE_STEPS,
    )
}

/// Uploads `history` to `device_id`, the calling thread's current device, takes a reader of each
/// readiness (the slice reader waiting for every slice), reads the fill back, and returns the parts
/// that differ from `history` by name: the device self-test of the upload. `Err` on a failed call
/// or an error word a reader's kernels would have seen set.
pub fn round_trip(
    device_id: usize,
    history: &impl HistoryTables,
    counts: DerivedRows,
    program: &Program,
    cpu_slice_steps: u32,
) -> Result<Vec<&'static str>, DeviceHistoryError> {
    crate::cuda_adaptor::create_mem_pool(device_id);
    let mem_pool = &crate::cuda_adaptor::get_global_mem_pool(device_id).0;
    let stream = || {
        CudaStream::create_with_flags(CudaStreamCreateFlags::NON_BLOCKING)
            .map_err(cuda("creating a stream"))
    };
    let (owner, copies, slices, rest) = (stream()?, [stream()?, stream()?], stream()?, stream()?);
    let program = DeviceProgram::of(device_id, program, &owner)?;
    let mut fill = DeviceHistory::upload(
        history,
        counts,
        program,
        mem_pool,
        &owner,
        [&copies[0], &copies[1]],
        cpu_slice_steps,
    )?;
    {
        let slice_reader = fill.reader(&slices, Readiness::Descriptor)?;
        for slice in 0..fill.slices() {
            slice_reader.wait_slice(slice)?;
        }
        let _complete = fill.reader(&rest, Readiness::Complete)?;
    }
    let decoded = fill.read_back()?;
    let differences = decoded.differences(history, fill.descriptor());
    fill.finish()?;
    Ok(differences)
}

/// The fill as one stream's kernels read it.
pub struct HistoryReader<'h, 'a> {
    history: &'h DeviceHistory<'a>,
    stream: &'h CudaStream,
    readiness: Readiness,
}

/// [`HistoryArgs`] for one reader's kernels, usable only while that reader lives: a kernel
/// launched after the reader drops would run past the mark the buffer's free waits on.
/// Transparent, so a pointer to it is a pointer to the arguments the kernel reads.
#[derive(Debug)]
#[repr(transparent)]
pub struct ReaderArgs<'r> {
    args: HistoryArgs,
    reader: PhantomData<&'r ()>,
}

impl Deref for ReaderArgs<'_> {
    type Target = HistoryArgs;

    fn deref(&self) -> &HistoryArgs {
        &self.args
    }
}

impl HistoryReader<'_, '_> {
    /// The argument every kernel reading the fill is launched with.
    #[must_use]
    pub fn args(&self) -> ReaderArgs<'_> {
        let history = self.history;
        ReaderArgs {
            args: HistoryArgs {
                fill: history.at(0).cast_const().cast(),
                expected: history.identity(),
                program: history.program.table(),
                exception_bits: std::ptr::null(),
                exception_first: std::ptr::null(),
                error: history.at(history.error_at).cast(),
                fill_bytes: history.allocation_bytes,
            },
            reader: PhantomData,
        }
    }

    #[must_use]
    pub const fn readiness(&self) -> Readiness {
        self.readiness
    }

    /// Makes the stream wait for CPU slice `slice` to have landed, the step after it included.
    pub fn wait_slice(&self, slice: usize) -> Result<(), DeviceHistoryError> {
        let landed =
            self.history
                .slices_landed
                .get(slice)
                .ok_or(DeviceHistoryError::NoSuchSlice {
                    slice,
                    slices: self.history.slices(),
                })?;
        self.stream
            .wait_event(landed, CudaStreamWaitEventFlags::DEFAULT)
            .map_err(cuda("waiting on a CPU slice's copy"))
    }
}

/// Marks the end of this stream's reads. If no mark can be recorded the stream is waited for on
/// the host, so the free can never overtake its kernels.
impl Drop for HistoryReader<'_, '_> {
    fn drop(&mut self) {
        let marked = event().and_then(|mark| {
            mark.record(self.stream)
                .map_err(cuda("marking a fill reader's end"))?;
            Ok(mark)
        });
        match marked {
            Ok(mark) => self.history.lock_marks().push(Mark(mark)),
            Err(e) => self.stream.synchronize().unwrap_or_else(|sync| {
                panic!("a fill reader could neither be marked ({e}) nor waited for: {sync}")
            }),
        }
    }
}
