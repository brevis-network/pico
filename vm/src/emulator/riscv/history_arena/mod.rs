//! The host history arena: fixed slots of pinned memory a chunk's execution history is written
//! into, so its tables reach the device by asynchronous copies from where they were written.
//!
//! - A slot holds one region per table, each sized from the history census ([`HistoryCapacity`]).
//!   A table that outgrows its region spills: it moves to a heap allocation that grows while the
//!   rest of the history stays in the slot, and the arena counts the spill per table and logs it.
//!   Under [`SpillPolicy::Refuse`] the write fails instead and the writer must stop at that row. A
//!   spill never drops a row: a lost row would move a chip's height, and with it the verifying key.
//! - A slot is taken when a history starts ([`HistoryArena::take`]) and goes back once the last of
//!   its tables drops, after every device copy handed to [`ExecutionHistory::hold_slot_until`] has
//!   run: never at upload, since host readers read the history after the device chips have. The
//!   history is its record's, so the slot goes back when the record drops.
//! - A pipeline replay takes in its chunk's turn ([`HistoryArena::take_in_turn`]), so a run's
//!   chunks are granted slots in chunk order ([`order`]); any other take is first come, first
//!   served.
//! - Cloning a history makes a heap copy: it never takes or returns a slot, so a clone cannot block
//!   on an empty arena or return a slot twice. [`ArenaStats`]' acquisitions and returns let a
//!   caller check that around a clone.
//! - Readers and the uploader go through per-table views ([`Rows`] and [`HistoryTables`]), never
//!   offsets from a slot's base.
//! - The arena never consults the record slots' process-wide unbounded switch
//!   ([`hold_records_unbounded`](super::record_slots::hold_records_unbounded)): its slots are
//!   fixed, and what grows is a table past its region. Which histories take a slot is the writer's
//!   decision ([`super::record_slots`]).
//!
//! The slots are pinned because they are the upload's source: from pageable memory
//! `cudaMemcpyAsync` stages the source through the driver on the calling thread, which holds the
//! host for the copy's length and serialises a slice's copy against the previous slice's kernel. A
//! spilled table is pageable and its copy pays that, which is why a spill is counted.

mod capacity;
pub mod order;
mod pinned;
mod table;
#[cfg(test)]
mod tests;

use std::{
    num::NonZeroUsize,
    ptr::NonNull,
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use crossbeam::channel::{bounded, Receiver, Sender, TryRecvError};

pub use capacity::{HistoryCapacity, RowShape, SlotLayout, Table, CAPACITY_FORMAT, TABLE_COUNT};
pub use order::{GrantOrder, GrantTicket};
pub use pinned::DeviceReadsDone;
pub use table::{Rows, SpillPolicy, TableFull};

use crate::emulator::riscv::{
    event_types::RvChunk,
    history::{Access, ChipSteps, ExecutionHistory, OperandException, ReadAccess, Step},
    syscalls::SyscallEvent,
};
use pinned::{PinnedSlot, SlotFence};

/// Each table's row, in [`Table::ALL`] order; every chip list holds `u32` step indices.
pub const ROW_SHAPES: [RowShape; TABLE_COUNT] = {
    let mut shapes = [RowShape::of::<u32>(); TABLE_COUNT];
    shapes[Table::Steps.index()] = RowShape::of::<Step>();
    shapes[Table::Reads.index()] = RowShape::of::<ReadAccess>();
    shapes[Table::Writes.index()] = RowShape::of::<Access>();
    shapes[Table::OperandExceptions.index()] = RowShape::of::<OperandException>();
    shapes[Table::Syscalls.index()] = RowShape::of::<SyscallEvent>();
    shapes
};

#[derive(Debug, thiserror::Error)]
pub enum ArenaError {
    #[error("a history arena needs at least one slot")]
    NoSlots,
    #[error(
        "the history capacities were measured at chunk size {measured}, and this run chunks at \
         {chunk_size}: its histories would spill by design"
    )]
    ChunkLargerThanMeasured { chunk_size: u32, measured: u32 },
    #[error("a history slot at these capacities would not fit the address space")]
    SlotTooLarge,
    #[error("{0}")]
    Pin(String),
}

#[derive(Default)]
struct Counters {
    acquisitions: AtomicU64,
    returns: AtomicU64,
    blocked_takes: AtomicU64,
    blocked_ns: AtomicU64,
    in_use: AtomicUsize,
    max_in_use: AtomicUsize,
    spills: [AtomicU64; TABLE_COUNT],
}

/// The arena's counts so far.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArenaStats {
    pub slots: usize,
    pub slot_bytes: usize,
    /// Slots taken, and slots given back.
    pub acquisitions: u64,
    pub returns: u64,
    /// Takes that found no free slot or had to wait for their turn, and how long they waited.
    pub blocked_takes: u64,
    pub blocked: Duration,
    /// The most slots held at once.
    pub max_in_use: usize,
    /// Per table, in [`Table::ALL`] order, the histories that spilled it.
    pub spills: [u64; TABLE_COUNT],
}

impl ArenaStats {
    /// The host memory the slots pin, all of it from [`HistoryArena::pin`] on.
    #[must_use]
    pub const fn pinned_bytes(&self) -> usize {
        self.slots * self.slot_bytes
    }

    /// Each table's spill count, by name.
    pub fn spills_by_table(&self) -> impl Iterator<Item = (&'static str, u64)> + '_ {
        Table::ALL
            .into_iter()
            .map(|table| (table.name(), self.spills[table.index()]))
    }
}

/// A fixed set of pinned slots, each with room for one chunk's history at the capacities it was
/// built with.
pub struct HistoryArena {
    capacity: HistoryCapacity,
    layout: SlotLayout,
    policy: SpillPolicy,
    slots: usize,
    free: Receiver<PinnedSlot>,
    home: Sender<PinnedSlot>,
    counters: Arc<Counters>,
}

impl HistoryArena {
    /// Pins `slots` slots at `capacity`, all of them here: a caller that times a run builds the
    /// arena outside its timer. Refused when `chunk_size` is larger than the chunk the capacities
    /// were measured at.
    pub fn pin(
        slots: NonZeroUsize,
        chunk_size: u32,
        capacity: HistoryCapacity,
        policy: SpillPolicy,
    ) -> Result<Self, ArenaError> {
        if chunk_size > capacity.chunk_size() {
            return Err(ArenaError::ChunkLargerThanMeasured {
                chunk_size,
                measured: capacity.chunk_size(),
            });
        }
        let layout = SlotLayout::new(&capacity, &ROW_SHAPES).ok_or(ArenaError::SlotTooLarge)?;
        let (home, free) = bounded(slots.get());
        for _ in 0..slots.get() {
            let mut slot = PinnedSlot::alloc(layout.bytes()).map_err(ArenaError::Pin)?;
            assert_eq!(
                slot.base().as_ptr() as usize % layout.align(),
                0,
                "a pinned slot under its rows' alignment"
            );
            home.try_send(slot)
                .unwrap_or_else(|_| unreachable!("a channel bounded at the slot count"));
        }
        Ok(Self {
            capacity,
            layout,
            policy,
            slots: slots.get(),
            free,
            home,
            counters: Arc::default(),
        })
    }

    #[must_use]
    pub const fn capacity(&self) -> &HistoryCapacity {
        &self.capacity
    }

    #[must_use]
    pub const fn layout(&self) -> &SlotLayout {
        &self.layout
    }

    #[must_use]
    pub const fn policy(&self) -> SpillPolicy {
        self.policy
    }

    /// An empty history of `chunk` in a free slot, waiting for one to come back when none is free.
    /// A wait is counted here and, for the stage ledger, on the calling thread.
    pub fn take(&self, chunk: RvChunk) -> ExecutionHistory {
        self.take_slot(chunk, None)
            .unwrap_or_else(|| unreachable!("only a take in turn gives up its wait"))
    }

    /// [`Self::take`] in `turn`: once every earlier place in its order has taken a slot or given
    /// its turn up, and before any later one. The wait for the turn is counted with the wait for a
    /// slot, as one. `None` if the order closes while it waits for a slot: the run has failed, and
    /// the slots it waits for may be held by records the failure never frees.
    pub fn take_in_turn(&self, chunk: RvChunk, turn: &GrantTicket) -> Option<ExecutionHistory> {
        self.take_slot(chunk, Some(turn))
    }

    fn take_slot(&self, chunk: RvChunk, turn: Option<&GrantTicket>) -> Option<ExecutionHistory> {
        let free_now = if turn.is_none_or(GrantTicket::is_due) {
            self.free.try_recv()
        } else {
            Err(TryRecvError::Empty)
        };
        let slot = match free_now {
            Ok(slot) => slot,
            Err(TryRecvError::Empty) => self.wait_for_slot(turn)?,
            Err(TryRecvError::Disconnected) => {
                unreachable!("the arena holds a sender of its own")
            }
        };
        if let Some(turn) = turn {
            turn.granted();
        }
        self.counters.acquisitions.fetch_add(1, Ordering::Relaxed);
        let in_use = self.counters.in_use.fetch_add(1, Ordering::Relaxed) + 1;
        self.counters
            .max_in_use
            .fetch_max(in_use, Ordering::Relaxed);
        Some(in_slot(
            chunk,
            slot,
            &self.capacity,
            &self.layout,
            self.policy,
            SlotLease {
                slot: None,
                home: self.home.clone(),
                counters: Arc::clone(&self.counters),
                fence: SlotFence::default(),
            },
        ))
    }

    /// A slot, once `turn` is due and one comes back. `turn` does not pass until it has one, so no
    /// later place in its order takes one first. `None` if `turn`'s order closes first.
    fn wait_for_slot(&self, turn: Option<&GrantTicket>) -> Option<PinnedSlot> {
        self.counters.blocked_takes.fetch_add(1, Ordering::Relaxed);
        let start = Instant::now();
        let slot = crate::mle::ledger::record_slot_wait(|| match turn {
            None => Some(self.free.recv()),
            Some(turn) => {
                turn.wait();
                crossbeam::channel::select! {
                    recv(self.free) -> slot => Some(slot),
                    recv(turn.closed()) -> _ => None,
                }
            }
        })
        .map(|slot| slot.unwrap_or_else(|_| unreachable!("the arena holds a sender of its own")));
        let waited = u64::try_from(start.elapsed().as_nanos()).unwrap_or(u64::MAX);
        self.counters
            .blocked_ns
            .fetch_add(waited, Ordering::Relaxed);
        slot
    }

    /// `history` copied into a slot, every table checked as a writer's rows are. On a refused row
    /// the slot goes back and nothing is kept.
    pub fn fill(&self, history: &ExecutionHistory) -> Result<ExecutionHistory, TableFull> {
        let mut filled = self.take(history.chunk);
        filled.steps.try_extend_from_slice(&history.steps)?;
        filled.reads.try_extend_from_slice(&history.reads)?;
        filled.writes.try_extend_from_slice(&history.writes)?;
        filled
            .operand_exceptions
            .try_extend_from_slice(&history.operand_exceptions)?;
        filled.syscalls.try_extend_from_slice(&history.syscalls)?;
        for (list, rows) in lists_of_mut(&mut filled.chip_steps)
            .into_iter()
            .zip(lists_of(&history.chip_steps))
        {
            list.try_extend_from_slice(rows)?;
        }
        Ok(filled)
    }

    #[must_use]
    pub fn stats(&self) -> ArenaStats {
        let counters = &self.counters;
        ArenaStats {
            slots: self.slots,
            slot_bytes: self.layout.bytes(),
            acquisitions: counters.acquisitions.load(Ordering::Relaxed),
            returns: counters.returns.load(Ordering::Relaxed),
            blocked_takes: counters.blocked_takes.load(Ordering::Relaxed),
            blocked: Duration::from_nanos(counters.blocked_ns.load(Ordering::Relaxed)),
            max_in_use: counters.max_in_use.load(Ordering::Relaxed),
            spills: std::array::from_fn(|index| counters.spills[index].load(Ordering::Relaxed)),
        }
    }
}

/// The chip lists of `chip_steps`, in [`Table::LISTS`] order. Destructured whole, so a list added
/// to the history does not go unwritten.
fn lists_of(chip_steps: &ChipSteps) -> [&Rows<u32>; 11] {
    let ChipSteps {
        add,
        sub,
        mul,
        bitwise,
        shift_left,
        shift_right,
        lt,
        divrem,
        memory,
        ecall,
        branch,
    } = chip_steps;
    [
        add,
        sub,
        mul,
        bitwise,
        shift_left,
        shift_right,
        lt,
        divrem,
        memory,
        ecall,
        branch,
    ]
}

/// [`lists_of`], to write.
fn lists_of_mut(chip_steps: &mut ChipSteps) -> [&mut Rows<u32>; 11] {
    let ChipSteps {
        add,
        sub,
        mul,
        bitwise,
        shift_left,
        shift_right,
        lt,
        divrem,
        memory,
        ecall,
        branch,
    } = chip_steps;
    [
        add,
        sub,
        mul,
        bitwise,
        shift_left,
        shift_right,
        lt,
        divrem,
        memory,
        ecall,
        branch,
    ]
}

/// A slot on loan to one history, shared by the tables in it; it goes back when the last of them
/// drops.
struct SlotLease {
    slot: Option<PinnedSlot>,
    home: Sender<PinnedSlot>,
    counters: Arc<Counters>,
    fence: SlotFence,
}

impl Drop for SlotLease {
    fn drop(&mut self) {
        self.fence.wait();
        if let Some(slot) = self.slot.take() {
            self.counters.in_use.fetch_sub(1, Ordering::Relaxed);
            self.counters.returns.fetch_add(1, Ordering::Relaxed);
            // Fails only once the arena has dropped, and the slot is then freed here: the channel
            // is bounded at the slot count and holds no more than was taken from it.
            let _ = self.home.try_send(slot);
        }
    }
}

/// The bytes of one table, for a copy to the device.
#[derive(Clone, Copy, Debug)]
pub struct TableBytes {
    pub ptr: *const u8,
    pub len: usize,
    /// In its slot's region, and so pinned; a spilled or heap table is pageable.
    pub pinned: bool,
}

impl TableBytes {
    fn of<T: Copy>(rows: &Rows<T>) -> Self {
        Self {
            ptr: rows.as_ptr().cast(),
            len: size_of_val(rows.as_slice()),
            pinned: rows.is_resident(),
        }
    }
}

/// A history's tables as a copy to the device reads them, wherever they are stored.
pub trait HistoryTables {
    fn chunk_index(&self) -> RvChunk;
    fn step_rows(&self) -> &[Step];
    fn read_rows(&self) -> &[ReadAccess];
    fn write_rows(&self) -> &[Access];
    fn exception_rows(&self) -> &[OperandException];
    fn syscall_rows(&self) -> &[SyscallEvent];

    /// # Panics
    ///
    /// If `table` is not a chip list.
    fn list_rows(&self, table: Table) -> &[u32];

    /// The bytes `table` holds, where they are: in pinned memory, which a copy reads after it is
    /// enqueued, or pageable.
    fn table(&self, table: Table) -> TableBytes;

    /// Keeps the tables' pinned memory from reuse until `done` has completed. Pageable tables are
    /// staged by the driver before a copy call returns, so a history with none drops `done`.
    fn hold_slot_until(&self, _done: DeviceReadsDone) {}

    /// The rows each table holds, in [`Table::ALL`] order.
    fn rows(&self) -> [usize; TABLE_COUNT] {
        Table::ALL.map(|table| self.table(table).len / ROW_SHAPES[table.index()].bytes)
    }
}

impl HistoryTables for ExecutionHistory {
    fn chunk_index(&self) -> RvChunk {
        self.chunk
    }

    fn step_rows(&self) -> &[Step] {
        &self.steps
    }

    fn read_rows(&self) -> &[ReadAccess] {
        &self.reads
    }

    fn write_rows(&self) -> &[Access] {
        &self.writes
    }

    fn exception_rows(&self) -> &[OperandException] {
        &self.operand_exceptions
    }

    fn syscall_rows(&self) -> &[SyscallEvent] {
        &self.syscalls
    }

    fn list_rows(&self, table: Table) -> &[u32] {
        lists_of(&self.chip_steps)[list_index(table)]
    }

    fn table(&self, table: Table) -> TableBytes {
        match table {
            Table::Steps => TableBytes::of(&self.steps),
            Table::Reads => TableBytes::of(&self.reads),
            Table::Writes => TableBytes::of(&self.writes),
            Table::OperandExceptions => TableBytes::of(&self.operand_exceptions),
            Table::Syscalls => TableBytes::of(&self.syscalls),
            list => TableBytes::of(lists_of(&self.chip_steps)[list_index(list)]),
        }
    }

    fn hold_slot_until(&self, done: DeviceReadsDone) {
        ExecutionHistory::hold_slot_until(self, done);
    }
}

/// Where a history's tables are stored.
impl ExecutionHistory {
    /// The slot the history's tables are in, held by every one still in its region.
    fn slot(&self) -> Option<&Arc<SlotLease>> {
        [
            self.steps.slot(),
            self.reads.slot(),
            self.writes.slot(),
            self.operand_exceptions.slot(),
            self.syscalls.slot(),
        ]
        .into_iter()
        .chain(lists_of(&self.chip_steps).map(Rows::slot))
        .flatten()
        .next()
    }

    /// Whether the history holds an arena slot; a copy, and a history written without one, does
    /// not.
    #[must_use]
    pub fn holds_slot(&self) -> bool {
        self.slot().is_some()
    }

    /// Whether `table` is in its slot's region, and so pinned.
    #[must_use]
    pub fn is_in_slot(&self, table: Table) -> bool {
        self.table(table).pinned
    }

    /// The rows each table holds, in [`Table::ALL`] order.
    #[must_use]
    pub fn rows(&self) -> [usize; TABLE_COUNT] {
        HistoryTables::rows(self)
    }

    /// The tables that outgrew their regions.
    pub fn spilled(&self) -> impl Iterator<Item = Table> + '_ {
        let lists = lists_of(&self.chip_steps);
        Table::ALL.into_iter().filter(move |&table| match table {
            Table::Steps => self.steps.is_spilled(),
            Table::Reads => self.reads.is_spilled(),
            Table::Writes => self.writes.is_spilled(),
            Table::OperandExceptions => self.operand_exceptions.is_spilled(),
            Table::Syscalls => self.syscalls.is_spilled(),
            list => lists[list_index(list)].is_spilled(),
        })
    }

    /// Keeps the slot from going back to the arena until `done` has completed: a copy out of the
    /// slot's pinned regions is read by the device after it was enqueued. A history without a slot
    /// has nothing a copy could outlive, and drops `done`.
    pub fn hold_slot_until(&self, done: DeviceReadsDone) {
        if let Some(slot) = self.slot() {
            slot.fence.hold(done);
        }
    }
}

/// An empty history of `chunk` in `slot`'s regions, each table holding the slot through `lease`.
fn in_slot(
    chunk: RvChunk,
    mut slot: PinnedSlot,
    capacity: &HistoryCapacity,
    layout: &SlotLayout,
    policy: SpillPolicy,
    mut lease: SlotLease,
) -> ExecutionHistory {
    let base = slot.base();
    lease.slot = Some(slot);
    let lease = Arc::new(lease);
    // SAFETY: each region lies inside the slot at its layout's offset, aligned for its rows and
    // disjoint from every other; every table holds the lease, so the slot stays this history's
    // alone until the last of them drops.
    let region = |table: Table| unsafe { SlotRegion::new(base, capacity, layout, table) };
    let [add, sub, mul, bitwise, shift_left, shift_right, lt, divrem, memory, ecall, branch] =
        Table::LISTS.map(|table| region(table).rows(policy, &lease));
    ExecutionHistory {
        chunk,
        steps: region(Table::Steps).rows(policy, &lease),
        reads: region(Table::Reads).rows(policy, &lease),
        writes: region(Table::Writes).rows(policy, &lease),
        chip_steps: ChipSteps {
            add,
            sub,
            mul,
            bitwise,
            shift_left,
            shift_right,
            lt,
            divrem,
            memory,
            ecall,
            branch,
        },
        operand_exceptions: region(Table::OperandExceptions).rows(policy, &lease),
        syscalls: region(Table::Syscalls).rows(policy, &lease),
    }
}

/// One table's region of a slot.
struct SlotRegion {
    table: Table,
    base: NonNull<u8>,
    capacity: usize,
}

impl SlotRegion {
    /// `table`'s region of the slot at `base`.
    ///
    /// # Safety
    ///
    /// `base` is a slot laid out by `layout` at `capacity`.
    unsafe fn new(
        base: NonNull<u8>,
        capacity: &HistoryCapacity,
        layout: &SlotLayout,
        table: Table,
    ) -> Self {
        Self {
            table,
            base: base.add(layout.offset(table)),
            capacity: capacity.rows(table),
        }
    }

    /// The empty table writing into the region, holding the slot through `lease`.
    ///
    /// # Panics
    ///
    /// If `T` is not the row the region was laid out for.
    fn rows<T: Copy>(self, policy: SpillPolicy, lease: &Arc<SlotLease>) -> Rows<T> {
        assert_eq!(
            RowShape::of::<T>(),
            ROW_SHAPES[self.table.index()],
            "rows of another shape in table {}'s region",
            self.table.name()
        );
        // SAFETY: `SlotRegion::new`'s caller vouched for the region, aligned for its table's
        // rows, and the table holds the slot it lies in for as long as it lives.
        unsafe {
            Rows::resident(
                self.table,
                self.base.cast(),
                self.capacity,
                policy,
                Some(Arc::clone(lease)),
            )
        }
    }
}

/// `table`'s place in [`Table::LISTS`].
fn list_index(table: Table) -> usize {
    Table::LISTS
        .iter()
        .position(|&list| list == table)
        .unwrap_or_else(|| panic!("table {} is not a chip list", table.name()))
}
