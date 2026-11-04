//! The copies that upload one chunk's history into its fill (`history_fill`'s layout), and the
//! read-back that checks them.
//!
//! One pool allocation per chunk holds the fill and, past its end, the error word.
//! [`UploadPlan`] lists every copy as source bytes and a destination offset, grouped by what must
//! land before what: the descriptor with the exceptions behind it, each CPU slice, the rest. A CPU
//! slice's copy carries the step after the slice too: that step's first read and write end the
//! rows of the slice's last step.

use crate::emulator::riscv::{
    history::{Access, OperandException, ReadAccess, Step},
    history_arena::{HistoryTables, Table, TableBytes},
    history_fill::{
        DerivedRows, FillDescriptor, FillIdentity, FillLayout, FillRows, LISTS, SYSCALL_ROW,
    },
    syscalls::SyscallEvent,
};

/// About 9 MiB of steps, reads and writes per slice at a reth chunk's density, and 17 MiB at the
/// worst case of 136 bytes a step.
pub const CPU_SLICE_STEPS: u32 = 1 << 17;

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum PlanError {
    #[error("table {table} holds {rows} rows, past the descriptor's u32 counts")]
    TooManyRows { table: &'static str, rows: usize },
    #[error("the CPU chip's slices need at least one step each")]
    EmptySlice,
    #[error(
        "step {step}'s first {what} is {at}, outside {lo}..={hi}: the rows of the steps before it \
         would not be contiguous"
    )]
    RowsOutOfOrder {
        step: usize,
        what: &'static str,
        at: usize,
        lo: usize,
        hi: usize,
    },
    #[error("the scan counted {counted} {what}, and the history's list holds {listed}")]
    ScanDisagrees {
        what: &'static str,
        counted: u64,
        listed: u64,
    },
}

/// One host-to-device copy: `len` bytes at `src` to `dst_at` in the fill.
#[derive(Clone, Copy, Debug)]
pub struct Piece {
    pub src: *const u8,
    pub len: usize,
    pub dst_at: u64,
    /// Pinned, so the device reads `src` after the copy is enqueued.
    pub pinned: bool,
}

impl Piece {
    fn rows(table: TableBytes, rows: std::ops::Range<usize>, row_bytes: usize, at: u64) -> Self {
        let start = rows.start * row_bytes;
        debug_assert!(rows.end * row_bytes <= table.len, "a piece past its table");
        Self {
            src: table.ptr.wrapping_add(start),
            len: rows.len() * row_bytes,
            dst_at: at + start as u64,
            pinned: table.pinned,
        }
    }
}

/// The steps the CPU chip's slice `index` covers, and the copies that land it.
#[derive(Clone, Debug)]
pub struct CpuSlice {
    pub index: usize,
    /// The slice's steps: `first..end`.
    pub steps: std::ops::Range<usize>,
    /// Its steps (with the step after them, when there is one), reads and writes.
    pub pieces: [Piece; 3],
}

/// Every copy of one fill, in the groups that order them.
pub struct UploadPlan {
    pub layout: FillLayout,
    pub descriptor: FillDescriptor,
    /// The error word's offset in the allocation, past the fill, and the allocation's length.
    pub error_at: u64,
    pub allocation_bytes: u64,
    /// The descriptor's bytes and the exception table's right behind them, copied first.
    pub head: Vec<u8>,
    pub slices: Vec<CpuSlice>,
    /// The chip lists and the syscall rows.
    pub rest: Vec<Piece>,
}

impl UploadPlan {
    /// The copies of `history` into the fill `nonce` names, against the program table keyed
    /// `program_key`. Refused when `counts` do not split the coarse add and sub lists, and when a
    /// slice's first step places its rows outside those of the slices around it, which the
    /// slice's copies would then not cover.
    pub fn new(
        history: &impl HistoryTables,
        nonce: u64,
        program_key: u64,
        derived: DerivedRows,
        cpu_slice_steps: u32,
    ) -> Result<Self, PlanError> {
        if cpu_slice_steps == 0 {
            return Err(PlanError::EmptySlice);
        }
        let rows = history.rows();
        for table in Table::ALL {
            let count = rows[table.index()];
            if u32::try_from(count).is_err() {
                return Err(PlanError::TooManyRows {
                    table: table.name(),
                    rows: count,
                });
            }
        }
        let entries: usize = Table::LISTS.map(|list| rows[list.index()]).iter().sum();
        if u32::try_from(entries).is_err() {
            return Err(PlanError::TooManyRows {
                table: "the chip lists together",
                rows: entries,
            });
        }
        let split = |one: u32, other: u32| u64::from(one) + u64::from(other);
        for (what, counted, list) in [
            (
                "ADD and ADDW rows",
                split(derived.add, derived.addw),
                Table::Add,
            ),
            (
                "SUB and SUBW rows",
                split(derived.sub, derived.subw),
                Table::Sub,
            ),
        ] {
            let listed = rows[list.index()] as u64;
            if counted != listed {
                return Err(PlanError::ScanDisagrees {
                    what,
                    counted,
                    listed,
                });
            }
        }
        let count = |table: Table| rows[table.index()];
        let layout = FillLayout::of(&FillRows {
            steps: count(Table::Steps),
            reads: count(Table::Reads),
            writes: count(Table::Writes),
            exceptions: count(Table::OperandExceptions),
            syscalls: count(Table::Syscalls),
            lists: Table::LISTS.map(count),
        });
        let identity = FillIdentity {
            chunk: history.chunk_index(),
            steps: count(Table::Steps) as u32,
            nonce,
        };
        let descriptor = layout.descriptor(identity, program_key, derived, cpu_slice_steps);
        let error_at = layout.buffer_bytes.next_multiple_of(8) as u64;
        let at = |offset: usize| offset as u64;

        let exceptions = history.table(Table::OperandExceptions);
        let mut head = Vec::with_capacity(size_of::<FillDescriptor>() + exceptions.len);
        // SAFETY: `FillDescriptor` is `repr(C)` with no padding (its fields sum to its asserted
        // size), and `exceptions` is the table's own bytes.
        unsafe {
            head.extend_from_slice(std::slice::from_raw_parts(
                (&raw const descriptor).cast::<u8>(),
                size_of::<FillDescriptor>(),
            ));
            head.extend_from_slice(std::slice::from_raw_parts(exceptions.ptr, exceptions.len));
        }

        let steps = history.step_rows();
        let (reads, writes) = (history.read_rows().len(), history.write_rows().len());
        let bound = |step: usize, what: &'static str, at: u32, lo: usize, hi: usize| {
            let at = at as usize;
            if (lo..=hi).contains(&at) {
                Ok(at)
            } else {
                Err(PlanError::RowsOutOfOrder {
                    step,
                    what,
                    at,
                    lo,
                    hi,
                })
            }
        };
        let slice_steps = cpu_slice_steps as usize;
        let mut slices = Vec::with_capacity(steps.len().div_ceil(slice_steps));
        let (mut read_from, mut write_from) = (0, 0);
        for (index, first) in (0..steps.len()).step_by(slice_steps).enumerate() {
            let end = (first + slice_steps).min(steps.len());
            let (read_end, write_end) = match steps.get(end) {
                Some(next) => (
                    bound(end, "read", next.first_read, read_from, reads)?,
                    bound(end, "write", next.first_write, write_from, writes)?,
                ),
                None => (reads, writes),
            };
            if index == 0 {
                bound(0, "read", steps[0].first_read, 0, 0)?;
                bound(0, "write", steps[0].first_write, 0, 0)?;
            }
            slices.push(CpuSlice {
                index,
                steps: first..end,
                pieces: [
                    Piece::rows(
                        history.table(Table::Steps),
                        first..(end + 1).min(steps.len()),
                        size_of::<Step>(),
                        at(layout.steps_at),
                    ),
                    Piece::rows(
                        history.table(Table::Reads),
                        read_from..read_end,
                        size_of::<ReadAccess>(),
                        at(layout.reads_at),
                    ),
                    Piece::rows(
                        history.table(Table::Writes),
                        write_from..write_end,
                        size_of::<Access>(),
                        at(layout.writes_at),
                    ),
                ],
            });
            (read_from, write_from) = (read_end, write_end);
        }

        let mut rest: Vec<Piece> = Table::LISTS
            .into_iter()
            .enumerate()
            .map(|(index, list)| {
                let bytes = history.table(list);
                Piece::rows(
                    bytes,
                    0..bytes.len / size_of::<u32>(),
                    size_of::<u32>(),
                    at(layout.entries_at) + u64::from(layout.list_start[index]) * 4,
                )
            })
            .collect();
        let syscalls = history.table(Table::Syscalls);
        rest.push(Piece::rows(
            syscalls,
            0..syscalls.len / size_of::<SyscallEvent>(),
            SYSCALL_ROW,
            at(layout.syscalls_at),
        ));
        Ok(Self {
            layout,
            descriptor,
            error_at,
            allocation_bytes: error_at + size_of::<u32>() as u64,
            head,
            slices,
            rest,
        })
    }

    /// The completion word's value: the fill's nonce.
    #[must_use]
    pub const fn completion(&self) -> u64 {
        self.descriptor.identity.nonce
    }
}

/// A fill read back from the device, by table.
#[derive(Debug)]
pub struct DecodedFill {
    pub descriptor: FillDescriptor,
    pub steps: Vec<Step>,
    pub reads: Vec<ReadAccess>,
    pub writes: Vec<Access>,
    pub operand_exceptions: Vec<OperandException>,
    pub lists: [Vec<u32>; LISTS],
    pub syscalls: Vec<SyscallEvent>,
    pub completion: u64,
    pub error: u32,
}

/// `count` rows of `T` at `at` in `bytes`, which need not be aligned for them.
fn rows_at<T: Copy>(bytes: &[u8], at: u64, count: usize) -> Vec<T> {
    let at = at as usize;
    let end = at + count * size_of::<T>();
    assert!(end <= bytes.len(), "rows past the fill");
    (0..count)
        // SAFETY: each row lies inside `bytes` (checked above), and every row type here is plain
        // data any bit pattern of which is a value.
        .map(|row| unsafe {
            bytes
                .as_ptr()
                .add(at + row * size_of::<T>())
                .cast::<T>()
                .read_unaligned()
        })
        .collect()
}

impl DecodedFill {
    /// The tables of `allocation`, a fill's pool allocation with the error word at `error_at`, read
    /// where `expected` places them; its own descriptor is read from the allocation.
    #[must_use]
    pub fn decode(allocation: &[u8], expected: &FillDescriptor, error_at: u64) -> Self {
        let d = expected;
        Self {
            descriptor: rows_at(allocation, 0, 1)[0],
            steps: rows_at(allocation, d.steps_at, d.identity.steps as usize),
            reads: rows_at(allocation, d.reads_at, d.reads as usize),
            writes: rows_at(allocation, d.writes_at, d.writes as usize),
            operand_exceptions: rows_at(allocation, d.exceptions_at, d.exceptions as usize),
            lists: std::array::from_fn(|list| {
                let (start, end) = (d.list_start[list], d.list_start[list + 1]);
                rows_at(
                    allocation,
                    d.entries_at + u64::from(start) * 4,
                    (end - start) as usize,
                )
            }),
            syscalls: rows_at(allocation, d.syscalls_at, d.syscalls as usize),
            completion: rows_at(allocation, d.completion_at, 1)[0],
            error: rows_at(allocation, error_at, 1)[0],
        }
    }

    /// The parts that differ from a fill of `history` under `descriptor`, by name: every row of
    /// every table field by field (a syscall row's padding is not a field), the descriptor and the
    /// completion word.
    #[must_use]
    pub fn differences(
        &self,
        history: &impl HistoryTables,
        descriptor: &FillDescriptor,
    ) -> Vec<&'static str> {
        let syscall = |e: &SyscallEvent| (e.chunk, e.clk, e.syscall_id, e.arg1, e.arg2);
        let mut differ = Vec::new();
        let mut check = |same: bool, what: &'static str| {
            if !same {
                differ.push(what);
            }
        };
        check(self.descriptor == *descriptor, "descriptor");
        check(self.steps == history.step_rows(), "steps");
        check(self.reads == history.read_rows(), "reads");
        check(self.writes == history.write_rows(), "writes");
        check(
            self.operand_exceptions == history.exception_rows(),
            "operand_exceptions",
        );
        for (list, table) in self.lists.iter().zip(Table::LISTS) {
            check(list == history.list_rows(table), table.name());
        }
        check(
            self.syscalls
                .iter()
                .map(syscall)
                .eq(history.syscall_rows().iter().map(syscall)),
            "syscalls",
        );
        check(self.completion == descriptor.identity.nonce, "completion");
        differ
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroUsize;

    use super::*;
    use crate::emulator::riscv::{
        history::{ChipSteps, ExecutionHistory},
        history_arena::{HistoryArena, HistoryCapacity, SpillPolicy},
    };

    /// `steps` steps, step `i` with `i % 3` reads and a write unless `i % 4 == 0`, each list
    /// holding the steps of its own residue, an exception every fifth step and a syscall every
    /// seventh.
    fn history(steps: u32) -> ExecutionHistory {
        let mut history = ExecutionHistory {
            chunk: 6,
            ..ExecutionHistory::default()
        };
        for i in 0..steps {
            history.steps.push(Step {
                clk: 8 + 4 * i,
                pc: 0x2000 + 4 * i,
                next_pc: 0x2004 + 4 * i,
                first_read: history.reads.len() as u32,
                first_write: history.writes.len() as u32,
            });
            for r in 0..i % 3 {
                history.reads.push(ReadAccess {
                    value: u64::from(i) << 32 | u64::from(r),
                    prev_chunk: 5,
                    prev_timestamp: i,
                });
            }
            if i % 4 != 0 {
                history.writes.push(Access {
                    value: u64::from(i) << 33,
                    prev_value: u64::from(i),
                    prev_chunk: 5,
                    prev_timestamp: i + 1,
                });
            }
            if i % 5 == 0 {
                history.operand_exceptions.push(OperandException {
                    step: i,
                    slot: 3,
                    value: u64::from(i) << 40,
                });
            }
            if i % 7 == 0 {
                history.syscalls.push(SyscallEvent {
                    chunk: 6,
                    clk: u64::from(8 + 4 * i),
                    syscall_id: i,
                    arg1: 1,
                    arg2: 2,
                });
            }
        }
        let list = |residue: u32| (0..steps).filter(|i| i % 11 == residue).collect();
        history.chip_steps = ChipSteps {
            add: list(0),
            sub: list(1),
            mul: list(2),
            bitwise: list(3),
            shift_left: list(4),
            shift_right: list(5),
            lt: list(6),
            divrem: list(7),
            memory: list(8),
            ecall: list(9),
            branch: list(10),
        };
        history
    }

    fn counts(history: &ExecutionHistory) -> DerivedRows {
        DerivedRows {
            divrem_add: 3,
            add: history.chip_steps.add.len() as u32,
            addw: 0,
            sub: 1.min(history.chip_steps.sub.len() as u32),
            subw: (history.chip_steps.sub.len() as u32).saturating_sub(1),
        }
    }

    /// Room for every table of [`history`] up to 1000 steps, so a slot pins kilobytes.
    fn arena() -> HistoryArena {
        let capacity = Table::ALL
            .into_iter()
            .fold(HistoryCapacity::CENSUS, |capacity, table| {
                capacity.with_rows(table, 4096)
            });
        HistoryArena::pin(NonZeroUsize::MIN, 1 << 20, capacity, SpillPolicy::Spill)
            .expect("an arena")
    }

    /// The fill the device holds once every copy of `plan` has landed, odd slices before even
    /// ones, as the two copy streams may land them.
    fn land(plan: &UploadPlan) -> Vec<u8> {
        let mut fill = vec![0xa5u8; plan.allocation_bytes as usize];
        let mut put = |at: u64, bytes: &[u8]| {
            fill[at as usize..at as usize + bytes.len()].copy_from_slice(bytes);
        };
        put(0, &plan.head);
        let (odd, even): (Vec<_>, Vec<_>) = plan.slices.iter().partition(|s| s.index % 2 == 1);
        for slice in odd.into_iter().chain(even) {
            for piece in &slice.pieces {
                // SAFETY: a piece's source is `len` bytes of one of the history's tables.
                put(piece.dst_at, unsafe {
                    std::slice::from_raw_parts(piece.src, piece.len)
                });
            }
        }
        for piece in &plan.rest {
            // SAFETY: as above.
            put(piece.dst_at, unsafe {
                std::slice::from_raw_parts(piece.src, piece.len)
            });
        }
        put(
            plan.layout.completion_at as u64,
            &plan.completion().to_ne_bytes(),
        );
        put(plan.error_at, &0u32.to_ne_bytes());
        fill
    }

    #[test]
    fn a_landed_plan_is_the_history_row_for_row() {
        let arena = arena();
        for steps in [0, 1, 2, 5, 64, 65, 1000] {
            let expected = history(steps);
            let filled = arena.fill(&expected).expect("room");
            for slice_steps in [1, 2, 7, 64, 1 << 17] {
                let plan = UploadPlan::new(&filled, 9, 77, counts(&expected), slice_steps)
                    .expect("a plan");
                let decoded = DecodedFill::decode(&land(&plan), &plan.descriptor, plan.error_at);
                assert_eq!(
                    decoded.differences(&filled, &plan.descriptor),
                    Vec::<&str>::new(),
                    "{steps} steps in slices of {slice_steps}"
                );
                assert_eq!(decoded.error, 0);
                assert_eq!(decoded.descriptor.identity.nonce, 9);
                assert_eq!(decoded.descriptor.program_key, 77);
            }
        }
    }

    /// The slices cover every step once, each slice's copy carries the step after it, and the
    /// reads and writes copies cover their tables once, in order.
    #[test]
    fn slices_partition_the_rows_and_carry_the_next_step() {
        let arena = arena();
        let expected = history(1000);
        let filled = arena.fill(&expected).expect("room");
        let plan = UploadPlan::new(&filled, 1, 0, counts(&expected), 64).expect("a plan");
        let d = &plan.descriptor;
        let (mut step, mut read, mut write) = (0, d.reads_at, d.writes_at);
        for slice in &plan.slices {
            assert_eq!(slice.steps.start, step);
            let carried = (slice.steps.end + 1).min(1000) - slice.steps.start;
            let [steps, reads, writes] = slice.pieces;
            assert_eq!(steps.len, carried * size_of::<Step>());
            assert_eq!(steps.dst_at, d.steps_at + (step * size_of::<Step>()) as u64);
            assert_eq!((reads.dst_at, writes.dst_at), (read, write));
            (step, read, write) = (
                slice.steps.end,
                read + reads.len as u64,
                write + writes.len as u64,
            );
        }
        assert_eq!(step, 1000);
        let rows = |table: Table| filled.rows()[table.index()] as u64;
        assert_eq!(read, d.reads_at + rows(Table::Reads) * 16);
        assert_eq!(write, d.writes_at + rows(Table::Writes) * 24);
    }

    #[test]
    fn every_table_lands_inside_the_fill_and_apart() {
        let arena = arena();
        let expected = history(300);
        let filled = arena.fill(&expected).expect("room");
        let plan = UploadPlan::new(&filled, 1, 0, counts(&expected), 64).expect("a plan");
        let (layout, d) = (&plan.layout, &plan.descriptor);
        assert_eq!(layout.exceptions_at, size_of::<FillDescriptor>());
        let mut regions = [
            (0, size_of::<FillDescriptor>() as u64),
            (d.exceptions_at, u64::from(d.exceptions) * 16),
            (d.steps_at, u64::from(d.identity.steps) * 20),
            (d.reads_at, u64::from(d.reads) * 16),
            (d.writes_at, u64::from(d.writes) * 24),
            (d.entries_at, u64::from(d.list_start[LISTS]) * 4),
            (d.syscalls_at, u64::from(d.syscalls) * 40),
            (d.completion_at, 8),
        ];
        for &(at, _) in &regions[1..] {
            assert_eq!(at % 8, 0);
        }
        regions.sort_unstable();
        for pair in regions.windows(2) {
            assert!(pair[0].0 + pair[0].1 <= pair[1].0, "{pair:?} overlap");
        }
        assert_eq!(d.completion_at + 8, d.buffer_bytes);
        assert!(plan.error_at >= d.buffer_bytes);
        assert_eq!(plan.allocation_bytes, plan.error_at + 4);
        assert_eq!(d.list_start[0], 0);
        for (index, list) in Table::LISTS.into_iter().enumerate() {
            assert_eq!(
                d.list_start[index + 1] - d.list_start[index],
                filled.list_rows(list).len() as u32
            );
        }
    }

    #[test]
    fn counts_that_do_not_split_the_coarse_lists_are_refused() {
        let arena = arena();
        let expected = history(100);
        let filled = arena.fill(&expected).expect("room");
        let mut wrong = counts(&expected);
        wrong.addw += 1;
        assert!(matches!(
            UploadPlan::new(&filled, 1, 0, wrong, 64),
            Err(PlanError::ScanDisagrees { .. })
        ));
    }

    #[test]
    fn a_slice_boundary_outside_its_neighbours_rows_is_refused() {
        let arena = arena();
        let mut expected = history(100);
        expected.steps[64].first_read = expected.reads.len() as u32 + 1;
        let filled = arena.fill(&expected).expect("room");
        assert_eq!(
            UploadPlan::new(&filled, 1, 0, counts(&expected), 64).err(),
            Some(PlanError::RowsOutOfOrder {
                step: 64,
                what: "read",
                at: expected.reads.len() + 1,
                lo: 0,
                hi: expected.reads.len(),
            })
        );
    }

    /// A history on the heap lands as the same fill as its copy in a slot, from pageable sources.
    #[test]
    fn a_heap_history_lands_as_its_slot_copy_does() {
        let arena = arena();
        let expected = history(300);
        let filled = arena.fill(&expected).expect("room");
        let in_slot = UploadPlan::new(&filled, 4, 5, counts(&expected), 64).expect("a plan");
        let on_heap = UploadPlan::new(&expected, 4, 5, counts(&expected), 64).expect("a plan");
        assert_eq!(on_heap.descriptor, in_slot.descriptor);
        assert_eq!(land(&on_heap), land(&in_slot));
        assert!(on_heap
            .slices
            .iter()
            .flat_map(|slice| slice.pieces)
            .chain(on_heap.rest.iter().copied())
            .all(|piece| !piece.pinned));
        let decoded = DecodedFill::decode(&land(&on_heap), &on_heap.descriptor, on_heap.error_at);
        assert!(decoded
            .differences(&expected, &on_heap.descriptor)
            .is_empty());
    }
}
