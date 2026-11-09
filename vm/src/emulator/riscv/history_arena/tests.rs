use std::{
    num::NonZeroUsize,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

use serde_json::{json, Value};

use super::*;

const SLOTS: NonZeroUsize = NonZeroUsize::new(2).unwrap();

/// Room for a few rows in every table.
const SMALL: HistoryCapacity = {
    let mut capacity = HistoryCapacity::CENSUS;
    let mut index = 0;
    while index < TABLE_COUNT {
        capacity = capacity.with_rows(Table::ALL[index], 8);
        index += 1;
    }
    capacity
};

/// Rows `0..rows` in every table, each row distinct within its table.
fn history(rows: u32) -> ExecutionHistory {
    let list = || (0..rows).collect::<Rows<u32>>();
    ExecutionHistory {
        chunk: 3,
        steps: (0..rows)
            .map(|i| Step {
                clk: 8 + 4 * i,
                pc: 0x1000 + 4 * i,
                next_pc: 0x1004 + 4 * i,
                first_read: 2 * i,
                first_write: i,
            })
            .collect(),
        reads: (0..rows)
            .map(|i| ReadAccess {
                value: u64::from(i) << 33 | 1,
                prev_chunk: 2,
                prev_timestamp: i,
            })
            .collect(),
        writes: (0..rows)
            .map(|i| Access {
                value: u64::from(i) << 34 | 2,
                prev_value: u64::from(i),
                prev_chunk: 1,
                prev_timestamp: i + 1,
            })
            .collect(),
        chip_steps: ChipSteps {
            add: list(),
            sub: list(),
            mul: list(),
            bitwise: list(),
            shift_left: list(),
            shift_right: list(),
            lt: list(),
            divrem: list(),
            memory: list(),
            ecall: list(),
            branch: list(),
        },
        operand_exceptions: (0..rows)
            .map(|i| OperandException {
                step: i,
                slot: 3,
                value: u64::from(i) << 40,
            })
            .collect(),
        syscalls: (0..rows)
            .map(|i| SyscallEvent {
                chunk: 3,
                clk: u64::from(i) << 35,
                syscall_id: i,
                arg1: u64::from(i) + 7,
                arg2: u64::from(i) + 9,
            })
            .collect(),
        // On the heap whatever the slot: no region holds it.
        unaligned: Rows::new(),
    }
}

/// Every row of every table, field by field.
fn assert_same_rows(got: &ExecutionHistory, expected: &ExecutionHistory) {
    let syscall = |e: &SyscallEvent| (e.chunk, e.clk, e.syscall_id, e.arg1, e.arg2);
    assert_eq!(got.chunk, expected.chunk);
    assert_eq!(got.steps, expected.steps);
    assert_eq!(got.reads, expected.reads);
    assert_eq!(got.writes, expected.writes);
    assert_eq!(got.chip_steps, expected.chip_steps);
    assert_eq!(got.operand_exceptions, expected.operand_exceptions);
    assert_eq!(
        got.syscalls.iter().map(syscall).collect::<Vec<_>>(),
        expected.syscalls.iter().map(syscall).collect::<Vec<_>>()
    );
}

fn arena(capacity: HistoryCapacity, policy: SpillPolicy) -> HistoryArena {
    HistoryArena::pin(SLOTS, 1 << 20, capacity, policy).expect("an arena")
}

#[test]
fn census_constants_are_the_committed_capacity_table() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../perf/aot/bench/history_capacity.json"
    );
    let text = std::fs::read_to_string(path).expect("the committed capacity table");
    assert_eq!(
        HistoryCapacity::from_capacity_table(&text, &ROW_SHAPES),
        Ok(HistoryCapacity::CENSUS)
    );
}

#[test]
fn a_census_slot_is_its_tables_and_nothing_else() {
    let layout = SlotLayout::new(&HistoryCapacity::CENSUS, &ROW_SHAPES).expect("a layout");
    assert_eq!(layout.bytes(), 697_061_444);
    let mut regions: Vec<(usize, usize)> = Table::ALL
        .into_iter()
        .map(|table| {
            let shape = ROW_SHAPES[table.index()];
            let start = layout.offset(table);
            assert_eq!(start % shape.align, 0, "table {} misaligned", table.name());
            (
                start,
                start + HistoryCapacity::CENSUS.rows(table) * shape.bytes,
            )
        })
        .collect();
    regions.sort_unstable();
    assert_eq!(regions.first().map(|r| r.0), Some(0));
    assert_eq!(regions.last().map(|r| r.1), Some(layout.bytes()));
    for pair in regions.windows(2) {
        assert_eq!(pair[0].1, pair[1].0, "a gap or an overlap between regions");
    }
}

#[test]
fn a_capacity_table_is_refused_when_it_does_not_describe_this_build() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../perf/aot/bench/history_capacity.json"
    );
    let text = std::fs::read_to_string(path).expect("the committed capacity table");
    let committed: Value = serde_json::from_str(&text).expect("json");
    type Change = fn(&mut Value);
    let changes: &[(&str, Change)] = &[
        ("another format", |t| {
            t["format"] = json!("pico-history-capacity/1")
        }),
        ("two tables swapped", |t| {
            t["tables"].as_array_mut().unwrap().swap(0, 1)
        }),
        ("another row size", |t| {
            t["tables"][0]["row_bytes"] = json!(24)
        }),
        ("a capacity under its rows", |t| {
            t["tables"][2]["capacity"] = json!(1)
        }),
        ("a slot that is not its tables' sum", |t| {
            t["slot_bytes"] = json!(1)
        }),
        ("a table missing", |t| {
            t["tables"].as_array_mut().unwrap().pop();
        }),
    ];
    for (what, change) in changes {
        let mut table = committed.clone();
        change(&mut table);
        assert!(
            HistoryCapacity::from_capacity_table(&table.to_string(), &ROW_SHAPES).is_err(),
            "{what} was accepted"
        );
    }
}

#[test]
fn a_chunk_larger_than_the_census_measured_is_refused() {
    assert!(matches!(
        HistoryArena::pin(SLOTS, 1 << 24, HistoryCapacity::CENSUS, SpillPolicy::Spill),
        Err(ArenaError::ChunkLargerThanMeasured { .. })
    ));
}

#[test]
fn a_history_round_trips_through_a_slot() {
    let arena = arena(SMALL, SpillPolicy::Spill);
    let expected = history(5);
    let filled = arena.fill(&expected).expect("room");
    assert!(filled.holds_slot());
    assert_eq!(filled.spilled().count(), 0);
    assert!(Table::ALL.into_iter().all(|table| filled.is_in_slot(table)));
    assert_eq!(filled.rows(), [5; TABLE_COUNT]);
    assert_same_rows(&filled, &expected);
    drop(filled);
    let stats = arena.stats();
    assert_eq!((stats.acquisitions, stats.returns), (1, 1));
    assert_eq!(stats.spills, [0; TABLE_COUNT]);
}

/// Each table past its region alone: that table spills, keeps every row in order, and is counted;
/// the others stay in the slot.
#[test]
fn each_table_spills_alone_and_keeps_every_row() {
    let expected = history(5);
    for table in Table::ALL {
        let arena = arena(SMALL.with_rows(table, 4), SpillPolicy::Spill);
        let filled = arena.fill(&expected).expect("a spill, not a refusal");
        assert_eq!(filled.spilled().collect::<Vec<_>>(), [table]);
        for other in Table::ALL {
            assert_eq!(filled.is_in_slot(other), other != table, "{}", other.name());
        }
        assert_same_rows(&filled, &expected);
        let mut spills = [0; TABLE_COUNT];
        spills[table.index()] = 1;
        assert_eq!(arena.stats().spills, spills, "{}", table.name());
    }
}

#[test]
fn a_table_with_no_room_at_all_spills_on_its_first_row() {
    let arena = arena(SMALL.with_rows(Table::Syscalls, 0), SpillPolicy::Spill);
    let expected = history(1);
    let filled = arena.fill(&expected).expect("a spill");
    assert_eq!(filled.spilled().collect::<Vec<_>>(), [Table::Syscalls]);
    assert_same_rows(&filled, &expected);
}

/// With spilling refused, an overfilled table stops the fill at its row with what it was asked
/// for, and the slot goes back.
#[test]
fn a_refused_spill_fails_loudly_and_returns_the_slot() {
    let arena = arena(SMALL.with_rows(Table::Ecall, 4), SpillPolicy::Refuse);
    let refused = arena.fill(&history(5)).err();
    assert_eq!(
        refused,
        Some(TableFull {
            table: Table::Ecall,
            capacity: 4,
            needed: 5
        })
    );
    let stats = arena.stats();
    assert_eq!((stats.acquisitions, stats.returns), (1, 1));
    assert_eq!(stats.spills, [0; TABLE_COUNT]);
}

/// A clone is a heap copy: it takes and returns no slot, and holds the same rows after the
/// original has gone back.
#[test]
fn a_clone_takes_no_slot() {
    let arena = arena(SMALL, SpillPolicy::Spill);
    let expected = history(5);
    let filled = arena.fill(&expected).expect("room");
    let before = arena.stats();
    let copy = filled.clone();
    assert_eq!(arena.stats(), before);
    assert!(!copy.holds_slot());
    assert!(Table::ALL.into_iter().all(|table| !copy.is_in_slot(table)));
    assert_eq!(copy.spilled().count(), 0);
    drop(filled);
    assert_same_rows(&copy, &expected);
    let after_original = arena.stats();
    drop(copy);
    assert_eq!(arena.stats(), after_original);
    assert_eq!(after_original.returns, 1);
}

/// A table moved out of its history keeps the slot: it goes back once the last table in it drops.
#[test]
fn a_slot_goes_back_with_its_last_table() {
    let arena = arena(SMALL, SpillPolicy::Spill);
    let mut filled = arena.fill(&history(5)).expect("room");
    let steps = std::mem::take(&mut filled.steps);
    drop(filled);
    assert_eq!(
        arena.stats().returns,
        0,
        "the slot went back under a live table"
    );
    assert_eq!(steps, history(5).steps);
    drop(steps);
    assert_eq!(arena.stats().returns, 1);
}

/// A later stretch's rows move into the earlier one's slot, and the later's slot goes back when it
/// drops, as a chunk's replay segments fold.
#[test]
fn an_appended_history_moves_into_the_earlier_ones_slot() {
    let arena = arena(SMALL, SpillPolicy::Spill);
    let mut expected = history(2);
    expected.append(&mut history(2));
    let mut folded = arena.fill(&history(2)).expect("room");
    let mut later = arena.fill(&history(2)).expect("room");
    folded.append(&mut later);
    assert!(later.steps.is_empty() && later.holds_slot());
    drop(later);
    assert_eq!(arena.stats().returns, 1);
    assert!(folded.holds_slot());
    assert_eq!(folded.spilled().count(), 0);
    assert_same_rows(&folded, &expected);
}

/// A history in a slot serializes as the same history on the heap does, and comes back on the
/// heap.
#[test]
fn a_history_in_a_slot_serializes_as_one_on_the_heap() {
    let arena = arena(SMALL, SpillPolicy::Spill);
    let expected = history(5);
    let filled = arena.fill(&expected).expect("room");
    let text = serde_json::to_string(&filled).expect("a history serializes");
    assert_eq!(
        text,
        serde_json::to_string(&expected).expect("a history serializes")
    );
    let back: ExecutionHistory = serde_json::from_str(&text).expect("a history deserializes");
    assert!(!back.holds_slot());
    assert_same_rows(&back, &expected);
}

/// A take with every slot held waits for one to come back, and is counted.
#[test]
fn a_take_waits_for_a_held_slot() {
    let arena = Arc::new(
        HistoryArena::pin(NonZeroUsize::MIN, 1 << 20, SMALL, SpillPolicy::Spill).expect("an arena"),
    );
    let held = arena.take(0);
    let released = Arc::new(AtomicBool::new(false));
    let taker = {
        let (arena, released) = (Arc::clone(&arena), Arc::clone(&released));
        std::thread::spawn(move || {
            let taken = arena.take(1);
            assert!(
                released.load(Ordering::SeqCst),
                "a take returned a held slot"
            );
            drop(taken);
        })
    };
    while arena.stats().blocked_takes == 0 && !taker.is_finished() {
        std::thread::yield_now();
    }
    released.store(true, Ordering::SeqCst);
    drop(held);
    taker.join().expect("the taker");
    let stats = arena.stats();
    assert_eq!(stats.blocked_takes, 1);
    assert_eq!(stats.max_in_use, 1);
    assert_eq!((stats.acquisitions, stats.returns), (2, 2));
}

#[test]
fn the_peak_restarts_from_the_slots_held_now() {
    let arena = arena(SMALL, SpillPolicy::Spill);
    let first = arena.take(1);
    let second = arena.take(2);
    drop(second);
    assert_eq!(arena.take_max_in_use(), 2);
    assert_eq!(arena.stats().max_in_use, 1, "one slot is still held");
    drop(first);
    assert_eq!(arena.take_max_in_use(), 1);
    assert_eq!(arena.take_max_in_use(), 0);
}

/// The pipeline's stash at the arena: two free slots, and the two places after a late one asking
/// first. Granted first come, first served, they would take both, and with their records held
/// behind the late chunk it would wait for good; in turn, they wait for it, and the wait counts.
#[test]
fn a_late_place_takes_before_the_places_after_it_that_asked_first() {
    let arena = Arc::new(arena(SMALL, SpillPolicy::Spill));
    let order = Arc::new(GrantOrder::default());
    let late = order.ticket();
    let takers: Vec<_> = (1..=2)
        .map(|chunk| {
            let (arena, ticket) = (Arc::clone(&arena), order.ticket());
            std::thread::spawn(move || assert!(arena.take_in_turn(chunk, &ticket).is_some()))
        })
        .collect();
    while arena.stats().blocked_takes < 2 && takers.iter().any(|taker| !taker.is_finished()) {
        std::thread::yield_now();
    }
    assert_eq!(
        arena.stats().acquisitions,
        0,
        "a later place took a slot before the late one"
    );
    drop(arena.take_in_turn(0, &late).expect("a free slot"));
    for taker in takers {
        taker.join().expect("a taker");
    }
    let stats = arena.stats();
    assert_eq!(stats.blocked_takes, 2);
    assert_eq!((stats.acquisitions, stats.returns), (3, 3));
}

/// A place that takes no slot, its chunk emulated to nothing or its replay failed, drops its
/// ticket, and the place after it takes without waiting for it.
#[test]
fn a_ticket_dropped_without_a_take_lets_the_next_place_take() {
    let arena = arena(SMALL, SpillPolicy::Spill);
    let order = Arc::new(GrantOrder::default());
    let (skipped, next) = (order.ticket(), order.ticket());
    assert!(!next.is_due());
    drop(skipped);
    let taken = arena.take_in_turn(1, &next).expect("a free slot");
    assert!(taken.holds_slot());
    assert_eq!(arena.stats().blocked_takes, 0);
}

/// A take in turn waiting for a slot gives up once its order closes: the run has failed, and the
/// slots may be held by records the failure never frees.
#[test]
fn a_take_in_turn_gives_up_its_wait_for_a_slot_when_its_order_closes() {
    let arena = Arc::new(arena(SMALL, SpillPolicy::Spill));
    let held = [arena.take(0), arena.take(1)];
    let order = Arc::new(GrantOrder::default());
    let taker = {
        let (arena, ticket) = (Arc::clone(&arena), order.ticket());
        std::thread::spawn(move || arena.take_in_turn(2, &ticket).is_none())
    };
    while arena.stats().blocked_takes == 0 && !taker.is_finished() {
        std::thread::yield_now();
    }
    order.close();
    assert!(
        taker.join().expect("the taker"),
        "a take got a slot none came back to"
    );
    let stats = arena.stats();
    assert_eq!(
        (stats.acquisitions, stats.returns, stats.blocked_takes),
        (2, 0, 1)
    );
    drop(held);
}

#[test]
fn a_table_spills_once_and_keeps_its_order_across_the_boundary() {
    let mut region = [0u64; 4];
    // SAFETY: the region outlives the table and is written through it alone.
    let mut table = unsafe {
        Rows::resident(
            Table::Reads,
            NonNull::new(region.as_mut_ptr()).unwrap(),
            4,
            SpillPolicy::Spill,
            None,
        )
    };
    assert_eq!(table.try_extend_from_slice(&[1, 2, 3]), Ok(false));
    assert!(table.is_resident());
    assert_eq!(table.try_extend_from_slice(&[4, 5]), Ok(true));
    assert!(table.is_spilled());
    table.push(6);
    assert_eq!(table.as_slice(), [1, 2, 3, 4, 5, 6]);
    drop(table);
    assert_eq!(region, [1, 2, 3, 0], "a spilled write landed in the region");
}

/// A push spills the way a slice does, and a pop reads back what was pushed, in either storage.
#[test]
fn a_push_past_the_region_spills_and_a_pop_undoes_it() {
    let mut region = [0u32; 2];
    // SAFETY: the region outlives the table and is written through it alone.
    let mut table = unsafe {
        Rows::resident(
            Table::Lt,
            NonNull::new(region.as_mut_ptr()).unwrap(),
            2,
            SpillPolicy::Spill,
            None,
        )
    };
    table.extend([1, 2]);
    assert!(table.is_resident());
    table.push(3);
    assert!(table.is_spilled());
    assert_eq!(table.pop(), Some(3));
    assert_eq!(table, [1, 2]);
    let copy = table.clone();
    assert!(!copy.is_resident() && !copy.is_spilled());
    drop(table);
    assert_eq!(region, [1, 2]);
}

/// Reserved past its room under a refusing policy, a region still refuses the row a push would.
#[test]
fn a_reservation_writes_no_row_and_leaves_a_region_in_place() {
    let mut region = [0u32; 2];
    // SAFETY: the region outlives the table and is written through it alone.
    let mut table = unsafe {
        Rows::resident(
            Table::Memory,
            NonNull::new(region.as_mut_ptr()).unwrap(),
            2,
            SpillPolicy::Refuse,
            None,
        )
    };
    table.push(7);
    table.reserve(16);
    assert!(table.is_resident());
    assert_eq!(table.as_slice(), [7]);
    assert_eq!(table.capacity(), 2);
    table.push(8);
    assert_eq!(
        table.try_extend_from_slice(&[9]),
        Err(TableFull {
            table: Table::Memory,
            capacity: 2,
            needed: 3
        })
    );
    drop(table);
    assert_eq!(region, [7, 8]);

    let mut heap = Rows::<u32>::new();
    heap.reserve(16);
    assert!(heap.is_empty() && heap.capacity() >= 16);
}

#[test]
fn a_refused_write_writes_nothing() {
    let mut region = [0u32; 2];
    // SAFETY: the region outlives the table and is written through it alone.
    let mut table = unsafe {
        Rows::resident(
            Table::Add,
            NonNull::new(region.as_mut_ptr()).unwrap(),
            2,
            SpillPolicy::Refuse,
            None,
        )
    };
    table.push(7);
    assert_eq!(
        table.try_extend_from_slice(&[8, 9]),
        Err(TableFull {
            table: Table::Add,
            capacity: 2,
            needed: 3
        })
    );
    assert_eq!(table.as_slice(), [7]);
    assert!(table.is_resident());
    drop(table);
    assert_eq!(region, [7, 0]);
}

/// A writer that cannot handle a refusal, the sink among them, stops at the refused row.
#[test]
#[should_panic(expected = "history table add is full at 1 rows and was asked for 2")]
fn a_refused_push_stops_the_writer() {
    let mut region = [0u32; 1];
    // SAFETY: the region outlives the table and is written through it alone.
    let mut table = unsafe {
        Rows::resident(
            Table::Add,
            NonNull::new(region.as_mut_ptr()).unwrap(),
            1,
            SpillPolicy::Refuse,
            None,
        )
    };
    table.push(1);
    table.push(2);
}
