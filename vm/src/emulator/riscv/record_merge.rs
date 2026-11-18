//! Fold a chunk's replay segments back into one record.
//!
//! Splitting a chunk's replay across threads only pays if the chunk still proves once, so the
//! segments' records have to become the record the unsplit replay would have produced.
//!
//! `cpu_local_memory_access` is concatenated, not re-aggregated by address: an unsplit chunk
//! already carries several windows per address, so folding them by address destroys ones it
//! keeps and the memory bus goes unbalanced. A split only adds the one window that spans the
//! cut, and the two chain, so the global LogUp still balances.
//!
//! Each added window is two cross-chunk events the chunk splitter did not count: it holds the
//! unsplit replay's events under the height of the chunk's `Global` table, and a fold can be
//! past it where that record is not. Such a fold has its chained windows rejoined
//! ([`rejoin_chained_windows`]), which leaves the unsplit replay's windows or fewer.
//!
//! An execution history holds indices into its own tables, so `append` folds it whatever the
//! caller, moving each later segment's past the steps and accesses before them
//! ([`super::history::ExecutionHistory::append`]). Segments either all carry a history or none
//! does: a fold of both kinds would hand on a history of only some of the chunk, so it is refused.
//!
//! The equivalence gate in [`super::record_digest`] is what says the fold is right.

use hashbrown::HashMap;

use super::record::EmulationRecord;
use crate::{
    chips::chips::riscv_memory::event::MemoryLocalEvent, emulator::record::RecordBehavior,
    mle::machine::shape::MLE_GLOBAL_LOG_HEIGHT,
};

/// `MLE_SPLIT_CHECK=1` logs what each fold saw. Read once: a value that changed mid-run would
/// make the numbers it prints incomparable.
static SPLIT_CHECK: std::sync::LazyLock<bool> =
    std::sync::LazyLock::new(|| std::env::var("MLE_SPLIT_CHECK").is_ok_and(|value| value == "1"));

/// Fold `segments` — a chunk's replay segments, in clock order — into a single record.
///
/// One segment folds to itself. The caller short-circuits that case rather than calling here, so
/// that with split replay off the shipped path does not run this code at all; the identity is
/// kept, and tested, so a caller that does pass one segment still gets the right answer.
pub fn merge_segments(segments: Vec<EmulationRecord>) -> EmulationRecord {
    merge_segments_within(segments, 1 << MLE_GLOBAL_LOG_HEIGHT)
}

/// [`merge_segments`] for a `Global` table of `global_event_cap` rows: the cap the chunk
/// splitter cut the chunk under ([`super::chunk_split::ChunkSplitConfig`]).
pub fn merge_segments_within(
    mut segments: Vec<EmulationRecord>,
    global_event_cap: usize,
) -> EmulationRecord {
    assert!(
        !segments.is_empty(),
        "a chunk always has at least one replay segment"
    );

    // The chunk's public values straddle the segments: where it started comes from the first,
    // where it ended from the last. `append` does not carry them at all.
    let last = segments.last().expect("checked non-empty");
    let mut tail_public_values = last.public_values;
    // A digest word lands in the record of the segment whose COMMIT wrote it, and each segment's
    // record starts with none, so the chunk's words are all the segments' together.
    for segment in &segments {
        let written = &segment.public_values;
        keep_written(
            &mut tail_public_values.committed_value_digest,
            &written.committed_value_digest,
        );
        keep_written(
            &mut tail_public_values.deferred_proofs_digest,
            &written.deferred_proofs_digest,
        );
    }
    let tail_is_last = last.is_last;
    let tail_shape = last.shape.clone();

    let segment_count = segments.len();
    let local_lens: Vec<usize> = segments
        .iter()
        .map(|segment| segment.cpu_local_memory_access.len())
        .collect();
    let step_lens: Vec<usize> = segments
        .iter()
        .filter_map(|segment| Some(segment.history.as_ref()?.steps.len()))
        .collect();
    assert!(
        step_lens.is_empty() || step_lens.len() == segment_count,
        "{} of a chunk's {segment_count} replay segments carry an execution history, which \
         folded would cover only theirs",
        step_lens.len()
    );

    let mut merged = segments.remove(0);
    let head_start_pc = merged.public_values.start_pc;

    for mut segment in segments {
        merged.append(&mut segment);
    }

    // The fold owes the caller every event it was handed; losing one proves the chunk short,
    // which is silent. Cheap to state, so state it.
    let merged_steps = merged
        .history
        .as_ref()
        .map_or(0, |history| history.steps.len());
    assert_eq!(
        merged_steps,
        step_lens.iter().sum::<usize>(),
        "the fold dropped history steps"
    );

    if *SPLIT_CHECK {
        tracing::info!(
            target: "bench",
            "[mergeprobe] segments={segment_count} local_lens={local_lens:?} \
             merged_local={} step_lens={step_lens:?} \
             merged_steps={merged_steps}",
            merged.cpu_local_memory_access.len(),
        );
    }

    // The splitter counted the unsplit replay's cross-chunk events against the cap; the fold
    // has two more for every address live across a cut. Only a fold past the cap is rejoined:
    // the join walks every window, and the windows it removes cancel on the bus as they are.
    if segment_count > 1 && global_events_at_most(&merged) > global_event_cap {
        let before = merged.cpu_local_memory_access.len();
        let rejoined = rejoin_chained_windows(&mut merged.cpu_local_memory_access);
        tracing::info!(
            target: "bench",
            "split replay: the fold of {segment_count} segments held {before} memory windows, \
             past what the chunk's Global table takes; {rejoined} rejoined across the cuts"
        );
    }

    merged.public_values = tail_public_values;
    merged.public_values.start_pc = head_start_pc;
    merged.is_last = tail_is_last;
    merged.shape = tail_shape;
    merged
}

/// The cross-chunk events of a chunk's own record, at most: two for every memory window (a
/// fresh one has one, which this does not look for) and one for every syscall, which the
/// chunk's history lists.
fn global_events_at_most(record: &EmulationRecord) -> usize {
    let syscalls = record
        .history
        .as_ref()
        .map_or(0, |history| history.syscalls.len());
    2 * record.cpu_local_memory_access.len() + syscalls
}

/// Join, per address, every window to the one it chains into: a window whose final access is
/// the initial access of the next one to close becomes one window with it. Returns how many
/// windows that removed. A joined window stays where the first of its run was.
///
/// The inner pair of two such windows cancels on the Global bus and on the chunk's memory bus,
/// so the joined window leaves both as they were. A cut gives every address live across it
/// exactly such a pair where the unsplit replay has one window.
pub fn rejoin_chained_windows(windows: &mut Vec<MemoryLocalEvent>) -> usize {
    let mut by_addr: HashMap<u64, Vec<usize>> = HashMap::with_capacity(windows.len());
    for (index, window) in windows.iter().enumerate() {
        by_addr.entry(window.addr).or_default().push(index);
    }
    let mut removed = vec![false; windows.len()];
    let mut rejoined = 0;
    for indices in by_addr.values_mut().filter(|indices| indices.len() > 1) {
        // In the order they close: an initial access carries the record from whenever the
        // address was last touched, which says nothing about where its window sits.
        indices.sort_unstable_by_key(|&index| windows[index].final_mem_access.timestamp);
        let mut run = indices[0];
        for &next in &indices[1..] {
            if windows[run].final_mem_access == windows[next].initial_mem_access {
                windows[run].final_mem_access = windows[next].final_mem_access;
                removed[next] = true;
                rejoined += 1;
            } else {
                run = next;
            }
        }
    }
    let mut removed = removed.into_iter();
    windows.retain(|_| !removed.next().expect("a flag for every window"));
    rejoined
}

/// Overwrites each word of `words` with `later`'s where `later`'s is nonzero: a record leaves a
/// word no COMMIT wrote at zero. A chunk committing two different values to one word fails the
/// ECALL constraints, so reading zero as unwritten loses nothing a provable chunk writes.
fn keep_written(words: &mut [u32], later: &[u32]) {
    for (word, &later) in words.iter_mut().zip(later) {
        if later != 0 {
            *word = later;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        chips::chips::{
            alu::event::AluEvent,
            byte::event::ByteLookupEvent,
            riscv_memory::event::{MemoryLocalEvent, MemoryRecord},
        },
        compiler::riscv::opcode::ByteOpcode,
        emulator::riscv::{
            history::{Access, ChipSteps, ExecutionHistory, ReadAccess, Step},
            record_digest::first_difference,
        },
    };

    /// One window over `addr`: entered from the chunk's entry record, closed at `timestamp`. An
    /// entry that opens and closes on the same access is not a state the AIR admits, so no
    /// fixture builds one.
    fn local_event(addr: u64, value: u64, timestamp: u32) -> MemoryLocalEvent {
        MemoryLocalEvent {
            addr,
            initial_mem_access: MemoryRecord::default(),
            final_mem_access: MemoryRecord {
                value,
                chunk: 1,
                timestamp,
            },
        }
    }

    /// A segment's history of `steps` steps of chunk 5, a read, a write and a memory-list entry
    /// each, indexed from its own first step.
    fn with_history(steps: u32) -> EmulationRecord {
        let history = ExecutionHistory {
            chunk: 5,
            steps: (0..steps)
                .map(|index| Step {
                    first_read: index,
                    first_write: index,
                    ..Step::default()
                })
                .collect(),
            reads: vec![ReadAccess::default(); steps as usize].into(),
            writes: vec![Access::default(); steps as usize].into(),
            chip_steps: ChipSteps {
                memory: (0..steps).collect(),
                ..ChipSteps::default()
            },
            ..ExecutionHistory::default()
        };
        EmulationRecord {
            history: Some(history),
            ..Default::default()
        }
    }

    /// Each later segment moves past everything folded before it.
    #[test]
    fn histories_fold_with_their_indices_moved_past_everything_before_them() {
        let merged = merge_segments(vec![with_history(2), with_history(3), with_history(1)]);
        let history = merged.history.expect("the folded history");
        let first_rows: Vec<(u32, u32)> = history
            .steps
            .iter()
            .map(|step| (step.first_read, step.first_write))
            .collect();
        assert_eq!(
            first_rows,
            (0..6).map(|index| (index, index)).collect::<Vec<_>>()
        );
        assert_eq!(history.chip_steps.memory, (0..6).collect::<Vec<u32>>());
        assert_eq!((history.reads.len(), history.writes.len()), (6, 6));
        assert_eq!(history.chunk, 5);
    }

    /// A fold of segments some of which wrote a history would hand on a history of only part of
    /// the chunk, whichever segment lacks one.
    #[test]
    fn segments_with_and_without_a_history_are_refused() {
        for order in [[true, false], [false, true]] {
            let segments: Vec<EmulationRecord> = order
                .into_iter()
                .map(|carries| {
                    if carries {
                        with_history(1)
                    } else {
                        EmulationRecord::default()
                    }
                })
                .collect();
            let refused = std::panic::catch_unwind(|| merge_segments(segments));
            assert!(refused.is_err(), "history in the segments {order:?}");
        }
    }

    #[test]
    fn one_segment_folds_to_itself() {
        let mut only = EmulationRecord::default();
        only.add_events.push(AluEvent::default());
        only.cpu_local_memory_access.push(local_event(0x100, 7, 3));
        let expected = only.clone();
        assert_eq!(
            first_difference(&merge_segments(vec![only]), &expected),
            None
        );
    }

    #[test]
    fn memory_indices_are_rebased_onto_the_merged_history() {
        let mut head = with_history(4);
        head.history.as_mut().unwrap().chip_steps.memory = vec![1, 3].into();
        let mut tail = with_history(3);
        tail.history.as_mut().unwrap().chip_steps.memory = vec![0, 2].into();

        let history = merge_segments(vec![head, tail]).history.unwrap();

        assert_eq!(history.steps.len(), 7);
        assert_eq!(history.chip_steps.memory, vec![1, 3, 4, 6]);
    }

    /// Both segments' windows survive: an unsplit chunk already carries more than one window
    /// per address, so folding them by address would destroy information. A split only adds the
    /// one window that spans the cut.
    #[test]
    fn both_segments_windows_survive() {
        let head = EmulationRecord {
            cpu_local_memory_access: vec![local_event(0x100, 1, 10), local_event(0x200, 2, 11)],
            ..Default::default()
        };
        let tail = EmulationRecord {
            cpu_local_memory_access: vec![local_event(0x100, 9, 42), local_event(0x300, 3, 43)],
            ..Default::default()
        };

        let merged = merge_segments(vec![head, tail]);

        assert_eq!(
            merged.cpu_local_memory_access.len(),
            4,
            "every window has to survive the fold"
        );
        let windows: Vec<(u64, u32)> = merged
            .cpu_local_memory_access
            .iter()
            .map(|event| (event.addr, event.final_mem_access.timestamp))
            .collect();
        assert_eq!(
            windows,
            vec![(0x100, 10), (0x200, 11), (0x100, 42), (0x300, 43)],
            "in segment order"
        );
    }

    /// A window of `addr` that opens on `initial` and closes on `(value, timestamp)`.
    fn window(addr: u64, initial: MemoryRecord, value: u64, timestamp: u32) -> MemoryLocalEvent {
        MemoryLocalEvent {
            addr,
            initial_mem_access: initial,
            final_mem_access: MemoryRecord {
                value,
                chunk: 1,
                timestamp,
            },
        }
    }

    /// Windows that chain are joined, each run into the place of its first; a window that
    /// opens on another record than the previous one closed on stays.
    #[test]
    fn chained_windows_are_rejoined() {
        let entry = MemoryRecord::default();
        let a1 = window(0x100, entry, 1, 10);
        let a2 = window(0x100, a1.final_mem_access, 2, 40);
        let a3 = window(0x100, a2.final_mem_access, 3, 70);
        // 0x200: a precompile wrote it between the two windows, so they do not chain.
        let b1 = window(0x200, entry, 5, 20);
        let other = MemoryRecord {
            value: 6,
            chunk: 1,
            timestamp: 30,
        };
        let b2 = window(0x200, other, 7, 50);
        let c = window(0x300, entry, 9, 60);
        // The list is in no order of closing: the later window of 0x100 comes first.
        let mut windows = vec![a3, b1, a1, c, b2, a2];

        assert_eq!(rejoin_chained_windows(&mut windows), 2);

        let joined = window(0x100, entry, 3, 70);
        let as_tuples = |windows: &[MemoryLocalEvent]| -> Vec<(u64, MemoryRecord, MemoryRecord)> {
            windows
                .iter()
                .map(|w| (w.addr, w.initial_mem_access, w.final_mem_access))
                .collect()
        };
        assert_eq!(as_tuples(&windows), as_tuples(&[b1, joined, c, b2]));
    }

    /// A fold whose windows take the chunk past its Global table has the pairs the cuts added
    /// rejoined, and is then the record the equivalence gate takes it for; a fold within the
    /// table is left as concatenated.
    #[test]
    fn a_fold_past_the_global_table_is_rejoined() {
        let entry = MemoryRecord::default();
        let segments = || {
            let head_100 = window(0x100, entry, 1, 10);
            let head = EmulationRecord {
                cpu_local_memory_access: vec![head_100, window(0x200, entry, 2, 11)],
                ..Default::default()
            };
            let tail = EmulationRecord {
                cpu_local_memory_access: vec![
                    window(0x100, head_100.final_mem_access, 9, 42),
                    window(0x300, entry, 3, 43),
                ],
                ..Default::default()
            };
            vec![head, tail]
        };

        // Four windows are eight events at most.
        let concatenated = merge_segments_within(segments(), 8);
        assert_eq!(concatenated.cpu_local_memory_access.len(), 4);

        let rejoined = merge_segments_within(segments(), 7);
        let windows: Vec<(u64, u32)> = rejoined
            .cpu_local_memory_access
            .iter()
            .map(|event| (event.addr, event.final_mem_access.timestamp))
            .collect();
        assert_eq!(windows, vec![(0x100, 42), (0x200, 11), (0x300, 43)]);
        assert_eq!(first_difference(&rejoined, &concatenated), None);
    }

    #[test]
    fn public_values_straddle_the_fold() {
        let mut head = EmulationRecord::default();
        head.public_values.start_pc = [0x1000, 0, 0];
        head.public_values.next_pc = [0x1004, 0, 0];
        let mut tail = EmulationRecord::default();
        tail.public_values.start_pc = [0x2000, 0, 0];
        tail.public_values.next_pc = [0x2004, 0, 0];
        tail.public_values.exit_code = 7;

        let merged = merge_segments(vec![head, tail]);

        assert_eq!(
            merged.public_values.start_pc,
            [0x1000, 0, 0],
            "start comes from the first segment"
        );
        assert_eq!(
            merged.public_values.next_pc,
            [0x2004, 0, 0],
            "end comes from the last segment"
        );
        assert_eq!(merged.public_values.exit_code, 7);
    }

    /// Each segment's record holds only the digest words its own COMMITs wrote, so taking the
    /// last segment's values would lose the words an earlier one committed.
    #[test]
    fn digest_words_committed_in_any_segment_survive_the_fold() {
        let mut head = EmulationRecord::default();
        head.public_values.committed_value_digest[..4].copy_from_slice(&[1, 2, 3, 4]);
        head.public_values.deferred_proofs_digest[0] = 9;
        let mut middle = EmulationRecord::default();
        middle.public_values.committed_value_digest[3] = 40;
        let mut tail = EmulationRecord::default();
        tail.public_values.committed_value_digest[4..].copy_from_slice(&[5, 6, 7, 8]);

        let merged = merge_segments(vec![head, middle, tail]);

        assert_eq!(
            merged.public_values.committed_value_digest,
            [1, 2, 3, 40, 5, 6, 7, 8]
        );
        assert_eq!(merged.public_values.deferred_proofs_digest[0], 9);
    }

    /// Three segments, because the rebase carries a running offset: with two, an implementation
    /// that shifted by the first segment's length instead of by everything merged so far would
    /// still pass.
    #[test]
    fn indices_are_rebased_against_everything_merged_so_far() {
        let mut first = with_history(2);
        first.history.as_mut().unwrap().chip_steps.memory = vec![0].into();
        let mut second = with_history(3);
        second.history.as_mut().unwrap().chip_steps.memory = vec![1].into();
        let mut third = with_history(4);
        third.history.as_mut().unwrap().chip_steps.memory = vec![0, 3].into();

        let history = merge_segments(vec![first, second, third]).history.unwrap();

        assert_eq!(history.steps.len(), 9);
        assert_eq!(history.chip_steps.memory, vec![0, 3, 5, 8]);
    }

    /// `is_last` and `shape` describe where the chunk ends, so they come from the last segment —
    /// `append` carries neither, and a head that answered for them would mark the chunk complete
    /// at the first cut.
    #[test]
    fn the_tail_decides_where_the_chunk_ends() {
        let head = EmulationRecord {
            is_last: false,
            ..Default::default()
        };
        let tail = EmulationRecord {
            is_last: true,
            ..Default::default()
        };

        assert!(merge_segments(vec![head, tail]).is_last);
    }

    /// The one field folded by addition rather than concatenation: `byte_lookups` is a
    /// multiplicity map, so a lookup both segments made has to come out counted twice.
    #[test]
    fn byte_lookup_multiplicities_add_across_the_fold() {
        let shared = ByteLookupEvent {
            opcode: ByteOpcode::AND,
            a1: 1,
            a2: 0,
            b: 2,
            c: 3,
        };
        let only_in_tail = ByteLookupEvent {
            opcode: ByteOpcode::XOR,
            ..shared
        };

        let mut head = EmulationRecord::default();
        head.byte_lookups.insert(shared, 2);
        let mut tail = EmulationRecord::default();
        tail.byte_lookups.insert(shared, 5);
        tail.byte_lookups.insert(only_in_tail, 1);

        let merged = merge_segments(vec![head, tail]);

        assert_eq!(merged.byte_lookups.get(&shared), Some(&7));
        assert_eq!(merged.byte_lookups.get(&only_in_tail), Some(&1));
    }
}
