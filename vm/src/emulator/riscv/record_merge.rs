//! Fold a chunk's replay segments back into one record.
//!
//! Splitting a chunk's replay across threads only pays if the chunk still proves once, so the
//! segments' records have to become the record the unsplit replay would have produced.
//!
//! One field makes that more than a concatenation, and it is silent when wrong:
//! `memory_read_write_event_indices` index into `cpu_events`, so they move with it.
//! [`RecordBehavior::append`] concatenates them as they are, which is right for every other
//! caller — they append records whose `cpu_events` is empty, so there is nothing to shift by —
//! and wrong here.
//!
//! `cpu_local_memory_access` is concatenated, not re-aggregated by address: an unsplit chunk
//! already carries several windows per address, so folding them by address destroys ones it
//! keeps and the memory bus goes unbalanced. A split only adds the one window that spans the
//! cut, and the two chain, so the global cumulative sum still closes.
//!
//! The equivalence gate in [`super::record_digest`] is what says the fold is right.

use super::record::EmulationRecord;
use crate::emulator::record::RecordBehavior;

/// `MLE_SPLIT_CHECK=1` logs what each fold saw. Read once: a value that changed mid-run would
/// make the numbers it prints incomparable.
static SPLIT_CHECK: std::sync::LazyLock<bool> =
    std::sync::LazyLock::new(|| std::env::var("MLE_SPLIT_CHECK").is_ok_and(|value| value == "1"));

/// Fold `segments` — a chunk's replay segments, in clock order — into a single record.
///
/// One segment folds to itself. The caller short-circuits that case rather than calling here, so
/// that with split replay off the shipped path does not run this code at all; the identity is
/// kept, and tested, so a caller that does pass one segment still gets the right answer.
pub fn merge_segments(mut segments: Vec<EmulationRecord>) -> EmulationRecord {
    assert!(
        !segments.is_empty(),
        "a chunk always has at least one replay segment"
    );

    // The chunk's public values straddle the segments: where it started comes from the first,
    // where it ended from the last. `append` does not carry them at all.
    let last = segments.last().expect("checked non-empty");
    let tail_public_values = last.public_values;
    let tail_is_last = last.is_last;
    let tail_shape = last.shape.clone();

    let segment_count = segments.len();
    let local_lens: Vec<usize> = segments
        .iter()
        .map(|segment| segment.cpu_local_memory_access.len())
        .collect();
    let cpu_lens: Vec<usize> = segments
        .iter()
        .map(|segment| segment.cpu_events.len())
        .collect();

    let mut merged = segments.remove(0);
    let head_start_pc = merged.public_values.start_pc;

    for mut segment in segments {
        let cpu_base = merged.cpu_events.len();
        merged.memory_read_write_event_indices.extend(
            segment
                .memory_read_write_event_indices
                .iter()
                .map(|index| index + cpu_base),
        );
        // Taken out of the segment so `append` cannot concatenate them behind our back.
        segment.memory_read_write_event_indices.clear();

        merged.append(&mut segment);
    }

    // The fold owes the caller every event it was handed; losing one proves the chunk short,
    // which is silent. Cheap to state, so state it.
    assert_eq!(
        merged.cpu_events.len(),
        cpu_lens.iter().sum::<usize>(),
        "the fold dropped CPU events"
    );

    if *SPLIT_CHECK {
        tracing::info!(
            target: "bench",
            "[mergeprobe] segments={segment_count} local_lens={local_lens:?} \
             merged_local={} cpu_lens={cpu_lens:?} merged_cpu={}",
            merged.cpu_local_memory_access.len(),
            merged.cpu_events.len(),
        );
    }

    merged.public_values = tail_public_values;
    merged.public_values.start_pc = head_start_pc;
    merged.is_last = tail_is_last;
    merged.shape = tail_shape;
    merged
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        chips::chips::{
            alu::event::AluEvent,
            byte::event::ByteLookupEvent,
            riscv_cpu::event::CpuEvent,
            riscv_memory::event::{MemoryLocalEvent, MemoryRecord},
        },
        compiler::riscv::opcode::ByteOpcode,
        emulator::riscv::record_digest::first_difference,
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

    fn with_cpu_events(count: usize) -> EmulationRecord {
        EmulationRecord {
            cpu_events: vec![CpuEvent::default(); count],
            ..Default::default()
        }
    }

    #[test]
    fn one_segment_folds_to_itself() {
        let mut only = EmulationRecord::default();
        only.mul_events.push(AluEvent::default());
        only.cpu_local_memory_access.push(local_event(0x100, 7, 3));
        let expected = only.clone();
        assert_eq!(
            first_difference(&merge_segments(vec![only]), &expected),
            None
        );
    }

    /// The hazard: the indices point into `cpu_events`, so the second segment's have to shift by
    /// the first segment's event count. `append` alone leaves them pointing at the wrong events.
    #[test]
    fn indices_are_rebased_onto_the_merged_cpu_events() {
        let mut head = with_cpu_events(4);
        head.memory_read_write_event_indices = vec![1, 3];
        let mut tail = with_cpu_events(3);
        tail.memory_read_write_event_indices = vec![0, 2];

        let merged = merge_segments(vec![head, tail]);

        assert_eq!(merged.cpu_events.len(), 7);
        assert_eq!(merged.memory_read_write_event_indices, vec![1, 3, 4, 6]);
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

    /// Three segments, because the rebase carries a running offset: with two, an implementation
    /// that shifted by the first segment's length instead of by everything merged so far would
    /// still pass.
    #[test]
    fn indices_are_rebased_against_everything_merged_so_far() {
        let mut first = with_cpu_events(2);
        first.memory_read_write_event_indices = vec![0];
        let mut second = with_cpu_events(3);
        second.memory_read_write_event_indices = vec![1];
        let mut third = with_cpu_events(4);
        third.memory_read_write_event_indices = vec![0, 3];

        let merged = merge_segments(vec![first, second, third]);

        assert_eq!(merged.cpu_events.len(), 9);
        assert_eq!(merged.memory_read_write_event_indices, vec![0, 3, 5, 8]);
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
