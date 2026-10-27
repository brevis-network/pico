//! Fold a chunk's replay segments back into one record.
//!
//! Splitting a chunk's replay across threads only pays if the chunk still proves once, so the
//! segments' records have to become the record the unsplit replay would have produced.
//!
//! One field makes that more than a concatenation, and it is silent when wrong:
//! `memory_read_write_event_indices` index into `cpu_events`, so they move with it.
//! [`RecordBehavior::append`] concatenates them as they are — correct for its own caller
//! (precompile-only records, whose `cpu_events` is empty) and wrong here.
//!
//! `cpu_local_memory_access` looked like it needed re-aggregating by address, since an entry
//! holds an address's first and last access. Measuring says no: an unsplit chunk already carries
//! well over one entry per address, so folding by address destroys windows the unsplit replay
//! keeps — which it did, and the proof failed on an unbalanced memory bus. What a split does
//! change is that an address live across a cut gets two chained windows where the unsplit replay
//! had one; the address set is identical either way, and the global cumulative sum still closes.
//!
//! The equivalence gate in [`super::record_digest`] is what says the fold is right; run it
//! before trusting a measurement.

use crate::emulator::record::RecordBehavior;

/// `MLE_SPLIT_CHECK=1` logs what each fold saw. Read once: a value that changed mid-run would
/// make the numbers it prints incomparable.
static SPLIT_CHECK: std::sync::LazyLock<bool> =
    std::sync::LazyLock::new(|| std::env::var("MLE_SPLIT_CHECK").is_ok_and(|value| value == "1"));

use super::record::EmulationRecord;

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

    // `append` funnels the CPU events through `add_cpu_events`, which returns how many it took
    // and drops the rest when the pinned buffer is full — and its caller ignores that. A chunk's
    // events fit the buffer by construction, but only just (measured: 692 spare on a full one),
    // so say so loudly rather than prove a chunk short.
    assert_eq!(
        merged.cpu_events.len(),
        cpu_lens.iter().sum::<usize>(),
        "the fold dropped CPU events: the pinned buffer was too small for the merged chunk"
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
        emulator::riscv::{
            cpu_event_pool::{init_cpu_event_buffer_pool, is_pool_initialized},
            event_pool::HostAllocFlags,
            record_digest::first_difference,
        },
    };
    use std::sync::{Mutex, MutexGuard, PoisonError};

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

    /// CPU events live in a pinned pool buffer, and with no pool `add_cpu_events` silently adds
    /// nothing (it returns `Ok(0)`) — so a test that needs real ones has to bring the pool up.
    /// The pool blocks when empty, so the tests holding buffers take turns behind the guard.
    fn ensure_cpu_event_pool() -> MutexGuard<'static, ()> {
        static ONCE: std::sync::Once = std::sync::Once::new();
        static TURN: Mutex<()> = Mutex::new(());
        ONCE.call_once(|| {
            if !is_pool_initialized() {
                // The size every other test site passes: the pool is process-wide.
                init_cpu_event_buffer_pool(50, HostAllocFlags::DEFAULT);
            }
        });
        TURN.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn with_cpu_events(count: usize) -> EmulationRecord {
        let mut record = EmulationRecord::default();
        let events = vec![CpuEvent::default(); count];
        let added = record.add_cpu_events(&events).expect("add cpu events");
        assert_eq!(added, count, "the pool did not hand out a buffer");
        record
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
        let _turn = ensure_cpu_event_pool();
        let mut head = with_cpu_events(4);
        head.memory_read_write_event_indices = vec![1, 3];
        let mut tail = with_cpu_events(3);
        tail.memory_read_write_event_indices = vec![0, 2];

        let merged = merge_segments(vec![head, tail]);

        assert_eq!(merged.cpu_events.len(), 7);
        assert_eq!(merged.memory_read_write_event_indices, vec![1, 3, 4, 6]);
    }

    /// Both segments' windows survive: an unsplit chunk already carries more than one window
    /// per address, so folding them by address would destroy information (measured: 1.6 entries
    /// per address). A split only adds the one window that spans the cut.
    #[test]
    fn both_segments_windows_survive() {
        let mut head = EmulationRecord::default();
        head.cpu_local_memory_access = vec![local_event(0x100, 1, 10), local_event(0x200, 2, 11)];
        let mut tail = EmulationRecord::default();
        tail.cpu_local_memory_access = vec![local_event(0x100, 9, 42), local_event(0x300, 3, 43)];

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
        let _turn = ensure_cpu_event_pool();
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
        let mut head = EmulationRecord::default();
        head.is_last = false;
        let mut tail = EmulationRecord::default();
        tail.is_last = true;

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
