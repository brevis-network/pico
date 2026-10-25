//! Per-field digests of an [`EmulationRecord`], for the split-replay equivalence gate.
//!
//! A record is a deterministic function of the execution, so replaying a chunk as one segment
//! and as several must produce the same record. Proofs are not deterministic — two runs of the
//! same code differ — so this, not a proof comparison, is what a change to how a chunk is
//! replayed has to be judged against.
//!
//! Two fields are drained from hash maps and carry no meaningful order (`bump_record`: "output
//! order is irrelevant"), so they are canonicalised before digesting. Without that the gate
//! fires on two runs of the *same* code and sends the reader after a bug that is not there.

use std::io::Write;

use crate::chips::chips::riscv_memory::event::MemoryRecord;

use super::record::EmulationRecord;

const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

/// A `Write` sink that folds bytes into an FNV-1a hash, so a 2.5 GB field is digested as it is
/// serialised instead of being materialised first.
struct Fnv(u64);

impl Write for Fnv {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        // Eight bytes at a time: the biggest field is gigabytes, and byte-at-a-time FNV makes
        // the gate cost more than the replay it is checking. Still FNV's mix, just wider.
        let mut h = self.0;
        let (words, tail) = buf.as_chunks::<8>();
        for word in words {
            h ^= u64::from_le_bytes(*word);
            h = h.wrapping_mul(FNV_PRIME);
        }
        for b in tail {
            h ^= u64::from(*b);
            h = h.wrapping_mul(FNV_PRIME);
        }
        self.0 = h;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Digest of anything the record can serialise. Serialisation rather than raw bytes because the
/// event structs carry padding, and padding is not guaranteed to be initialised — hashing it
/// would make the gate flap.
fn digest<T: serde::Serialize + ?Sized>(value: &T) -> u64 {
    let mut sink = Fnv(FNV_OFFSET);
    bincode::serialize_into(&mut sink, value).expect("record digest: serialize");
    sink.0
}

/// `(field, element count, digest)` for every field a replay fills in.
///
/// `program` is left out: it is a shared `Arc` that the replay never writes.
pub fn field_digests(record: &EmulationRecord) -> Vec<(&'static str, usize, u64)> {
    let precompiles: Vec<(u64, u64)> = record
        .precompile_events
        .sorted_groups()
        .into_iter()
        .map(|(code, events)| (digest(code), digest(events)))
        .collect();

    // Per address, the chain of windows the chunk leaves behind — reduced.
    //
    // Windows over one address are ordered by when they CLOSE: an initial access carries the
    // record from whenever that address was last touched, which may be chunks ago, so its
    // timestamp says nothing about where the window sits in this chunk.
    //
    // Two adjacent windows whose inner accesses meet — one's final is the next one's initial —
    // are one span as far as the global bus is concerned, because that inner pair cancels on it.
    // Collapsing them is what makes this comparable across a split, which adds exactly such a
    // pair. What it must not collapse is a window that went missing: its neighbours then do not
    // meet, and the chain stays two links where the unsplit replay had one.
    let mut windows_by_addr: std::collections::HashMap<
        u64,
        Vec<(u32, u64, MemoryRecord, MemoryRecord)>,
    > = std::collections::HashMap::new();
    for event in &record.cpu_local_memory_access {
        windows_by_addr.entry(event.addr).or_default().push((
            event.final_mem_access.timestamp,
            digest(&(event.initial_mem_access, event.final_mem_access)),
            event.initial_mem_access,
            event.final_mem_access,
        ));
    }
    let mut local_chains: Vec<(u64, u64)> = windows_by_addr
        .into_iter()
        .map(|(addr, mut windows)| {
            // The digest breaks ties, so two windows closing on the same clock still order the
            // same way in both runs.
            windows.sort_unstable_by_key(|(closes, tie, _, _)| (*closes, *tie));
            let mut reduced: Vec<(MemoryRecord, MemoryRecord)> = Vec::new();
            for (_, _, initial, final_access) in windows {
                match reduced.last_mut() {
                    Some(last) if last.1 == initial => last.1 = final_access,
                    _ => reduced.push((initial, final_access)),
                }
            }
            (addr, digest(&reduced))
        })
        .collect();
    local_chains.sort_unstable();

    // Canonicalised for the same reason. Keyed by digest because `ByteLookupEvent` is only a
    // hash-map key, not an ordered one.
    let mut byte_lookups: Vec<(u64, usize)> = record
        .byte_lookups
        .iter()
        .map(|(event, mult)| (digest(event), *mult))
        .collect();
    byte_lookups.sort_unstable();

    vec![
        (
            "cpu_events",
            record.cpu_events.len(),
            digest(record.cpu_events.as_slice()),
        ),
        (
            "memory_read_write_event_indices",
            record.memory_read_write_event_indices.len(),
            digest(&record.memory_read_write_event_indices),
        ),
        (
            "add_sub_events",
            record.add_sub_events.len(),
            digest(record.add_sub_events.as_slice()),
        ),
        (
            "mul_events",
            record.mul_events.len(),
            digest(&record.mul_events),
        ),
        (
            "bitwise_events",
            record.bitwise_events.len(),
            digest(&record.bitwise_events),
        ),
        (
            "shift_left_events",
            record.shift_left_events.len(),
            digest(&record.shift_left_events),
        ),
        (
            "shift_right_events",
            record.shift_right_events.len(),
            digest(&record.shift_right_events),
        ),
        (
            "divrem_events",
            record.divrem_events.len(),
            digest(&record.divrem_events),
        ),
        (
            "lt_events",
            record.lt_events.len(),
            digest(record.lt_events.as_slice()),
        ),
        ("byte_lookups", byte_lookups.len(), digest(&byte_lookups)),
        (
            "memory_initialize_events",
            record.memory_initialize_events.len(),
            digest(&record.memory_initialize_events),
        ),
        (
            "memory_finalize_events",
            record.memory_finalize_events.len(),
            digest(&record.memory_finalize_events),
        ),
        (
            "cpu_local_memory_chain",
            local_chains.len(),
            digest(&local_chains),
        ),
        // Reported, not compared — see `NOT_COMPARED`. No digest: nothing reads it but a human.
        (
            "cpu_local_memory_access",
            record.cpu_local_memory_access.len(),
            0,
        ),
        (
            "syscall_events",
            record.syscall_events.len(),
            digest(&record.syscall_events),
        ),
        (
            "poseidon2_events",
            record.poseidon2_events.len(),
            digest(&record.poseidon2_events),
        ),
        (
            "global_lookup_events",
            record.global_lookup_events.len(),
            digest(&record.global_lookup_events),
        ),
        ("precompile_events", precompiles.len(), digest(&precompiles)),
        ("public_values", 1, digest(&record.public_values)),
        ("is_cpu_chunk", 1, digest(&record.is_cpu_chunk)),
        ("is_last", 1, digest(&record.is_last)),
        ("shape", 1, digest(&record.shape)),
    ]
}

/// Fields reported but not compared.
///
/// `cpu_local_memory_access` holds one window per address per stretch of the chunk, and splitting
/// a chunk's replay gives an address live across a cut two chained windows where the unsplit
/// replay had one. The two chain — one window's final access is the next one's initial — so they
/// cancel on the global bus, which `cross-chunk GCS == 0` is the check on. The count differs
/// between the two replays by design, so it is reported rather than compared.
///
/// What must not change is the chain each address is left in once the cancelling pairs are
/// collapsed, and `cpu_local_memory_chain` above carries exactly that: the endpoints of every
/// maximal run, values included. A window that went missing breaks its run and is reported; an
/// access interior to a run that still glues is not, and by that same cancellation cannot move
/// the bus either way.
const NOT_COMPARED: &[&str] = &["cpu_local_memory_access"];

/// Whether a field from [`field_digests`] takes part in the comparison. Anything logging those
/// rows has to say which do, or a reader diffing two runs chases a row that is allowed to differ.
pub fn is_compared(field: &str) -> bool {
    !NOT_COMPARED.contains(&field)
}

/// The first field on which two records disagree, as a line ready to log.
///
/// First rather than all: a merge bug usually corrupts one field, and the rest differ only
/// because they were built from it.
pub fn first_difference(left: &EmulationRecord, right: &EmulationRecord) -> Option<String> {
    for ((field, l_len, l_hash), (_, r_len, r_hash)) in
        field_digests(left).into_iter().zip(field_digests(right))
    {
        if NOT_COMPARED.contains(&field) {
            continue;
        }
        if l_len != r_len || l_hash != r_hash {
            return Some(format!(
                "{field}: len {l_len} vs {r_len}, digest {l_hash:#018x} vs {r_hash:#018x}"
            ));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chips::chips::{
        alu::event::AluEvent,
        riscv_memory::event::{MemoryLocalEvent, MemoryRecord},
    };

    fn access(value: u64, timestamp: u32) -> MemoryRecord {
        MemoryRecord {
            value,
            chunk: 1,
            timestamp,
        }
    }

    /// One window over `addr`: entered from the chunk's entry record, closed in this chunk. An
    /// entry that opens and closes on the same access is not a state the AIR admits, so no
    /// fixture builds one.
    fn local_event(addr: u64, value: u64) -> MemoryLocalEvent {
        window(addr, MemoryRecord::default(), access(value, 8))
    }

    fn window(addr: u64, initial: MemoryRecord, final_access: MemoryRecord) -> MemoryLocalEvent {
        MemoryLocalEvent {
            addr,
            initial_mem_access: initial,
            final_mem_access: final_access,
        }
    }

    #[test]
    fn a_record_does_not_differ_from_itself() {
        let mut record = EmulationRecord::default();
        record.mul_events.push(AluEvent::default());
        record.cpu_local_memory_access.push(local_event(0x100, 7));
        assert_eq!(first_difference(&record, &record.clone()), None);
    }

    /// The gate must survive the two fields whose order is arbitrary, or it fires on two runs of
    /// the same code — and then every real finding is buried in false ones.
    #[test]
    fn local_memory_order_is_not_a_difference() {
        let mut left = EmulationRecord::default();
        left.cpu_local_memory_access = vec![local_event(0x100, 1), local_event(0x200, 2)];
        let mut right = EmulationRecord::default();
        right.cpu_local_memory_access = vec![local_event(0x200, 2), local_event(0x100, 1)];
        assert_eq!(first_difference(&left, &right), None);
    }

    #[test]
    fn a_changed_outermost_value_is_a_difference() {
        let mut left = EmulationRecord::default();
        left.cpu_local_memory_access = vec![local_event(0x100, 1)];
        let mut right = EmulationRecord::default();
        right.cpu_local_memory_access = vec![local_event(0x100, 2)];
        let reported = first_difference(&left, &right).expect("a changed value must be reported");
        assert!(
            reported.starts_with("cpu_local_memory_chain:"),
            "reported the wrong field: {reported}"
        );
    }

    /// The other side of the relaxation, stated so it is not mistaken for coverage: an access
    /// interior to a run that still glues is not compared. It cannot be — a split introduces
    /// exactly such an access — and it cancels against its neighbour, so the bus cannot see it.
    #[test]
    fn an_interior_access_is_deliberately_not_compared() {
        let mut left = EmulationRecord::default();
        left.cpu_local_memory_access = vec![
            window(0x100, access(1, 5), access(2, 40)),
            window(0x100, access(2, 40), access(3, 90)),
        ];
        let mut right = EmulationRecord::default();
        right.cpu_local_memory_access = vec![
            window(0x100, access(1, 5), access(0xdead, 40)),
            window(0x100, access(0xdead, 40), access(3, 90)),
        ];
        assert_eq!(first_difference(&left, &right), None);
    }

    /// What the relaxation is for: a split gives an address live across a cut two chained windows
    /// where the unsplit replay had one. Same span, so not a difference.
    #[test]
    fn a_window_split_in_two_at_the_same_span_is_not_a_difference() {
        let mut unsplit = EmulationRecord::default();
        unsplit.cpu_local_memory_access = vec![window(0x100, access(1, 5), access(9, 90))];
        let mut split = EmulationRecord::default();
        split.cpu_local_memory_access = vec![
            window(0x100, access(1, 5), access(4, 40)),
            window(0x100, access(4, 40), access(9, 90)),
        ];
        assert_eq!(first_difference(&unsplit, &split), None);
    }

    /// An initial access carries the record from whenever that address was last touched, which
    /// can be chunks ago and carry a far larger timestamp than anything in this chunk. Ordering
    /// the windows by it picks the wrong one as the chunk's entry, and then a split and an
    /// unsplit replay of the same execution disagree for no real reason.
    #[test]
    fn windows_are_ordered_by_when_they_close() {
        let mut split = EmulationRecord::default();
        split.cpu_local_memory_access = vec![
            window(0x100, access(1, 9_000), access(2, 10)),
            window(0x100, access(2, 10), access(3, 20)),
        ];
        let mut unsplit = EmulationRecord::default();
        unsplit.cpu_local_memory_access = vec![window(0x100, access(1, 9_000), access(3, 20))];
        assert_eq!(first_difference(&split, &unsplit), None);
    }

    /// And what the relaxation must NOT let through: the same two windows, but the chunk now
    /// ends that address on a different access.
    #[test]
    fn a_split_window_that_ends_elsewhere_is_a_difference() {
        let mut unsplit = EmulationRecord::default();
        unsplit.cpu_local_memory_access = vec![window(0x100, access(1, 5), access(9, 90))];
        let mut split = EmulationRecord::default();
        split.cpu_local_memory_access = vec![
            window(0x100, access(1, 5), access(4, 40)),
            window(0x100, access(4, 40), access(9, 110)),
        ];
        let reported =
            first_difference(&unsplit, &split).expect("a changed final access must be reported");
        assert!(
            reported.starts_with("cpu_local_memory_chain:"),
            "reported the wrong field: {reported}"
        );
    }

    /// The hole a criterion that only compared the outermost pair would have left: with three
    /// windows over one address, dropping the middle one leaves the first and last untouched.
    /// The chain does not: its neighbours no longer meet, so it stays two links.
    #[test]
    fn a_dropped_middle_window_is_a_difference() {
        let mut whole = EmulationRecord::default();
        whole.cpu_local_memory_access = vec![
            window(0x100, access(1, 5), access(2, 40)),
            window(0x100, access(2, 40), access(3, 90)),
            window(0x100, access(3, 90), access(4, 150)),
        ];
        let mut dropped = EmulationRecord::default();
        dropped.cpu_local_memory_access = vec![
            window(0x100, access(1, 5), access(2, 40)),
            window(0x100, access(3, 90), access(4, 150)),
        ];
        let reported =
            first_difference(&whole, &dropped).expect("a dropped window must be reported");
        assert!(
            reported.starts_with("cpu_local_memory_chain:"),
            "reported the wrong field: {reported}"
        );
    }

    /// And the chain has to survive the legitimate case it exists for: three windows that meet
    /// reduce to the one span an unsplit replay would have left.
    #[test]
    fn a_chain_of_windows_reduces_to_the_unsplit_span() {
        let mut split = EmulationRecord::default();
        split.cpu_local_memory_access = vec![
            window(0x100, access(1, 5), access(2, 40)),
            window(0x100, access(2, 40), access(3, 90)),
            window(0x100, access(3, 90), access(4, 150)),
        ];
        let mut unsplit = EmulationRecord::default();
        unsplit.cpu_local_memory_access = vec![window(0x100, access(1, 5), access(4, 150))];
        assert_eq!(first_difference(&split, &unsplit), None);
    }

    /// The merge hazard this gate exists for: the indices point into `cpu_events`, so a segment
    /// appended without rebasing them leaves this field — and only this field — wrong.
    #[test]
    fn an_unrebased_index_is_a_difference() {
        let mut left = EmulationRecord::default();
        left.memory_read_write_event_indices = vec![0, 5, 9];
        let mut right = EmulationRecord::default();
        right.memory_read_write_event_indices = vec![0, 5, 8];
        let reported =
            first_difference(&left, &right).expect("an unrebased index must be reported");
        assert!(
            reported.starts_with("memory_read_write_event_indices:"),
            "reported the wrong field: {reported}"
        );
    }

    #[test]
    fn a_missing_event_is_a_difference() {
        let mut left = EmulationRecord::default();
        left.mul_events = vec![AluEvent::default(), AluEvent::default()];
        let mut right = EmulationRecord::default();
        right.mul_events = vec![AluEvent::default()];
        let reported = first_difference(&left, &right).expect("a dropped event must be reported");
        assert!(
            reported.starts_with("mul_events:"),
            "reported the wrong field: {reported}"
        );
    }
}
