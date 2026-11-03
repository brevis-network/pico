//! Per-field digests of an [`EmulationRecord`], for the split-replay equivalence gate.
//!
//! A record is a deterministic function of the execution, so replaying a chunk as one segment
//! and as several must produce the same record. Proofs are not deterministic — two runs of the
//! same code differ — so this, not a proof comparison, is what a change to how a chunk is
//! replayed has to be judged against.
//!
//! `byte_lookups` and `precompile_events` reach the record out of a hash map and carry no
//! meaningful order, so both are canonicalised before digesting. Without that the gate fires on
//! two runs of the *same* code and sends the reader after a bug that is not there.

use std::{collections::HashMap, io::Write};

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

/// FNV-1a over a stream of 32-bit words, two to a step as [`Fnv`] folds bytes: the stage ledger's
/// per-chip trace digest, over each cell's canonical value.
pub fn digest_words(words: impl IntoIterator<Item = u32>) -> u64 {
    let mut h = FNV_OFFSET;
    let mut words = words.into_iter();
    while let Some(lo) = words.next() {
        let word = match words.next() {
            Some(hi) => u64::from(lo) | (u64::from(hi) << 32),
            None => u64::from(lo),
        };
        h ^= word;
        h = h.wrapping_mul(FNV_PRIME);
    }
    h
}

/// Digest of anything the record can serialise. Serialisation rather than raw bytes because the
/// event structs carry padding, and padding is not guaranteed to be initialised — hashing it
/// would make the gate flap.
fn digest<T: serde::Serialize + ?Sized>(value: &T) -> u64 {
    let mut sink = Fnv(FNV_OFFSET);
    bincode::serialize_into(&mut sink, value).expect("record digest: serialize");
    sink.0
}

/// One row of [`field_digests`]: `(field, element count, digest)`.
pub type FieldDigest = (&'static str, usize, u64);

/// The one field the pipeline's sequencer writes after a replay: it stamps the public values.
const PUBLIC_VALUES: &str = "public_values";

/// The row [`field_digests`] adds for a record's execution history.
pub const HISTORY: &str = "history";

/// `(field, element count, digest)` for every field a replay fills in.
///
/// `program` is left out: it is a shared `Arc` that the replay never writes. A record carrying an
/// execution history ends on one more row, its steps and `ExecutionHistory::digest`; deferred
/// records have no history row.
pub fn field_digests(record: &EmulationRecord) -> Vec<FieldDigest> {
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
    let mut windows_by_addr: HashMap<u64, Vec<(u32, u64, MemoryRecord, MemoryRecord)>> =
        HashMap::new();
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

    let mut rows = vec![
        (
            "add_events",
            record.add_events.len(),
            digest(&record.add_events),
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
        (PUBLIC_VALUES, 1, digest(&record.public_values)),
        ("is_cpu_chunk", 1, digest(&record.is_cpu_chunk)),
        ("is_last", 1, digest(&record.is_last)),
        ("shape", 1, digest(&record.shape)),
    ];
    if let Some(history) = &record.history {
        rows.push((HISTORY, history.steps.len(), history.digest()));
    }
    rows
}

/// Redo `digests`' public-values row from `record`, for digests taken before the public values
/// were stamped: every other field is what it was, so the rest of the work is not done twice.
pub fn restamp_public_values(digests: &mut [FieldDigest], record: &EmulationRecord) {
    for row in digests.iter_mut().filter(|row| row.0 == PUBLIC_VALUES) {
        row.2 = digest(&record.public_values);
    }
}

/// `(stream, elements, bytes)` for retained event collections, excluding the execution history,
/// so the stage ledger avoids [`field_digests`]' hashing cost. Bytes are
/// `len × size_of` of the element: what the record holds in place, not its vectors' spare capacity
/// and not heap an element points to.
pub fn record_streams(record: &EmulationRecord) -> Vec<(&'static str, usize, usize)> {
    fn vec<T>(name: &'static str, events: &[T]) -> (&'static str, usize, usize) {
        (name, events.len(), std::mem::size_of_val(events))
    }
    fn map<K, V>(
        name: &'static str,
        events: &hashbrown::HashMap<K, V>,
    ) -> (&'static str, usize, usize) {
        (
            name,
            events.len(),
            events.len() * std::mem::size_of::<(K, V)>(),
        )
    }
    let precompile_events: Vec<_> = record.precompile_events.events.values().collect();
    vec![
        vec("add_events", &record.add_events),
        map("byte_lookups", &record.byte_lookups),
        vec("memory_initialize_events", &record.memory_initialize_events),
        vec("memory_finalize_events", &record.memory_finalize_events),
        vec("cpu_local_memory_access", &record.cpu_local_memory_access),
        vec("poseidon2_events", &record.poseidon2_events),
        vec("global_lookup_events", &record.global_lookup_events),
        (
            "precompile_events",
            precompile_events.iter().map(|events| events.len()).sum(),
            precompile_events
                .iter()
                .map(|events| std::mem::size_of_val(events.as_slice()))
                .sum(),
        ),
    ]
}

/// `(stream, element count)` for retained event collections, excluding the execution history.
pub fn record_counts(record: &EmulationRecord) -> Vec<(&'static str, usize)> {
    record_streams(record)
        .into_iter()
        .map(|(name, len, _)| (name, len))
        .collect()
}

/// The bytes `record`'s event streams hold in place, summed over the streams of
/// [`record_counts`].
pub fn record_bytes(record: &EmulationRecord) -> usize {
    record_streams(record)
        .into_iter()
        .map(|(_, _, bytes)| bytes)
        .sum()
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
    let (left, right) = (field_digests(left), field_digests(right));
    for ((field, l_len, l_hash), (_, r_len, r_hash)) in left.iter().zip(&right) {
        if NOT_COMPARED.contains(field) {
            continue;
        }
        if l_len != r_len || l_hash != r_hash {
            return Some(format!(
                "{field}: len {l_len} vs {r_len}, digest {l_hash:#018x} vs {r_hash:#018x}"
            ));
        }
    }
    (left.len() != right.len()).then(|| {
        format!(
            "{HISTORY}: carried by the {} record alone",
            if left.len() > right.len() {
                "left"
            } else {
                "right"
            }
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        chips::chips::{
            alu::event::AluEvent,
            riscv_memory::event::{MemoryLocalEvent, MemoryRecord},
        },
        emulator::riscv::history::{ExecutionHistory, Step},
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
        record.add_events.push(AluEvent::default());
        record.cpu_local_memory_access.push(local_event(0x100, 7));
        assert_eq!(first_difference(&record, &record.clone()), None);
    }

    /// The gate must survive the two fields whose order is arbitrary, or it fires on two runs of
    /// the same code — and then every real finding is buried in false ones.
    #[test]
    fn local_memory_order_is_not_a_difference() {
        let left = EmulationRecord {
            cpu_local_memory_access: vec![local_event(0x100, 1), local_event(0x200, 2)],
            ..Default::default()
        };
        let right = EmulationRecord {
            cpu_local_memory_access: vec![local_event(0x200, 2), local_event(0x100, 1)],
            ..Default::default()
        };
        assert_eq!(first_difference(&left, &right), None);
    }

    #[test]
    fn a_changed_outermost_value_is_a_difference() {
        let left = EmulationRecord {
            cpu_local_memory_access: vec![local_event(0x100, 1)],
            ..Default::default()
        };
        let right = EmulationRecord {
            cpu_local_memory_access: vec![local_event(0x100, 2)],
            ..Default::default()
        };
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
        let left = EmulationRecord {
            cpu_local_memory_access: vec![
                window(0x100, access(1, 5), access(2, 40)),
                window(0x100, access(2, 40), access(3, 90)),
            ],
            ..Default::default()
        };
        let right = EmulationRecord {
            cpu_local_memory_access: vec![
                window(0x100, access(1, 5), access(0xdead, 40)),
                window(0x100, access(0xdead, 40), access(3, 90)),
            ],
            ..Default::default()
        };
        assert_eq!(first_difference(&left, &right), None);
    }

    /// What the relaxation is for: a split gives an address live across a cut two chained windows
    /// where the unsplit replay had one. Same span, so not a difference.
    #[test]
    fn a_window_split_in_two_at_the_same_span_is_not_a_difference() {
        let unsplit = EmulationRecord {
            cpu_local_memory_access: vec![window(0x100, access(1, 5), access(9, 90))],
            ..Default::default()
        };
        let split = EmulationRecord {
            cpu_local_memory_access: vec![
                window(0x100, access(1, 5), access(4, 40)),
                window(0x100, access(4, 40), access(9, 90)),
            ],
            ..Default::default()
        };
        assert_eq!(first_difference(&unsplit, &split), None);
    }

    /// An initial access carries the record from whenever that address was last touched, which
    /// can be chunks ago and carry a far larger timestamp than anything in this chunk. Ordering
    /// the windows by it picks the wrong one as the chunk's entry, and then a split and an
    /// unsplit replay of the same execution disagree for no real reason.
    #[test]
    fn windows_are_ordered_by_when_they_close() {
        let split = EmulationRecord {
            cpu_local_memory_access: vec![
                window(0x100, access(1, 9_000), access(2, 10)),
                window(0x100, access(2, 10), access(3, 20)),
            ],
            ..Default::default()
        };
        let unsplit = EmulationRecord {
            cpu_local_memory_access: vec![window(0x100, access(1, 9_000), access(3, 20))],
            ..Default::default()
        };
        assert_eq!(first_difference(&split, &unsplit), None);
    }

    /// And what the relaxation must NOT let through: the same two windows, but the chunk now
    /// ends that address on a different access.
    #[test]
    fn a_split_window_that_ends_elsewhere_is_a_difference() {
        let unsplit = EmulationRecord {
            cpu_local_memory_access: vec![window(0x100, access(1, 5), access(9, 90))],
            ..Default::default()
        };
        let split = EmulationRecord {
            cpu_local_memory_access: vec![
                window(0x100, access(1, 5), access(4, 40)),
                window(0x100, access(4, 40), access(9, 110)),
            ],
            ..Default::default()
        };
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
        let whole = EmulationRecord {
            cpu_local_memory_access: vec![
                window(0x100, access(1, 5), access(2, 40)),
                window(0x100, access(2, 40), access(3, 90)),
                window(0x100, access(3, 90), access(4, 150)),
            ],
            ..Default::default()
        };
        let dropped = EmulationRecord {
            cpu_local_memory_access: vec![
                window(0x100, access(1, 5), access(2, 40)),
                window(0x100, access(3, 90), access(4, 150)),
            ],
            ..Default::default()
        };
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
        let split = EmulationRecord {
            cpu_local_memory_access: vec![
                window(0x100, access(1, 5), access(2, 40)),
                window(0x100, access(2, 40), access(3, 90)),
                window(0x100, access(3, 90), access(4, 150)),
            ],
            ..Default::default()
        };
        let unsplit = EmulationRecord {
            cpu_local_memory_access: vec![window(0x100, access(1, 5), access(4, 150))],
            ..Default::default()
        };
        assert_eq!(first_difference(&split, &unsplit), None);
    }

    #[test]
    fn an_unrebased_index_is_a_difference() {
        let left = EmulationRecord {
            history: Some(ExecutionHistory {
                steps: vec![Step::default(); 10].into(),
                chip_steps: crate::emulator::riscv::history::ChipSteps {
                    memory: vec![0, 5, 9].into(),
                    ..Default::default()
                },
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut right = left.clone();
        right.history.as_mut().unwrap().chip_steps.memory[2] = 8;
        let reported =
            first_difference(&left, &right).expect("an unrebased index must be reported");
        assert!(
            reported.starts_with("history:"),
            "reported the wrong field: {reported}"
        );
    }

    #[test]
    fn a_missing_event_is_a_difference() {
        let left = EmulationRecord {
            add_events: vec![AluEvent::default(), AluEvent::default()],
            ..Default::default()
        };
        let right = EmulationRecord {
            add_events: vec![AluEvent::default()],
            ..Default::default()
        };
        let reported = first_difference(&left, &right).expect("a dropped event must be reported");
        assert!(
            reported.starts_with("add_events:"),
            "reported the wrong field: {reported}"
        );
    }

    #[test]
    fn counts_and_bytes_come_from_lengths() {
        let record = EmulationRecord {
            add_events: vec![AluEvent::default(); 3],
            cpu_local_memory_access: vec![local_event(0x100, 1), local_event(0x108, 2)],
            ..Default::default()
        };
        let counts = record_counts(&record);
        assert!(counts.contains(&("add_events", 3)));
        assert!(counts.contains(&("cpu_local_memory_access", 2)));
        assert_eq!(
            record_bytes(&record),
            3 * std::mem::size_of::<AluEvent>() + 2 * std::mem::size_of::<MemoryLocalEvent>()
        );
    }

    #[test]
    fn a_history_ends_the_rows_on_its_digest_and_leaves_the_others_alone() {
        let streams = EmulationRecord {
            add_events: vec![AluEvent::default()],
            ..Default::default()
        };
        let history = ExecutionHistory {
            chunk: 3,
            steps: vec![Step::default(); 2].into(),
            ..Default::default()
        };
        let carrying = EmulationRecord {
            history: Some(history.clone()),
            ..streams.clone()
        };
        let mut rows = field_digests(&carrying);
        assert_eq!(rows.pop(), Some((HISTORY, 2, history.digest())));
        assert_eq!(rows, field_digests(&streams));

        let reported =
            first_difference(&streams, &carrying).expect("a history on one side must be reported");
        assert!(
            reported.starts_with("history:"),
            "reported the wrong field: {reported}"
        );
        let mut other = carrying.clone();
        other.history.as_mut().unwrap().chunk = 4;
        let reported =
            first_difference(&carrying, &other).expect("a changed history must be reported");
        assert!(
            reported.starts_with("history:"),
            "reported the wrong field: {reported}"
        );
    }

    /// A digest taken before the public values were stamped, then restamped, is the digest of the
    /// stamped record.
    #[test]
    fn restamping_matches_digesting_the_stamped_record() {
        let mut record = EmulationRecord {
            add_events: vec![AluEvent::default()],
            ..Default::default()
        };
        let mut digests = field_digests(&record);
        record.public_values.chunk = 7;
        restamp_public_values(&mut digests, &record);
        assert_eq!(digests, field_digests(&record));
    }

    /// Every stream `field_digests` digests is counted, so a stream added to the record and to the
    /// gate cannot go missing from the ledger's facts.
    #[test]
    fn every_digested_stream_is_counted() {
        const NOT_STREAMS: &[&str] = &[
            "cpu_local_memory_chain",
            PUBLIC_VALUES,
            "is_cpu_chunk",
            "is_last",
            "shape",
        ];
        let record = EmulationRecord::default();
        let digested: Vec<&str> = field_digests(&record)
            .into_iter()
            .map(|(name, _, _)| name)
            .filter(|name| !NOT_STREAMS.contains(name))
            .collect();
        let counted: Vec<&str> = record_counts(&record)
            .into_iter()
            .map(|(name, _)| name)
            .collect();
        assert_eq!(digested, counted);
    }
}
