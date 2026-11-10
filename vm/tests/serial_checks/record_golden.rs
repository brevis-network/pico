//! The serial interpreter's records on every parity guest, pinned to `record_digests.txt`.
//!
//! The parity suites compare two ways of emulating against each other inside one process; this
//! compares the interpreter against what it emitted when the file was written. For every run the
//! suites make, each record contributes its chunk index, every compared row of `field_digests`, and
//! — since one interpreter never splits a chunk, so its local-memory windows have no reason to
//! differ — their count and a digest of them in address order. A changed line is a change in what
//! the interpreter emits.
//!
//! Precompile events are digested here rather than through `field_digests`, with each event's
//! local-memory windows sorted by address first. Those windows are drained from hash maps whose
//! hasher has fixed keys but is a different function on a target with hardware AES, so their
//! order is fixed for a build and not the same on every target.
//!
//! The same check pins which syscalls the guests reach. Every syscall the emulator implements is
//! either reached by some guest or named in `unreached_syscalls.txt`, and no syscall is both: a new
//! syscall with no guest fails here, and so does a listed one a guest has started to reach. An
//! event-writing syscall is reached when a record carries its event, any other when the emulator
//! counted a call to it, so the list also says whether a guest opens an unconstrained block.

use std::{collections::BTreeSet, path::PathBuf};

use pico_vm::{
    emulator::{
        record::RecordBehavior,
        riscv::{
            emulator::RiscvEmulator,
            record::EmulationRecord,
            record_digest::{field_digests, is_compared},
            syscalls::{default_syscall_map, precompiles::PrecompileEvents, SyscallCode},
        },
    },
    mle::machine::riscv::Kb,
};

use crate::{
    golden::{digest, in_order, local_mem_access_mut, rewrite_section, section, sort_windows},
    record_parity::GUESTS,
};

const DIGESTS: &str = "record_digests.txt";
const UNREACHED: &str = "unreached_syscalls.txt";
const REWRITE: &str = "RECORD_DIGESTS_REWRITE";

/// A guest's differing lines past this many are counted, not listed.
const LISTED: usize = 20;

// The header of `unreached_syscalls.txt`, whose lines are compared but not its header: an edit
// here changes that file on its next rewrite.
const UNREACHED_HEADER: &str = "\
# Syscalls the emulator implements that no record-parity guest reaches, one name per line. An
# event-writing syscall is reached when a record carries its event, any other when the emulator
# counted a call. record_digest_golden fails on a name here that a guest reaches, and on an
# unreached syscall missing from here. Rewritten with the digests, never by hand.
";

const HEADER: &str = "\
# The serial interpreter's records on the record-parity guests.
# guest\tchunk_size\trecord\tfield\tlen\tdigest
# chunk_index carries its value in the len column. cpu_local_memory_access_by_addr is the
# record's local-memory windows sorted by address, precompile_events_by_addr its precompile events
# (len: how many) with each event's windows sorted by address; every other field is a compared
# row of field_digests. Rewrite with RECORD_DIGESTS_REWRITE=1, never by hand.
";

fn path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join(name)
}

fn rewrite() -> bool {
    std::env::var(REWRITE).is_ok_and(|value| value == "1")
}

/// `(events, digest)` over the precompile events in syscall-code order, each event digested with
/// its windows sorted.
fn precompiles_by_addr(precompiles: &mut PrecompileEvents) -> (usize, u64) {
    let mut groups: Vec<_> = precompiles
        .events
        .iter_mut()
        .filter(|(_, events)| !events.is_empty())
        .collect();
    groups.sort_by_key(|(code, _)| **code);
    let groups: Vec<(SyscallCode, Vec<u64>)> = groups
        .into_iter()
        .map(|(code, events)| {
            let digests = events
                .iter_mut()
                .map(|(syscall_event, event)| {
                    sort_windows(local_mem_access_mut(event));
                    digest(&(&*syscall_event, &*event))
                })
                .collect();
            (*code, digests)
        })
        .collect();
    let events = groups.iter().map(|(_, digests)| digests.len()).sum();
    (events, digest(&groups))
}

/// The record's rows. Digests its precompile events once, here, rather than also through
/// `field_digests`: on bls12381-fp they run to gigabytes. Leaves the record as it found it but for
/// its windows, the chunk's and every precompile event's, which it sorts in place.
fn record_lines(prefix: &str, record: &mut EmulationRecord, out: &mut Vec<String>) {
    out.push(format!(
        "{prefix}\tchunk_index\t{}\t-",
        record.chunk_index()
    ));
    let mut precompiles = std::mem::take(&mut record.precompile_events);
    for (field, len, hash) in field_digests(record) {
        if is_compared(field) && field != "precompile_events" {
            out.push(format!("{prefix}\t{field}\t{len}\t{hash:016x}"));
        }
    }
    let (events, hash) = precompiles_by_addr(&mut precompiles);
    record.precompile_events = precompiles;
    out.push(format!(
        "{prefix}\tprecompile_events_by_addr\t{events}\t{hash:016x}"
    ));
    sort_windows(&mut record.cpu_local_memory_access);
    out.push(format!(
        "{prefix}\tcpu_local_memory_access_by_addr\t{}\t{:016x}",
        record.cpu_local_memory_access.len(),
        digest(&record.cpu_local_memory_access)
    ));
}

/// What a guest reached: the ids on the records' syscall events, and every syscall the emulator
/// counted a call to. The counts fold some event-writing syscalls into one another
/// (`SyscallCode::count_map`), so those are taken from the events alone.
#[derive(Default)]
pub struct Reached {
    event_ids: BTreeSet<u32>,
    called: BTreeSet<SyscallCode>,
}

/// One guest's records against its lines of `record_digests.txt`.
pub struct Check {
    guest: &'static str,
    lines: Vec<String>,
    records: usize,
    run_records: usize,
    reached: Reached,
}

impl Check {
    pub fn new(guest: &'static str) -> Self {
        Self {
            guest,
            lines: Vec::new(),
            records: 0,
            run_records: 0,
            reached: Reached::default(),
        }
    }

    /// The record's lines and the syscalls it reached. See [`record_lines`] for what it leaves.
    pub fn record(&mut self, chunk_size: u32, record: &mut EmulationRecord) {
        self.reached
            .event_ids
            .extend(record.syscalls().iter().map(|event| event.syscall_id));
        let prefix = format!("{}\t{chunk_size}\t{}", self.guest, self.run_records);
        record_lines(&prefix, record, &mut self.lines);
        self.run_records += 1;
    }

    /// The run is over: `emulator` holds the syscalls it counted a call to.
    pub fn end_run(&mut self, chunk_size: u32, emulator: &RiscvEmulator) {
        self.reached.called.extend(
            emulator
                .state
                .syscall_counts
                .iter()
                .filter(|(_, calls)| **calls > 0)
                .map(|(code, _)| *code),
        );
        println!(
            "{} @ chunk {chunk_size}: {} record(s)",
            self.guest, self.run_records
        );
        self.records += std::mem::take(&mut self.run_records);
    }

    /// The problems of the guest's lines against the pinned ones, or none once they are
    /// rewritten; and what the guest reached.
    pub fn finish(self) -> (Vec<String>, Reached) {
        let Self {
            guest,
            lines,
            records,
            reached,
            ..
        } = self;
        println!("{guest}: {records} record(s), {} row(s)", lines.len());
        if records == 0 || lines.is_empty() {
            return (vec![format!("{guest}: nothing was compared")], reached);
        }
        let order = GUESTS.map(|guest| guest.name);
        if rewrite() {
            rewrite_section(&path(DIGESTS), HEADER, &order, guest, &lines);
            println!("rewrote {guest}'s lines of {DIGESTS}");
            return (Vec::new(), reached);
        }
        let file = std::fs::read_to_string(path(DIGESTS)).expect("read the digests");
        let pinned: Vec<(usize, &str)> = section(&file, guest).collect();
        let differing: Vec<String> = pinned
            .iter()
            .zip(&lines)
            .filter(|((_, p), a)| p != a)
            .map(|((n, p), a)| format!("  line {n}\n    pinned: {p}\n    actual: {a}"))
            .collect();
        if differing.is_empty() && pinned.len() == lines.len() {
            return (Vec::new(), reached);
        }
        let problem = format!(
            "the interpreter's records changed: {} differing line(s), {} pinned vs {} actual; the \
             first:\n{}\nIf intended, rerun with {REWRITE}=1.",
            differing.len(),
            pinned.len(),
            lines.len(),
            differing
                .iter()
                .take(LISTED)
                .cloned()
                .collect::<Vec<_>>()
                .join("\n")
        );
        (vec![problem], reached)
    }
}

/// Every syscall the emulator implements, split by whether some guest reached it, against the
/// committed list of the unreached ones.
pub fn check_syscall_coverage<'a>(guests: impl IntoIterator<Item = &'a Reached>) {
    let mut reached = Reached::default();
    for guest in guests {
        reached.event_ids.extend(&guest.event_ids);
        reached.called.extend(&guest.called);
    }
    let implemented: BTreeSet<SyscallCode> = default_syscall_map::<Kb>().keys().copied().collect();
    let (reached_codes, unreached): (Vec<SyscallCode>, Vec<SyscallCode>) =
        implemented.iter().partition(|code| {
            if code.should_send() != 0 {
                reached.event_ids.contains(&code.syscall_id())
            } else {
                reached.called.contains(code)
            }
        });
    let unknown: Vec<u32> = reached
        .event_ids
        .iter()
        .copied()
        .filter(|id| !implemented.iter().any(|code| code.syscall_id() == *id))
        .collect();
    let names =
        |codes: &[SyscallCode]| -> Vec<String> { codes.iter().map(|c| format!("{c}")).collect() };
    let (reached, unreached) = (names(&reached_codes), names(&unreached));
    println!("reached syscalls: {}", reached.join(" "));
    assert!(!reached.is_empty(), "no guest reached any syscall");
    assert!(
        unknown.is_empty(),
        "syscall ids on the records that the emulator does not implement: {unknown:?}"
    );

    if rewrite() {
        let mut names = unreached.clone();
        names.sort();
        let listed: String = names.iter().map(|name| format!("{name}\n")).collect();
        std::fs::write(path(UNREACHED), format!("{UNREACHED_HEADER}{listed}"))
            .expect("write the unreached syscalls");
        println!("rewrote {UNREACHED}");
        return;
    }

    let listed: BTreeSet<String> = std::fs::read_to_string(path(UNREACHED))
        .expect("read the unreached syscalls")
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(str::to_owned)
        .collect();
    println!(
        "listed as unreached: {}",
        listed.iter().cloned().collect::<Vec<_>>().join(" ")
    );

    let unlisted: Vec<&String> = unreached.iter().filter(|n| !listed.contains(*n)).collect();
    let listed_but_reached: Vec<&String> = reached.iter().filter(|n| listed.contains(*n)).collect();
    let stale: Vec<&String> = listed
        .iter()
        .filter(|n| !unreached.contains(n) && !reached.contains(n))
        .collect();
    assert!(
        unlisted.is_empty() && listed_but_reached.is_empty() && stale.is_empty(),
        "syscall coverage moved: reached by no guest and not in {UNREACHED}: {unlisted:?}; \
         in {UNREACHED} but reached: {listed_but_reached:?}; in {UNREACHED} but not a syscall \
         the emulator implements: {stale:?}. If intended, rerun with {REWRITE}=1."
    );
}

/// `record_digests.txt` is its header and then each guest's lines, in the order the guests run:
/// what a rewrite of every guest writes. Each guest's test compares its own lines only.
pub fn check_file_layout() {
    let file = std::fs::read_to_string(path(DIGESTS)).expect("read the digests");
    let rebuilt = in_order(&file, HEADER, &GUESTS.map(|guest| guest.name));
    if let Some((n, (pinned, rebuilt))) = file
        .lines()
        .zip(rebuilt.lines())
        .enumerate()
        .find(|(_, (pinned, rebuilt))| pinned != rebuilt)
    {
        panic!(
            "{DIGESTS} line {}: {pinned:?}, where its header and each guest's lines in turn give \
             {rebuilt:?}. Rewrite it with {REWRITE}=1.",
            n + 1
        );
    }
    assert!(
        file == rebuilt,
        "{DIGESTS} holds {} line(s), its header and each guest's lines in turn {}",
        file.lines().count(),
        rebuilt.lines().count()
    );
}
