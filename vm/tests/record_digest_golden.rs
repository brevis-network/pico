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
//! The same test pins which syscalls the guests reach. Every syscall the emulator implements is
//! either reached by some guest or named in `unreached_syscalls.txt`, and no syscall is both: a new
//! syscall with no guest fails here, and so does a listed one a guest has started to reach. An
//! event-writing syscall is reached when a record carries its event, any other when the emulator
//! counted a call to it, so the list also says whether a guest opens an unconstrained block.
//!
//! The variables in `RECORD_SHAPING_VARS` change where the deferred records split and how
//! precompile windows merge; the file is written with each at its default, so the test removes
//! them before the first emulation reads them.
//!
//! To rewrite both files after an intended change:
//!   RECORD_DIGESTS_REWRITE=1 cargo test --release -p pico-vm --test record_digest_golden

use std::{collections::BTreeSet, io::Write, path::PathBuf, sync::Arc};

use pico_vm::{
    chips::chips::riscv_memory::event::MemoryLocalEvent,
    emulator::{
        record::RecordBehavior,
        riscv::{
            emulator::RiscvEmulator,
            public_values::RecordFinalPvsState,
            record::EmulationRecord,
            record_digest::{field_digests, is_compared},
            record_slots::hold_records_unbounded,
            syscalls::{
                default_syscall_map,
                precompiles::{PrecompileEvent, PrecompileEvents},
                SyscallCode,
            },
        },
    },
    mle::machine::riscv::Kb,
};

// Only the guests and their runs: the comparison in there is between two arms, and this has one.
#[allow(dead_code)]
#[path = "common/record_parity.rs"]
mod record_parity;
use record_parity::{opts, program, stdin, Run, GUESTS};

const DIGESTS: &str = "record_digests.txt";
const UNREACHED: &str = "unreached_syscalls.txt";
const REWRITE: &str = "RECORD_DIGESTS_REWRITE";

/// Every variable the emulation reads that changes the records it emits. `PICO_GPU_MEM` picks
/// the deferred split thresholds.
const RECORD_SHAPING_VARS: [&str; 6] = [
    "DEFERRED_TAIL_MERGE",
    "MLE_PRECOMPILE_LOCAL_MEM_MERGE",
    "CHUNK_EVENT_LIMIT_SCALE",
    "CHUNK_EVENT_LIMITS_OFF",
    "CHUNK_COMMIT_TAIL_HOLD_OFF",
    "PICO_GPU_MEM",
];

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

/// FNV-1a over the bincode encoding.
fn digest<T: serde::Serialize + ?Sized>(value: &T) -> u64 {
    struct Fnv(u64);
    impl Write for Fnv {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            for byte in buf {
                self.0 ^= u64::from(*byte);
                self.0 = self.0.wrapping_mul(0x0000_0100_0000_01b3);
            }
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut fnv = Fnv(0xcbf2_9ce4_8422_2325);
    bincode::serialize_into(&mut fnv, value).expect("serialize");
    fnv.0
}

/// Windows in a total order: the maps they are drained from iterate in no fixed one.
fn sort_windows(windows: &mut [MemoryLocalEvent]) {
    windows.sort_unstable_by_key(|w| {
        let (i, f) = (w.initial_mem_access, w.final_mem_access);
        (
            w.addr,
            i.chunk,
            i.timestamp,
            i.value,
            f.chunk,
            f.timestamp,
            f.value,
        )
    });
}

fn local_mem_access_mut(event: &mut PrecompileEvent) -> &mut Vec<MemoryLocalEvent> {
    match event {
        PrecompileEvent::ShaExtend(e) => &mut e.local_mem_access,
        PrecompileEvent::ShaCompress(e) => &mut e.local_mem_access,
        PrecompileEvent::KeccakPermute(e) => &mut e.local_mem_access,
        PrecompileEvent::EdDecompress(e) => &mut e.local_mem_access,
        PrecompileEvent::EdAdd(e)
        | PrecompileEvent::Secp256k1Add(e)
        | PrecompileEvent::Secp256r1Add(e)
        | PrecompileEvent::Bn254Add(e)
        | PrecompileEvent::Bls12381Add(e) => &mut e.local_mem_access,
        PrecompileEvent::Secp256k1Double(e)
        | PrecompileEvent::Secp256r1Double(e)
        | PrecompileEvent::Bn254Double(e)
        | PrecompileEvent::Bls12381Double(e) => &mut e.local_mem_access,
        PrecompileEvent::Secp256k1Decompress(e)
        | PrecompileEvent::Secp256r1Decompress(e)
        | PrecompileEvent::K256Decompress(e)
        | PrecompileEvent::Bls12381Decompress(e) => &mut e.local_mem_access,
        PrecompileEvent::Bn254Fp(e)
        | PrecompileEvent::Bls12381Fp(e)
        | PrecompileEvent::Secp256k1Fp(e) => &mut e.local_mem_access,
        PrecompileEvent::Bn254Fp2AddSub(e) | PrecompileEvent::Bls12381Fp2AddSub(e) => {
            &mut e.local_mem_access
        }
        PrecompileEvent::Bn254Fp2Mul(e) | PrecompileEvent::Bls12381Fp2Mul(e) => {
            &mut e.local_mem_access
        }
        PrecompileEvent::Uint256Mul(e) => &mut e.local_mem_access,
        PrecompileEvent::Poseidon2Permute(e) => &mut e.local_mem_access,
    }
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

/// The record's rows. Sorts its windows in place, and digests its precompile events once, here,
/// rather than also through `field_digests`: on bls12381-fp they run to gigabytes.
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

/// `emulate_with_opts`' run, each record handed to `each` as the emulator returns it and dropped
/// there: held whole, the longer guests' runs take the test past a CI runner's memory. Returns
/// what the output drops, the syscalls the emulator counted a call to.
fn emulate(
    guest: &str,
    elf: &[u8],
    run: &Run,
    mut each: impl FnMut(EmulationRecord),
) -> Vec<SyscallCode> {
    hold_records_unbounded();
    let mut emulator = RiscvEmulator::new_single::<Kb>(
        program(elf),
        Arc::new(RecordFinalPvsState::default()),
        opts(run.chunk_size),
    );
    emulator.write_stdin(&stdin(&run.stdin));
    loop {
        let report = emulator
            .emulate_batch(&mut each)
            .unwrap_or_else(|err| panic!("{guest} @ chunk {}: {err}", run.chunk_size));
        if report.done {
            break;
        }
    }
    emulator
        .state
        .syscall_counts
        .iter()
        .filter(|(_, calls)| **calls > 0)
        .map(|(code, _)| *code)
        .collect()
}

#[test]
fn the_interpreter_emits_the_pinned_records() {
    for var in RECORD_SHAPING_VARS {
        std::env::remove_var(var);
    }
    let rewrite = std::env::var(REWRITE).is_ok_and(|value| value == "1");

    let mut lines = Vec::new();
    let mut records = 0;
    let mut reached = Reached::default();
    for guest in &GUESTS {
        for run in guest.runs() {
            let mut index = 0;
            let called = emulate(guest.name, guest.elf, &run, |mut record| {
                let prefix = format!("{}\t{}\t{index}", guest.name, run.chunk_size);
                reached
                    .event_ids
                    .extend(record.syscalls().iter().map(|e| e.syscall_id));
                record_lines(&prefix, &mut record, &mut lines);
                index += 1;
            });
            reached.called.extend(called);
            println!(
                "{} @ chunk {}: {index} record(s)",
                guest.name, run.chunk_size
            );
            records += index;
        }
    }
    println!("{records} record(s), {} row(s)", lines.len());
    assert!(records > 0 && !lines.is_empty(), "nothing was compared");

    let actual = format!("{HEADER}{}\n", lines.join("\n"));
    if rewrite {
        std::fs::write(path(DIGESTS), &actual).expect("write the digests");
        println!("rewrote {DIGESTS}");
    } else {
        let pinned = std::fs::read_to_string(path(DIGESTS)).expect("read the digests");
        let differing: Vec<String> = pinned
            .lines()
            .zip(actual.lines())
            .enumerate()
            .filter(|(_, (p, a))| p != a)
            .map(|(n, (p, a))| format!("  line {}\n    pinned: {p}\n    actual: {a}", n + 1))
            .collect();
        let (pinned_len, actual_len) = (pinned.lines().count(), actual.lines().count());
        assert!(
            differing.is_empty() && pinned_len == actual_len,
            "the interpreter's records changed: {} differing line(s), {pinned_len} pinned vs \
             {actual_len} actual; the first:\n{}\nIf intended, rerun with {REWRITE}=1.",
            differing.len(),
            differing
                .iter()
                .take(20)
                .cloned()
                .collect::<Vec<_>>()
                .join("\n")
        );
    }

    check_syscall_coverage(&reached, rewrite);
}

/// What the guests reached: the ids on the records' syscall events, and every syscall the
/// emulator counted a call to. The counts fold some event-writing syscalls into one another
/// (`SyscallCode::count_map`), so those are taken from the events alone.
#[derive(Default)]
struct Reached {
    event_ids: BTreeSet<u32>,
    called: BTreeSet<SyscallCode>,
}

/// Every syscall the emulator implements, split by whether a guest reached it, against the
/// committed list of the unreached ones.
fn check_syscall_coverage(reached: &Reached, rewrite: bool) {
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

    if rewrite {
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
