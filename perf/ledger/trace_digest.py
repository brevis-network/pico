#!/usr/bin/env python3
"""Compare two runs' chip traces record by record, from the `trace_digest` each `prove.tracegen.<chip>`
stage-ledger line carries.

Each input is one run's stage ledger, as `MLE_LEDGER=<path>` writes it (`perf/ledger/summarise.py`
describes the format), from an arm that generates traces (`tracegen-aot`, or a prove arm) with
`MLE_LEDGER_DIGESTS=1` set, so every tracegen line carries its digest. aot_bench.sh writes one ledger
per run with a prefix such as

  -e h='env MLE_LEDGER_DIGESTS=1 MLE_LEDGER={out}/{rep}-{arm}@{label}.jsonl'

Records are matched by their index in the run's emission order, and must name the same chunk in
both: a CPU chunk by its number, a deferred record by none. Per record the two runs must agree on
which chips generated a trace, and per chip on its `trace_digest`, `rows` and `cols`; and on which
chips' `extra_record` ran, and per chip on its `events_added`. A record in one ledger only fails the
comparison.

`--chips` narrows every comparison to the chips it names: the two branch-compare choices are
compared on `LessThan` alone, since with `indices` the CPU chip's `extra_record` adds no comparison
and its `events_added` differs by design.

`--reference-source` and `--candidate-source` say what each run traced its CPU chunks from, read off
every CPU chunk's `prove.augment.clone` line: `streams` requires `trace_source` "streams"; `history`
requires "history", every producer stream empty and `history_bytes` above zero, so a run that read
the streams under the history's name fails. `any` (the default) checks neither, for a ledger written
before those facts existed. A record that carries no history has a null `trace_source`, so a CPU
chunk without one fails `history`; deferred records, which carry none, are not checked. `streams`
reads a ledger written before the streams were removed, when a record could be traced from either.
The line is written only where a record is copied before its trace generation, as `tracegen-aot`
copies each; the prover of a prove arm owns its records and traces them in place, writing none, so
either check fails such a ledger on every CPU chunk.

`--reference-sink` and `--candidate-sink` say what each run's replay workers wrote, read off the
envelope and every `worker.replay` line: `legacy`, `dual` or `history` requires the envelope's
`representation` to be "streams", "dual" or "history" and every line's `sink` to name that sink.
`legacy` also requires no line to carry `history_bytes`; `dual` and `history` require every line that
produced a record to carry `history_bytes` above zero; and `history` requires each of those lines to
list any surviving producer streams at zero; removed streams may be absent. A run with no
`worker.replay` line fails. `any` (the default) checks none of this.

`--reference-split` and `--candidate-split` say whether a run cut its chunks' replays into segments:
`split` requires the envelope's `split` to name more than one segment and at least one chunk to have
been replayed in more than one, by its `worker.replay` lines, else the comparison of a split run with
an unsplit one is vacuous; `unsplit` requires one segment and no chunk replayed in more. `any` (the
default) checks neither.

`--split-vs-unsplit` compares a split replay (the candidate) with an unsplit one (the reference), and
implies `--reference-split unsplit --candidate-split split`. A cut through a chunk's replay gives an
address live across it two chained local-memory windows where the unsplit replay had one, on every
sink, so four chips differ by design and are left out of every comparison: MemoryLocal, its global
lookups (Global), their Poseidon2 hashes (RiscvKoalaBearPoseidon2) and the byte lookups behind them
(Byte). Each is printed as an `EXCLUDED` line with the traces it left out. The two windows chain and
cancel on the global bus, but no ledger line carries the global cumulative sum or the local-memory
chain, so neither is compared here. Every other chip is compared exactly. Without the flag every chip
is, as runs of the same segmentation should agree on all of them.

One difference is allowed, between a record traced from the streams and the same record traced
from the history, by each side's `trace_source`: on the streams the CPU chip's `extra_record` appends
one less-than event per branch step, and on the history it appends none, as the LessThan chip reads
the branch steps from the history. So the CPU chip's `events_added` may differ by an `lt_events` key
on the streams side alone, every other key equal, and only where the LessThan chip traced the same
rows on both sides. The ledger carries no per-record count of branch steps, so that LessThan trace is
what shows the history handed over the comparisons the streams appended. Every record the allowance
admits is counted on an `ALLOWED` line. Records traced from the same source are compared exactly.

Prints each differing record and chip, then one `TRACE_DIGEST` line with the counts and the verdict.

Exit status: 0 the traces agree; 1 they do not, or a source, sink or split check failed; 2 bad or
stale input (not one run in a file, a run with no complete envelope, another schema version, the two
runs on different ELFs or inputs, a stage line with no record, a record's stage written twice, a
tracegen line with no digest).

Deliberately stdlib-only, so it runs as-is on any host a ledger comes from.
"""

from __future__ import annotations

import argparse
import json
import sys

SCHEMA_VERSION = 2
TRACEGEN = "prove.tracegen."
AUGMENT = "prove.augment."
CLONE = "prove.augment.clone"
REPLAY = "worker.replay"
# Producer stream keys in older ledgers, retained for reading those ledgers.
PRODUCER_STREAMS = ("cpu_events", "memory_read_write_event_indices", "add_events", "sub_events",
                    "mul_events", "bitwise_events", "shift_left_events", "shift_right_events",
                    "lt_events", "divrem_events", "syscall_events")
# The envelope's `representation` for each replay sink.
REPRESENTATION = {"legacy": "streams", "dual": "dual", "history": "history"}
# The chips a split replay's traces differ in from an unsplit one's, by design.
SPLIT_EXCLUDED = ("MemoryLocal", "Global", "RiscvKoalaBearPoseidon2", "Byte")
# What the CPU chip appends for the branch steps on a record traced from the streams alone.
BRANCH_COMPARES = "lt_events"


class BadInput(Exception):
    pass


def load(path: str) -> dict:
    """The run in `path`: its last envelope, per record the facts of each prove stage, and its
    `worker.replay` lines."""
    runs, envelope, records, replays = set(), None, {}, []
    with open(path, encoding="utf-8") as lines:
        for number, raw in enumerate(lines, 1):
            if not raw.strip():
                continue
            try:
                line = json.loads(raw)
            except json.JSONDecodeError:
                print(f"warning: {path}:{number} is not JSON, the torn end of a killed run",
                      file=sys.stderr)
                continue
            if line.get("v") != SCHEMA_VERSION:
                raise BadInput(f"{path}:{number}: schema version {line.get('v')!r}, "
                               f"not {SCHEMA_VERSION}")
            runs.add(line.get("run"))
            if len(runs) > 1:
                raise BadInput(f"{path}:{number}: a second run, {line.get('run')!r}; give one "
                               f"ledger per run")
            if line.get("kind") == "envelope":
                envelope = line
                continue
            stage = line.get("stage") or ""
            if stage == REPLAY and not line.get("skipped"):
                replays.append({"line": number, "chunk": line.get("chunk"), "seg": line.get("seg"),
                                "facts": line.get("facts") or {}})
                continue
            if not stage.startswith((TRACEGEN, AUGMENT)) or line.get("skipped"):
                continue
            record = line.get("record")
            if not isinstance(record, int):
                raise BadInput(f"{path}:{number}: a {stage} line with no record")
            entry = records.setdefault(record, {"chunk": line.get("chunk"), "stages": {}})
            if entry["chunk"] != line.get("chunk"):
                raise BadInput(f"{path}:{number}: record {record} names chunks "
                               f"{entry['chunk']} and {line.get('chunk')}")
            if stage in entry["stages"]:
                raise BadInput(f"{path}:{number}: record {record} has {stage} twice")
            facts = line.get("facts") or {}
            if stage.startswith(TRACEGEN) and facts.get("trace_digest") is None:
                raise BadInput(f"{path}:{number}: {stage} of record {record} carries no "
                               f"trace_digest; set MLE_LEDGER_DIGESTS=1")
            entry["stages"][stage] = facts
    if not runs:
        raise BadInput(f"{path}: no line; give one run's ledger")
    # The opening envelope says `"complete": false`; only the driver's finish writes a complete one.
    if envelope is None or envelope.get("complete") is not True:
        raise BadInput(f"{path}: the run has no complete envelope, so it did not finish")
    if not records:
        raise BadInput(f"{path}: no prove.tracegen or prove.augment line; trace a record first")
    return {"path": path, "envelope": envelope, "records": records, "replays": replays}


def digest_of(envelope: dict, field: str):
    """The sha256 the envelope names for its `elf` or `input`; none when it names none."""
    named = envelope.get(field)
    return named.get("sha256") if isinstance(named, dict) else None


def chips(stages: dict, prefix: str, only: set[str] | None, excluded: tuple = ()) -> dict:
    """Each chip's facts under `prefix`, of the chips in `only` when it names some and not in
    `excluded`, the augment pass's clone left out."""
    named = {stage[len(prefix):]: facts for stage, facts in stages.items()
             if stage.startswith(prefix) and stage != CLONE}
    return {chip: facts for chip, facts in named.items()
            if (only is None or chip in only) and chip not in excluded}


def check_source(run: dict, source: str, problems: list[str]) -> None:
    """That every CPU chunk of `run` was traced from `source`, by its `prove.augment.clone` facts."""
    if source == "any":
        return
    side = run["path"]
    for record, entry in sorted(run["records"].items()):
        if entry["chunk"] is None:
            continue
        facts = entry["stages"].get(CLONE)
        if facts is None:
            problems.append(f"{side}: record {record} (chunk {entry['chunk']}) has no {CLONE} line")
            continue
        if facts.get("trace_source") != source:
            problems.append(f"{side}: record {record} (chunk {entry['chunk']}) was traced from "
                            f"{facts.get('trace_source')!r}, not {source!r}")
        if source == "history":
            streams = facts.get("streams") or {}
            held = {name: length for name, length in streams.items() if length}
            if not streams or held:
                problems.append(f"{side}: record {record} (chunk {entry['chunk']}) entered the "
                                f"augment pass holding producer streams {held or 'unlisted'}")
            if not (facts.get("history_bytes") or 0) > 0:
                problems.append(f"{side}: record {record} (chunk {entry['chunk']}) entered the "
                                f"augment pass with no history")


def check_sink(run: dict, sink: str, problems: list[str]) -> None:
    """That `run`'s replay workers wrote through `sink`, by its envelope and `worker.replay` lines."""
    if sink == "any":
        return
    side = run["path"]
    representation = run["envelope"].get("representation")
    if representation != REPRESENTATION[sink]:
        problems.append(f"{side}: the envelope's representation is {representation!r}, not "
                        f"{REPRESENTATION[sink]!r}")
    if not run["replays"]:
        problems.append(f"{side}: no {REPLAY} line, so nothing says what the replay workers wrote")
    for replay in run["replays"]:
        facts = replay["facts"]
        where = f"{side}:{replay['line']}: chunk {replay['chunk']} segment {replay['seg']}"
        if facts.get("sink") != sink:
            problems.append(f"{where} was replayed through the {facts.get('sink')!r} sink, not "
                            f"{sink!r}")
        history_bytes = facts.get("history_bytes")
        produced = (facts.get("records") or 0) > 0
        if sink == "legacy":
            if history_bytes is not None:
                problems.append(f"{where} wrote a history of {history_bytes} bytes")
        elif produced and not (history_bytes or 0) > 0:
            problems.append(f"{where} produced a record and no history")
        if sink == "history" and produced:
            events = facts.get("events") or {}
            held = {name: events[name] for name in PRODUCER_STREAMS
                    if name in events and events[name] != 0}
            if "add_events" not in events:
                held["add_events"] = "unlisted"
            if held:
                problems.append(f"{where} wrote producer streams {held}")


def split_chunks(run: dict) -> int:
    """How many chunks `run` replayed in more than one segment, by their `worker.replay` lines."""
    segments: dict = {}
    for replay in run["replays"]:
        seg = replay["seg"]
        if isinstance(seg, list) and len(seg) == 2:
            segments.setdefault(replay["chunk"], set()).add(seg[0])
    return sum(len(indices) > 1 for indices in segments.values())


def check_split(run: dict, want: str, problems: list[str]) -> None:
    """That `run` did, or did not, replay its chunks in segments, as `want` says."""
    if want == "any":
        return
    side = run["path"]
    split = run["envelope"].get("split")
    segments = split.get("segments") if isinstance(split, dict) else None
    chunks = split_chunks(run)
    if want == "split":
        if not (isinstance(segments, int) and segments > 1):
            problems.append(f"{side}: the envelope's split is {split!r}, so split replay was off")
        if chunks == 0:
            problems.append(f"{side}: no chunk was replayed in more than one segment, so this "
                            f"comparison is vacuous")
    else:
        if segments != 1:
            problems.append(f"{side}: the envelope's split is {split!r}, not one segment")
        if chunks:
            problems.append(f"{side}: {chunks} chunk(s) were replayed in more than one segment")


def traced_from(entry: dict):
    """The record's `trace_source`, by its `prove.augment.clone` line; none without one."""
    return (entry["stages"].get(CLONE) or {}).get("trace_source")


def branch_compares_alone(streams: dict, history: dict) -> str | None:
    """None when the CPU chip's `events_added` on a record traced from the streams and on the same
    record traced from the history differ by the streams' branch compares alone; else why not."""
    def added(entry: dict) -> dict:
        return (entry["stages"].get(AUGMENT + "Cpu") or {}).get("events_added") or {}

    appended, handed = added(streams), added(history)
    if handed.get(BRANCH_COMPARES):
        return f"the history side appended {BRANCH_COMPARES} too"
    other = {key for key in set(appended) | set(handed) if key != BRANCH_COMPARES}
    if any(appended.get(key) != handed.get(key) for key in other):
        return f"keys other than {BRANCH_COMPARES} differ"
    if not appended.get(BRANCH_COMPARES):
        return f"the streams side appended no {BRANCH_COMPARES}"
    traces = [entry["stages"].get(TRACEGEN + "LessThan") for entry in (streams, history)]
    if None in traces:
        return "the LessThan chip did not trace on both sides"
    for field in ("trace_digest", "rows", "cols"):
        if traces[0].get(field) != traces[1].get(field):
            return f"the LessThan chip's {field} differs"
    return None


def compare_record(record: int, left: dict, right: dict, only: set[str] | None,
                   excluded: tuple, allowed: list[int], out: list[str]) -> int:
    """The differences between one record's two entries, as lines in `out`, and the record added to
    `allowed` if the branch-compare allowance admitted it; returns how many chip traces were
    compared."""
    where = f"record {record} (chunk {left['chunk']})"
    left_traces = chips(left["stages"], TRACEGEN, only, excluded)
    right_traces = chips(right["stages"], TRACEGEN, only, excluded)
    if set(left_traces) != set(right_traces):
        out.append(f"{where}: traced chips differ; only in the reference "
                   f"{sorted(set(left_traces) - set(right_traces))}, only in the candidate "
                   f"{sorted(set(right_traces) - set(left_traces))}")
    common = sorted(set(left_traces) & set(right_traces))
    for chip in common:
        for field in ("trace_digest", "rows", "cols"):
            ours, theirs = left_traces[chip].get(field), right_traces[chip].get(field)
            if ours != theirs:
                out.append(f"{where}: {chip} {field} {ours} in the reference, {theirs} in the "
                           f"candidate")
    left_added = chips(left["stages"], AUGMENT, only, excluded)
    right_added = chips(right["stages"], AUGMENT, only, excluded)
    if set(left_added) != set(right_added):
        out.append(f"{where}: extra_record ran for different chips; only in the reference "
                   f"{sorted(set(left_added) - set(right_added))}, only in the candidate "
                   f"{sorted(set(right_added) - set(left_added))}")
    sources = (traced_from(left), traced_from(right))
    for chip in sorted(set(left_added) & set(right_added)):
        ours = left_added[chip].get("events_added")
        theirs = right_added[chip].get("events_added")
        if ours == theirs:
            continue
        why = ""
        if chip == "Cpu" and set(sources) == {"streams", "history"}:
            streams, history = (left, right) if sources[0] == "streams" else (right, left)
            reason = branch_compares_alone(streams, history)
            if reason is None:
                allowed.append(record)
                continue
            why = f"; not the streams' branch compares alone: {reason}"
        out.append(f"{where}: {chip} events_added {ours} in the reference, {theirs} in the "
                   f"candidate{why}")
    return len(common)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("reference", help="the reference run's stage ledger")
    parser.add_argument("candidate", help="the candidate run's stage ledger")
    sources = ["any", "streams", "history"]
    parser.add_argument("--reference-source", choices=sources, default="any",
                        help="what the reference traced its CPU chunks from (default any)")
    parser.add_argument("--candidate-source", choices=sources, default="any",
                        help="what the candidate traced its CPU chunks from (default any)")
    sinks = ["any", "legacy", "dual", "history"]
    parser.add_argument("--reference-sink", choices=sinks, default="any",
                        help="what the reference's replay workers wrote (default any)")
    parser.add_argument("--candidate-sink", choices=sinks, default="any",
                        help="what the candidate's replay workers wrote (default any)")
    splits = ["any", "unsplit", "split"]
    parser.add_argument("--reference-split", choices=splits, default="any",
                        help="whether the reference replayed chunks in segments (default any)")
    parser.add_argument("--candidate-split", choices=splits, default="any",
                        help="whether the candidate replayed chunks in segments (default any)")
    parser.add_argument("--split-vs-unsplit", action="store_true",
                        help="the candidate is a split replay of the reference's unsplit one: leave "
                             f"out {', '.join(SPLIT_EXCLUDED)}")
    parser.add_argument("--chips", help="compare only these chips, comma-separated (default all)")
    args = parser.parse_args()
    only = {chip.strip() for chip in args.chips.split(",") if chip.strip()} if args.chips else None
    excluded: tuple = ()
    if args.split_vs_unsplit:
        excluded = SPLIT_EXCLUDED
        for side, want in (("reference", "unsplit"), ("candidate", "split")):
            given = getattr(args, f"{side}_split")
            if given not in ("any", want):
                parser.error(f"--split-vs-unsplit takes an {want} {side}, not "
                             f"--{side}-split {given}")
            setattr(args, f"{side}_split", want)
        if only and only & set(excluded):
            parser.error(f"--chips names {sorted(only & set(excluded))}, which --split-vs-unsplit "
                         f"leaves out")

    try:
        reference, candidate = load(args.reference), load(args.candidate)
        for field in ("elf", "input"):
            ours = digest_of(reference["envelope"], field)
            theirs = digest_of(candidate["envelope"], field)
            if ours != theirs:
                raise BadInput(f"the runs' {field} differs: {ours} in the reference, {theirs} in "
                               f"the candidate")
        if digest_of(reference["envelope"], "elf") is None:
            raise BadInput("the reference's envelope names no ELF, so nothing says what it ran")
    except (BadInput, OSError) as err:
        print(f"error: {err}", file=sys.stderr)
        return 2

    problems: list[str] = []
    check_source(reference, args.reference_source, problems)
    check_source(candidate, args.candidate_source, problems)
    check_sink(reference, args.reference_sink, problems)
    check_sink(candidate, args.candidate_sink, problems)
    check_split(reference, args.reference_split, problems)
    check_split(candidate, args.candidate_split, problems)
    left, right = reference["records"], candidate["records"]
    for record in sorted(set(left) ^ set(right)):
        problems.append(f"record {record} is in only the "
                        f"{'reference' if record in left else 'candidate'}")
    common = sorted(set(left) & set(right))
    traces, differing, cpu_chunks = 0, 0, 0
    left_out = {chip: 0 for chip in excluded}
    allowed: list[int] = []
    across = 0
    for record in common:
        if left[record]["chunk"] != right[record]["chunk"]:
            problems.append(f"record {record} is chunk {left[record]['chunk']} in the reference, "
                            f"{right[record]['chunk']} in the candidate")
            continue
        cpu_chunks += left[record]["chunk"] is not None
        for chip in excluded:
            left_out[chip] += sum(TRACEGEN + chip in side[record]["stages"] for side in (left, right))
        across += {traced_from(left[record]), traced_from(right[record])} == {"streams", "history"}
        found: list[str] = []
        traces += compare_record(record, left[record], right[record], only, excluded, allowed,
                                 found)
        for line in found:
            print(f"DIFFERS {line}")
        differing += bool(found)
    if differing:
        problems.append(f"{differing} record(s) differ")
    if cpu_chunks == 0:
        problems.append("no CPU chunk compared")
    if traces == 0:
        problems.append("no chip trace compared")

    for chip, count in left_out.items():
        print(f"EXCLUDED {chip}: {count} trace(s) not compared, by the split reading")
    if across:
        print(f"ALLOWED Cpu {BRANCH_COMPARES} on {len(allowed)} record(s): streams appends branch "
              f"compares, history hands them as indices ({across} record(s) traced from the streams "
              f"on one side and the history on the other)")
    for problem in problems:
        print(f"FAIL: {problem}")
    print(f"TRACE_DIGEST reference={reference['path']} "
          f"reference_label={reference['envelope'].get('label')} "
          f"candidate={candidate['path']} "
          f"candidate_label={candidate['envelope'].get('label')} "
          f"records={len(common)} cpu_chunks={cpu_chunks} deferred={len(common) - cpu_chunks} "
          f"chips={','.join(sorted(only)) if only else 'all'} "
          f"excluded={','.join(excluded) if excluded else 'none'} chip_traces={traces} "
          f"differing_records={differing} allowed_cpu_lt_events={len(allowed)} "
          f"reference_split_chunks={split_chunks(reference)} "
          f"candidate_split_chunks={split_chunks(candidate)} "
          f"verdict={'FAIL' if problems else 'PASS'}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
