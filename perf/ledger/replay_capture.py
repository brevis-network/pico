#!/usr/bin/env python3
"""The pooled replay readings and the precompile capture cost, from stage ledgers.

The input is what `MLE_LEDGER=<path>` writes (JSON Lines, `"v": 2`; several runs and files, lines
joined on `run`), and with `--bench`, repeatable, the `results.txt` files `perf/aot/aot_bench.sh`
writes, whose `AOT_BENCH` lines join a run on its `label` and `rep`. The bench line carries what a
ledger does not: the binary's allocator, memory backing and big-integer backend (`alloc`, `mem`,
`bigint`), the arm's storage and table growth (`storage`, `realloc`), its page faults
(`minor_faults`, `major_faults`), its compiled-block count (`aot_dispatches`), the lock file read
before and after it (`lock_held`), and for `retained-rows` the retained ECALL rows' write time
(`retained_rows_us`).

A run is counted unless it is a warm-up or its rep is in `--discard-reps`. Printed, in this order:

  RUN      one per run, counted or not: label, rep, sink, worker engine, chunks, replay median.
  REPLAY   per label, `worker.replay` per CPU chunk over the loaded chunks (`--chunks`, default
           12-37): each run's median, the median of those, and the median of every run's loaded
           chunks pooled, with how many chunks each run gave (fewer than 20 is flagged).
  BAND     per label whose runs replay with interpreter workers writing the event streams into
           pooled storage: the median of its runs' medians against `--band` (default 584-673 ms),
           inside or outside.
  SHRINK   per arm run with both sinks: the history label's pooled median against the streams',
           each rep's difference of run medians and their range, and the regime: `reserved` when
           every history run's tables read 0 growths, else `growth`.
  FAULTS   per run: the minor and major page faults over its timed call, and the facts the ledger
           sums for it (`faults.*`, `pool.blocked_gets`, `pool.blocked_us`).
  ANCHOR   per label run on the AOT snapshot thread, per chunk `--anchor` names: the snapshot
           thread's time (`snapshot.emulate` less the precompile timers' enclosed cost when they
           ran), median over runs, against the anchor +-10 %; its pool wait printed beside, not
           subtracted.
  CAPTURE  per counted run with the precompile timers on: per syscall kind the worker role's count
           and event-path time and the snapshot role's count and compute-only time, each less its
           bracket count x its timer's empty-pair cost; the drain, one bracket per precompile call
           (`drain.calls`, the words it drained printed beside as `drain.words`), less its own,
           and its brackets' enclosed cost taken out of the event path that holds them; and
           X = sum over kinds of (event path - compute only) - drain. Beside it: the deferred
           assembly (`deferred.extend_us`) and, apart from it, the end-of-run memory extend
           (`deferred.memory_extend_us`), each less its bracket count x its timer's empty-pair
           cost, and the final split's phases.
  READ     per pricing label, per read (one pair of counted reps, in rep order): X, the assembly
           and the anchor (chunks 4-8, each the mean of the read's two runs, within +-10 %) as the
           mean of the read's two runs; the rows (`--rows-ms`, else the slowest `retained-rows`
           line); X + rows + assembly. Then the worst read's X + rows + assembly and the best
           read's X. Only the anchor has a threshold; the totals are left to the reader.

Exit status: 0; 1 a vacuous run or read, each named on a VACUOUS line after everything else; 2 bad
input, or a counted run with the precompile timers on and no `--expect-events`. Vacuous:
  - a counted run whose workload differs from the others' (CPU chunks, cycles, ELF and input
    digests) or from `--expect-chunks` / `--expect-cycles`;
  - on a pooled arm, no bench line, or one that says other than production's build (`alloc`
    tcmalloc, `mem` mmap, `bigint` rug) or `storage` other than pooled;
  - on the AOT snapshot thread, `aot_dispatches` 0 or a `snapshot.emulate` line with no compiled
    block entered; with AOT replay workers, such a `worker.replay` line;
  - unpinned: `cpus_allowed_list` other than `--cpus`, a memory policy other than bind to `--mems`
    on every mapping, or a lock file not proven held: the envelope's `lock_held` and the bench
    line's, read from the lock file before and after the run, must both be true (`aot_bench.sh` reads
    the lock named by `BENCH_LOCK_FILE` and `BENCH_LOCK_HOLDER`, and without them says false);
  - writing the history with a CPU chunk of no history bytes, or the streams with one of no record
    bytes;
  - with the precompile timers on: a sink other than the streams; no kind counted; a kind whose
    worker-role count differs from its snapshot-role count; worker-role counts that do not sum to
    `--expect-events`; a mixed role; a timer's calibration missing; a drain with no call;
  - a read without its pair, or whose anchor is outside or missing.
`--cpus any`, `--mems any` and `--lock no` waive the pinning checks, for a run off the measurement
host.

Deliberately stdlib-only, so it runs as-is on any host a ledger comes from.
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
from collections import defaultdict

SCHEMA_VERSION = 2
# The defaults below belong to one measurement setup: reth block 23993050 at chunk size 2^23 with 12
# replay workers on an 8-card production run. DEFAULT_CHUNKS are its loaded chunks, DEFAULT_BAND
# the replay median of its stream arm and DEFAULT_ANCHORS the snapshot thread's per-chunk times
# for chunks 4-8, in ms. DEFAULT_CPUS and DEFAULT_MEMS are the measurement host's NUMA node 1.
# Another workload or host passes --chunks, --band, --anchor, --cpus and --mems.
DEFAULT_CPUS = "62-123"
DEFAULT_MEMS = "1"
DEFAULT_CHUNKS = "12-37"
DEFAULT_BAND = "584-673"
DEFAULT_ANCHORS = "4:212.9,5:146.6,6:115.0,7:89.3,8:73.3"
ANCHOR_TOLERANCE = 0.10
MIN_LOADED_CHUNKS = 20
HISTORY_TABLES = 16

EVENT_PATH = "precompile_event_path"
COMPUTE = "precompile_compute"
DRAIN = "drain_cpu_window"
EXTEND = "deferred_extend"
MEMORY_EXTEND = "deferred_memory_extend"
SPLIT = "split_last"
# Each timer's sum and the count of brackets it holds, as the ledger names them. The drain's
# bracket is one per precompile call; the words it went through are a count, never a bracket count.
DRAIN_FACTS = ("drain.cpu_window_us", "drain.calls")
DRAIN_WORDS = "drain.words"
EXTEND_FACTS = ("deferred.extend_us", "deferred.extends")
MEMORY_EXTEND_FACTS = ("deferred.memory_extend_us", "deferred.memory_extends")
SPLIT_PHASES = ("extract", "sort", "records", "memory", "wall")
RUN_FACTS = ("faults.minor", "faults.major", "pool.blocked_gets", "pool.blocked_us")


class Fail(Exception):
    """Input this script refuses to read."""


def is_int(x) -> bool:
    return isinstance(x, int) and not isinstance(x, bool)


def is_num(x) -> bool:
    return isinstance(x, (int, float)) and not isinstance(x, bool)


def ms(us) -> str:
    return "-" if us is None else f"{us / 1000:.3f}"


def median(vals):
    return statistics.median(vals) if vals else None


def mean(vals):
    return statistics.mean(vals) if vals else None


def parse_range(text: str) -> tuple[float, float]:
    lo, sep, hi = text.partition("-")
    if not sep:
        raise argparse.ArgumentTypeError(f"`{text}` is not a range: write LO-HI")
    return float(lo), float(hi)


def parse_anchors(text: str) -> dict:
    anchors = {}
    for entry in text.split(","):
        chunk, sep, value = entry.partition(":")
        if not sep:
            raise argparse.ArgumentTypeError(f"`{entry}` is not an anchor: write CHUNK:MS")
        anchors[int(chunk)] = float(value)
    return anchors


def parse_reps(text: str) -> set:
    return {rep for rep in text.split(",") if rep}


class Run:
    def __init__(self, rid: str):
        self.id = rid
        self.envelopes: list[dict] = []
        self.stages: list[dict] = []
        self.bench: dict | None = None

    @property
    def env(self) -> dict:
        complete = [e for e in self.envelopes if e.get("complete") is True]
        if complete:
            return complete[-1]
        return self.envelopes[-1] if self.envelopes else {}

    @property
    def label(self) -> str:
        env = self.env
        return env.get("label") or env.get("arm") or "-"

    @property
    def rep(self) -> str:
        rep = self.env.get("rep")
        return "-" if rep is None else str(rep)

    def lines(self, stage: str) -> list[dict]:
        return [s for s in self.stages if s["stage"] == stage]

    @property
    def sink(self):
        return next((s["facts"]["sink"] for s in self.lines("worker.replay")
                     if "sink" in s["facts"]), None)

    @property
    def timers_on(self) -> bool:
        return (self.env.get("knobs") or {}).get("MLE_LEDGER_PRECOMPILE_TIMERS") == "1"

    def per_chunk(self, stage: str) -> dict:
        """`dur_us` summed per CPU chunk: a split chunk's segments together."""
        out: dict = defaultdict(int)
        for s in self.lines(stage):
            if is_int(s["chunk"]):
                out[s["chunk"]] += s["dur"]
        return out

    def summed(self, name: str) -> float:
        return sum(s["facts"][name] for s in self.stages if is_num(s["facts"].get(name)))

    def calibration(self, timer: str, which: str):
        value = (self.env.get("timer_calibration") or {}).get(f"timer.{timer}.{which}_pair_ns")
        return value if is_num(value) else None


def load_ledgers(paths: list[str]) -> dict:
    runs: dict = {}
    for path in paths:
        try:
            with open(path, encoding="utf-8") as fh:
                for n, raw in enumerate(fh, start=1):
                    if raw.strip():
                        take_line(raw, f"{path}:{n}", runs)
        except OSError as exc:
            raise Fail(f"{path}: {exc.strerror or exc}")
        except UnicodeDecodeError as exc:
            raise Fail(f"{path}: not UTF-8 ({exc.reason})")
    if not runs:
        raise Fail("no ledger line to read")
    return runs


def take_line(raw: str, where: str, runs: dict) -> None:
    try:
        obj = json.loads(raw)
    except json.JSONDecodeError:
        print(f"warning: {where}: not JSON; skipped as a killed run's torn last line",
              file=sys.stderr)
        return
    if not isinstance(obj, dict) or not is_int(obj.get("v")) or obj["v"] != SCHEMA_VERSION:
        raise Fail(f"{where}: not a v{SCHEMA_VERSION} ledger line")
    rid = obj["run"] if isinstance(obj.get("run"), str) else "-"
    run = runs.setdefault(rid, Run(rid))
    kind = obj.get("kind")
    if kind == "envelope":
        run.envelopes.append(obj)
        return
    if kind is not None:
        raise Fail(f"{where}: unknown line kind {kind!r}")
    if obj.get("skipped") is True:
        return
    lane = obj.get("lane")
    if not isinstance(obj.get("stage"), str) or not isinstance(lane, dict):
        raise Fail(f"{where}: a stage line without a stage name or a lane")
    if not is_int(obj.get("dur_us")):
        raise Fail(f"{where}: {obj['stage']} is not marked skipped but has no integer dur_us")
    chunk = obj.get("chunk")
    if chunk is not None and not is_int(chunk):
        raise Fail(f"{where}: {obj['stage']}: chunk must be an integer or null")
    facts = obj.get("facts")
    run.stages.append({
        "stage": obj["stage"],
        "lane": lane.get("role"),
        "chunk": chunk,
        "dur": obj["dur_us"],
        "facts": facts if isinstance(facts, dict) else {},
    })


def load_bench(paths: list[str]) -> dict:
    """`(label, rep) -> fields` for each `AOT_BENCH` line of every file."""
    lines: dict = {}
    for path in paths:
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                for n, raw in enumerate(fh, start=1):
                    tok = raw.split()
                    if not tok or tok[0] != "AOT_BENCH":
                        continue
                    fields = dict(t.split("=", 1) for t in tok[1:] if "=" in t)
                    key = (fields.get("label", fields.get("arm")), fields.get("rep"))
                    if key in lines:
                        raise Fail(f"{path}:{n}: a second AOT_BENCH line for label {key[0]} rep "
                                   f"{key[1]}")
                    lines[key] = fields
        except OSError as exc:
            raise Fail(f"{path}: {exc.strerror or exc}")
    return lines


def bench_int(bench: dict | None, key: str):
    value = (bench or {}).get(key)
    return int(value) if value is not None and value.isdigit() else None


# ---------------------------------------------------------------------------------------------
# The replay


def loaded(run: Run, chunks: tuple[float, float]) -> list[int]:
    lo, hi = chunks
    return [dur for chunk, dur in sorted(run.per_chunk("worker.replay").items())
            if lo <= chunk <= hi]


def replay_lines(groups: dict, args) -> tuple[list[str], dict]:
    out, pooled = [], {}
    for label, runs in groups.items():
        per_run = [(run, loaded(run, args.chunks)) for run in runs]
        medians = [median(vals) for _, vals in per_run if vals]
        pooled[label] = median([v for _, vals in per_run for v in vals])
        few = [run.rep for run, vals in per_run if len(vals) < MIN_LOADED_CHUNKS]
        out.append(
            f"REPLAY label={label} runs={len(runs)} "
            f"chunks_per_run={','.join(str(len(vals)) for _, vals in per_run)} "
            f"run_medians_ms={','.join(ms(m) for m in medians) or '-'} "
            f"median_of_medians_ms={ms(median(medians))} pooled_median_ms={ms(pooled[label])}"
            + (f" FEWER_THAN_{MIN_LOADED_CHUNKS}_LOADED_CHUNKS(reps={','.join(few)})"
               if few else ""))
    return out, pooled


def band_lines(groups: dict, args) -> list[str]:
    lo, hi = args.band
    out = []
    for label, runs in groups.items():
        if not all(run.sink == "legacy" and run.env.get("worker_kind") == "interpreter"
                   and (run.bench or {}).get("storage") == "pooled" for run in runs):
            continue
        medians = [median(vals) for vals in (loaded(run, args.chunks) for run in runs) if vals]
        mid = median(medians)
        where = "-" if mid is None else ("inside" if lo <= mid / 1000 <= hi else "outside")
        out.append(f"BAND label={label} n={len(medians)} median_of_medians_ms={ms(mid)} "
                   f"band_ms={lo:g}-{hi:g} {where}")
    return out


def no_growth(run: Run) -> bool:
    """Every history table of the run read 0 growths on its bench line."""
    entries = (run.bench or {}).get("realloc", "-").split(",")
    tables = [entry.partition(":") for entry in entries[:HISTORY_TABLES]]
    return len(tables) == HISTORY_TABLES and all(count == "0" for _, _, count in tables)


def shrink_lines(groups: dict, pooled: dict, args) -> list[str]:
    by_arm: dict = defaultdict(dict)
    for label, runs in groups.items():
        sinks = {run.sink for run in runs}
        if len(sinks) == 1:
            by_arm[runs[0].env.get("arm")][sinks.pop()] = label
    out = []
    for arm, labels in sorted(by_arm.items(), key=lambda kv: str(kv[0])):
        if "legacy" not in labels or "history" not in labels:
            continue
        streams, history = labels["legacy"], labels["history"]
        a, b = pooled[streams], pooled[history]
        ratio = "-" if not a or b is None else f"{b / a:.4f}"
        delta = None if a is None or b is None else b - a
        by_rep = {label: {run.rep: median(loaded(run, args.chunks)) for run in groups[label]}
                  for label in (streams, history)}
        pairs = [(rep, by_rep[history][rep] - by_rep[streams][rep])
                 for rep in sorted(by_rep[streams], key=rep_key)
                 if rep in by_rep[history] and None not in (by_rep[history][rep],
                                                            by_rep[streams][rep])]
        diffs = [d for _, d in pairs]
        span = f"{ms(min(diffs))}..{ms(max(diffs))}" if diffs else "-"
        regime = "reserved" if all(no_growth(run) for run in groups[history]) else "growth"
        out.append(f"SHRINK arm={arm} streams={streams} history={history} streams_ms={ms(a)} "
                   f"history_ms={ms(b)} delta_ms={ms(delta)} ratio={ratio} "
                   f"pair_deltas_ms={','.join(f'{rep}:{ms(d)}' for rep, d in pairs) or '-'} "
                   f"pair_range_ms={span} regime={regime}")
    return out


def rep_key(rep: str):
    return (0, int(rep)) if rep.isdigit() else (1, rep)


def fault_lines(groups: dict) -> list[str]:
    out = []
    for label, runs in groups.items():
        for run in runs:
            facts = " ".join(f"{name}={run.summed(name):g}" for name in RUN_FACTS
                             if any(name in s["facts"] for s in run.stages))
            bench = run.bench or {}
            out.append(f"FAULTS label={label} rep={run.rep} "
                       f"minor_faults={bench.get('minor_faults', '-')} "
                       f"major_faults={bench.get('major_faults', '-')}"
                       + (f" {facts}" if facts else ""))
    return out


# ---------------------------------------------------------------------------------------------
# The snapshot thread's anchor


def snapshot_own(run: Run) -> dict:
    """Per chunk, the snapshot thread's time less the precompile timers' enclosed cost."""
    own = dict(run.per_chunk("snapshot.emulate"))
    enclosed = (run.calibration(COMPUTE, "enclosed") or 0) / 1000
    for s in run.lines("snapshot.emulate"):
        if is_int(s["chunk"]) and s["facts"].get("role") == "snapshot":
            count = sum(v for k, v in s["facts"].items()
                        if k.startswith("precompile.") and k.endswith(".count") and is_num(v))
            own[s["chunk"]] -= count * enclosed
    return own


def within(value_us, anchor_ms: float) -> bool:
    return abs(value_us / 1000 - anchor_ms) <= ANCHOR_TOLERANCE * anchor_ms


def anchor_lines(groups: dict, args) -> list[str]:
    out = []
    for label, runs in groups.items():
        runs = [run for run in runs if run.env.get("snapshot_main") == "aot"]
        if not runs:
            continue
        owns = [snapshot_own(run) for run in runs]
        waits = [run.per_chunk("snapshot.pool_wait") for run in runs]
        for chunk, anchor in sorted(args.anchors.items()):
            vals = [own[chunk] for own in owns if chunk in own]
            mid = median(vals)
            where = "missing" if mid is None else ("within" if within(mid, anchor) else "outside")
            wait = median([w.get(chunk, 0) for w in waits])
            out.append(f"ANCHOR label={label} chunk={chunk} n={len(vals)} snapshot_ms={ms(mid)} "
                       f"pool_wait_ms={ms(wait)} anchor_ms={anchor:g} {where}")
    return out


def read_anchor(runs: list, anchors: dict) -> str:
    owns = [snapshot_own(run) for run in runs]
    verdict = "within"
    for chunk, anchor in anchors.items():
        vals = [own[chunk] for own in owns if chunk in own]
        if len(vals) != len(runs):
            return "missing"
        if not within(mean(vals), anchor):
            verdict = "outside"
    return verdict


# ---------------------------------------------------------------------------------------------
# The capture


def role_sums(run: Run) -> tuple[dict, list[str]]:
    """The precompile and drain facts summed per role, and the lines whose role was mixed."""
    sums: dict = defaultdict(lambda: defaultdict(float))
    mixed = []
    for s in run.stages:
        role = s["facts"].get("role")
        if role is None:
            continue
        if role not in ("snapshot", "worker"):
            mixed.append(f"{s['stage']}@{s['chunk']}")
            continue
        for name, value in s["facts"].items():
            if is_num(value) and name.startswith(("precompile.", "drain.")):
                sums[role][name] += value
    return sums, mixed


def kinds(sums: dict) -> list[str]:
    found = set()
    for facts in sums.values():
        for name in facts:
            parts = name.split(".")
            if len(parts) == 3 and parts[0] == "precompile" and parts[2] == "count":
                found.add(parts[1])
    return sorted(found)


def capture(run: Run, expect_events: int) -> tuple[list[str], dict, list[str]]:
    """The run's CAPTURE lines, its quantities in microseconds, and why it is vacuous if it is."""
    sums, mixed = role_sums(run)
    worker, snapshot = sums.get("worker", {}), sums.get("snapshot", {})
    vacuous = [f"role mixed on {', '.join(mixed[:3])}"] if mixed else []
    if run.sink != "legacy":
        vacuous.append(f"the pricing arm writes sink={run.sink}, not the event streams")
    drain_sum, drain_count = DRAIN_FACTS
    brackets = worker.get(drain_count, 0)
    words = worker.get(DRAIN_WORDS, 0)
    needed = [EVENT_PATH, COMPUTE] + ([DRAIN] if drain_sum in worker else [])
    missing = [t for t in needed if run.calibration(t, "empty") is None]
    if missing:
        vacuous.append(f"no calibration for timer(s) {','.join(missing)}")
    e_path = (run.calibration(EVENT_PATH, "empty") or 0) / 1000
    e_compute = (run.calibration(COMPUTE, "empty") or 0) / 1000
    e_drain = (run.calibration(DRAIN, "empty") or 0) / 1000
    enc_drain = (run.calibration(DRAIN, "enclosed") or 0) / 1000
    out = []
    x = 0.0
    n_worker = 0
    found = kinds(sums)
    if not found:
        vacuous.append("no precompile kind counted")
    for kind in found:
        nw = int(worker.get(f"precompile.{kind}.count", 0))
        ns = int(snapshot.get(f"precompile.{kind}.count", 0))
        path = worker.get(f"precompile.{kind}.event_path_us", 0.0) - nw * e_path
        compute = snapshot.get(f"precompile.{kind}.compute_us", 0.0) - ns * e_compute
        n_worker += nw
        x += path - compute
        out.append(f"CAPTURE run={run.id} rep={run.rep} kind={kind} count_worker={nw} "
                   f"count_snapshot={ns} event_path_ms={ms(path)} compute_ms={ms(compute)} "
                   f"increment_ms={ms(path - compute)}")
        if nw != ns:
            vacuous.append(f"kind {kind} counted {nw} in the worker role and {ns} in the "
                           f"snapshot role")
    if n_worker != expect_events:
        vacuous.append(f"the worker role counted {n_worker} precompile events, not "
                       f"{expect_events}")
    drain = worker.get(drain_sum, 0.0) - brackets * e_drain
    # The drain's own clock reads sit inside the event-path bracket that holds it.
    x -= brackets * enc_drain + drain
    if n_worker and not brackets:
        vacuous.append(f"the drain counted no call ({drain_count})")
    extend_sum, extend_count = EXTEND_FACTS
    assembly = (run.summed(extend_sum)
                - run.summed(extend_count) * (run.calibration(EXTEND, "empty") or 0) / 1000)
    memory_sum, memory_count = MEMORY_EXTEND_FACTS
    memory_extend = None
    if any(memory_sum in s["facts"] for s in run.stages):
        memory_extend = (run.summed(memory_sum) - run.summed(memory_count)
                         * (run.calibration(MEMORY_EXTEND, "empty") or 0) / 1000)
    splits = run.summed("split.last.splits")
    split_cal = splits * (run.calibration(SPLIT, "empty") or 0) / 1000
    split = []
    for phase in SPLIT_PHASES:
        name = f"split.last.{phase}_us"
        present = any(name in s["facts"] for s in run.stages)
        split.append(f"{phase}:{ms(run.summed(name) - split_cal) if present else '-'}")
    out.append(f"CAPTURE run={run.id} rep={run.rep} drain_ms={ms(drain)} "
               f"drain_brackets={int(brackets)} drain_words={int(words)} "
               f"drain_timer_in_event_path_ms={ms(brackets * enc_drain)} "
               f"events_worker={n_worker} expected={expect_events}")
    out.append(f"CAPTURE run={run.id} rep={run.rep} X_ms={ms(x)} assembly_ms={ms(assembly)} "
               f"deferred_extends={int(run.summed(extend_count))} "
               f"memory_extend_ms={ms(memory_extend)} "
               f"memory_extends={int(run.summed(memory_count))} split_last_ms={','.join(split)} "
               f"splits={int(splits)}")
    return out, {"x": x, "assembly": assembly}, vacuous


def read_lines(label: str, runs: list, quantities: dict, rows_us, anchors: dict
               ) -> tuple[list[str], list[str]]:
    """A pricing label's reads, one per pair of counted reps, and why any is vacuous."""
    runs = sorted(runs, key=lambda run: rep_key(run.rep))
    out, vacuous, reads = [], [], []
    for i in range(0, len(runs), 2):
        pair = runs[i:i + 2]
        reps = ",".join(run.rep for run in pair)
        if len(pair) < 2:
            vacuous.append(f"VACUOUS label={label} read reps={reps}: a read without its pair")
            continue
        x = mean([quantities[run.id]["x"] for run in pair])
        assembly = mean([quantities[run.id]["assembly"] for run in pair])
        anchor = read_anchor(pair, anchors)
        total = None if rows_us is None else x + rows_us + assembly
        n = len(reads) + 1
        reads.append((n, x, total))
        out.append(f"READ label={label} read={n} reps={reps} X_ms={ms(x)} rows_ms={ms(rows_us)} "
                   f"assembly_ms={ms(assembly)} X_plus_rows_plus_assembly_ms={ms(total)} "
                   f"anchor={anchor}")
        if anchor != "within":
            vacuous.append(f"VACUOUS label={label} read={n} reps={reps}: anchor {anchor}")
    if reads:
        best = min(reads, key=lambda r: r[1])
        totals = [r for r in reads if r[2] is not None]
        worst = max(totals, key=lambda r: r[2]) if totals else None
        out.append(f"READS label={label} reads={len(reads)} "
                   f"worst_X_plus_rows_plus_assembly_ms={ms(worst[2]) if worst else '-'} "
                   f"worst_read={worst[0] if worst else '-'} best_X_ms={ms(best[1])} "
                   f"best_read={best[0]}")
    return out, vacuous


# ---------------------------------------------------------------------------------------------
# Vacuity


def bound(policy, node: str) -> bool:
    return isinstance(policy, dict) and bool(policy) and set(policy) == {f"bind:{node}"}


def workload(run: Run) -> tuple:
    env = run.env
    cycles = sum(s["facts"]["cycles_delta"] for s in run.lines("snapshot.emulate")
                 if is_int(s["facts"].get("cycles_delta")))
    return (len(run.per_chunk("worker.replay")), cycles or None,
            (env.get("elf") or {}).get("sha256"), (env.get("input") or {}).get("sha256"))


def workload_vacuity(runs: list, args) -> list[str]:
    out = []
    if not runs:
        return out
    first = workload(runs[0])
    names = ("chunks", "cycles", "elf_sha256", "input_sha256")
    for run in runs:
        seen = workload(run)
        for name, value, base in zip(names, seen, first):
            if value != base:
                out.append(f"VACUOUS run={run.id} label={run.label} {name}={value}, but "
                           f"{runs[0].label} rep {runs[0].rep} has {base}")
        for name, want, value in (("chunks", args.expect_chunks, seen[0]),
                                  ("cycles", args.expect_cycles, seen[1])):
            if want is not None and value != want:
                out.append(f"VACUOUS run={run.id} label={run.label} {name}={value}, not {want}")
    return out


def vacuity(run: Run, args) -> list[str]:
    env, bench = run.env, run.bench
    arm = env.get("arm") or ""
    out = []
    if "pooled" in arm:
        if bench is None:
            out.append("no AOT_BENCH line joins this run")
        else:
            for key, want in (("alloc", "tcmalloc"), ("mem", "mmap"), ("bigint", "rug"),
                              ("storage", "pooled")):
                if bench.get(key) != want:
                    out.append(f"{key}={bench.get(key)}")
    if env.get("snapshot_main") == "aot":
        if bench is not None and bench_int(bench, "aot_dispatches") in (0, None):
            out.append(f"aot_dispatches={bench.get('aot_dispatches')}")
        idle = [s["chunk"] for s in run.lines("snapshot.emulate")
                if not (is_int(s["facts"].get("dispatches_delta"))
                        and s["facts"]["dispatches_delta"] > 0)]
        if idle:
            out.append(f"the snapshot thread entered no compiled block in chunk(s) {idle[:5]}")
    replays = [s for s in run.lines("worker.replay") if is_int(s["chunk"])]
    if env.get("worker_kind") == "aot":
        idle = [s["chunk"] for s in replays
                if not (is_int(s["facts"].get("dispatches")) and s["facts"]["dispatches"] > 0)]
        if idle:
            out.append(f"the AOT replay workers entered no compiled block in chunk(s) {idle[:5]}")
    for sink, fact in (("history", "history_bytes"), ("legacy", "record_bytes")):
        if run.sink == sink:
            empty = [s["chunk"] for s in replays if not s["facts"].get(fact)]
            if empty:
                out.append(f"no {fact} in chunk(s) {empty[:5]}")
    if args.cpus != "any" and env.get("cpus_allowed_list") != args.cpus:
        out.append(f"cpus_allowed_list={env.get('cpus_allowed_list')}")
    if args.mems != "any" and not bound(env.get("mempolicy"), args.mems):
        policy = json.dumps(env.get("mempolicy"))
        out.append(f"memory not bound to node {args.mems} (mempolicy={policy})")
    if args.lock == "yes":
        if env.get("lock_held") is not True:
            out.append(f"the envelope's lock_held={json.dumps(env.get('lock_held'))}")
        if (bench or {}).get("lock_held") != "true":
            out.append(f"the lock file was not read held before and after the run "
                       f"(lock_held={(bench or {}).get('lock_held')}, "
                       f"before={(bench or {}).get('lock_before')}, "
                       f"after={(bench or {}).get('lock_after')})")
    return out


# ---------------------------------------------------------------------------------------------


def parse_args(argv):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("ledgers", nargs="+", help="MLE_LEDGER files")
    ap.add_argument("--bench", action="append", default=[],
                    help="an aot_bench.sh results.txt for the same runs; repeatable")
    ap.add_argument("--chunks", type=parse_range, default=parse_range(DEFAULT_CHUNKS),
                    help=f"the loaded chunks, inclusive [default {DEFAULT_CHUNKS}]")
    ap.add_argument("--band", type=parse_range, default=parse_range(DEFAULT_BAND),
                    help=f"the stream arm's band, ms [default {DEFAULT_BAND}]")
    ap.add_argument("--anchor", dest="anchors", type=parse_anchors,
                    default=parse_anchors(DEFAULT_ANCHORS),
                    help=f"the snapshot thread's per-chunk anchors, ms [default {DEFAULT_ANCHORS}]")
    ap.add_argument("--rows-ms", type=float,
                    help="the retained ECALL rows' write time, when no retained-rows line gives it")
    ap.add_argument("--expect-events", type=int,
                    help="the block's precompile events; required with the precompile timers on")
    ap.add_argument("--expect-chunks", type=int, help="the workload's CPU chunks")
    ap.add_argument("--expect-cycles", type=int, help="the workload's cycles")
    ap.add_argument("--discard-reps", type=parse_reps, default=set(),
                    help="reps no reading counts, comma-separated (the ledgers' runs)")
    ap.add_argument("--cpus", default=DEFAULT_CPUS, help="required cpus_allowed_list, or any")
    ap.add_argument("--mems", default=DEFAULT_MEMS, help="required memory node, or any")
    ap.add_argument("--lock", choices=("yes", "no"), default="yes",
                    help="require the lock file proven held")
    return ap.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        runs = load_ledgers(args.ledgers)
        bench = load_bench(args.bench)
    except Fail as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    for run in runs.values():
        run.bench = bench.get((run.label, run.rep))

    rows_us = None if args.rows_ms is None else args.rows_ms * 1000
    if rows_us is None:
        writes = [float(f["retained_rows_us"]) for f in bench.values()
                  if f.get("arm") == "retained-rows" and f.get("retained_rows_us", "-") != "-"]
        rows_us = max(writes) if writes else None

    groups: dict = defaultdict(list)
    counted = []
    for run in sorted(runs.values(), key=lambda r: (r.label, rep_key(r.rep), r.id)):
        skip = run.env.get("warmup") is True or run.rep in args.discard_reps
        print(f"RUN run={run.id} label={run.label} rep={run.rep} counted={str(not skip).lower()} "
              f"sink={run.sink} worker_kind={run.env.get('worker_kind')} "
              f"chunks={len(run.per_chunk('worker.replay'))} "
              f"loaded_median_ms={ms(median(loaded(run, args.chunks)))}")
        if not skip:
            groups[run.label].append(run)
            counted.append(run)
    if any(run.timers_on for run in counted) and args.expect_events is None:
        print("error: a counted run has the precompile timers on: give --expect-events",
              file=sys.stderr)
        return 2

    vacuous = workload_vacuity(counted, args)
    for run in counted:
        vacuous += [f"VACUOUS run={run.id} label={run.label} {why}" for why in vacuity(run, args)]
    lines, pooled = replay_lines(groups, args)
    lines += band_lines(groups, args) + shrink_lines(groups, pooled, args) + fault_lines(groups)
    lines += anchor_lines(groups, args)
    for label, label_runs in groups.items():
        priced = [run for run in label_runs if run.timers_on]
        if not priced:
            continue
        quantities = {}
        for run in priced:
            captured, quantities[run.id], why = capture(run, args.expect_events)
            lines += captured
            vacuous += [f"VACUOUS run={run.id} label={run.label} {w}" for w in why]
        read, why = read_lines(label, priced, quantities, rows_us, args.anchors)
        lines += read
        vacuous += why
    for line in lines + vacuous:
        print(line)
    return 1 if vacuous else 0


if __name__ == "__main__":
    sys.exit(main())
