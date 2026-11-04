#!/usr/bin/env python3
"""Summarise the prover's stage ledger: one verdict per run, a bracket check per lane, medians per stage.

The input is what `MLE_LEDGER=<path>` writes: JSON Lines, every line carrying `"v": 2`. Only a build
with `pico-vm`'s `stage-ledger` feature writes one (`perf/aot/aot_bench.sh` builds with it; any other
build prints a warning at the pipeline's start and writes nothing). A file may
hold several runs and several files may be given; lines join on `run`. Three kinds of line:

  * an envelope (`"kind": "envelope"`). One is written when the run opens (`"complete": false`) and
    a second when the driver finishes (`"complete": true`); the complete one wins. It names the arm,
    the launcher's `label`, `rep` and `warmup`, the build, the knobs, the host and its pinning, and
    once complete the peak RSS, the setup brackets (`setup_us`), the phase walls (`stage_walls_us`,
    which start where the emulator's setup ends) and the memory policy (`mempolicy`). A run that
    overlapped another in its process carries `"overlapped": true`.
  * a stage, with no `kind`: `run`, `arm`, `chunk`, `batch`, `seg`, `record`, `stage`, `lane`
    {`role`, `idx`}, `t0_us`, `t1_us`, `dur_us` and `facts`. Times are microseconds from the run's
    origin. `chunk` is a CPU chunk's index on either side of the run; `record` is a record's index
    in proving order, on the prove side only. A deferred record has a `record` and no `chunk`, and so
    does a bundle verify line, which is read as the chunk its record's prove line names. The roles
    are `snapshot`, `emulate`, `sequencer`, `prove` (one lane per prove slot), `verify` (the bundle
    verify after the prove jobs) and `driver`; `prove.verify` may sit on either `prove` or `verify`.
    A prove stage's `nested_us` fact is the part of its interval its thread spent on another
    record's whole prove job, and the per-stage figures below (the LEDGER medians, STAGE, DEFERRED
    and CHUNK0) are the stage's own time: `dur_us` less `nested_us`. Smaller tasks of another
    record's prove that the thread stole stay in it, so above PROVE_CONCURRENCY=1 a prove stage's own
    time is an upper bound. The walls and the lane check read the intervals as written.
  * a skipped stage: a stage line with `"skipped": true` and no times or facts, written when the arm
    lacks the stage by design. Skipped stages are counted, never read as zero-length ones.

A line that is not JSON is the torn end of a killed run: it is skipped with a warning, and the run
it belonged to has no complete envelope.

A ledger `X.jsonl` with a span recording `X.spans.csv` beside it (what `MLE_SPANS=<path>` writes:
`lane,index,state,work,item,start_us,end_us`, on the same origin) has its spans joined to the one
run it holds. The spans add what the stages cannot say: when a lane was idle or waiting.

`--bench <results.txt>` adds a second input: the `AOT_BENCH` lines the bench driver writes, one per
arm and repeat, grouped by `label=` when the line has one and otherwise by arm (`<arm>+ledger` when
that run wrote a ledger), for an A/B on `wall_s`.

Three summaries come out, in this order:

  (a) one LEDGER line per run: the emulate and riscv walls, the per-CPU-chunk replay and prove
      medians, the snapshot thread's busy fraction, peak RSS, setup, the anti-vacuity count and
      whether the run was pinned to the required CPUs and memory node and held the host lock. A run
      that was not, or whose envelope is missing, provisional or overlapped, carries `NOT A RESULT
      (<field>=<value>)` per failed check and enters no GROUP or VERDICT; a warm-up run enters none
      either. Runs group by label. A run with spans adds a BOUND line: which side of the emulation
      was saturated. With `--control`, a GROUP line per group and a VERDICT line per other group.
  (b) per lane, how much of the lane's lifetime its named stages and its idle and wait spans cover. A
      lane under the threshold names its largest unbracketed interval and what lies either side of
      it, so the missing bracket is found by reading the line rather than the code.
  (c) per stage, the median, min, max and spread over CPU chunks >= 1. Chunk 0 is printed apart: it
      pays first touch (page faults, pool fill, a keygen on a cache miss), and folding it in moves
      every median it touches. A prove stage's deferred records are summarised on DEFERRED lines,
      and its nested time on NESTED lines.

Exit status: 0 clean; 2 bad input (a malformed stage, another schema version, nothing to read); 3 an
AOT run with a chunk that entered no compiled block, which measured the interpreter under an AOT
label; 4 a lane under the coverage threshold. 3 wins over 4, and either is returned only after
everything has been printed.

Deliberately stdlib-only, so it runs as-is on any host a ledger comes from.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import statistics
import sys
from collections import Counter, defaultdict

SCHEMA_VERSION = 2

# A timing is a result only when the whole driver ran pinned to one NUMA node of the measurement
# host, its CPUs and its memory, with the host's lock held. Anything else ran beside an unknown
# neighbour, or across a node boundary the arms do not share. The defaults are the measurement
# host's second node.
DEFAULT_CPUS = "62-123"
DEFAULT_MEMS = "1"

ROLE_ORDER = ("snapshot", "emulate", "sequencer", "prove", "verify", "driver")
EMULATE_ROLES = ("snapshot", "emulate", "sequencer")
# `verify` is the bundle verify after every prove job, on the caller's thread. It belongs to the
# riscv wall, but it is one thread doing one thing, so its lane check is a single window.
PROVE_ROLES = ("prove",)
RISCV_ROLES = ("prove", "verify")

SPAN_COLUMNS = ("lane", "index", "state", "work", "item", "start_us", "end_us")
SPAN_STATES = ("busy", "idle", "wait")

# The bench line's pinning evidence. A line with none of these keys predates them. The flags come
# spelled either way: y/n and true/false, or the driver's yes/no and the launcher's 1/0.
BENCH_EVIDENCE = ("label", "prefix", "cpus_allowed_list", "mems_allowed_list", "mempolicy",
                  "ledger_set", "lock_held")
BENCH_YES = ("y", "yes", "true", "1")

# The stage vocabulary in pipeline order, which is also the print order. An entry ending in "." is a
# family whose members carry a chip name after the dot. The last block is reserved: named before
# anything measures it, so that a new timer cannot land between two existing ones unnoticed.
STAGE_ORDER = (
    "snapshot.setup",
    "snapshot.emulate",
    "snapshot.pool_wait",
    "snapshot.send",
    "snapshot.finish",
    "worker.recover",
    "worker.replay",
    "worker.fold",
    "worker.drop",
    "sequencer.wait",
    "sequencer.finalize",
    "prove.augment.clone",
    "prove.augment.",
    "prove.shape",
    "prove.tracegen.",
    "prove.build_ctx_gpu",
    "prove.prove",
    "prove.verify",
    "prove.drop_record",
    "gpu.tracegen",
    "history.",
)
STAGE_RANK = {name: i for i, name in enumerate(STAGE_ORDER)}
STAGE_FAMILIES = tuple(name for name in STAGE_ORDER if name.endswith("."))

LEDGER_METRICS = (
    "emulate_wall_us",
    "riscv_wall_us",
    "median_replay_us",
    "median_prove_us",
    "snapshot_busy_frac",
    "peak_rss_kib",
    "setup_us",
)


class Fail(Exception):
    """Input the script refuses to summarise. Raised before anything is printed."""


class Torn(Exception):
    """A line that is not JSON: the end of a run killed mid-write."""


_warned: set = set()


def warn_once(key, msg: str) -> None:
    if key not in _warned:
        _warned.add(key)
        print(f"warning: {msg}", file=sys.stderr)


def is_int(x) -> bool:
    # `bool` is a subclass of `int`, and `True == 1`: without this a `"v": true` would read as v1.
    return isinstance(x, int) and not isinstance(x, bool)


def dig(obj, *keys):
    for key in keys:
        if not isinstance(obj, dict):
            return None
        obj = obj.get(key)
    return obj


def fmt(x, dp: int | None = None) -> str:
    if x is None:
        return "-"
    if dp is not None:
        return f"{x:.{dp}f}"
    if isinstance(x, bool):
        return "true" if x else "false"
    if isinstance(x, float):
        # A median of an even count lands on a half; print what it is rather than round it away.
        return str(int(x)) if x.is_integer() else f"{x:.6f}".rstrip("0").rstrip(".")
    return str(x)


def spread(vals: list) -> float | None:
    med = statistics.median(vals)
    return None if med == 0 else (max(vals) - min(vals)) / med


def stage_rank(name: str) -> int:
    if name in STAGE_RANK and not name.endswith("."):
        return STAGE_RANK[name]
    for family in STAGE_FAMILIES:
        if name.startswith(family) and len(name) > len(family):
            return STAGE_RANK[family]
    return len(STAGE_ORDER)


def stage_key(name: str) -> tuple:
    return (stage_rank(name), name)


def lane_key(lane: tuple) -> tuple:
    role, idx = lane
    return (ROLE_ORDER.index(role) if role in ROLE_ORDER else len(ROLE_ORDER), role, idx)


class Required:
    """What a run must show to be a result. `None` for a check the command line waived."""

    def __init__(self, cpus: str, mems: str, lock: str, exempt: list[str]):
        self.cpus = None if cpus == "any" else cpus
        self.mems = None if mems == "any" else mems
        self.lock = lock == "yes"
        self.exempt = set(exempt)


def bound_by_policy(policy, node: str) -> bool:
    # `numactl --membind` sets a memory policy, which the cpuset's `Mems_allowed_list` never shows: a
    # bound run reads `0-1` there. Every mapping under the one bind policy is what shows it.
    return isinstance(policy, dict) and set(policy) == {f"bind:{node}"}


def pin_failures(req: Required, cpus, mems, policy, lock_ok: bool, lock_shown) -> list[str]:
    """One `<field>=<value>` per failed check, in a fixed order."""
    out = []
    if req.cpus is not None and cpus != req.cpus:
        out.append(f"cpus_allowed_list={fmt(cpus)}")
    if req.mems is not None and mems != req.mems and not bound_by_policy(policy, req.mems):
        out.append(f"mems_allowed_list={fmt(mems)}")
    if req.lock and not lock_ok:
        out.append(f"lock_held={fmt(lock_shown)}")
    return out


def not_a_result(failures: list[str]) -> str:
    return "".join(f" NOT A RESULT ({f})" for f in failures)


def parse_mempolicy(text: str | None) -> dict | None:
    """`bind:1:450,default:3` -> {"bind:1": 450, "default": 3}; the count follows the last colon."""
    if not text or text == "-":
        return None
    policy = {}
    for entry in text.split(","):
        key, _, count = entry.rpartition(":")
        policy[key or entry] = int(count) if key and count.isdigit() else None
    return policy


class Run:
    def __init__(self, rid: str):
        self.id = rid
        self.envelopes: list[dict] = []
        self.stages: list[dict] = []
        self.skipped: Counter = Counter()
        self.stage_arm: str | None = None
        self.spans: list[dict] | None = None

    def envelope(self) -> dict | None:
        complete = [env for env in self.envelopes if env.get("complete") is True]
        if complete:
            return complete[-1]
        return self.envelopes[-1] if self.envelopes else None


def take_ledger_line(raw: str, where: str, runs: dict) -> str:
    try:
        obj = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise Torn(f"{where}: not JSON ({exc.msg}, column {exc.colno}); skipped as a killed run's "
                   f"torn last line")
    if not isinstance(obj, dict):
        raise Fail(f"{where}: expected a JSON object, got {type(obj).__name__}")
    v = obj.get("v")
    if not is_int(v) or v != SCHEMA_VERSION:
        raise Fail(f"{where}: schema version v={json.dumps(v)}; this script reads v={SCHEMA_VERSION} "
                   f"only")

    rid = obj["run"] if isinstance(obj.get("run"), str) else "-"
    if rid not in runs:
        runs[rid] = Run(rid)
    run = runs[rid]

    kind = obj.get("kind")
    if kind == "envelope":
        run.envelopes.append(obj)
        return rid
    if kind is not None:
        raise Fail(f"{where}: unknown line kind {kind!r}")

    name, lane = obj.get("stage"), obj.get("lane")
    if not isinstance(name, str) or not name:
        raise Fail(f"{where}: a stage line without a stage name")
    if not isinstance(lane, dict) or not isinstance(lane.get("role"), str) or not is_int(lane.get("idx")):
        raise Fail(f"{where}: {name}: lane must be {{\"role\": <str>, \"idx\": <int>}}")
    if run.stage_arm is None and isinstance(obj.get("arm"), str):
        run.stage_arm = obj["arm"]
    if stage_rank(name) == len(STAGE_ORDER):
        warn_once(("stage", name), f"{where}: unknown stage name {name!r}; summarised as given")
    if obj.get("skipped") is True:
        run.skipped[name] += 1
        return rid

    role = lane["role"]
    if role not in ROLE_ORDER:
        warn_once(("role", role), f"{where}: unknown lane role {role!r}; checked as a single-window "
                                  f"lane")
    t0, t1, dur = obj.get("t0_us"), obj.get("t1_us"), obj.get("dur_us")
    if not (is_int(t0) and is_int(t1) and is_int(dur)):
        raise Fail(f"{where}: {name} is not marked skipped but lacks an integer t0_us, t1_us or dur_us")
    if t1 < t0:
        raise Fail(f"{where}: {name} ends before it starts (t0_us={t0} > t1_us={t1})")
    # Durations are read from dur_us and intervals from t0/t1; a writer whose two disagree beyond
    # rounding would make the stage table and the lane check describe different runs.
    if abs(dur - (t1 - t0)) > 1:
        warn_once(("dur", rid), f"{where}: {name}: dur_us={dur} but t1_us - t0_us = {t1 - t0}")
    chunk, record = obj.get("chunk"), obj.get("record")
    if chunk is not None and not is_int(chunk):
        raise Fail(f"{where}: {name}: chunk must be an integer or null")
    if record is not None and not is_int(record):
        raise Fail(f"{where}: {name}: record must be an integer or null")
    facts = obj.get("facts")
    facts = facts if isinstance(facts, dict) else {}
    nested = facts.get("nested_us")
    run.stages.append({
        "stage": name,
        "role": role,
        "idx": lane["idx"],
        "chunk": chunk,
        "record": record,
        "t0": t0,
        "t1": t1,
        "dur": dur,
        "own": dur - min(nested, dur) if is_int(nested) and nested > 0 else dur,
        "nested": nested if is_int(nested) else 0,
        "facts": facts,
    })
    return rid


def load_ledger(path: str, runs: dict) -> list[str]:
    """Read one ledger file into `runs`; the ids of the runs it holds, in order of appearance."""
    seen: dict = {}
    try:
        with open(path, encoding="utf-8") as fh:
            for n, raw in enumerate(fh, start=1):
                if not raw.strip():
                    continue
                try:
                    seen[take_ledger_line(raw, f"{path}:{n}", runs)] = None
                except Torn as torn:
                    print(f"warning: {torn}", file=sys.stderr)
    except OSError as exc:
        raise Fail(f"{path}: {exc.strerror or exc}")
    except UnicodeDecodeError as exc:
        raise Fail(f"{path}: not UTF-8 ({exc.reason})")
    return list(seen)


def spans_beside(path: str) -> str | None:
    if not path.endswith(".jsonl"):
        return None
    candidate = path[: -len(".jsonl")] + ".spans.csv"
    return candidate if os.path.exists(candidate) else None


def load_spans(path: str) -> list[dict]:
    spans = []
    try:
        with open(path, newline="", encoding="utf-8") as fh:
            rdr = csv.DictReader(fh)
            missing = set(SPAN_COLUMNS) - set(rdr.fieldnames or [])
            if missing:
                raise Fail(f"{path}: missing span column(s) {sorted(missing)}")
            for n, r in enumerate(rdr, start=2):
                where = f"{path}:{n}"
                if r["state"] not in SPAN_STATES:
                    raise Fail(f"{where}: unknown span state {r['state']!r}")
                try:
                    idx, t0, t1 = int(r["index"]), int(r["start_us"]), int(r["end_us"])
                    item = int(r["item"]) if r["item"] else None
                except (TypeError, ValueError):
                    raise Fail(f"{where}: index, item, start_us and end_us must be integers")
                if t1 < t0:
                    raise Fail(f"{where}: span ends before it starts ({t0} > {t1})")
                spans.append({"role": r["lane"], "idx": idx, "state": r["state"],
                              "work": r["work"], "item": item, "t0": t0, "t1": t1})
    except OSError as exc:
        raise Fail(f"{path}: {exc.strerror or exc}")
    except UnicodeDecodeError as exc:
        raise Fail(f"{path}: not UTF-8 ({exc.reason})")
    return spans


def join_spans(path: str, ids: list[str], runs: dict) -> None:
    csv_path = spans_beside(path)
    if csv_path is None:
        return
    if len(ids) != 1:
        warn_once(("join", path), f"{path} holds {len(ids)} runs, so {csv_path} cannot be joined to "
                                  f"one; its lanes are checked on stages only")
        return
    run = runs[ids[0]]
    if run.spans is not None:
        warn_once(("join", path), f"run {run.id} already has spans; {csv_path} is not joined")
        return
    spans = []
    for sp in load_spans(csv_path):
        # The prove lanes have no spans of their own, and the recorder's other lanes have no stages
        # to be checked against, so only the emulation's lanes take part in the bracket check.
        if sp["role"] in EMULATE_ROLES:
            spans.append(sp)
        else:
            warn_once(("span-role", sp["role"]), f"{csv_path}: spans on lane {sp['role']!r} are not "
                                                 f"joined; only {', '.join(EMULATE_ROLES)} are")
    run.spans = spans


def load_bench(path: str) -> tuple[list, list, int]:
    """The `AOT_BENCH` lines of one results file, as (label, fields, where) rows, plus its failures.

    The driver's other records (`AOT_BENCH_RUN`, `_BUILD`, `_ORDER`, `_WARN`, `_WARMUP`) carry no
    measurement. `AOT_BENCH_FAIL` is the driver reporting that an arm printed no line at all, so it is
    a failure whatever exit code it carries.
    """
    rows, failed, no_exit = [], [], 0
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for n, raw in enumerate(fh, start=1):
                tok = raw.split()
                if not tok or tok[0] not in ("AOT_BENCH", "AOT_BENCH_FAIL"):
                    continue
                fields = dict(t.split("=", 1) for t in tok[1:] if "=" in t)
                where = f"{path}:{n}"
                if tok[0] == "AOT_BENCH_FAIL" or fields.get("exit", "0") != "0":
                    failed.append((where, fields))
                    continue
                if "exit" not in fields:
                    no_exit += 1
                label = fields.get("label", "-")
                if label == "-":
                    label = fields.get("arm", "-")
                    if "ledger_set" in fields:
                        instrumented = fields["ledger_set"] in BENCH_YES
                    else:
                        instrumented = fields.get("ledger", "-") != "-"
                    if instrumented:
                        label += "+ledger"
                rows.append((label, fields, where))
    except OSError as exc:
        raise Fail(f"{path}: {exc.strerror or exc}")
    return rows, failed, no_exit


def bench_failures(fields: dict, req: Required, path: str) -> list[str]:
    if not any(key in fields for key in BENCH_EVIDENCE):
        warn_once(("legacy", path), f"{path}: AOT_BENCH line(s) without pinning evidence "
                                    f"({', '.join(BENCH_EVIDENCE)}); passed as legacy")
        return []
    present = {k: (None if fields.get(k, "-") == "-" else fields[k])
               for k in ("cpus_allowed_list", "mems_allowed_list", "lock_held")}
    return pin_failures(req, present["cpus_allowed_list"], present["mems_allowed_list"],
                        parse_mempolicy(fields.get("mempolicy")),
                        present["lock_held"] in BENCH_YES, present["lock_held"])


def wall(stages: list[dict], roles: tuple) -> int | None:
    # The emulator's setup is setup, reported apart, and in no wall.
    sel = [s for s in stages if s["role"] in roles and s["stage"] != "snapshot.setup"]
    if not sel:
        return None
    return max(s["t1"] for s in sel) - min(s["t0"] for s in sel)


def per_chunk(stages: list[dict]) -> tuple[dict, dict, Counter]:
    """Σ own time per (stage, CPU chunk), the same per (stage, deferred record), and the count of
    lines with neither per stage.

    A sum, because a split chunk's segments share one chunk id and differ only in `seg`: the chunk's
    figure for a stage is all of its lines for that stage, not whichever segment came last. A line
    with a record and no chunk is that record's chunk when another of its lines names one: the
    bundle verify cannot tell which records are chunks, and their prove lines can.
    """
    chunk_of = {s["record"]: s["chunk"] for s in stages
                if s["record"] is not None and s["chunk"] is not None}
    chunked: dict = defaultdict(lambda: defaultdict(int))
    deferred: dict = defaultdict(lambda: defaultdict(int))
    nullchunk: Counter = Counter()
    for s in stages:
        chunk = s["chunk"] if s["chunk"] is not None else chunk_of.get(s["record"])
        if chunk is not None:
            chunked[s["stage"]][chunk] += s["own"]
        elif s["record"] is not None:
            deferred[s["stage"]][s["record"]] += s["own"]
        else:
            nullchunk[s["stage"]] += 1
    return chunked, deferred, nullchunk


def later_chunks(chunked: dict, name: str) -> list:
    return [dur for chunk, dur in chunked.get(name, {}).items() if chunk >= 1]


def verdict(run: Run, req: Required) -> dict:
    env = run.envelope()
    stages = run.stages
    chunked, deferred, nullchunk = per_chunk(stages)

    emulate_wall = dig(env, "stage_walls_us", "emulate")
    if not is_int(emulate_wall):
        emulate_wall = wall(stages, EMULATE_ROLES)
    riscv_wall = dig(env, "stage_walls_us", "riscv")
    if not is_int(riscv_wall):
        riscv_wall = wall(stages, RISCV_ROLES)

    replay = later_chunks(chunked, "worker.replay")
    prove = later_chunks(chunked, "prove.prove")

    snap = [s for s in stages if s["stage"] == "snapshot.emulate"]
    busy = None
    if snap and emulate_wall:
        # Both snapshot threads write their wait on the memory pool, inside the emulate bracket, as
        # a stage of its own: the thread waiting, not emulating.
        pool = sum(s["dur"] for s in stages
                   if s["stage"] == "snapshot.pool_wait" and s["role"] == "snapshot")
        busy = (sum(s["dur"] for s in snap) - pool) / emulate_wall

    # Per line, never a sum over the run: one chunk that fell back to the interpreter disappears
    # inside a run-wide total of compiled-block dispatches.
    snapshot_main = dig(env, "snapshot_main")
    if snapshot_main == "aot":
        vacuous = sum(1 for s in snap
                      if not (is_int(s["facts"].get("dispatches_delta"))
                              and s["facts"]["dispatches_delta"] > 0))
    elif snapshot_main is None:
        vacuous = None
    else:
        vacuous = 0

    setup_parts = [dig(env, "setup_us", k) for k in ("keygen", "emulator_setup", "aot_build")]
    setup_parts = [p for p in setup_parts if is_int(p)]
    peak = dig(env, "peak_rss_kib")

    arm = dig(env, "arm")
    if not isinstance(arm, str):
        arm = run.stage_arm or "-"
    label = dig(env, "label")
    if not isinstance(label, str):
        label = arm
    lock_held = dig(env, "lock_held")
    failures = pin_failures(req, dig(env, "cpus_allowed_list"), dig(env, "mems_allowed_list"),
                            dig(env, "mempolicy"), lock_held is True, lock_held)
    if env is None:
        envelope = "none"
    elif env.get("complete") is True:
        envelope = "complete"
    else:
        envelope = "provisional"
    # Not waived by --unpinned-arm: a run that never finished, or shared its process with another,
    # measured something other than one whole run.
    broken = [] if envelope == "complete" else [f"envelope={envelope}"]
    if dig(env, "overlapped") is True:
        broken.append("overlapped=true")
    workers = dig(env, "workers")

    return {
        "run": run.id,
        "arm": arm,
        "label": label,
        "warmup": dig(env, "warmup") is True,
        "chunks": len({s["chunk"] for s in stages
                       if s["stage"] == "worker.replay" and s["chunk"] is not None}),
        "emulate_wall_us": emulate_wall,
        "riscv_wall_us": riscv_wall,
        "median_replay_us": statistics.median(replay) if replay else None,
        "median_prove_us": statistics.median(prove) if prove else None,
        "snapshot_busy_frac": busy,
        "peak_rss_kib": peak if is_int(peak) else None,
        "vacuous_chunks": vacuous,
        "setup_us": sum(setup_parts) if setup_parts else None,
        "pinned": not any(f.startswith(("cpus_", "mems_")) for f in failures),
        "lock": lock_held is True,
        "envelope": envelope,
        "not_a_result": ([] if label in req.exempt else failures) + broken,
        "workers": workers if is_int(workers) else None,
        "chunked": chunked,
        "deferred": deferred,
        "nullchunk": nullchunk,
    }


def ledger_line(v: dict) -> str:
    return (
        f"LEDGER run={v['run']} arm={v['arm']} label={v['label']} chunks={v['chunks']}"
        f" emulate_wall_us={fmt(v['emulate_wall_us'])} riscv_wall_us={fmt(v['riscv_wall_us'])}"
        f" median_replay_us={fmt(v['median_replay_us'])} median_prove_us={fmt(v['median_prove_us'])}"
        f" snapshot_busy_frac={fmt(v['snapshot_busy_frac'], 4)}"
        f" peak_rss_kib={fmt(v['peak_rss_kib'])} vacuous_chunks={fmt(v['vacuous_chunks'])}"
        f" setup_us={fmt(v['setup_us'])} pinned={'y' if v['pinned'] else 'n'}"
        f" lock={'y' if v['lock'] else 'n'} envelope={v['envelope']}"
        + (" warmup=y" if v["warmup"] else "")
        + not_a_result(v["not_a_result"])
    )


def bound_line(run: Run, v: dict, threshold: float) -> str | None:
    """Which side of the emulation was saturated: the one snapshot thread, or the replay workers.

    Busy spans only, and only their part inside the emulate wall, which starts where the emulator's
    setup ends: the snapshot thread's outer busy span covers its setup too. The snapshot thread's
    wait for the memory pool is a span of its own nested inside its emulate bracket, and the
    recorder writes nesting flat, so it is already not busy.
    """
    if run.spans is None:
        return None
    wall_us, workers = v["emulate_wall_us"], v["workers"]
    start = max((s["t1"] for s in run.stages if s["stage"] == "snapshot.setup"), default=0)
    end = start + (wall_us or 0)

    def busy_in_wall(role: str) -> int:
        return sum(max(0, min(sp["t1"], end) - max(sp["t0"], start)) for sp in run.spans
                   if sp["role"] == role and sp["state"] == "busy")

    snap, work = busy_in_wall("snapshot"), busy_in_wall("emulate")
    snap_frac = snap / wall_us if wall_us else None
    work_frac = work / (workers * wall_us) if wall_us and workers else None
    if snap_frac is None:
        bound = "-"
    elif snap_frac >= threshold:
        bound = "producer"
    elif work_frac is None:
        bound = "-"
    else:
        bound = "consumer" if work_frac >= threshold else "neither"
    return (f"BOUND run={run.id} snapshot_busy_frac={fmt(snap_frac, 4)} "
            f"worker_busy_frac={fmt(work_frac, 4)} verdict={bound}")


def stage_mark(s: dict) -> dict:
    about = f"chunk {s['chunk']}" if s["chunk"] is not None else f"record {fmt(s['record'])}"
    return {"t0": s["t0"], "t1": s["t1"], "name": f"{s['stage']}({about})"}


def span_mark(sp: dict) -> dict:
    return {"t0": sp["t0"], "t1": sp["t1"],
            "name": f"{sp['state']}:{sp['work']}(item {fmt(sp['item'])})"}


def union(marks: list[dict]) -> list[list]:
    """Intervals merged into disjoint blocks: [start, end, first mark, last mark].

    Coverage is the union's length, not Σ dur_us: stages may nest or overlap, and a sum counts the
    shared time twice -- enough to lift a lane with a real hole in it over the threshold.
    """
    blocks: list[list] = []
    for m in sorted(marks, key=lambda m: (m["t0"], -m["t1"])):
        if blocks and m["t0"] <= blocks[-1][1]:
            if m["t1"] > blocks[-1][1]:
                blocks[-1][1] = m["t1"]
                blocks[-1][3] = m
        else:
            blocks.append([m["t0"], m["t1"], m, m])
    return blocks


def check_lane(role: str, stages: list[dict], spans: list[dict]) -> tuple[int, int, tuple | None]:
    """(lifetime, covered, largest gap) for one lane.

    A prove slot proves several records and waits between them for work that is not its own, so its
    lifetime is the sum of its per-record windows and a gap is looked for only inside one. Every
    other lane is a single window from its first instant to its last, over its stages and all its
    spans.

    Idle and wait spans cover; busy spans do not. A lane's outer busy span is the bracket that keeps
    unnamed work from reading idle, so it spans exactly the time a missing stage would leave bare,
    and counting it would pass every lane.
    """
    if role in PROVE_ROLES:
        by_record: dict = defaultdict(list)
        for s in stages:
            by_record[s["record"] if s["record"] is not None else s["chunk"]].append(stage_mark(s))
        windows = [(marks, None) for marks in by_record.values()]
    else:
        marks = [stage_mark(s) for s in stages] + [span_mark(sp) for sp in spans
                                                   if sp["state"] != "busy"]
        every = stages + spans
        windows = [(marks, (min(x["t0"] for x in every), max(x["t1"] for x in every)))]
    lifetime = covered = 0
    worst = None
    for marks, extent in windows:
        blocks = union(marks)
        start, end = extent or (blocks[0][0], blocks[-1][1])
        lifetime += end - start
        covered += sum(b[1] - b[0] for b in blocks)
        at, before = start, "lane start"
        holes = []
        for block in blocks:
            holes.append((at, block[0], before, block[2]["name"]))
            at, before = block[1], block[3]["name"]
        holes.append((at, end, before, "lane end"))
        for lo, hi, left, right in holes:
            if hi > lo and (worst is None or hi - lo > worst[0]):
                worst = (hi - lo, lo, hi, left, right)
    return lifetime, covered, worst


def lane_lines(run: Run, threshold: float) -> tuple[list[str], int]:
    lanes: dict = defaultdict(lambda: ([], []))
    for s in run.stages:
        lanes[(s["role"], s["idx"])][0].append(s)
    for sp in run.spans or []:
        lanes[(sp["role"], sp["idx"])][1].append(sp)
    out, passed, failed = [], 0, 0
    for lane in sorted(lanes, key=lane_key):
        stages, spans = lanes[lane]
        lifetime, covered, worst = check_lane(lane[0], stages, spans)
        coverage = covered / lifetime if lifetime else 1.0
        ok = coverage >= threshold
        passed, failed = passed + ok, failed + (not ok)
        joined = "none" if run.spans is None else len(spans)
        out.append(f"LANE run={run.id} lane={lane[0]}-{lane[1]} spans={joined} lifetime_us={lifetime} "
                   f"covered_us={covered} coverage={coverage:.4f} {'PASS' if ok else 'FAIL'}")
        if not ok and worst:
            gap, lo, hi, left, right = worst
            out.append(f"  gap {lo}..{hi} ({gap} us) between {left} and {right}")
    out.append(f"LANES run={run.id} pass={passed} fail={failed}")
    return out, failed


def spread_fields(vals: list) -> str:
    return (f"n={len(vals)} median_us={fmt(statistics.median(vals))} min_us={min(vals)} "
            f"max_us={max(vals)} spread={fmt(spread(vals), 4)}")


def stage_lines(run: Run, chunked: dict, deferred: dict, nullchunk: Counter) -> list[str]:
    names = sorted(set(chunked) | set(deferred) | set(nullchunk), key=stage_key)
    out = []
    for name in names:
        if name not in chunked and name not in nullchunk:
            continue
        vals = later_chunks(chunked, name)
        if vals:
            out.append(f"STAGE run={run.id} stage={name} {spread_fields(vals)}")
        else:
            out.append(f"STAGE run={run.id} stage={name} n=0 median_us=- min_us=- max_us=- spread=-")
    for name in names:
        if name in deferred:
            out.append(f"DEFERRED run={run.id} stage={name} "
                       f"{spread_fields(list(deferred[name].values()))}")
    for name in names:
        if 0 in chunked.get(name, {}):
            out.append(f"CHUNK0 run={run.id} stage={name} dur_us={chunked[name][0]}")
    for name in names:
        if nullchunk[name]:
            out.append(f"NULLCHUNK run={run.id} stage={name} n={nullchunk[name]}")
    nested: dict = defaultdict(list)
    for s in run.stages:
        if s["nested"] > 0:
            nested[s["stage"]].append(s["nested"])
    for name in sorted(nested, key=stage_key):
        out.append(f"NESTED run={run.id} stage={name} lines={len(nested[name])} "
                   f"nested_us={sum(nested[name])}")
    for name in sorted(run.skipped, key=stage_key):
        out.append(f"SKIPPED run={run.id} stage={name} n={run.skipped[name]}")
    return out


def group_lines(groups: dict) -> list[str]:
    out = []
    for label, vals in groups.items():
        sp = spread(vals)
        out.append(f"GROUP label={label} n={len(vals)} median={fmt(statistics.median(vals))} "
                   f"min={fmt(min(vals))} max={fmt(max(vals))} spread={fmt(sp, 4)}")
    return out


def verdict_lines(groups: dict, control: str, metric: str) -> list[str]:
    if len(groups) < 2:
        warn_once("groups", f"only one group ({control}); no verdict to draw")
        return []
    ctl = groups[control]
    med_ctl = statistics.median(ctl)
    sp_ctl = spread(ctl)
    # One sample has no spread, and against a resolution of zero every difference would clear.
    if len(ctl) < 2:
        warn_once("ctl-n", f"control {control} has one sample; its resolution is unknown")
    out = []
    for label, vals in groups.items():
        if label == control:
            continue
        med = statistics.median(vals)
        delta = None if med_ctl == 0 else med / med_ctl
        if delta is None or sp_ctl is None or len(ctl) < 2:
            clears = "-"
        else:
            clears = "y" if abs(delta - 1) > 2 * sp_ctl else "n"
        out.append(f"VERDICT metric={metric} arm={label} control={control} median_arm={fmt(med)} "
                   f"median_control={fmt(med_ctl)} delta={fmt(delta, 4)} n={len(vals)}+{len(ctl)} "
                   f"spread_control={fmt(sp_ctl, 4)} clears_resolution={clears}")
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("ledger", nargs="*",
                    help="ledger file(s) written by MLE_LEDGER=<path>; X.spans.csv beside X.jsonl "
                         "is joined to the run it holds")
    ap.add_argument("--bench", action="append", default=[], metavar="RESULTS",
                    help="a bench results file of AOT_BENCH lines; repeatable. A line groups under "
                         "its label= when it has one, else under its arm (<arm>+ledger when "
                         "ledger_set is y or yes, or without ledger_set when ledger= names a "
                         "file)")
    ap.add_argument("--control", metavar="LABEL",
                    help="the control group for the A/B verdicts: a run label for ledgers (the "
                         "arm's name for a run without one), or a bench group label for --bench")
    ap.add_argument("--metric",
                    help=f"what the A/B compares: one of {', '.join(LEDGER_METRICS)} for ledgers "
                         f"(default emulate_wall_us), or a numeric AOT_BENCH key for --bench input "
                         f"(default wall_s). With --bench given, the A/B reads the bench input")
    ap.add_argument("--cpus-allowed", default=DEFAULT_CPUS, metavar="LIST",
                    help=f"the cpus_allowed_list a result must show, or `any` (default "
                         f"{DEFAULT_CPUS})")
    ap.add_argument("--mems-allowed", default=DEFAULT_MEMS, metavar="NODES",
                    help=f"the memory node a result must be bound to, or `any` (default "
                         f"{DEFAULT_MEMS}). Met by mems_allowed_list equal to it, or by a memory "
                         f"policy whose only entry is bind:<NODES>: numactl --membind sets the "
                         f"policy and leaves mems_allowed_list as the whole machine's")
    ap.add_argument("--lock-held", default="yes", choices=("yes", "no", "any"),
                    help="whether a result must have held the host lock (default yes; no and any "
                         "both waive it)")
    ap.add_argument("--unpinned-arm", action="append", default=[], metavar="LABEL",
                    help="exempt this run label (ledgers) or group label (--bench) from the three "
                         "checks above; repeatable. pinned= and lock= still print what the run "
                         "showed. For smoke runs on a development machine")
    ap.add_argument("--lane-threshold", type=float, default=0.95, metavar="FRAC",
                    help="a lane passes when its stages, and its idle and wait spans, cover at "
                         "least this fraction of its lifetime (default 0.95)")
    ap.add_argument("--bound-threshold", type=float, default=0.80, metavar="FRAC",
                    help="for a run with spans: producer-bound when the snapshot thread was busy "
                         "for at least this fraction of the emulate wall, else consumer-bound when "
                         "the workers were, on average, else neither (default 0.80)")
    ap.add_argument("--quiet-stages", action="store_true", help="do not print the per-stage table")
    ap.add_argument("--run", metavar="ID", help="summarise only this run")
    args = ap.parse_args(argv)

    if not args.ledger and not args.bench:
        ap.error("no input: give a ledger file, --bench <results.txt>, or both")
    if args.run and not args.ledger:
        ap.error("--run selects a ledger run, and no ledger was given")
    req = Required(args.cpus_allowed, args.mems_allowed, args.lock_held, args.unpinned_arm)

    runs: dict = {}
    for path in args.ledger:
        join_spans(path, load_ledger(path, runs), runs)
    if args.ledger and not runs:
        raise Fail(f"no run in {', '.join(args.ledger)}: an arm that never opens a window (the "
                   f"single interpreter) writes no ledger")
    if args.run:
        if args.run not in runs:
            raise Fail(f"no run {args.run!r} in the ledger input; runs: {', '.join(runs) or 'none'}")
        runs = {args.run: runs[args.run]}
    benches = [(path, *load_bench(path)) for path in args.bench]

    # Everything is computed before anything is printed, so a refusal leaves no partial summary
    # behind it to be mistaken for a whole one.
    verdicts = [verdict(run, req) for run in runs.values()]

    metric = args.metric or ("wall_s" if benches else "emulate_wall_us")
    groups: dict = defaultdict(list)
    excluded: set = set()
    bench_out = []
    if benches:
        for path, rows, failed, no_exit in benches:
            used, rejected = 0, []
            for label, fields, where in rows:
                failures = [] if label in req.exempt else bench_failures(fields, req, path)
                if failures:
                    rejected.append(f"BENCHNOTRESULT {where} label={label}{not_a_result(failures)}")
                    excluded.add(label)
                    continue
                try:
                    groups[label].append(float(fields[metric]))
                    used += 1
                except (KeyError, ValueError):
                    warn_once(("metric", where), f"{where}: no numeric {metric}=; left out")
            if no_exit:
                warn_once(("exit", path), f"{path}: {no_exit} AOT_BENCH line(s) carry no exit=; "
                                          f"used as if it were 0")
            bench_out.append(f"BENCH file={path} used={used} failed={len(failed)} "
                             f"notresult={len(rejected)}")
            for where, fields in failed:
                bench_out.append(f"BENCHFAIL {where} arm={fields.get('arm', '-')} "
                                 f"rep={fields.get('rep', '-')} exit={fields.get('exit', '-')}")
            bench_out += rejected
    else:
        if metric not in LEDGER_METRICS:
            raise Fail(f"--metric {metric}: a ledger metric is one of {', '.join(LEDGER_METRICS)}")
        for v in verdicts:
            if v["warmup"]:
                warn_once(("warmup", v["run"]), f"run {v['run']} is a warm-up; left out of group "
                                                f"{v['label']}")
                continue
            if v["not_a_result"]:
                warn_once(("excluded", v["run"]), f"run {v['run']} is not a result; left out of "
                                                  f"group {v['label']}")
                excluded.add(v["label"])
                continue
            if v[metric] is None:
                warn_once(("metric", v["run"]), f"run {v['run']} has no {metric}; left out of group "
                                                f"{v['label']}")
                continue
            groups[v["label"]].append(v[metric])
    if args.control and args.control not in groups:
        why = " (every member is not a result)" if args.control in excluded else ""
        raise Fail(f"--control {args.control}: no such group{why}; groups: "
                   f"{', '.join(groups) or 'none'}")

    head = []
    for run, v in zip(runs.values(), verdicts):
        head.append(ledger_line(v))
        bound = bound_line(run, v, args.bound_threshold)
        if bound:
            head.append(bound)
    head += bench_out
    if args.control or benches:
        head += group_lines(groups)
    if args.control:
        head += verdict_lines(groups, args.control, metric)
    sections = [head]

    lanes_failed = 0
    lane_out = []
    for run in runs.values():
        lines, failed = lane_lines(run, args.lane_threshold)
        lane_out += lines
        lanes_failed += failed
    sections.append(lane_out)

    if not args.quiet_stages:
        sections.append([line for run, v in zip(runs.values(), verdicts)
                         for line in stage_lines(run, v["chunked"], v["deferred"],
                                                 v["nullchunk"])])

    print("\n\n".join("\n".join(sec) for sec in sections if sec))

    if any(v["vacuous_chunks"] for v in verdicts):
        return 3
    if lanes_failed:
        return 4
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Fail as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(2)
