#!/usr/bin/env python3
"""
Emit CSV:
    context,start_ms,end_ms,duration_ms,unit,prover_id,chunk_id,deferred_index,role

At the end print the remaining chunk-id queues.
"""

import re
import sys
import csv
from typing import Optional, Set, Iterator, Tuple
from collections import defaultdict
from datetime import datetime, timezone

# ── units → ms ----------------------------------------------------------------
UNIT = {"ms": 1, "s": 1_000, "us": 0.001, "µs": 0.001, "ns": 0.000001}

# ── shared regexes ------------------------------------------------------------
TS_RX = re.compile(
    r"""^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2}))\s+(.*)$"""
)
METRIC_RX = re.compile(r"""([\w-]+)\s*=\s*([0-9.]+)\s*([a-zA-Zµ]+)\b""")
PROVER_EMPTY_RX = re.compile(r"""\[(?:primary-|secondary-)?gpu-prover]""")
PROVER_RX = re.compile(r"""\[(?:primary-|secondary-)?gpu-prover-(\d+)]""")
PROVER_TAG_RX = PROVER_RX  # same pattern, reused
ROLE_TAG_RX = re.compile(r"""\[(primary|secondary)(?:-[^\]]+)?]""", re.IGNORECASE)
CHUNK_ID_RX = re.compile(r"""\(chunk-(\d+)\)""")
DEFERRED_ID_RX = re.compile(r"""\(deferred-(\d+)\)""")
EMULATOR_RX = re.compile(r"""\[emulator-(\d+)]""")
COUNT_RX = re.compile(r"""count\s*=\s*(\d+)""")


# ── helpers -------------------------------------------------------------------
INFO_RX = re.compile(r"""^\s*INFO\s+""", re.I)


def canon_non_idle(s: str) -> str:
    s = INFO_RX.sub("", s)  # drop leading INFO …
    s = PROVER_TAG_RX.sub("", s)  # drop [gpu-prover-N]
    s = PROVER_EMPTY_RX.sub("", s)  # drop [gpu-prover]
    s = ROLE_TAG_RX.sub("", s)  # drop [primary-...] / [secondary-...]
    s = CHUNK_ID_RX.sub("", s)  # drop (chunk-N)
    s = EMULATOR_RX.sub("", s)  # drop [emulator-N]
    s = DEFERRED_ID_RX.sub("", s)

    s = s.replace("[bench]", "")
    s = s.rstrip("= ").rstrip()  # drop trailing '=' + spaces
    s = s.removesuffix(": running")
    return " ".join(s.split())  # collapse internal WS


def to_dt(iso: str) -> datetime:
    return datetime.fromisoformat(iso.replace("Z", "+00:00")).astimezone(timezone.utc)


def first_timestamp(path: str) -> Optional[datetime]:
    with open(path, encoding="utf-8", errors="replace") as fh:
        for ln in fh:
            if "coordinator started" in ln:
                if m := TS_RX.match(ln):
                    return to_dt(m.group(1))
    return None


def e2e_time(path: str) -> Optional[float]:
    with open(path, encoding="utf-8", errors="replace") as fh:
        for ln in fh:
            if "E2E_total" in ln:
                print("\n" + ln, file=sys.stderr)
                parts = ln.split("=")
                value_str, unit = parts[1].strip().split()

                assert unit == "s", f"Unexpected time unit: {unit}"
                return float(value_str) * 1000.0
    return None


# ── iterator ------------------------------------------------------------------
def iter_events(
    path: str, t0: datetime
) -> Iterator[Tuple[str, float, float, float, str, int, int, int, int, int, str]]:
    """
    Parse log file and yield timing events.

    Args:
        path: Path to log file
        t0: Reference timestamp for relative time calculation

    Yields:
        Tuple of (context, start_ms, end_ms, duration_ms, unit, prover_id,
                 emulator_id, chunk_id, deferred_index, burst_count, role)
    """
    with open(path, encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            # Skip non-bench lines or idle entries
            if "[bench]" not in raw or "=" not in raw or "idle" in raw:
                continue
            if not (m_ts := TS_RX.match(raw)):
                continue

            end_abs = to_dt(m_ts.group(1))
            rest = m_ts.group(2)
            end_ms = (end_abs - t0).total_seconds() * 1_000

            # Extract IDs and role from log line
            prover_match = PROVER_RX.search(rest)
            prover_id = int(prover_match.group(1)) if prover_match is not None else -1

            emulator_match = EMULATOR_RX.search(rest)
            emulator_id = (
                int(emulator_match.group(1)) if emulator_match is not None else -1
            )

            chunk_match = CHUNK_ID_RX.search(rest)
            cid = int(chunk_match.group(1)) if chunk_match is not None else -1

            deferred_match = DEFERRED_ID_RX.search(rest)
            deferred_id = (
                int(deferred_match.group(1)) if deferred_match is not None else -1
            )
            role_match = ROLE_TAG_RX.search(rest)
            role = role_match.group(1).lower() if role_match is not None else "unknown"

            # Handle split-burst: instantaneous event on emulator lane
            if "[split-burst]" in rest:
                count_match = COUNT_RX.search(rest)
                cnt = int(count_match.group(1)) if count_match is not None else 0
                yield (
                    "split-burst",
                    end_ms,
                    end_ms,
                    0.0,
                    "ms",
                    -1,
                    emulator_id,
                    -1,
                    -1,
                    cnt,
                    role,
                )
                continue

            for m in METRIC_RX.finditer(rest):
                ctx_raw = rest[: m.end(1) + 1]
                ctx = canon_non_idle(ctx_raw)

                value, unit = float(m.group(2)), m.group(3)
                dur_ms = value * UNIT.get(unit, 1)
                start_ms = end_ms - dur_ms

                yield (
                    ctx,
                    start_ms,
                    end_ms,
                    dur_ms,
                    unit,
                    prover_id,
                    emulator_id,
                    cid,
                    deferred_id,
                    -1,
                    role,
                )


# ── main ----------------------------------------------------------------------
def main() -> None:
    """
    Main entry point. Parses log file and emits CSV to stdout, statistics to stderr.
    """
    if len(sys.argv) != 2:
        sys.exit(f"Usage: {sys.argv[0]} logfile")

    t0 = first_timestamp(sys.argv[1])
    e2e_t = e2e_time(sys.argv[1])
    if not t0:
        sys.exit("No timestamp found in the log file.")

    contexts: Set[str] = set()

    # Bookkeeping for statistics
    running_intervals = defaultdict(list)  # prover_id → [(start_ms, end_ms)]
    max_pid = -1
    sum_ctx = defaultdict(float)
    len_ctx = defaultdict(int)

    # Use csv.writer for better performance
    writer = csv.writer(sys.stdout, lineterminator="\n")
    writer.writerow(
        [
            "context",
            "start_ms",
            "end_ms",
            "duration_ms",
            "unit",
            "prover_id",
            "emulator_id",
            "chunk_id",
            "deferred_index",
            "burst_count",
            "role",
        ]
    )

    for ctx, s_ms, e_ms, d_ms, unit, pid, eid, cid, did, bcnt, role in iter_events(
        sys.argv[1], t0
    ):
        if s_ms >= 0:
            contexts.add(ctx)
            sum_ctx[ctx] += d_ms
            len_ctx[ctx] += 1
            writer.writerow(
                [
                    ctx,
                    f"{s_ms:.3f}",
                    f"{e_ms:.3f}",
                    f"{d_ms:.3f}",
                    unit,
                    pid,
                    eid,
                    cid,
                    did,
                    bcnt,
                    role,
                ]
            )

        # Keep track of largest seen prover id (skip -1)
        if pid >= 0:
            max_pid = max(max_pid, pid)

        # Collect GPU intervals for idle gap calculation
        if pid >= 0 and s_ms >= 0:
            running_intervals[pid].append((s_ms, e_ms))

    for ctx, s in sum_ctx.items():
        print(ctx, s / len_ctx[ctx], file=sys.stderr)
    # ── compute idle gaps per prover ───────────────────────────────────────
    idle_gap_ms = {}
    for pid, intervals in running_intervals.items():
        # sort by start time
        intervals.sort(key=lambda t: t[0])
        total_idle = 0.0
        last_end = 0
        for start, end in intervals:
            if start > last_end:  # positive gap
                total_idle += start - last_end
            # advance the cursor: handle possible overlaps gracefully
            last_end = max(last_end, end)
        idle_gap_ms[pid] = total_idle
        if e2e_t is not None and last_end < e2e_t:
            idle_gap_ms[pid] += e2e_t - last_end

    # ── tidy summary ───────────────────────────────────────────────────────
    if max_pid >= 0:
        print("# accumulated idle-gap time per prover_id (ms)", file=sys.stderr)
        for pid in range(max_pid + 1):
            total = idle_gap_ms.get(pid, 0.0)
            print(f"prover-{pid},{total:.3f} ms", file=sys.stderr)

    # print("\n# unique canonical contexts")
    # for c in sorted(contexts):
    #     print(c)


if __name__ == "__main__":
    main()
