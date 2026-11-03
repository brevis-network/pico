#!/usr/bin/env python3
"""Read the GPU prover's device readings out of one or more run logs, one log per run.

The readings are log lines a GPU build writes when `RUST_LOG` enables the `gpu_tracegen` target
at debug level (`vm/src/mle/spans/device.rs` describes them): one `[gpu-tracegen]` summary and one
`[gpu-tracegen-brackets]` line per proved record, a `[host-wait]` line per timed wait, a
`[gpu-air-prove]` line per record with each AIR's round-0 and GKR-input time, a `[jit-gate]` line
per AIR and size gate at keygen, and a `[queue-pickup]` line per chunk a prove lane takes. The
driver's own `mle-gpu-prover: running=` line counts the proved records.

Per run the figures are medians over the run's CPU chunks, after dropping each card's first chunk,
the last CPU chunk (it is short) and every chunk with `events_unread` above zero; across runs, the
median of the runs' medians. The figures:

- device idle ms per CPU chunk (`device.idle_us`): the span from the chunk's first device event to
  its last end, less the bracketed device work in it;
- host-blocked ms per CPU chunk (`host_wait_us`), reported alongside the idle time and not a
  substitute for it: each timed wait includes the kernels still queued on its stream;
- the host-wait count, the bridge's final wait apart (`host_wait_final_us`);
- the Global + Poseidon2 + local memory kernel sum, an upper bound: it holds those chips'
  in-launcher fills and Global's host round trip;
- the exposed copy ms (`h2d.exposed_us`);
- each wait site's total over the kept chunks;
- each bracket of the trace generator (`chip.*`, `step.*`, `copy.*`, `bridge.*`, `other_ms`,
  `sum_ms`, `union_ms`, `span_ms`) and `union_ms` over `span_ms`, the share of the device span
  some bracket covers, when the build writes them. `sum_ms` counts work that overlaps across
  streams once per figure, so it can exceed the span and is no coverage figure.

A run is vacuous, and the script exits 1, when it has no `[gpu-tracegen]` line, when a CPU chunk
reports no host wait, when every chunk has `events_unread` above zero, or when the number of
summaries differs from the number of proved records.

Usage: python3 -I perf/ledger/gpu_readings.py RUN.log [RUN.log ...]
"""

import argparse
import json
import re
import statistics
import sys
from collections import defaultdict

TRACEGEN = "[gpu-tracegen]"
BRACKETS = "[gpu-tracegen-brackets]"
HOST_WAIT = "[host-wait]"
AIR_PROVE = "[gpu-air-prove]"
JIT_GATE = "[jit-gate]"
PICKUP = "[queue-pickup]"
PROVED = re.compile(r"\(chunk-\d+\) mle-gpu-prover: running=")
JIT_GATE_FIELDS = re.compile(
    r"air=(?P<air>\S+) family=(?P<family>\S+) rules=(?P<rules>\d+) gate=\((?P<gate>[^)]*)\) "
    r"on=(?P<on>\S+) forced=(?P<forced>\S+) admitted=(?P<admitted>\S+)"
)

OVERLAPPABLE = "kernel.global_poseidon2_local_memory.us"


def fields(line, tag):
    """The `key=value` tokens after `tag`, values read as JSON where they parse."""
    out = {}
    for token in line.split(tag, 1)[1].split():
        key, sep, value = token.partition("=")
        if not sep:
            continue
        try:
            out[key] = json.loads(value)
        except ValueError:
            out[key] = value
    return out


def parse(lines):
    """One run's readings, from its log lines."""
    run = {
        "tracegen": [],
        "brackets": [],
        "waits": [],
        "airs": [],
        "gates": [],
        "pickups": [],
        "proved": 0,
    }
    for line in lines:
        if TRACEGEN in line:
            run["tracegen"].append(fields(line, TRACEGEN))
        elif BRACKETS in line:
            run["brackets"].append(fields(line, BRACKETS))
        elif HOST_WAIT in line:
            run["waits"].append(fields(line, HOST_WAIT))
        elif AIR_PROVE in line:
            run["airs"].append(fields(line, AIR_PROVE))
        elif JIT_GATE in line:
            match = JIT_GATE_FIELDS.search(line)
            if match:
                run["gates"].append(match.groupdict())
        elif PICKUP in line:
            run["pickups"].append(fields(line, PICKUP))
        elif PROVED.search(line):
            run["proved"] += 1
    return run


def kept_cpu_chunks(run):
    """The CPU chunk summaries the statistic reads, and why each other one was dropped."""
    cpu = [t for t in run["tracegen"] if t.get("cpu") is True]
    seen_devices = set()
    first_per_card = set()
    for index, summary in enumerate(run["tracegen"]):
        device = summary.get("device")
        if device not in seen_devices:
            seen_devices.add(device)
            first_per_card.add(index)
    last_cpu = max((t["chunk"] for t in cpu), default=None)
    kept, dropped = [], defaultdict(int)
    for index, summary in enumerate(run["tracegen"]):
        if summary.get("cpu") is not True:
            continue
        if index in first_per_card:
            dropped["first chunk on its card"] += 1
        elif summary["chunk"] == last_cpu:
            dropped["last CPU chunk"] += 1
        elif summary.get("events_unread", 0) > 0:
            dropped["events unread"] += 1
        else:
            kept.append(summary)
    return kept, dropped


def vacuity(run):
    """Why a run cannot be read, or an empty list."""
    reasons = []
    if not run["tracegen"]:
        return ["no [gpu-tracegen] line"]
    for summary in run["tracegen"]:
        if summary.get("cpu") is True and summary.get("host_waits", 0) == 0:
            reasons.append(f"CPU chunk {summary.get('chunk')} reports no host wait")
    if all(summary.get("events_unread", 0) > 0 for summary in run["tracegen"]):
        reasons.append("every chunk has events_unread above zero")
    if len(run["tracegen"]) != run["proved"]:
        reasons.append(
            f"{len(run['tracegen'])} [gpu-tracegen] lines against {run['proved']} proved records"
        )
    return reasons


def median_ms(kept, key):
    values = [summary[key] for summary in kept if isinstance(summary.get(key), (int, float))]
    return statistics.median(values) / 1000 if values else None


FIGURES = [
    ("device idle ms per CPU chunk", "device.idle_us"),
    ("host-blocked ms per CPU chunk (includes queued kernel time)", "host_wait_us"),
    ("final bridge wait ms", "host_wait_final_us"),
    ("Global + Poseidon2 + local memory kernel ms (upper bound)", OVERLAPPABLE),
    ("exposed copy ms", "h2d.exposed_us"),
]


def bracket_medians(run, kept):
    """Each bracket's median ms over the kept CPU chunks, and the median of `union_ms` over
    `span_ms` (`union_over_span`)."""
    kept_at = {(summary["chunk"], summary.get("device")) for summary in kept}
    values = defaultdict(list)
    for line in run["brackets"]:
        if line.get("cpu") is not True or (line.get("chunk"), line.get("device")) not in kept_at:
            continue
        for key, value in line.items():
            if key.endswith("_ms") and isinstance(value, (int, float)):
                values[key].append(value)
        union, span = line.get("union_ms"), line.get("span_ms")
        if isinstance(union, (int, float)) and isinstance(span, (int, float)) and span > 0:
            values["union_over_span"].append(union / span)
    return {key: statistics.median(found) for key, found in sorted(values.items())}


def summarise(run):
    kept, dropped = kept_cpu_chunks(run)
    figures = {label: median_ms(kept, key) for label, key in FIGURES}
    waits = [s["host_waits"] for s in kept if isinstance(s.get("host_waits"), int)]
    figures["host waits per CPU chunk"] = statistics.median(waits) if waits else None
    kept_chunks = {summary["chunk"] for summary in kept}
    sites = defaultdict(lambda: [0, 0])
    for wait in run["waits"]:
        if (
            wait.get("cpu") is True
            and wait.get("chunk") in kept_chunks
            and wait.get("final") is not True
        ):
            sites[wait.get("site")][0] += 1
            sites[wait.get("site")][1] += wait.get("us", 0)
    return {
        "kept": len(kept),
        "dropped": dict(dropped),
        "figures": figures,
        "sites": dict(sites),
        "brackets": bracket_medians(run, kept),
    }


def show(value):
    if value is None:
        return "n/a"
    return f"{value:.3f}" if isinstance(value, float) else str(value)


def report_run(name, run, summary):
    print(f"== {name}")
    print(
        f"   {len(run['tracegen'])} summaries, {run['proved']} proved records, "
        f"{summary['kept']} CPU chunks kept, dropped: {summary['dropped'] or 'none'}"
    )
    for label, value in summary["figures"].items():
        print(f"   {label}: {show(value)}")
    print("   wait sites over the kept chunks (count, total ms):")
    for site, (count, total) in sorted(summary["sites"].items(), key=lambda kv: -kv[1][1]):
        print(f"     {site}: {count}, {total / 1000:.3f}")
    if summary["brackets"]:
        print("   trace generator brackets, median ms over the kept chunks:")
        for key, value in summary["brackets"].items():
            if key != "union_over_span":
                print(f"     {key}: {show(value)}")
        ratio = summary["brackets"].get("union_over_span")
        print(f"   share of the device span the brackets cover: {show(ratio)}")
    airs = defaultdict(list)
    for record in run["airs"]:
        for key, value in record.items():
            if key.startswith("air.") and key.endswith(".prove_us"):
                airs[key[len("air.") : -len(".prove_us")]].append(value)
    if airs:
        print("   per-AIR prove ms, median over records (top 10):")
        ranked = sorted(airs.items(), key=lambda kv: -statistics.median(kv[1]))
        for air, values in ranked[:10]:
            print(f"     {air}: {statistics.median(values) / 1000:.3f} over {len(values)}")
    gated = sorted(
        {(g["air"], g["family"], g["rules"]) for g in run["gates"] if g["admitted"] != "true"}
    )
    print(f"   size-gated (air, family, rules): {gated or 'none'}")
    if run["pickups"]:
        waits = [p["wait_us"] for p in run["pickups"] if isinstance(p.get("wait_us"), int)]
        deferred = sum(1 for p in run["pickups"] if p.get("queue.kind") == "deferred")
        print(
            f"   pick-ups: {len(run['pickups'])} ({deferred} deferred), median wait ms "
            f"{show(statistics.median(waits) / 1000 if waits else None)}"
        )


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("logs", nargs="+", help="one run's log per file")
    args = parser.parse_args(argv)

    vacuous = False
    summaries = []
    for path in args.logs:
        with open(path, encoding="utf-8", errors="replace") as log:
            run = parse(log)
        reasons = vacuity(run)
        if reasons:
            vacuous = True
            print(f"== {path}: VACUOUS: " + "; ".join(reasons))
            continue
        summary = summarise(run)
        summaries.append(summary)
        report_run(path, run, summary)

    if len(summaries) > 1:
        print(f"== median of {len(summaries)} runs' medians")
        for label in summaries[0]["figures"]:
            values = [s["figures"][label] for s in summaries if s["figures"][label] is not None]
            print(f"   {label}: {show(statistics.median(values) if values else None)}")
        for key in sorted({key for s in summaries for key in s["brackets"]}):
            values = [s["brackets"][key] for s in summaries if key in s["brackets"]]
            print(f"   {key}: {show(statistics.median(values))}")
    return 1 if vacuous else 0


if __name__ == "__main__":
    sys.exit(main())
