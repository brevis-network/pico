#!/usr/bin/env python3
"""The two gate figures, read off a run's span CSV.

One line of JSON per input file, for `bench-report.awk` to consume. The report keeps doing what it is
good at — comparing arms, computing spreads, rendering Markdown — and only stops scraping these two
numbers out of prose.

Why the CSV rather than the log: the same harness field carries different meanings at different
layers (one place a cross-card union, another a sum), so scraping it puts that ambiguity inside the
gate. Accumulating per lane here has no such question, the CSV has a header and fixed columns where
the log is prose that a reworded `tracing::info!` can silently break, and `export_csv` validates
before it writes, so the gate's input arrives already checked.

Parsing is imported from `draw-mle-timeline.py` on purpose: two parsers for one format drift, and the
figure and the picture explaining it must not disagree about what they read.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))


def _load_timeline_module():
    """Import the drawing script for its parser. Its filename is not an identifier, hence the spec
    dance; it guards its own entry point, so importing runs only definitions."""
    path = os.path.join(_HERE, "draw-mle-timeline.py")
    spec = importlib.util.spec_from_file_location("mle_timeline", path)
    if spec is None or spec.loader is None:
        raise SystemExit(f"cannot load the span parser from {path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_TL = _load_timeline_module()

# Mirrors `WorkKind::touches_gpu` in vm/src/mle/spans/record.rs. Nothing checks that the two agree,
# so a kind that changes sides there has to change here too — but a kind that is *added* there is
# caught, because the shared parser rejects a work name it does not know.
GPU_WORK = {"keygen", "prove-riscv", "prove-convert", "prove-combine"}

# Reported on their own as well as in the total, because this is the breakdown a reader compares
# against the prover's own per-role lines.
BREAKDOWN = ("prove-riscv", "prove-convert", "prove-combine", "keygen")

_ITER_RX = re.compile(r"\.iter(\d+)$")


def metrics(path: str) -> dict:
    spans = _TL.load_spans(path)
    if not spans:
        raise _TL.Fail(f"{path}: no spans")

    # The window is the recording window itself: the origin is zero by construction (the driver opens
    # it with `set_origin`), so the last span's end is its width. Measured, not taken from the log —
    # that is what makes it checkable against the log rather than a copy of it.
    e2e_ms = max(s["e"] for s in spans)

    # Lane-time, so a sum and not a union: four cards busy for one second is four card-seconds of
    # work, which is the quantity a change to the prover is supposed to move.
    gpu_ms = 0.0
    per_work: dict[str, float] = {k: 0.0 for k in BREAKDOWN}
    for s in spans:
        if s["state"] != "busy":
            continue
        dur = s["e"] - s["s"]
        if s["work"] in GPU_WORK:
            gpu_ms += dur
        if s["work"] in per_work:
            per_work[s["work"]] += dur

    m = _ITER_RX.search(path)
    # Two totals, because two readings of "GPU work" are both in use and they differ by the keygen:
    # `gpu_work` is everything `WorkKind::touches_gpu` covers, which is what the prover itself calls
    # GPU work and what the gate reads; `prove_total` is the three proving kinds alone, the figure
    # earlier reports quote. Both are emitted so the two can be reconciled by hand.
    prove_total = sum(per_work[k] for k in ("prove-riscv", "prove-convert", "prove-combine"))
    # Seconds, because that is the unit every other field in the bench record already uses and a
    # report mixing the two would be wrong in a way that still renders. `span_e2e` is named apart
    # from the record's own `e2e`: the log's figure stays, and having both is what makes the CSV
    # checkable against it rather than a replacement for it.
    out = {
        "file": os.path.basename(path),
        "iter": int(m.group(1)) if m else None,
        "span_e2e": round(e2e_ms / 1000.0, 3),
        "gpu_work": round(gpu_ms / 1000.0, 3),
        "prove_total": round(prove_total / 1000.0, 3),
        "spans": len(spans),
        "lanes": len({s["lane"] for s in spans}),
    }
    for k in BREAKDOWN:
        out[k.replace("-", "_")] = round(per_work[k] / 1000.0, 3)
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("csv", nargs="+", help="span CSV(s); a repeat run writes one per iteration")
    ap.add_argument("--best", action="store_true",
                    help="emit only the iteration with the smallest span_e2e, which is the one a gate "
                         "reads and therefore the one whose timeline has to be drawn beside it")
    ap.add_argument("--drop-warmup", action="store_true",
                    help="ignore iteration 1 when several were given. The first proof in a process "
                         "pays every one-off cost — pools, JIT, the first keygen — so it is a "
                         "different measurement from the steady-state ones after it, and averaging "
                         "or minimising across the two mixes them")
    ap.add_argument("--kv", action="store_true",
                    help="emit `key=value` fields on one line instead of JSON, to append to the "
                         "bench record the report already parses that way. The report reads two of "
                         "them; the rest are there for reading a run by hand, which is what the "
                         "JSON form is for as well")
    args = ap.parse_args()

    # One unreadable iteration should cost that iteration, not the cell. A repeat run hands us
    # several files and the gate needs one of them; refusing them all because the third was truncated
    # would drop every gate figure for the run and leave the report with nothing to compare. Failing
    # only when none survived keeps a corrupt single-file call an error, as it should be.
    rows, failed = [], 0
    for p in args.csv:
        try:
            rows.append(metrics(p))
        except (_TL.Fail, OSError) as e:
            failed += 1
            print(f"mle-gate-metrics: skipping {p}: {e}", file=sys.stderr)
    if not rows:
        print(f"mle-gate-metrics: no usable span CSV among {len(args.csv)} given", file=sys.stderr)
        return 3

    # A truncated export is shorter in every dimension at once, so minimising on it prefers exactly
    # the broken file — and because both gated figures shrink together the result reads as a
    # consistent gain rather than a partial write. Judge each iteration against the others: they are
    # the same block on the same cards minutes apart, so a real one cannot be a fraction of its
    # siblings. Only meaningful with something to compare against.
    if len(rows) > 1:
        median = sorted(r["spans"] for r in rows)[len(rows) // 2]
        keep = [r for r in rows if r["spans"] >= median * 0.8]
        for r in rows:
            if r not in keep:
                print(f"mle-gate-metrics: ignoring {r['file']}: {r['spans']} spans against a median "
                      f"of {median} — the export looks truncated", file=sys.stderr)
        if keep:
            rows = keep

    if args.drop_warmup:
        # Iteration 1 pays every one-off cost in the process, so it is a different measurement from
        # the ones after it. A cell whose only export is that one has no steady-state sample at all,
        # and reporting the warm-up as if it were one is worse than reporting nothing: the caller's
        # missing-figure path says so out loud, where a warm-up figure would just read slow.
        # `iter` is None for a run that did not repeat, which has no warm-up to drop.
        rows = [r for r in rows if r["iter"] != 1]
        if not rows:
            print("mle-gate-metrics: every export given is iteration 1, the warm-up — no "
                  "steady-state sample to report", file=sys.stderr)
            return 3
    if args.best:
        rows = [min(rows, key=lambda r: r["span_e2e"])]
    for r in rows:
        if args.kv:
            # `file` is dropped and `iter` renamed: the record already identifies the run, and the
            # only thing worth carrying over is which iteration these figures came from — the report
            # has to name it beside the figure, or the two cannot be checked against each other.
            fields = {("span_iter" if k == "iter" else k): v for k, v in r.items() if k != "file"}
            print(" ".join(f"{k}={'' if v is None else v}" for k, v in fields.items()))
        else:
            print(json.dumps(r, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
