#!/usr/bin/env python3
"""Turn a block-sweep run log into setup.csv and summary.csv.

    sweep-csv.py <run.log> <outdir> [--manifest <manifest.csv>]

Two reading disciplines are baked in here, because getting either wrong is silent:

1. **Slice by the block delimiters.** The pipeline emits a `MLE block: k/N block=n starting|done`
   pair around every block. A slicer keyed on `MLE repeat:` markers sees nothing here: they only
   appear when MLE_REPEAT > 1. Without slicing, every per-block extractor here -- last-match,
   first-match, count -- reads some other block's numbers and files them under this block's name.

2. **`total=` never reaches summary.csv.** It is process-wide, so reading it per block is wrong by
   construction. It goes next to setup.csv as `run_total_s`.

Setup figures are emitted once, not per block, which is the whole point of a resident sweep: a
per-block `keygen` column would describe a cost that is paid on block 1 and never again.
"""
import argparse
import csv
import os
import re
import subprocess
import sys

# The headline, printed once per block by `run_pipeline`. Field names match the log exactly; the
# CSV column names match what `mle-gate-metrics.py --kv` calls the same quantities, so the two
# sides of the report can be joined without a translation table -- `cycles` excepted, which the
# gate metrics do not carry.
BENCH = re.compile(
    r"MLE bench: chunks=(?P<chunks>\d+) prover_count=(?P<cards>\d+) lanes=(?P<lanes>\d+)"
    r" \| sum\(prove\)=(?P<sum_prove>[\d.]+)s avg/chunk=(?P<avg_chunk>[\d.]+)s"
    r" \| prove\(wall\)=(?P<prove_wall>[\d.]+)s"
    r" \| keygen=(?P<keygen>[\d.]+)s"
    r" \| emulate=(?P<emulate>[\d.]+)s(?: cycles=(?P<cycles>\d+))? prepare=(?P<prepare>[\d.]+)s"
    r" \| e2e=(?P<e2e>[\d.]+)s"
    r" \| root-accept=(?P<root_accept>[\d.]+)s"
    r" \| total=(?P<total>[\d.]+)s"
)
DELIM = re.compile(r"MLE block: (?P<epoch>\d+)/(?P<n>\d+) block=(?P<block>\d+) (?P<edge>starting|done)")
SHAPES = re.compile(
    r"MLE combine shapes: block keygens=(?P<keygens>\d+) hits=(?P<hits>\d+) evictions=(?P<evictions>\d+)"
)
GCS_OK = re.compile(r"cross-chunk global cumulative sum == 0")
CONVERT_OK = re.compile(r"all \d+ chunk\(s\) .*convert|convert .*complete", re.I)
COMBINE_OK = re.compile(r"combine \[\d+,\d+\]: OK")
COMPILE_S = re.compile(r"MLE program compile done in ([\d.]+)s")
KEYGEN_S = re.compile(r"MLE keygen done in ([\d.]+)s")
CONV_KEYGEN_S = re.compile(r"MLE convert warmup keygen done in ([\d.]+)s")
PREWARM_S = re.compile(r"MLE prewarm done in ([\d.]+)s")
LANES = re.compile(r"MLE prover lanes: (\d+) per card \((\d+) card")
PREPARERS = re.compile(r"MLE (\w+) preparers: (\d+)")
POOLS = re.compile(r"MLE event pools pre-sized to (\d+) buffers")
PACKED = re.compile(r"packed event pools initialized: (\d+)")


def slice_blocks(lines):
    """[(epoch, block, [lines])], one entry per delimited block.

    A block with a `starting` and no `done` is still returned -- that is a crashed block, and its
    partial lines are how you find out why. Returning nothing there would hide the failure.
    """
    out, cur = [], None
    for ln in lines:
        m = DELIM.search(ln)
        if m and m.group("edge") == "starting":
            cur = {"epoch": int(m.group("epoch")), "block": m.group("block"), "lines": []}
            continue
        if m and m.group("edge") == "done":
            if cur is not None:
                cur["done"] = True
                out.append(cur)
                cur = None
            continue
        if cur is not None:
            cur["lines"].append(ln)
    if cur is not None:  # started, never finished
        cur["done"] = False
        out.append(cur)
    return out


def last(rx, lines, group=1, default=""):
    """Last match wins. Within one block's slice that is the block's own value; across an unsliced
    log it would be the last block's, which is exactly the bug the slicing prevents."""
    val = default
    for ln in lines:
        m = rx.search(ln)
        if m:
            val = m.group(group)
    return val



def span_fields(base, epoch):
    """Span-side figures for ONE block, from `<base>.iter<epoch>`.

    Called once per block, deliberately. `mle-gate-metrics.py` given several CSVs takes the median
    span count and discards anything below 80% of it as a truncated export -- its comment states
    the premise, "they are the same block on the same cards minutes apart". A sweep violates that
    by construction: a 6-chunk block beside a 70-chunk one has a legitimately small span count and
    would be thrown away, taking every span column of that row with it, silently.

    `--best` and `--drop-warmup` are wrong here for the same family of reasons -- the latter would
    discard the first block's only sample.
    """
    if not base:
        return {}
    path = f"{base}.iter{epoch}"
    if not os.path.exists(path):
        return {}
    tool = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mle-gate-metrics.py")
    try:
        out = subprocess.run([sys.executable, tool, "--kv", path],
                             capture_output=True, text=True, timeout=120)
    except Exception:
        return {}
    if out.returncode != 0 or not out.stdout.strip():
        return {}
    kv = {}
    for tok in out.stdout.strip().splitlines()[0].split():
        if "=" in tok:
            k, v = tok.split("=", 1)
            kv[k] = v
    # Names are the tool's own, so the two sides of the report join without a translation table.
    # Two are prefixed because they would otherwise collide with a bench-line column of the same
    # name meaning something else: `lanes` (bench: lanes per card) and `keygen` (bench: the setup
    # keygen, which is resident and belongs in setup.csv).
    return {("span_lanes" if k == "lanes" else "span_keygen" if k == "keygen" else k): v
            for k, v in kv.items()}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("log")
    ap.add_argument("outdir")
    ap.add_argument("--manifest", default=None, help="epoch,block,input -- names the input file")
    ap.add_argument("--spans-base", default=None,
                    help="span export base; block K's figures come from <base>.iterK")
    args = ap.parse_args()

    with open(args.log, errors="replace") as fh:
        lines = fh.readlines()

    inputs = {}
    if args.manifest and os.path.exists(args.manifest):
        with open(args.manifest) as fh:
            for row in csv.DictReader(fh):
                inputs[row["block"]] = row.get("input", "")

    blocks = slice_blocks(lines)
    if not blocks:
        print("sweep-csv: no 'MLE block:' delimiters found -- was this a sweep?", file=sys.stderr)
        return 1

    os.makedirs(args.outdir, exist_ok=True)

    # ---- setup.csv: one row, from the process-wide (pre-block) region ------------------------
    # Everything here is paid once. Taken from the whole log rather than a block slice precisely
    # because it is emitted before the first delimiter.
    # Block 1's headline is the only one whose `total=` includes the setup.
    first = None
    for b in blocks:
        for ln in b["lines"]:
            m = BENCH.search(ln)
            if m:
                first = m
                break
        if first:
            break
    setup_total = ""
    if first:
        g = first.groupdict()
        setup_total = f"{float(g['total']) - float(g['e2e']) - float(g['root_accept']):.3f}"

    lane_m = LANES.search("".join(lines))
    preparers = {k: v for k, v in PREPARERS.findall("".join(lines))}
    setup_row = {
        "cards": lane_m.group(2) if lane_m else "",
        "lanes": lane_m.group(1) if lane_m else "",
        "preparers_riscv": preparers.get("riscv", ""),
        "preparers_convert": preparers.get("convert", ""),
        "preparers_combine": preparers.get("combine", ""),
        "event_pool": last(POOLS, lines),
        "packed_pool": last(PACKED, lines),
        "elf_sha": os.environ.get("SWEEP_ELF_SHA", ""),
        # The CUDA sibling is a path dependency, so nothing else in the artefacts says which
        # revision produced these numbers. A wrong one can compile and still prove wrongly.
        "ppg_sha": os.environ.get("SWEEP_PPG_SHA", ""),
        "program_compile_s": last(COMPILE_S, lines),
        "setup_riscv_keygen_s": last(KEYGEN_S, lines),
        "setup_convert_keygen_s": last(CONV_KEYGEN_S, lines),
        "prewarm_s": last(PREWARM_S, lines),
        # Derived from block 1, which is the only block whose `total=` contains the setup:
        # total = setup + e2e + root-accept, so setup = total - e2e - root-accept. Later blocks
        # skip setup entirely, which is the point -- on the four-block smoke block 1 totalled
        # 69.2s and block 2, proving the SAME block, totalled 3.1s.
        #
        # `total=` itself is deliberately absent from summary.csv: it means different things on
        # block 1 and on the rest, so a per-block column of it invites exactly the wrong comparison.
        "setup_total_s": setup_total,
        "blocks": str(len(blocks)),
    }
    with open(os.path.join(args.outdir, "setup.csv"), "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(setup_row), lineterminator="\n")
        w.writeheader()
        w.writerow(setup_row)

    # ---- summary.csv: one row per block ------------------------------------------------------
    cols = [
        "epoch", "block", "input", "warmup", "rc",
        "chunks", "cycles", "lanes",
        "e2e", "emulate", "prepare", "sum_prove", "prove_wall", "root_accept",
        "shape_keygens", "shape_hits", "shape_evictions",
        "gcs_ok", "convert_ok", "combine_ok",
        # Span-side, as an independent cross-check on the log-side figures above.
        "span_e2e", "e2e_vs_span_pct", "gpu_work", "prove_total",
        "prove_riscv", "prove_convert", "prove_combine", "span_keygen", "spans", "span_lanes",
    ]
    with open(os.path.join(args.outdir, "summary.csv"), "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=cols, lineterminator="\n")
        w.writeheader()
        for i, b in enumerate(blocks):
            text = b["lines"]
            m = None
            for ln in text:
                mm = BENCH.search(ln)
                if mm:
                    m = mm
            g = m.groupdict() if m else {}
            sh = None
            for ln in text:
                mm = SHAPES.search(ln)
                if mm:
                    sh = mm
            row = {
                "epoch": b["epoch"],
                "block": b["block"],
                "input": inputs.get(b["block"], ""),
                # The first block carries the process-wide one-off costs inside its window, so it
                # is marked rather than silently averaged in with the rest.
                "warmup": 1 if i == 0 else 0,
                "rc": 0 if b.get("done") else 1,
                "chunks": g.get("chunks", ""),
                # `or`, not a default: an optional group that did not participate is present
                # in the dict as None, so the two-argument form never fires.
                "cycles": g.get("cycles") or "",
                "lanes": g.get("lanes", ""),
                "e2e": g.get("e2e", ""),
                "emulate": g.get("emulate", ""),
                "prepare": g.get("prepare", ""),
                "sum_prove": g.get("sum_prove", ""),
                "prove_wall": g.get("prove_wall", ""),
                "root_accept": g.get("root_accept", ""),
                "shape_keygens": sh.group("keygens") if sh else "",
                "shape_hits": sh.group("hits") if sh else "",
                "shape_evictions": sh.group("evictions") if sh else "",
                "gcs_ok": sum(1 for ln in text if GCS_OK.search(ln)),
                "convert_ok": sum(1 for ln in text if CONVERT_OK.search(ln)),
                "combine_ok": sum(1 for ln in text if COMBINE_OK.search(ln)),
            }
            sp = span_fields(args.spans_base, b["epoch"])
            row.update({k: v for k, v in sp.items() if k in cols})
            # The gate: the log-side window and the span-side window describe the same interval,
            # so a disagreement means one of them is measuring something else. Reported rather than
            # asserted -- a number in the table is checkable later; an assertion here would only
            # fail the extraction after the expensive part is already done.
            try:
                a, bb = float(row["e2e"]), float(sp["span_e2e"])
                row["e2e_vs_span_pct"] = f"{abs(a - bb) / a * 100:.2f}"
            except (KeyError, ValueError, ZeroDivisionError):
                row["e2e_vs_span_pct"] = ""
            w.writerow(row)

    print(f"sweep-csv: {len(blocks)} block(s) -> {args.outdir}/summary.csv, setup.csv")
    return 0


if __name__ == "__main__":
    sys.exit(main())
