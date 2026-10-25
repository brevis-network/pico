#!/usr/bin/env python3
"""Draw the MLE prover's pipeline timeline from a span CSV.

The input is what `MLE_SPANS=<path>` writes (vm/src/mle/spans): one row per interval during which
one lane was in one state.

    lane,index,state,work,item,start_us,end_us

Two figures come out of it, and they answer different questions:

  * the LANE view (`--lane`) puts a lane on every row -- who was busy, who was waiting, and on what.
  * the CHUNK view (`--chunk`) puts a chunk on every row -- where one chunk's latency went. Its gaps
    are classified: time when that chunk's prover was busy on ANOTHER chunk is queueing, which a
    saturated card cannot avoid; time when the prover was free is real loss. Without that split the
    figure reports a 10x latency amplification that is entirely queueing, i.e. it lies.

Deliberately stdlib-only: no pandas, no matplotlib. Every bar carries a `<title>`, so hovering it in
a browser names the lane, state, work and item -- which is the whole reason for hand-written SVG.

Nothing here is scaled off the window unless the window is known: pass `--log` to read `e2e=` and the
run's shape from the run's log, or the figures fall back to the last recorded instant.
"""

from __future__ import annotations

import argparse
import csv
import html
import os
import re
import sys
from collections import defaultdict

# --------------------------------------------------------------------------------------- vocabulary
#
# Both tables are exhaustive on purpose: an unknown role or work kind is an error, not a colour
# fallback. FRI's timeline degrades silently into a tab10 colour plus an "Unknown" legend group, so a
# renamed context there reads as a new kind of work that nobody notices. Here the script stops and
# names what it did not recognise -- the vocabulary lives in `Role::as_str` / `WorkKind::as_str`, and
# if it changed, this file has to change with it.

# The prover lanes -- both of them. `prove-rec` split off `prove` when convert and combine stopped
# sharing riscv's thread, and every figure below that means "the card's prover" has to count both:
# counting only `prove` would classify a chunk waiting on its own card's convert lane as upstream,
# and would halve the lane-seconds denominator the window accounting is checked against.
#
# A run under `MLE_RECURSION_LANE=0` emits no `prove-rec` lane at all, and every use below is a
# filter over the lanes that exist, so such a log draws with `prove` alone and needs nothing else.
PROVE_ROLES = ("prove", "prove-rec")


def is_prove_lane(lane):
    return lane[0] in PROVE_ROLES


ROLE_ORDER = [
    "snapshot",     # emulate: untraced forward pass (AOT when the factory is registered)
    "emulate",      # emulate: traced replay workers
    "riscv-prep",
    "conv-prep",
    "comb-prep",
    "prove",        # per-card riscv lane
    "prove-rec",    # per-card recursion lane: convert + combine
    "dispatch",
]

WORK_COLOR = {
    "snapshot": "#003F5C",
    "emulate": "#2F4B7C",
    "emulate-recover": "#6A7BA2",
    "prepare-riscv": "#4C78A8",
    "prepare-convert": "#72B7B2",
    "prepare-combine": "#54A24B",
    "keygen": "#B279A2",
    "prove-riscv": "#E45756",
    "prove-convert": "#F58518",
    "prove-combine": "#9D755D",
    "dispatch": "#7F7F7F",
    "-": "#BAB0AC",         # WorkKind::Unattributed
}

# `item` is not one key space. The prepare and prove lanes count chunks; the emulate lanes count
# snapshot batches, and one tail batch becomes several chunks; combine work carries the FIRST chunk of
# its node, which many nodes of a binary tree share. Only the first kind may be drawn against a chunk
# row, and the other two get a prefix so no one reads them as chunk numbers.
CHUNK_ITEM_WORK = {
    "prepare-riscv",
    "prove-riscv",
    "prepare-convert",
    "prove-convert",
    # The dispatcher's `wait` names the chunk it was blocked routing, so it belongs to that chunk's
    # journey: blocking because the one shared queue was full is exactly what a chunk row is for.
    "dispatch",
}
# Kinds that never carry an item, so no key space applies.
ITEMLESS_WORK = {"keygen", "-"}
BATCH_ITEM_WORK = {"snapshot", "emulate", "emulate-recover"}
NODE_ITEM_WORK = {"prepare-combine", "prove-combine"}

def _check_key_spaces() -> None:
    """Every work kind belongs to exactly one key space, and the compiler cannot say so.

    Runs at import rather than in a test: a kind added to the prover and not classified here would
    otherwise be drawn against a chunk row it may not belong to, which is a wrong figure rather than a
    missing one.
    """
    spaces = {
        "CHUNK_ITEM_WORK": CHUNK_ITEM_WORK,
        "BATCH_ITEM_WORK": BATCH_ITEM_WORK,
        "NODE_ITEM_WORK": NODE_ITEM_WORK,
        "ITEMLESS_WORK": ITEMLESS_WORK,
    }
    classified = set().union(*spaces.values())
    unknown = classified - set(WORK_COLOR)
    missing = set(WORK_COLOR) - classified
    twice = {
        kind: [name for name, members in spaces.items() if kind in members]
        for kind in classified
        if sum(kind in members for members in spaces.values()) > 1
    }
    problems = []
    if missing:
        problems.append(f"work kind(s) in no key space: {sorted(missing)}")
    if unknown:
        problems.append(f"key space names(s) absent from WORK_COLOR: {sorted(unknown)}")
    if twice:
        problems.append(f"work kind(s) in more than one key space: {twice}")
    if problems:
        raise SystemExit(
            "draw-mle-timeline.py: " + "; ".join(problems) + ". The prover's `WorkKind::as_str` and "
            "this file's key spaces have drifted apart; classify the kind before drawing anything."
        )


_check_key_spaces()

FONT = "-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif"
LOSS_COLOR = "#D62728"
QUEUE_COLOR = "#B8BEC6"
UPSTREAM_COLOR = "#6C9BC0"

# Density and the width it is allowed to buy. 0.25 px/ms keeps a chunk label inside a 150 ms bar; a
# long block would then be tens of thousands of pixels wide (reth-246's 89 s window comes to 22.5k),
# so the default density yields to the cap and the figure says by how much. An explicit
# `--px-per-ms` is honoured as given -- someone asking for a density has a reason.
DEFAULT_PX_PER_MS = 0.25
MAX_FIGURE_PX = 12000

# Label column and figure margins, named once: the density cap has to subtract them, and when they
# were literals in three places a wider label column silently broke the cap.
LANE_GUTTER = 118      # lane view: "conv-prep-11" plus room
LANE_RIGHT = 96        # lane view: "97% . 45.9s"
CHUNK_GUTTER = 88      # chunk view: "chunk 106"
CHUNK_RIGHT = 300      # chunk view: life / work / wait / upstream / loss / amplification
MAX_MARGINS = max(LANE_GUTTER + LANE_RIGHT, CHUNK_GUTTER + CHUNK_RIGHT)

# Row geometry, chosen by lane count: 12 emulate workers plus 6/12/7 preparers is 41 lanes on one
# card and 55 on eight, and a 26px row would make that a 1.4k-tall figure.
def row_height(n_rows: int) -> int:
    if n_rows <= 20:
        return 26
    if n_rows <= 30:
        return 22
    return 18


class Frame:
    """The geometry both views share: rows of a fixed height against a time axis.

    Split out because the two figures agreed on all of it and disagreed only about what a row means,
    and a frame computed twice is a frame that can drift once.
    """

    def __init__(self, n_rows: int, spans: list, window_ms: float, px_per_ms: float,
                 gutter: int, right: int, top: int):
        self.rows = n_rows
        self.row = row_height(n_rows)
        self.bar = self.row - 7 if self.row <= 20 else self.row - 11
        self.gutter, self.right, self.top = gutter, right, top
        self.px_per_ms = px_per_ms
        # Draw to the window even when the last span stops short, so two runs of the same block are
        # read on the same scale; extend past it if a span somehow outlives it (the checks complain
        # separately).
        self.t1 = max(window_ms, max(sp["e"] for sp in spans))
        self.width = gutter + int(self.t1 * px_per_ms) + right
        self.bottom = top + n_rows * self.row
        # Provisional: `set_legend` fixes it once the legend's own wrapping is known. A short window
        # makes a narrow canvas, the legend wraps to more rows than a wide one, and a fixed reservation
        # drew all of it below the bottom edge.
        self.height = self.bottom + 40 + 3 * 18 + 24

    def legend_columns(self) -> int:
        return max(1, int((self.width - 24) // 168))

    def set_legend(self, n_entries: int) -> None:
        per = self.legend_columns()
        rows = (n_entries + per - 1) // per
        self.height = self.bottom + 40 + (rows + 1) * 18 + 24

    def x(self, t: float) -> float:
        return self.gutter + t * self.px_per_ms

    def row_y(self, i: int) -> float:
        return self.top + i * self.row

    def bar_y(self, i: int) -> float:
        return self.row_y(i) + (self.row - self.bar) / 2

    def stripe(self, o: list, i: int) -> None:
        """Alternating row background. Every second row, so a long row is followed across the axis."""
        if i % 2 == 0:
            o.append(f'<rect x="{self.gutter}" y="{self.row_y(i)}" '
                     f'width="{self.width - self.gutter - self.right}" height="{self.row}" '
                     f'fill="#F7F8FA"/>')

    def label(self, o: list, i: int, text: str) -> None:
        o.append(f'<text x="{self.gutter - 8}" y="{self.row_y(i) + self.row / 2 + 4}" '
                 f'font-size="{min(11, self.row - 7)}" text-anchor="end">{text}</text>')


class Fail(Exception):
    """A refusal to draw. Raised for anything that would put a wrong figure on screen."""


# ------------------------------------------------------------------------------------------- input

def load_spans(path: str) -> list[dict]:
    with open(path, newline="", encoding="utf-8") as fh:
        rdr = csv.DictReader(fh)
        need = {"lane", "index", "state", "work", "item", "start_us", "end_us"}
        missing = need - set(rdr.fieldnames or [])
        if missing:
            raise Fail(f"{path}: missing column(s) {sorted(missing)}")
        spans = []
        for n, r in enumerate(rdr, start=2):
            if r["lane"] not in ROLE_ORDER:
                raise Fail(
                    f"{path}:{n}: unknown lane role {r['lane']!r}. The prover's `Role::as_str` "
                    f"gained a name this script does not know; add it to ROLE_ORDER."
                )
            if r["work"] not in WORK_COLOR:
                raise Fail(
                    f"{path}:{n}: unknown work kind {r['work']!r}. The prover's `WorkKind::as_str` "
                    f"gained a name this script does not know; add it to WORK_COLOR."
                )
            if r["state"] not in ("busy", "idle", "wait"):
                raise Fail(f"{path}:{n}: unknown state {r['state']!r}")
            s, e = int(r["start_us"]), int(r["end_us"])
            if e < s:
                raise Fail(f"{path}:{n}: span ends before it starts ({s} > {e})")
            spans.append(
                {
                    "lane": (r["lane"], int(r["index"])),
                    "state": r["state"],
                    "work": r["work"],
                    "item": int(r["item"]) if r["item"] != "" else None,
                    "s": s / 1000.0,
                    "e": e / 1000.0,
                }
            )
    if not spans:
        raise Fail(f"{path}: no spans")
    return spans


LOG_LANE_RX = re.compile(
    r"MLE lane: ([a-z-]+)x(\d+) busy=([0-9.]+)s idle=([0-9.]+)s \(wait=([0-9.]+)s\)"
)
LOG_E2E_RX = re.compile(r"MLE bench:.*?\be2e=([0-9.]+)s")
LOG_PIPELINE_RX = re.compile(r"MLE bench:.*?\bpipeline=([0-9.]+)s")  # pre-rename field name
LOG_CHUNKS_RX = re.compile(r"MLE bench: chunks=(\d+) prover_count=(\d+)")


def load_log(path: str) -> dict:
    """What the log adds: the window and the run's shape.

    Optional by design -- an archived spans CSV may arrive without its log, and the figures must
    still draw. Every field here is therefore allowed to be absent.
    """
    info: dict = {"lane_busy": {}, "window_ms": None, "chunks": None, "prover_count": None}
    with open(path, encoding="utf-8", errors="replace") as fh:
        for ln in fh:
            if m := LOG_LANE_RX.search(ln):
                info["lane_busy"][m.group(1)] = (
                    int(m.group(2)),
                    float(m.group(3)) * 1000.0,
                    float(m.group(4)) * 1000.0,   # idle, which already contains wait
                    float(m.group(5)) * 1000.0,
                )
            if "MLE bench:" in ln:
                # `e2e=` is today's name for the window; older logs called it `pipeline=`. Take
                # whichever is present rather than guessing, so an archived run still scales right.
                if m := LOG_E2E_RX.search(ln):
                    info["window_ms"] = float(m.group(1)) * 1000.0
                elif m := LOG_PIPELINE_RX.search(ln):
                    info["window_ms"] = float(m.group(1)) * 1000.0
                if m := LOG_CHUNKS_RX.search(ln):
                    info["chunks"], info["prover_count"] = int(m.group(1)), int(m.group(2))
    return info


# ------------------------------------------------------------------------------------------ figures

def merge(iv: list[tuple[float, float]]) -> list[tuple[float, float]]:
    out: list[list[float]] = []
    for s, e in sorted(iv):
        if e <= s:
            continue
        if out and s <= out[-1][1]:
            out[-1][1] = max(out[-1][1], e)
        else:
            out.append([s, e])
    return [(a, b) for a, b in out]


def classify_gaps(sp_list: list[dict], prove_busy: dict) -> list[dict]:
    """The gaps between one chunk's spans, each attributed to whatever the chunk was waiting for.

    Only a wait for a prover can be queueing or loss: that is the question "was device time wasted",
    and it has no meaning for a chunk waiting on a preparer slot or a keygen. Pure, so
    the self-test can pin the numbers down rather than looking for a colour somewhere in the file.
    """
    out: list[dict] = []
    cursor = None
    for sp in sp_list:
        if cursor is not None and sp["s"] > cursor + 0.05:
            gap = sp["s"] - cursor
            if is_prove_lane(sp["lane"]):
                q = overlap(prove_busy[sp["lane"]], cursor, sp["s"])
                loss = gap - q
                out.append({"s": cursor, "e": sp["s"], "gap": gap, "queueing": q, "loss": loss,
                            "upstream": 0.0, "kind": "loss" if loss > q else "queue",
                            "waiting_for": sp["lane"]})
            else:
                out.append({"s": cursor, "e": sp["s"], "gap": gap, "queueing": 0.0, "loss": 0.0,
                            "upstream": gap, "kind": "upstream", "waiting_for": sp["lane"]})
        cursor = sp["e"] if cursor is None else max(cursor, sp["e"])
    return out


def overlap(iv: list[tuple[float, float]], a: float, b: float) -> float:
    return sum(max(0.0, min(b, y) - max(a, x)) for x, y in iv)


def lane_stats(spans: list[dict]) -> dict:
    """Per lane: first/last instant, and time in each state. `gap` is what no span accounted for."""
    by: dict = defaultdict(lambda: {"first": None, "last": None, "busy": 0.0, "idle": 0.0,
                                    "wait": 0.0, "spans": []})
    for sp in spans:
        st = by[sp["lane"]]
        st["first"] = sp["s"] if st["first"] is None else min(st["first"], sp["s"])
        st["last"] = sp["e"] if st["last"] is None else max(st["last"], sp["e"])
        st[sp["state"]] += sp["e"] - sp["s"]
        st["spans"].append(sp)
    for st in by.values():
        st["life"] = st["last"] - st["first"]
        st["gap"] = max(0.0, st["life"] - st["busy"] - st["idle"] - st["wait"])
        st["occ"] = (st["busy"] / st["life"] * 100.0) if st["life"] > 0 else None
    return by


def lane_sort_key(lane, stats) -> tuple:
    """Roles upstream-first; inside a pool, the lanes that did something come first.

    A pool of 12 convert preparers mostly does nothing on a small block, and sorting by index would
    scatter the two that worked among ten empty rows. The label keeps the real index, so the row is
    still identifiable.
    """
    role, idx = lane
    return (ROLE_ORDER.index(role), -stats[lane]["busy"], idx)


def header_height(n_notes: int) -> int:
    """Where the rows may start. Fixed at 92 it put the fourth note inside the first row."""
    return 53 + n_notes * 14 + 10


def svg_header(w: int, h: int, title: str, subtitle: str, notes: list[str]) -> list[str]:
    o = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" '
        f'viewBox="0 0 {w} {h}" font-family="{FONT}">',
        '<defs>'
        '<pattern id="waitfill" width="5" height="5" patternTransform="rotate(45)" '
        'patternUnits="userSpaceOnUse">'
        '<rect width="5" height="5" fill="#ffffff"/>'
        '<line x1="0" y1="0" x2="0" y2="5" stroke="#C44" stroke-width="2.4"/>'
        '</pattern></defs>',
        f'<rect width="{w}" height="{h}" fill="#ffffff"/>',
        f'<text x="12" y="21" font-size="14" font-weight="600">{html.escape(title)}</text>',
        f'<text x="12" y="38" font-size="11" fill="#555">{html.escape(subtitle)}</text>',
    ]
    for i, n in enumerate(notes):
        o.append(f'<text x="12" y="{53 + i * 14}" font-size="10.5" fill="#777">{html.escape(n)}</text>')
    return o


def axis(o: list[str], x, t0: float, t1: float, top: float, bottom: float, left: float, right: float):
    span = t1 - t0
    # Last resort scales with the window: a fixed list ran out past ~300 s and left a 400 s figure
    # drawing 400 ticks.
    step = max(1000.0, span / 20.0)
    for cand in (100.0, 250.0, 500.0, 1000.0, 2000.0, 5000.0, 10000.0, 20000.0, 30000.0, 60000.0):
        if span / cand <= 30:
            step = cand
            break
    t = (int(t0 / step)) * step
    while t <= t1:
        if t >= t0:
            px = x(t)
            o.append(f'<line x1="{px:.1f}" y1="{top}" x2="{px:.1f}" y2="{bottom}" stroke="#E3E6EA"/>')
            lbl = f"{t / 1000:g}s"
            o.append(
                f'<text x="{px:.1f}" y="{bottom + 14}" font-size="10" fill="#666" '
                f'text-anchor="middle">{lbl}</text>'
            )
        t += step
    o.append(f'<line x1="{left}" y1="{bottom}" x2="{right}" y2="{bottom}" stroke="#C9D1DA"/>')


def legend(o: list[str], y: float, per: int, kinds: list[str]) -> float:
    """One flow of swatches, wrapped to `per` columns. The two state explainers ride in the same flow,
    because placing them at a fixed x put them off the edge of a narrow canvas."""
    entries: list[tuple[str, str]] = []
    for k in kinds:
        # `-` is WorkKind::Unattributed, which is a name only inside the prover.
        entries.append((WORK_COLOR[k], "(unattributed)" if k == "-" else k))
    for i, (fill, label) in enumerate(entries):
        lx = 12 + (i % per) * 168
        ly = y + (i // per) * 18
        o.append(f'<rect x="{lx}" y="{ly - 9}" width="11" height="11" fill="{fill}"/>')
        o.append(f'<text x="{lx + 16}" y="{ly}" font-size="10">{html.escape(label)}</text>')
    ly = y + ((len(entries) + per - 1) // per) * 18
    o.append(
        f'<rect x="12" y="{ly - 9}" width="11" height="11" fill="url(#waitfill)" '
        f'stroke="#333" stroke-width="0.5"/>'
        f'<text x="28" y="{ly}" font-size="10">wait (blocked on capacity someone else holds)</text>'
    )
    # The wait explainer is ~260px of text, so it needs two columns to itself: anything less puts the
    # idle swatch on top of it.
    if per >= 3:
        x2, y2 = 12 + 2 * 168, ly
    else:
        x2, y2 = 12, ly + 18
    o.append(
        f'<rect x="{x2}" y="{y2 - 9}" width="11" height="11" fill="#8899AA" fill-opacity="0.13"/>'
        f'<text x="{x2 + 16}" y="{y2}" font-size="10">idle (nothing to do)</text>'
    )
    return y2 + 18


def bar(o: list[str], x0: float, y: float, w: float, h: float, color: str, state: str, tip: str):
    if state == "busy":
        fill, op, stroke = color, "1", 0.4
    elif state == "wait":
        fill, op, stroke = "url(#waitfill)", "1", 0.6
    else:
        fill, op, stroke = color, "0.13", 0.0
    extra = f' stroke="#333" stroke-width="{stroke}"' if stroke else ""
    o.append(
        f'<g><title>{html.escape(tip)}</title>'
        f'<rect x="{x0:.1f}" y="{y:.1f}" width="{max(w, 0.7):.1f}" height="{h}" '
        f'fill="{fill}" fill-opacity="{op}"{extra}/></g>'
    )


def item_label(sp: dict) -> str:
    """`5`, `b5` and `c5` are three different fives — see the key-space note at the top."""
    if sp["item"] is None:
        return ""
    if sp["work"] in BATCH_ITEM_WORK:
        return f"b{sp['item']}"
    if sp["work"] in NODE_ITEM_WORK:
        return f"c{sp['item']}"
    return str(sp["item"])


def draw_lane_view(spans, stats, window_ms, px_per_ms, meta, out_path):
    lanes = sorted(stats.keys(), key=lambda l: lane_sort_key(l, stats))
    notes = [
        "bar colour = work kind · solid = busy · hatched = wait · pale = idle · hover a bar for detail",
        "lane occupancy, NOT GPU utilisation: a lane counts as working while its thread is inside "
        "GPU-related work, which is not the same as kernels being in flight",
    ]
    if any(l[0] == "emulate" for l in lanes):
        notes.append(
            "sparse emulate lanes are expected when the run has fewer snapshot batches than workers "
            "— that is not starvation; judge the pool size on a block with many more batches"
        )
    top = header_height(len(notes))
    # Only kinds that were actually worked: a solid swatch for a kind that never got past `idle` claims
    # time that does not exist.
    kinds = [k for k in WORK_COLOR if any(sp["work"] == k and sp["state"] == "busy" for sp in spans)]
    f = Frame(len(lanes), spans, window_ms, px_per_ms, LANE_GUTTER, LANE_RIGHT, top)
    f.set_legend(len(kinds))
    row, barh, gut, rgut = f.row, f.bar, f.gutter, f.right
    width, height, t1, x = f.width, f.height, f.t1, f.x

    o = svg_header(width, height, meta["title"], meta["subtitle"], notes)

    bottom = f.bottom
    prev_role = None
    for i, lane in enumerate(lanes):
        y = f.row_y(i)
        f.stripe(o, i)
        if prev_role is not None and lane[0] != prev_role:
            o.append(f'<line x1="{gut}" y1="{y}" x2="{width - rgut}" y2="{y}" stroke="#9AA3AE"/>')
        prev_role = lane[0]
        f.label(o, i, f"{lane[0]}-{lane[1]}")
        st = stats[lane]
        occ = "n/a" if st["occ"] is None else f'{st["occ"]:.0f}%'
        o.append(
            f'<text x="{width - rgut + 8}" y="{y + row / 2 + 4}" font-size="9.5" fill="#666">'
            f'{occ} · {st["busy"] / 1000:.1f}s</text>'
        )
    axis(o, x, 0.0, t1, top, bottom, gut, width - rgut)

    lane_y = {lane: top + i * row for i, lane in enumerate(lanes)}
    for sp in spans:
        y = lane_y[sp["lane"]] + (row - barh) / 2
        w = (sp["e"] - sp["s"]) * px_per_ms
        tip = (
            f'{sp["lane"][0]}-{sp["lane"][1]} · {sp["state"]} · {sp["work"]}'
            f' · item={item_label(sp) or "-"}'
            f' · {sp["e"] - sp["s"]:.1f} ms · {sp["s"]:.0f}→{sp["e"]:.0f} ms'
        )
        bar(o, x(sp["s"]), y, w, barh, WORK_COLOR[sp["work"]], sp["state"], tip)
        lbl = item_label(sp)
        if lbl and sp["state"] == "busy" and w > 7 * len(lbl):
            o.append(
                f'<text x="{x(sp["s"]) + w / 2:.1f}" y="{y + barh - 3}" font-size="8.5" '
                f'fill="#ffffff" text-anchor="middle">{lbl}</text>'
            )
    legend(o, bottom + 40, f.legend_columns(), kinds)
    o.append("</svg>")
    write(out_path, o)
    return len(lanes)


def draw_chunk_view(spans, stats, window_ms, px_per_ms, meta, out_path, acct):
    # Chunk-keyed work only. A snapshot batch and a combine node are not chunks, and drawing them here
    # put a whole combine subtree on the row of its first chunk -- which made that row's life the whole
    # window and its amplification meaningless.
    chunk_spans = [sp for sp in spans if sp["item"] is not None and sp["work"] in CHUNK_ITEM_WORK]
    items = sorted({sp["item"] for sp in chunk_spans})
    if not items:
        return 0
    by_item = defaultdict(list)
    for sp in chunk_spans:
        by_item[sp["item"]].append(sp)

    # Busy time per prove lane: `classify_gaps` keys off the lane a chunk actually ran on. Chunks are
    # not pinned to a card under either lane shape -- the shared dispatch queue is what decides, not
    # the split -- so a gap here reads as that lane's own idleness, not the run's.
    prove_busy_by_lane = {
        lane: merge([(sp["s"], sp["e"]) for sp in st["spans"] if sp["state"] == "busy"])
        for lane, st in stats.items() if is_prove_lane(lane)
    }

    kinds = [k for k in WORK_COLOR
             if any(sp["work"] == k and sp["state"] == "busy" for sp in chunk_spans)]
    notes = [
        "one row = one chunk's life · colour = work kind · hatched = wait · pale = idle",
        "gaps are lines: grey = queueing (the prover it was waiting for was busy on another chunk, "
        "which a saturated card cannot avoid) · red = real loss (that prover was free) · blue = "
        "waiting upstream, for a preparer slot or a keygen, where the prover is "
        "not the question",
        f'window accounting over {acct["lanes"]} prove lane(s): non-busy '
        f'{acct["nonbusy"] / 1000:.2f}s of {acct["lane_window"] / 1000:.2f}s lane-seconds = head '
        f'{acct["head"] / 1000:.2f}s + middle {acct["middle"] / 1000:.2f}s + tail '
        f'{acct["tail"] / 1000:.2f}s. The per-chunk loss column cannot see the head: it '
        f'classifies gaps BETWEEN a chunk\'s spans.',
        "keygen carries no item, so a chunk's convert keygen is absent here — it is on the lane view, "
        "immediately before that chunk's prepare-convert",
    ]
    f = Frame(len(items), spans, window_ms, px_per_ms, CHUNK_GUTTER, CHUNK_RIGHT,
              header_height(len(notes)))
    f.set_legend(len(kinds))
    row, barh, gut, rgut = f.row, f.bar, f.gutter, f.right
    width, height, t1, x = f.width, f.height, f.t1, f.x
    top = f.top

    o = svg_header(width, height, meta["title_chunk"], meta["subtitle"], notes)
    bottom = f.bottom
    axis(o, x, 0.0, t1, top, bottom, gut, width - rgut)

    for i, item in enumerate(items):
        y = f.row_y(i)
        sp_list = sorted(by_item[item], key=lambda s: (s["s"], s["e"]))
        f.stripe(o, i)
        f.label(o, i, f"chunk {item}")
        life = sp_list[-1]["e"] - sp_list[0]["s"]
        work = sum(s["e"] - s["s"] for s in sp_list if s["state"] == "busy")
        wait_ms = sum(s["e"] - s["s"] for s in sp_list if s["state"] == "wait")
        gaps = classify_gaps(sp_list, prove_busy_by_lane)
        loss = sum(g["loss"] for g in gaps)
        upstream = sum(g["upstream"] for g in gaps)
        for g in gaps:
            if g["kind"] == "upstream":
                col, lw = UPSTREAM_COLOR, 1.6
                gtip = "gap {:.1f} ms · waiting upstream for {}-{}, not for a prover".format(
                    g["gap"], g["waiting_for"][0], g["waiting_for"][1]
                )
            else:
                col = LOSS_COLOR if g["kind"] == "loss" else QUEUE_COLOR
                lw = 2.0 if g["kind"] == "loss" else 1.2
                gtip = "gap {:.1f} ms · queueing {:.1f} ms · loss {:.1f} ms".format(
                    g["gap"], g["queueing"], g["loss"]
                )
            ymid = y + row / 2
            o.append(
                f'<g><title>{html.escape(gtip)}</title>'
                f'<line x1="{x(g["s"]):.1f}" y1="{ymid:.1f}" x2="{x(g["e"]):.1f}" y2="{ymid:.1f}" '
                f'stroke="{col}" stroke-width="{lw}"/></g>'
            )
        for sp in sp_list:
            w = (sp["e"] - sp["s"]) * px_per_ms
            tip = (
                f'{sp["lane"][0]}-{sp["lane"][1]} · {sp["state"]} · {sp["work"]}'
                f' · {sp["e"] - sp["s"]:.1f} ms · {sp["s"]:.0f}→{sp["e"]:.0f} ms'
            )
            bar(o, x(sp["s"]), y + (row - barh) / 2, w, barh, WORK_COLOR[sp["work"]], sp["state"], tip)
        amp = (life / work) if work else 0.0
        o.append(
            f'<text x="{width - rgut + 6}" y="{y + row / 2 + 4}" font-size="9" fill="#444">'
            f'life {life / 1000:.2f}s · work {work / 1000:.2f}s · wait {wait_ms / 1000:.2f}s · '
            f'<tspan fill="{UPSTREAM_COLOR}">up {upstream / 1000:.2f}s</tspan> · '
            f'<tspan fill="{LOSS_COLOR if loss > 20 else "#444"}">loss {loss / 1000:.2f}s</tspan>'
            f' · {amp:.1f}x</text>'
        )
    legend(o, bottom + 40, f.legend_columns(), kinds)
    o.append("</svg>")
    write(out_path, o)
    return len(items)


def write(path: str, lines: list[str]) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


# -------------------------------------------------------------------------------------- accounting

def window_accounting(spans, stats, window_ms) -> dict:
    """Split the prove lanes' non-busy time into head / middle / tail against the window.

    This exists because the per-chunk view's `loss` column structurally cannot see the head: the
    pipeline fill happens before chunk 0's first span, so there is no gap BETWEEN two spans to
    classify, and on a real run the head is the largest block of prove-lane idleness there is.
    """
    prove_lanes = [l for l in stats if is_prove_lane(l)]
    n_lanes = len(prove_lanes) or 1
    # Every figure below is a sum over lanes, so its unit is lane-seconds and its denominator is
    # `lanes x window` — reporting it against one window made a four-card run look oversubscribed.
    acct = {"window": window_ms, "lanes": n_lanes, "lane_window": window_ms * n_lanes,
            "head": 0.0, "middle": 0.0, "tail": 0.0, "post": 0.0, "recorded_nonbusy": 0.0}
    for lane in prove_lanes:
        st = stats[lane]
        busy = merge([(sp["s"], sp["e"]) for sp in st["spans"] if sp["state"] == "busy"])
        acct["recorded_nonbusy"] += st["idle"] + st["wait"]
        if not busy:
            acct["head"] += window_ms
            continue
        first, last = busy[0][0], busy[-1][1]
        # Split against this lane, not the pool: with several cards a lane has its own first and last
        # prove, and pooling them would put one card's head inside another card's working time.
        acct["head"] += first
        acct["middle"] += (last - first) - sum(b - a for a, b in busy)
        acct["tail"] += max(0.0, window_ms - last)
        # Between the lane's last prove and the end of its spans. Part of the window's tail, but it is
        # the part the lane itself recorded, so the reconciliation below has to know about it.
        acct["post"] += max(0.0, st["last"] - last)
    acct["nonbusy"] = acct["head"] + acct["middle"] + acct["tail"]
    return acct


def run_checks(spans, stats, log_info, acct, path) -> list[str]:
    """Every figure-facing number, re-derived and compared against an independent source."""
    fails = []
    # 1. per-role busy against the prover's own `MLE lane:` line.
    if log_info and log_info["lane_busy"]:
        role_busy = defaultdict(float)
        role_lanes = defaultdict(set)
        for sp in spans:
            if sp["state"] == "busy":
                role_busy[sp["lane"][0]] += sp["e"] - sp["s"]
            role_lanes[sp["lane"][0]].add(sp["lane"][1])
        for role, (n, busy_ms, _idle_ms, _wait_ms) in log_info["lane_busy"].items():
            got = role_busy.get(role, 0.0)
            if abs(got - busy_ms) > 1.0:  # the log prints ms-truncated seconds
                fails.append(f"role {role}: CSV busy {got:.3f} ms != log {busy_ms:.3f} ms")
            if len(role_lanes.get(role, ())) != n:
                fails.append(
                    f"role {role}: CSV has {len(role_lanes.get(role, ()))} lane(s), log says {n}"
                )
    # 2. per-lane time conservation.
    for lane, st in stats.items():
        total = st["busy"] + st["idle"] + st["wait"] + st["gap"]
        if abs(total - st["life"]) > 0.002:
            fails.append(
                f"lane {lane[0]}-{lane[1]}: busy+idle+wait+gap {total:.3f} != life {st['life']:.3f} ms"
            )
    # 3. The prove lanes' idleness, derived twice: once by walking their busy intervals (head, middle
    # and the stretch after the last prove) and once by summing the spans they recorded as not busy.
    # The figure's window accounting is built from the first, the `MLE lane:` report from the second,
    # and a disagreement means the interval arithmetic or the tiling is wrong. Not a tautology: the
    # two sides share no term.
    from_intervals = acct["head"] + acct["middle"] + acct["post"]
    from_spans = acct["recorded_nonbusy"]
    tol = max(5.0, from_spans * 0.005)
    if abs(from_intervals - from_spans) > tol:
        fails.append(
            f"prove idleness: {from_intervals:.3f} ms from busy intervals (head "
            f"{acct['head']:.3f} + middle {acct['middle']:.3f} + post {acct['post']:.3f}) != "
            f"{from_spans:.3f} ms of recorded idle+wait spans"
        )
    # And against the prover's own report, when it is available -- a third derivation, by the code
    # that produced the spans rather than by this script.
    # Summed over every prove role, because `from_spans` is: reading `prove` alone would compare a
    # two-lane total against one lane and fail on every run built after the lanes split.
    log_roles = [r for r in PROVE_ROLES if r in log_info["lane_busy"]] if log_info else []
    if log_roles:
        log_idle = sum(log_info["lane_busy"][r][2] for r in log_roles)
        if abs(from_spans - log_idle) > max(5.0, log_idle * 0.005):
            fails.append(
                f"prove idle: {from_spans:.3f} ms of spans != {log_idle:.3f} ms in the log's "
                f"`MLE lane: {'/'.join(log_roles)}` line(s)"
            )
    # 4. Busy and non-busy must together fill the lane-seconds the window offers — the unit check for
    # the sums above, which are per-lane totals and not shares of one window.
    prove_busy = sum(
        sp["e"] - sp["s"] for sp in spans if is_prove_lane(sp["lane"]) and sp["state"] == "busy"
    )
    if abs(prove_busy + acct["nonbusy"] - acct["lane_window"]) > max(
        5.0, acct["lane_window"] * 0.005
    ):
        fails.append(
            f"prove lane-seconds: busy {prove_busy:.3f} + non-busy {acct['nonbusy']:.3f} != "
            f"{acct['lane_window']:.3f} ({acct['lanes']} lane(s) x {acct['window']:.3f} ms window)"
        )
    # 5. no span may sit outside the window (a figure clipped at the window would hide it).
    late = [sp for sp in spans if sp["e"] > acct["window"] + 1.0]
    if late:
        worst = max(sp["e"] for sp in late)
        fails.append(
            f"{len(late)} span(s) end after the window ({worst:.1f} ms > {acct['window']:.1f} ms) -- "
            f"the window came from the log's e2e= and the spans disagree with it"
        )
    return fails


# --------------------------------------------------------------------------------------- self-test

SELF_TEST_ROWS = [
    # A snapshot lane and two replay workers, one of which never gets a batch: the empty lane must
    # still appear in the lane view, which is the finding on a block with fewer batches than workers.
    # Their `item` is a batch number, so none of them may appear in the chunk view.
    ("snapshot", 0, "busy", "snapshot", "0", 0, 50_000),
    ("snapshot", 0, "busy", "snapshot", "1", 50_000, 100_000),
    ("emulate", 0, "idle", "-", "", 0, 50_000),
    ("emulate", 0, "busy", "emulate-recover", "0", 50_000, 55_000),
    ("emulate", 0, "busy", "emulate", "0", 55_000, 300_000),
    ("emulate", 0, "idle", "-", "", 300_000, 900_000),
    ("emulate", 1, "idle", "-", "", 1_000, 900_000),
    # One prover, tiled end to end, proving three chunks.
    ("prove", 0, "idle", "-", "", 0, 300_000),
    ("prove", 0, "busy", "prove-riscv", "0", 300_000, 500_000),
    ("prove", 0, "idle", "-", "", 500_000, 700_000),
    ("prove", 0, "busy", "prove-riscv", "1", 700_000, 800_000),
    ("prove", 0, "idle", "-", "", 800_000, 860_000),
    ("prove", 0, "busy", "prove-riscv", "2", 860_000, 900_000),
    # Chunk 1 waits 340 ms for the prover, 200 ms of it with the prover free: real loss.
    ("riscv-prep", 0, "busy", "prepare-riscv", "1", 320_000, 360_000),
    # Chunk 2 waits 550 ms, 290 ms of it behind the prover working on others: queueing.
    ("riscv-prep", 0, "busy", "prepare-riscv", "2", 305_000, 310_000),
    # Chunk 3 never reaches a prover: its 390 ms gap ends on a preparer, so it is upstream waiting and
    # neither queueing nor loss.
    ("riscv-prep", 0, "busy", "prepare-riscv", "3", 200_000, 210_000),
    ("conv-prep", 0, "busy", "prepare-convert", "3", 600_000, 620_000),
    # A combine node named by its first chunk, which must not land on any chunk row.
    ("comb-prep", 0, "busy", "prepare-combine", "0", 810_000, 820_000),
]

# What `classify_gaps` must say about the fixture, worked out by hand from the rows above. Asserting the
# numbers rather than "some line of each colour exists" is the point: four wrong classifiers (colours
# swapped, the chunk's first lane instead of the awaited one, every gap against all lanes, combine work
# treated as chunk-keyed) all passed a self-test that only looked for colours.
SELF_TEST_GAPS = {
    0: [],
    # In ms: the rows above are in us, and the loader divides.
    1: [{"gap": 340.0, "queueing": 140.0, "loss": 200.0, "kind": "loss"}],
    2: [{"gap": 550.0, "queueing": 290.0, "loss": 260.0, "kind": "queue"}],
    3: [{"gap": 390.0, "queueing": 0.0, "loss": 0.0, "kind": "upstream"}],
}


def self_test(tmp_dir: str) -> int:
    """Check the parts a bad CSV would otherwise sail past. Run: `--self-test`.

    Covers what the per-run checks cannot: that the refusals refuse, that the gap classifier tells
    queueing from loss, and that a lane which did nothing still gets drawn.
    """
    failures = []

    def write(rows, name):
        path = os.path.join(tmp_dir, name)
        with open(path, "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh, lineterminator="\n")
            w.writerow(["lane", "index", "state", "work", "item", "start_us", "end_us"])
            w.writerows(rows)
        return path

    def expect_fail(rows, name, needle):
        try:
            load_spans(write(rows, name))
        except Fail as exc:
            if needle not in str(exc):
                failures.append(f"{name}: refused, but not for {needle!r}: {exc}")
            return
        failures.append(f"{name}: accepted a CSV it should have refused ({needle})")

    expect_fail([("sequencer", 0, "busy", "emulate", "", 0, 10)], "unknown-role.csv", "unknown lane role")
    expect_fail([("prove", 0, "busy", "prove-embed", "", 0, 10)], "unknown-work.csv", "unknown work kind")
    expect_fail([("prove", 0, "sleeping", "prove-riscv", "", 0, 10)], "bad-state.csv", "unknown state")
    expect_fail([("prove", 0, "busy", "prove-riscv", "", 20, 10)], "inverted.csv", "ends before it starts")

    good = write(SELF_TEST_ROWS, "good.spans.csv")
    spans = load_spans(good)
    stats = lane_stats(spans)
    acct = window_accounting(spans, stats, 900.0)
    if fails := run_checks(spans, stats, None, acct, good):
        failures.append(f"good.spans.csv: {fails}")
    expected_lanes = {("snapshot", 0), ("emulate", 0), ("emulate", 1), ("prove", 0),
                      ("riscv-prep", 0), ("conv-prep", 0), ("comb-prep", 0)}
    if set(stats) != expected_lanes:
        failures.append(f"lanes {sorted(set(stats) ^ expected_lanes)} unexpectedly present or absent")
    if ("emulate", 1) not in stats:
        failures.append("the worker that never received a batch produced no lane")

    # The classifier, number by number.
    prove_busy = {
        lane: merge([(sp["s"], sp["e"]) for sp in st["spans"] if sp["state"] == "busy"])
        for lane, st in stats.items() if is_prove_lane(lane)
    }
    by_item: dict = defaultdict(list)
    for sp in spans:
        if sp["item"] is not None and sp["work"] in CHUNK_ITEM_WORK:
            by_item[sp["item"]].append(sp)
    for item, want in SELF_TEST_GAPS.items():
        got = classify_gaps(sorted(by_item[item], key=lambda s: (s["s"], s["e"])), prove_busy)
        if len(got) != len(want):
            failures.append(f"chunk {item}: {len(got)} gap(s), expected {len(want)}")
            continue
        for g, w in zip(got, want):
            for key, value in w.items():
                if isinstance(value, str):
                    if g[key] != value:
                        failures.append(f"chunk {item}: {key} {g[key]!r}, expected {value!r}")
                elif abs(g[key] - value) > 0.5:
                    failures.append(f"chunk {item}: {key} {g[key]:.1f}, expected {value:.1f}")

    meta = {"title": "self-test", "title_chunk": "self-test", "subtitle": "self-test"}
    chunk_svg = os.path.join(tmp_dir, "chunk.svg")
    rows = draw_chunk_view(spans, stats, 900.0, 1.0, meta, chunk_svg, acct)
    body = open(chunk_svg, encoding="utf-8").read()
    if rows != len(SELF_TEST_GAPS):
        failures.append(f"chunk view drew {rows} rows for {len(SELF_TEST_GAPS)} chunks")
    # Each row's line must be the colour its classification calls for. Rows are found by their label,
    # whose baseline sits 4px below the line -- so a swapped colour table cannot pass.
    want_colour = {1: LOSS_COLOR, 2: QUEUE_COLOR, 3: UPSTREAM_COLOR}
    for item, colour in want_colour.items():
        m = re.search(rf'<text x="[\d.]+" y="([\d.]+)"[^>]*>chunk {item}</text>', body)
        if not m:
            failures.append(f"chunk view has no row labelled chunk {item}")
            continue
        line_y = float(m.group(1)) - 4
        drawn = re.findall(rf'<line x1="[\d.]+" y1="{line_y:.1f}"[^>]*stroke="([^"]+)"', body)
        if colour not in drawn:
            failures.append(f"chunk {item}: expected a {colour} gap line, drew {drawn}")
    # The other two key spaces must stay out of it: a batch and a combine node are not chunks.
    for stray in sorted(BATCH_ITEM_WORK | NODE_ITEM_WORK):
        if f"· {stray} ·" in body:
            failures.append(f"chunk view contains {stray!r} work, which is not chunk-keyed")

    lane_svg = os.path.join(tmp_dir, "lane.svg")
    draw_lane_view(spans, stats, 900.0, 1.0, meta, lane_svg)
    lane_body = open(lane_svg, encoding="utf-8").read()
    for needed in ("<svg", "emulate-1", "snapshot-0", "</svg>"):
        if needed not in lane_body:
            failures.append(f"lane view is missing {needed!r}")

    # A corrupted CSV: drop the idle span that covers the pipeline head. The two derivations of
    # prove-lane idleness then disagree, which is the one check a plausible-looking figure needs.
    corrupt = [r for r in SELF_TEST_ROWS if not (r[0] == "prove" and r[2] == "idle" and r[5] == 0)]
    c_path = write(corrupt, "corrupt.spans.csv")
    c_spans = load_spans(c_path)
    c_stats = lane_stats(c_spans)
    c_acct = window_accounting(c_spans, c_stats, 900.0)
    if not any("prove idleness" in f for f in run_checks(c_spans, c_stats, None, c_acct, c_path)):
        failures.append("dropping the head idle span did not trip the prove-idleness check")

    for f in failures:
        print(f"SELF-TEST FAILED: {f}", file=sys.stderr)
    print(f"self-test: {'ok' if not failures else f'{len(failures)} failure(s)'}")
    return 0 if not failures else 5


# -------------------------------------------------------------------------------------------- main

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("csv", nargs="?", help="span CSV written by MLE_SPANS=<path>")
    ap.add_argument("--lane", help="output SVG for the lane view (default: <base>.lane.svg)")
    ap.add_argument("--chunk", help="output SVG for the chunk view (default: <base>.chunk.svg)")
    ap.add_argument("--overview", help="output SVG for the fit-to-width lane view "
                                       "(default: <base>.lane-overview.svg)")
    ap.add_argument("--log", help="the run's log, for the window and the run's shape")
    ap.add_argument("--px-per-ms", type=float, default=None,
                    help=f"horizontal density of the lane and chunk views (default "
                         f"{DEFAULT_PX_PER_MS}, reduced automatically to keep the figure under "
                         f"{MAX_FIGURE_PX}px; an explicit value is used as given)")
    ap.add_argument("--overview-width", type=int, default=1600,
                    help="target width in px for the overview figure (default 1600)")
    ap.add_argument("--check-only", action="store_true", help="run the checks, write no SVG")
    ap.add_argument("--self-test", action="store_true",
                    help="check the refusals and the gap classifier against synthetic spans, then exit")
    args = ap.parse_args()

    if args.self_test:
        import tempfile
        with tempfile.TemporaryDirectory(prefix="mle-timeline-selftest-") as tmp:
            return self_test(tmp)

    if not args.csv:
        ap.error("a span CSV is required (or pass --self-test)")
    spans = load_spans(args.csv)
    stats = lane_stats(spans)
    log_info = load_log(args.log) if args.log else None
    last = max(sp["e"] for sp in spans)
    window_ms = (log_info or {}).get("window_ms") or last

    acct = window_accounting(spans, stats, window_ms)
    fails = run_checks(spans, stats, log_info, acct, args.csv)

    # A repeat run's exports are named `<path>.iterN` (see `csv_path_for_iteration`), so lift the index
    # off before stripping the CSV suffix and put it back after. Stripping in the other order leaves the
    # whole name as the prefix: `run.spans.csv.iter2.lane.svg` where a single run gives `run.lane.svg`.
    base = args.csv
    iter_suffix = ""
    if m := re.search(r"\.iter\d+$", base):
        iter_suffix, base = m.group(0), base[: m.start()]
    for suffix in (".spans.csv", ".csv"):
        if base.endswith(suffix):
            base = base[: -len(suffix)]
            break
    base += iter_suffix
    # Density: honour an explicit request, otherwise take the default and let the cap reduce it.
    if args.px_per_ms is not None:
        px_per_ms, clamped = args.px_per_ms, False
    else:
        room = (MAX_FIGURE_PX - MAX_MARGINS) / max(window_ms, 1.0)
        px_per_ms = min(DEFAULT_PX_PER_MS, room)
        clamped = px_per_ms < DEFAULT_PX_PER_MS

    shape = ""
    if log_info and log_info["chunks"]:
        shape = f' · {log_info["chunks"]} chunks · prover_count={log_info["prover_count"]}'
    density_note = (
        f' · density {px_per_ms:.3f} px/ms (reduced from {DEFAULT_PX_PER_MS} to fit '
        f'{MAX_FIGURE_PX}px)' if clamped else ''
    )
    subtitle_base = (
        f'window = e2e {window_ms / 1000:.2f}s{shape} · {len(spans)} spans · {len(stats)} lanes · '
        f'setup/keygen before the window is not recorded and not shown'
    )
    subtitle = subtitle_base + density_note
    meta = {
        "title": f"MLE pipeline timeline by lane — {os.path.basename(base)}",
        "title_chunk": f"MLE per-chunk critical path — {os.path.basename(base)}",
        "subtitle": subtitle,
    }

    print(f"{args.csv}: {len(spans)} spans, {len(stats)} lanes, window {window_ms / 1000:.3f}s")
    print(
        f"  prove lanes non-busy {acct['nonbusy'] / 1000:.3f}s of {acct['lane_window'] / 1000:.3f}s"
        f" lane-seconds ({acct['lanes']} lane(s)) = head {acct['head'] / 1000:.3f}s"
        f" + middle {acct['middle'] / 1000:.3f}s + tail {acct['tail'] / 1000:.3f}s"
    )
    if not log_info:
        # Said out loud: some of the checks compare against the prover's own report, and without it a
        # clean run means less than it looks like.
        print("  no --log: window taken from the last span; the checks against the prover's own "
              "`MLE lane:` figures are skipped")
    for lane in sorted(stats, key=lambda l: lane_sort_key(l, stats)):
        st = stats[lane]
        occ = "n/a" if st["occ"] is None else f"{st['occ']:.1f}%"
        print(
            f"  {lane[0]}-{lane[1]:<3} busy {st['busy'] / 1000:7.3f}s idle {st['idle'] / 1000:7.3f}s"
            f" wait {st['wait'] / 1000:7.3f}s gap {st['gap'] / 1000:6.3f}s life"
            f" {st['life'] / 1000:7.3f}s occ {occ}"
        )
    if fails:
        for f in fails:
            print(f"CHECK FAILED: {f}", file=sys.stderr)
        return 4
    print("  checks: ok")

    if args.check_only:
        return 0

    lane_out = args.lane or f"{base}.lane.svg"
    chunk_out = args.chunk or f"{base}.chunk.svg"
    over_out = args.overview or f"{base}.lane-overview.svg"
    lanes_drawn = draw_lane_view(spans, stats, window_ms, px_per_ms, meta, lane_out)
    fit = max(0.01, (args.overview_width - LANE_GUTTER - LANE_RIGHT) / max(window_ms, 1.0))
    # Its own subtitle: the overview is drawn at another density, and handing it the detail figure's
    # note put "0.131 px/ms" on a figure drawn at 0.0155.
    meta_overview = dict(meta)
    meta_overview["subtitle"] = f"{subtitle_base} · overview at {fit:.4f} px/ms"
    draw_lane_view(spans, stats, window_ms, fit, meta_overview, over_out)
    chunks_drawn = draw_chunk_view(spans, stats, window_ms, px_per_ms, meta,
                                   chunk_out, acct)
    print(f"  wrote {lane_out} ({lanes_drawn} lanes), {over_out} (fit {args.overview_width}px), "
          f"{chunk_out} ({chunks_drawn} chunks)")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Fail as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(3)
