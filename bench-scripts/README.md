# 📊 Benchmark Timeline Analysis – README

The Python scripts that read the MLE prover's benchmark output: `draw-mle-timeline.py` draws a run's
pipeline timeline, `mle-gate-metrics.py` prints the figures a benchmark gates on, and `sweep-csv.py`
turns a block-sweep log into CSVs. Requires `python3` (stdlib only).

---

## 🔧 Python Scripts

### 1. `draw-mle-timeline.py` (MLE prover)

**Purpose:**
Draws the MLE prover's pipeline timeline from the span CSV the prover itself writes.

**Input:** whatever `MLE_SPANS=<path>` wrote (`vm/src/mle/spans`) — one row per interval during which
one lane was in one state: `lane,index,state,work,item,start_us,end_us`. `single_node_mle.sh` sets
`MLE_SPANS` for you and calls this script.

**Usage:**

```bash
python3 bench-scripts/draw-mle-timeline.py run.spans.csv [--log run.log]
python3 bench-scripts/draw-mle-timeline.py run.spans.csv --check-only    # numbers only, no SVG
python3 bench-scripts/draw-mle-timeline.py --self-test                   # no run needed
```

Other options: `--lane` / `--chunk` / `--overview` put a figure somewhere other than beside the CSV;
`--px-per-ms` sets the horizontal density (default 0.25, and an explicit value is used as given);
`--overview-width` sizes the fit-to-width figure (default 1600px).

Exit codes: `0` drew (or checked) everything, `3` refused the CSV (unknown role or work kind, a span
that ends before it starts, missing columns, no spans), `4` a consistency check failed — **no figure is
written in that case, because the numbers on it would not be trustworthy** — and `5` the self-test
failed. `single_node_mle.sh` swallows all of them so a drawing problem cannot fail a proving run; the
message is on stderr.

**Outputs** (beside the CSV, same prefix):

* `run.lane.svg` — one row per lane. Colour is the kind of work, solid/hatched/pale is
  busy/wait/idle. This is the figure to read first: every conclusion it supports points at a knob
  (pool sizes, card count).
* `run.lane-overview.svg` — the same figure scaled to fit ~1600px.
* `run.chunk.svg` — one row per chunk. Its gaps are classified against the prover that chunk was
  waiting for: grey means that prover was busy on *another* chunk (queueing, which a saturated card
  cannot avoid), red means it was free (real loss). Read the `loss` column, not the amplification
  factor — on a saturated single card the latency of a chunk is several times its work and essentially
  all of it is queueing. Only chunk-keyed work appears here: a snapshot batch becomes several chunks
  and a combine node is named by its first chunk, so both would land on a row they do not belong to.
  They are in the lane view, labelled `b<batch>` and `c<first chunk>`.

**Notes:**

* stdlib only — no `pandas`, no `matplotlib`. Every bar carries a `<title>`, so hovering it in a
  browser names the lane, state, work and item.
* `--log` is optional and only adds the window (`e2e=`) and the run's shape (chunk count, card count);
  without it the window is the last recorded instant and the checks that compare against the prover's
  own `MLE lane:` figures are skipped, which the script says on stdout. Pass it through
  `MLE_TIMELINE_LOG` when driving the prover from a script that owns the log.
* `--self-test` checks the parts a bad CSV would otherwise sail past: that the refusals refuse, that
  the gap classifier tells queueing from real loss, and that a lane which never did anything is still
  drawn. It needs no run and no GPU.
* An unknown lane role or work kind is a hard error, not a colour fallback: the vocabulary comes from
  `Role::as_str` / `WorkKind::as_str`, and if those gained a name this script has to gain it too.
* The figures cover the `e2e=` window only: the process-wide setup before it — compilation, the
  pools, the riscv keygen — is deliberately not recorded. Keygen that happens *inside* the window, on a
  shape cache miss, is recorded and drawn on the preparer lane that took the miss (21.2 s of it on
  reth-246), and it carries no item, so it appears in the lane view and not on a chunk row.
* A density lower than `--px-per-ms` asked for means the figure hit the 12000px cap; the subtitle says
  by how much it was reduced.
* `MLE_TIMELINE` is read by `single_node_mle.sh`, not by this script. **Drawing is opt-in: set
  `MLE_TIMELINE=1` to get the figures.** A proving run writes the CSV either way — to
  `logs/mle_<elf><n>_<stamp>/run.spans.csv` unless `MLE_SPANS` says otherwise — so any run, including
  an archived one, can be drawn afterwards by pointing this script at its
  CSV. Under `MLE_REPEAT` with more than one iteration, each pass exports its own window instead, to
  `<MLE_SPANS>.iterN` and nothing new at the bare path; their figures are `run.iterN.lane.svg` and so
  on, the same prefix as a single run's. Note what that costs: only the **last** iteration gets `--log`, because the log covers the
  whole process and this script keeps the last match it finds — so the other iterations are drawn with
  the window taken from their last span and with the checks against the prover's own `MLE lane:`
  figures skipped. Draw one of them with `--log` by hand and the checks fail instead.

---

### 2. `mle-gate-metrics.py` (MLE prover)

**Purpose:**
Reads a run's span CSV and prints the two figures a benchmark gates on: the recording window
(`span_e2e`) and the card-seconds spent inside GPU work (`gpu_work`, everything `WorkKind::touches_gpu`
covers). Parsing is imported from `draw-mle-timeline.py`, so the number and the picture explaining it
cannot disagree about what they read.

**Outputs:**

* One line of JSON per input file, or `--kv` for `key=value` fields to append to a bench record.
* `--drop-warmup` ignores iteration 1 of a repeat run, which pays every one-off cost; `--best` keeps
  only the fastest of what remains, which is the iteration a gate quotes and therefore the one whose
  timeline belongs beside it.

**Usage:**

```bash
python3 bench-scripts/mle-gate-metrics.py --drop-warmup --best run.spans.csv.iter{1,2,3}
```

### 3. `sweep-csv.py` (block sweeps)

**Purpose:**
Turns the log of a block sweep (`sweep_reth_mle.sh`, one process proving many blocks) into
`setup.csv` (the once-per-process setup figures) and `summary.csv` (one row per block), slicing the
log by its `MLE block:` delimiters. `sweep_reth_mle.sh` calls it; `ci/test_sweep_csv.sh` tests it.

**Usage:**

```bash
python3 bench-scripts/sweep-csv.py run.log <outdir> [--manifest manifest.csv]
```
