# Re-measuring the recursion tier tables

The recursion tier tables in `vm/src/mle/machine/shape.rs` — the convert ladder
(`MLE_RECURSION_CONVERT_LADDER`, three rows), the combine row (`MLE_RECURSION_COMBINE_LOG_HEIGHTS`),
the embed row and the compress row — are the heights every whitelist-mode recursion program pads
to. They are measured, not derived. This page is how they were set for the 128-bit parameters
and how to set them again.

## When

After a change to a recursion circuit (the convert, combine, deferred, embed or compress program, or
the compiler that lowers them), to a recursion preset, or to a recursion chip's columns or row count
(`PACK_LANES`, a chip added or removed). Such a change moves the natural heights: a table that no
longer holds them panics at keygen in whitelist mode (`check_recursion_tier`), a table with slack
over them pads every proof. Every edit to a table but the embed row is a whitelist rebuild
(`docs/whitelist-rebuild.md`). The embed row is not in the config digest and shapes no leaf:
it moves only the embed key, so regenerate the soundness manifest (the artifact unit
test holds the embed key against it) and redo what bakes that key in: the wrap circuit, its
Groth16 setup and the on-chain verifier (the gnark setup and `contracts/test/dev`, as
`contracts/README.md` does them).

## Measure

`vm/examples/mle_tier_probe.rs` walks every whitelist shape, builds the convert program each
would be verified by, then the 36 combine node shapes, the deferred and compress nodes, and the
embed node over the compress proof's layout (synthesized from a keygen of the compress program,
`compress_proof_layout`), and prints every natural height. On tables the circuits have outgrown it
runs in report-only mode, which asserts nothing:

```bash
MLE_TIER_PROBE_REPORT_ONLY=1 MLE_TIER_PROBE_STRIDE=50 MLE_SHAPE_MARGIN=1 \
  RUST_LOG=info,mle_shape_margin=info cargo run --release -p pico-vm --example mle_tier_probe
MLE_TIER_PROBE_REPORT_ONLY=1 MLE_SHAPE_MARGIN=1 \
  RUST_LOG=info,mle_shape_margin=info cargo run --release -p pico-vm --example mle_tier_probe
```

The first command (every 50th shape) is a timing run; the second is the measurement, about six
minutes on a many-core host. Its log carries, at `RUST_LOG=info`:

- `probe_columns: label <chip ×21>`, once: the chip order of every line below;
- `probe_natural: convert <label> <log2 ×21>`, one per riscv shape (15,646 for the shipped
  whitelist), and
  `<label>: no convert row holds it` for each shape the current ladder cannot hold;
- `probe_natural: combine <node> <log2 ×21>`, one per node shape (36; `<node>` is the label with
  its space replaced by `_`, e.g. `[C0,C1]_complete`); `probe_natural: deferred`,
  `probe_natural: embed` and `probe_natural: compress`, one each;
- `probe_widths: <chip> prep=<p> main=<m>`, one per chip: this binary's trace widths;
- `probe_summary: …`, last.

Run it from the repository root (it reads `perf/bench_data/rv64/fib-elf`), on a host fit to build
the whitelist ("Where to run" in `docs/whitelist-rebuild.md`): the full walk is CPU-bound for
minutes.

## Fit the convert ladder

The convert rows are a fit over a corpus: the natural heights of every whitelist shape, weighted
by how often the 80-block p99 corpus uses each. The fitting and accounting tools, and the corpus,
are not part of this repository. The fit takes the probe's convert lines and this binary's trace
widths, extracted from the log as

```bash
sed -n 's/^.*probe_columns: /# columns: /p; s/^.*probe_natural: convert //p' probe.log | gzip -c > tier-probe.txt.gz
sed -n 's/^.*probe_widths: //p' probe.log > widths.txt
```

together with the corpus's core-row weights under the current core ladder, and chooses the three
rows that minimise the corpus's padded cost. Before a new fit, reproduce the previous one with the
same tools: a fit that does not reproduce means the tools or the weights have drifted. The three
rows go into `MLE_RECURSION_CONVERT_LADDER`, cheapest first. For the shipped tables they came out
at W 19 / 42 / 74 (KoalaBear⁴: 21 / 37 / 62), with the corpus padded 6.6% over its natural
heights. Re-measuring all 15,646 shapes after the core ladder grew to 30 rows (27 of the 30 core
shapes new) reproduced the three rows chip for chip (corpus 859 / 4,290 / 34 chunks per row, padded
6.5%), and the combine, embed and compress rows measured over them were unchanged, so no table
moved.

## Write the other rows

The combine row is the per-chip maximum over the 36 `probe_natural: combine` lines; the embed and
compress rows are their one `probe_natural:` line each. No slack: the compress row decides the
whitelist-mode proof size, which must be the largest dev-mode shape, and the embed row
decides the embed proof's size and the wrap circuit's. The combine nodes verify children padded to
the convert rows, the deferred and compress programs a child padded to the combine row, and the
embed program a compress proof padded to the compress row as written (`compress_proof_layout`
reads `MLE_RECURSION_COMPRESS_LOG_HEIGHTS`), so the rows come from four probe runs, each over the
rows written before it. Run 1 gives the convert rows. Run 2, over the new convert rows, gives the
combine row, and over the old B child provisional compress and embed rows. Run 3 confirms the
combine row (its B-child nodes now verify a child padded to it) and gives the compress row. Run 4
confirms the combine and compress rows and gives the embed row (the embed program verifies a
compress proof padded to the compress row just written); if the compress row run 3 gave is the one
it ran over, run 3's embed line is already the row and run 4 only confirms it. For the shipped
tables run 2 moved Poseidon2Packed's combine peak to 2^18 at [C2,C2], and run 3 moved four B-child
nodes one notch on MemoryVar / ExtDotProduct, under the row already taken, and left the embed and
compress rows unchanged. A change to the compress row or the compress preset alone means run 4
again.

Then the assert-mode run must pass, with no "no row" line and no negative slack:

```bash
MLE_SHAPE_MARGIN=1 RUST_LOG=info,mle_shape_margin=info cargo run --release -p pico-vm --example mle_tier_probe
```

`total reclaimable notches` is the per-chip slack summed over a row: 0 on every row when the rows
are exact envelopes. A self-built-whitelist e2e (`VK_VERIFICATION=true` without `MLE_VK_MAP`,
`--step compress`, `MLE_SHAPE_MARGIN=1`) then shows the compress proof at its row: every `[compress]
<chip>: 2^a -> 2^b (slack s)` line at slack 0, and `Compress: stacked widths per commit` and
`Compress: proof serialized size` at the largest dev-mode shape (25 and 299,179 bytes); with
`--step embed` the embed proof likewise shows its row (`Embed: stacked widths per commit` 11 and
`Embed: proof serialized size` 239,319 bytes).

## What moves with the tables

- the convert ladder's doc comment in `shape.rs` (the per-row shape counts, the corpus split) and
  the rows' provenance lines;
- the `RecursionTier` doc, and the compress and embed presets' docs in `mle-core/src/config/mod.rs`;
- `docs/soundness/README.md`, section 3 (the measured compress size);
- `docs/whitelist-rebuild.md`, step 4's log line, if the leaf set changes;
- the whitelist artifact: every table edit but the embed row's is a rebuild; the embed row moves the
  soundness manifest and, through the embed key, the wrap circuit, its Groth16 setup and the
  on-chain verifier.
