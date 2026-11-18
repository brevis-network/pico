# Re-measuring the recursion tier tables

The recursion tier tables in `vm/src/mle/machine/shape.rs` — the convert ladder
(`MLE_RECURSION_CONVERT_LADDER`, three rows), the row of the global LogUp's group nodes
(`MLE_RECURSION_GROUP_NODE_LOG_HEIGHTS`), the combine row (`MLE_RECURSION_COMBINE_LOG_HEIGHTS`),
the embed row and the compress row — are the heights every whitelist-mode recursion program pads
to. They are measured, not derived. This page is how they were set for the 128-bit parameters
and how to set them again.

## When

After a change to a recursion circuit (the convert, combine, deferred, embed or compress program,
a node program of the global LogUp, or the compiler that lowers them), to a recursion preset, or to a recursion chip's columns or row count
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
would be verified by, then the global LogUp's nodes (the group node over 1 to 15 tables, the
image node at each of its 7 tiers), the 50 combine node shapes, the deferred and compress nodes,
and the embed node over the compress proof's layout (synthesized from a keygen of the compress program,
`compress_proof_layout`), and prints every natural height. On tables the circuits have outgrown it
runs in report-only mode, which asserts nothing:

```bash
MLE_TIER_PROBE_REPORT_ONLY=1 MLE_TIER_PROBE_STRIDE=50 MLE_SHAPE_MARGIN=1 \
  RUST_LOG=info,mle_shape_margin=info cargo run --release -p pico-vm --example mle_tier_probe
MLE_TIER_PROBE_REPORT_ONLY=1 MLE_SHAPE_MARGIN=1 \
  RUST_LOG=info,mle_shape_margin=info cargo run --release -p pico-vm --example mle_tier_probe
```

The first command (every 50th shape) is a timing run; the second is the measurement, about two
minutes on a many-core host. Its log carries, at `RUST_LOG=info`:

- `probe_columns: label <chip ×21>`, once: the chip order of every line below;
- `probe_natural: convert <label> <log2 ×21>`, one per riscv shape (4,598 for the shipped
  whitelist), and
  `<label>: no convert row holds it` for each shape the current ladder cannot hold;
- `probe_natural: group_node <tables> <log2 ×21>`, one per group size (15), and
  `probe_natural: image_node <tier> <log2 ×21>`, one per image tier (7);
- `probe_natural: combine <node> <log2 ×21>`, one per node shape (50; `<node>` is the label with
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

together with the number of the corpus's chunks that select each whitelist shape under the current
core ladder, and chooses the three rows that minimise the corpus's padded cost. Before a new fit,
reproduce the previous one with the same tools: a fit that does not reproduce means the tools or
the weights have drifted. The three rows go into `MLE_RECURSION_CONVERT_LADDER`, cheapest first.
For the shipped tables they came out at W 21 / 35 / 61, with the corpus padded 2.3% over its
natural heights (4,256, 457 and none of its 4,713 chunks per row). Row 2 was then raised by hand
to W 68 (ExtAlu 2^19, MleOpen 2^13) for the BLS12-381 G2 shapes, which no fitted row held.

Two things the fit does not know of. The last row has to sit over the other rows on every chip
(`convert_ladder_rows_close_under_the_last`), so it is the per-chip maximum over the whole
enumeration, not over the shapes that select it. And the first row has to hold the global LogUp's
image node at every tier, which pads to it; the probe checks that.

## Write the other rows

The group nodes' row is the per-chip maximum over the 15 `probe_natural: group_node` lines. It
depends on no other row. The combine row is the per-chip maximum over the 50
`probe_natural: combine` lines; the embed and compress rows are their one `probe_natural:` line
each. No slack: the compress row decides the whitelist-mode proof size, which must be the largest
dev-mode shape, and the embed row decides the embed proof's size and the wrap circuit's. The
combine nodes verify children padded to the convert rows, the group nodes' row and the combine
row, the deferred and compress programs a child padded to the combine row, and the embed program a
compress proof padded to the compress row as written (`compress_proof_layout` reads
`MLE_RECURSION_COMPRESS_LOG_HEIGHTS`), so the rows come from four probe runs, each over the rows
written before it. Run 1 gives the convert rows and the group nodes' row. Run 2, over them, gives
the combine row; its compress and embed lines are provisional, since the programs they measure
verify a child padded to the combine row as it stood before the run. Run 3, over the combine row
run 2 gave, confirms that row (the nodes with a combine-row child verify a child padded to it)
and gives the compress row. Run 4 confirms the combine and compress rows and gives the embed row
(the embed program verifies a compress proof padded to the compress row just written); if the
compress row run 3 gave is the one it ran over, run 3's embed line is already the row and run 4
only confirms it. For the shipped tables no pair with a group node sets a combine peak. A change
to the compress row or the compress preset alone means run 4 again.

Then the assert-mode run must pass, with no "no row" line and no negative slack:

```bash
MLE_SHAPE_MARGIN=1 RUST_LOG=info,mle_shape_margin=info cargo run --release -p pico-vm --example mle_tier_probe
```

`total reclaimable notches` is the per-chip slack summed over a row: 0 on every row when the rows
are exact envelopes, but for the last convert row, which carries what sitting over the other rows
costs it (7 for the shipped tables, on the chips whose heights keccak's and Bls12381DoubleAssign's shapes set in the row before it). A self-built-whitelist e2e (`VK_VERIFICATION=true` without `MLE_VK_MAP`,
`--step compress`, `MLE_SHAPE_MARGIN=1`) then shows the compress proof at its row: every `[compress]
<chip>: 2^a -> 2^b (slack s)` line at slack 0, and `Compress: stacked widths per commit` and
`Compress: proof serialized size` at the largest dev-mode shape (25 and 299,231 bytes); with
`--step embed` the embed proof likewise shows its row (`Embed: stacked widths per commit` 11 and
`Embed: proof serialized size` 239,371 bytes).

## What moves with the tables

- the convert ladder's doc comment in `shape.rs` (the per-row shape counts, the corpus split) and
  the rows' provenance lines;
- the `RecursionTier` doc, and the compress and embed presets' docs in `mle-core/src/config/mod.rs`;
- `docs/soundness/README.md`, section 3 (the measured compress size);
- `docs/whitelist-rebuild.md`, step 4's log line, if the leaf set changes;
- the whitelist artifact: every table edit but the embed row's is a rebuild; the embed row moves the
  soundness manifest and, through the embed key, the wrap circuit, its Groth16 setup and the
  on-chain verifier.
