# Rebuilding the MLE VK whitelist

The whitelist is the artifact `VK_VERIFICATION=true` proves under. It is a per-config, per-code
deliverable: when the code that determines a recursion verifying key changes, the artifact is
rebuilt in full. There is one procedure, no partial update. This page is that procedure.

The procedure runs on the CPU prover's tree. The GPU prover's tree copies the artifact while the
two trees' AIRs agree and builds its own while they do not (see "The CPU and GPU trees" below).
The GPU tree's CI does not run the artifact unit test, so where this page says CI checks
something, it means the CPU tree's CI.

## What ships

Two files in `vm/src/mle/shape_vk_bins/`, committed together and read together:

| file | holds | read by |
|---|---|---|
| `mle_vk_map_kb.bin` | the whitelist: the `(pre_hash, merged_preprocessed_commit)` identity of every admitted convert VK (one per riscv shape the shape config enumerates), of every combine node VK and of the deferred node VK, in leaf order, plus the shape config digest and the Merkle root | `MleVkMap::load` (`MLE_VK_MAP`); every combine and deferred witness looks its children up in it |
| `mle_vk_root.txt` | the same digest and root as text, the `MLE_VK_ROOT="..."` line being the constant a deployment pins | operators (`MLE_VK_ROOT`), the SDK's whitelist tests, the artifact unit test |

The bin is self-contained for membership proofs: the tree is rebuilt from the leaves on load,
`path(index)` gives the sibling path. The root file is what makes the bin trusted: `MleVkMap::load`
refuses an artifact whose root is not the pinned one (when `MLE_VK_ROOT`, or the SDK's
`trusted_vk_root`, pins one), whose digest is not this binary's, or whose leaves do not recompute
its root. Nothing else is needed at runtime; the VKs themselves are
keygen'd by the prover and checked against the map.

`mle_vk_map_kb.json` is the same artifact in a readable form for debugging. It is not shipped.

## When a rebuild is due

Any of these, on the branch the artifact ships from:

| change | what moves | caught before a proving run by |
|---|---|---|
| a shape table (`MLE_CORE_LADDER`, `MLE_RISCV_MAIN_LOG_HEIGHTS`, the precompile or memory enumeration, `MLE_RISCV_PROGRAM_LOG_HEIGHT`), a recursion tier table (`MLE_RECURSION_CONVERT_LADDER`, combine, embed), `MLE_VK_MERKLE_DEPTH` | the config digest, the leaf set, the root | the digest check in `MleVkMap::load`, the artifact unit test |
| an AIR's columns, constraints or interactions | the convert VKs of every shape that AIR is present in: a precompile AIR moves its kind's shapes, `Cpu` or `Ecall` the core rows, `MemoryInitialize` the memory shapes | the constraint parity test (`riscv_constraint_parity`), and the artifact unit test through the shape it probes for that family |
| an AIR added or removed, `DEFAULT_LOG_STACKED_HEIGHT`, the riscv or recursion params, the recursion compiler or lowering, the combine or deferred circuit | every convert VK and/or every combine node VK and/or the deferred node VK | the artifact unit test |

The digest covers only the first line of the table. The others move keys without moving the
digest, which is why the artifact unit test (`the_shipped_artifact_matches_this_binary`, run by
the CPU tree's CI) keygens, from the binary under test, the riscv vk, one convert VK per shape family (the first
core row, the first memory shape, the first shape of each precompile kind), one combine node and
the deferred node, and requires them to be members. When that test or the parity test fails after a change, rebuild;
there is no way to patch the file.

Do not classify the change to save keygen time. The full build is about an hour and a half on
eight workers; the classification is where mistakes are made (a checkpoint reused across a
compiler change puts stale keys in the artifact, and only the shapes a self-check happens to
touch would notice).

## Where to run

The build is CPU keygen, no GPU. Before running, agree with the operator of the machine on the
box, the working directory, the number of workers (`MLE_VK_MAP_THREADS`, default 8; each worker
is one keygen at a time, memory per worker is single-digit GB) and how long it may hold the
machine.

The inputs are in the tree, in the builder's default `MLE_VK_MAP_RETH_DIR`
(`./perf/bench_data/rv64`, relative, so run from the repository root): `fib-elf`, the program the
riscv vk and self-check (b) are keygen'd and proved on; `reth-elf` and four reth witnesses,
`reth-17106222.bin`, `reth-18884864.bin`, `reth-23993050.bin` and `reth-24600825.bin`, which
self-check (a) emulates. More blocks are optional: point `MLE_VK_MAP_RETH_DIR` at a directory that
holds `fib-elf`, `reth-elf` and their `reth-<block>.bin` files.

Leave `MLE_LOG_STACKED_HEIGHT` unset: the artifact is keyed to the stacked height the prover
ships with (`DEFAULT_LOG_STACKED_HEIGHT`), and a build at another height is a different config.
Set `CHUNK_SIZE=8388608` and `SPLIT_THRESHOLD=2097152`: the self-checks emulate with the default
emulator options, whose chunk size and deferred split threshold otherwise follow the host's memory,
while the SDK prover cuts chunks of 2^23 at the shipped stacked height and splits deferred
records at a quarter of that, 2^21. Unpinned, (a) on another host checks chunks the prover never
cuts.

## Procedure

1. Start from the latest commit of the branch the artifact ships from, on a clean tree:
   `git fetch origin && git switch -c <branch> origin/<that branch>` (a local ref can be far
   behind), and note `git rev-parse HEAD` beside the build log. The CPU tree builds the artifact;
   the section on the two trees says when the GPU tree builds its own.
2. Remove any checkpoint from an earlier build: `rm -f mle_vk_map.ckpt` (or whatever
   `MLE_VK_MAP_CKPT` names). The builder refuses a checkpoint written by another build of the
   convert programs, but a full rebuild starts from none.
3. Run the builder with both self-checks on, from the repository root:

   ```bash
   OUT=<a new directory outside the repository>
   mkdir -p "$OUT"
   RUST_LOG=info CHUNK_SIZE=8388608 SPLIT_THRESHOLD=2097152 \
   MLE_VK_MAP_OUT="$OUT/mle_vk_map_kb.bin" \
   MLE_VK_MAP_THREADS=8 \
   MLE_VK_MAP_RETH_BLOCKS=17106222,18884864,23993050,24600825 \
   cargo run --release -p pico-vm --example mle_build_vk_map 2>&1 | tee "$OUT/build.log"
   echo "exit=${PIPESTATUS[0]}"
   ```

   Three details of this command matter. `RUST_LOG=info`: the logger is off unless `RUST_LOG` is
   set, and without it none of the lines step 4 reads are printed. `mkdir -p`: the builder writes
   into the directory only after the last keygen, so a missing directory costs the whole run.
   `PIPESTATUS[0]`: behind `tee`, `$?` is `tee`'s status, not the builder's.

   The artifact, its `.json` twin and `mle_vk_root.txt` land in `$OUT`. Self-check (a)
   emulates the named blocks and requires every chunk's selected shape to be an enumerated one;
   (b) proves fib-10 and requires each real proof's layout to equal the one synthesized for its
   shape and each real convert VK to be a member. `MLE_VK_MAP_PROVE_BLOCK=<block>` makes (b)
   prove a reth block instead; it is slower and not required. `MLE_VK_MAP_LIMIT=<n>` keygens only
   the first `n` shapes and writes no artifact: a timing run, which still appends to the
   checkpoint, so remove the checkpoint again before the build.
4. Read the exit code and the log. `0` means built and every validation passed; `3` built but a
   validation failed (each is logged as `VALIDATION FAILED`); `101` a panic, which can come
   before or after the artifact file is written, so a file on disk is not a successful build.
   Keep these lines from the log, as printed, with the change that triggered the rebuild:
   - `whitelist riscv shapes: N (0 checkpointed, N to keygen, 8 workers)`: a full build starts
     from 0;
   - `leaves: N convert + M combine + 1 deferred = T`;
   - `  config digest = [...]` and `  root          = [...]   (MLE_VK_ROOT="...")`;
   - `(a) ✓ ... chunk(s) over 4 block(s)` and `(b) ✓ fib-10: ...`;
   - the last line, ``validations passed; artifact `...` ``.

   Anything else stops the rebuild: an exit code other than `0`, a missing line, a panic, a
   test failing in step 7. Report the exit code and the log to the person who asked for the
   rebuild and agree the next step with them; do not change tables, rerun with other settings or
   ship the files on your own.
5. Copy the two outputs from `$OUT` into `vm/src/mle/shape_vk_bins/`, overwriting the
   shipped pair: `mle_vk_map_kb.bin` and `mle_vk_root.txt`. Nothing else in the tree changes with
   the artifact but the soundness manifest (step 6): the leaf count the unit test expects is
   derived from the shape config. (A shape-table change moves three literals with the change
   itself, not with the artifact: the count in `the_whitelist_shape_count_is_pinned`, the headroom
   figures on `MLE_VK_MERKLE_DEPTH` and the shape counts in the `MLE_RECURSION_CONVERT_LADDER` doc
   comment.)
6. Regenerate the soundness manifest (`docs/soundness/README.md` section 2) from the repository
   root, with `CHUNK_SIZE` and `SPLIT_THRESHOLD` unset: step 3 sets them for the builder only, and
   the generator refuses them.

   ```bash
   cargo run --release -p pico-vm --example mle_soundness_manifest
   ```

   The manifest records the shipped whitelist's root, and the artifact unit test of step 7 fails
   until that root is the one in `mle_vk_root.txt`. It also records the commit it was generated at
   and every tracked file, itself excepted, that differs from that commit; with the two new files
   not committed yet, this run records them and is marked `dirty`, which `pico-mle-core`'s
   `manifest_identities_are_recorded` refuses. Step 8 regenerates it from the commit.
7. Verify the tree against the new files:

   ```bash
   cargo test --release -p pico-vm --lib mle::machine::vk_map
   cargo test --release -p pico-prover -- --ignored --test-threads=1 tests::whitelist
   ```

   The first includes the test CI runs. CI's own proving runs are whitelist-off
   (`VK_VERIFICATION: false` in the workflow): its whitelist checks are that test and the SDK's
   `the_shipped_whitelist_loads_under_its_published_root`, and neither proves under the
   whitelist. The second command does: it proves fib under the whitelist with the shipped root and
   verifies the proof in a fresh process, which takes minutes and tens of GB (hence one thread;
   CI skips it). It is the check that the artifact works end to end.
8. Commit the two files in one commit whose message names the change that made the rebuild
   necessary and quotes the leaf count, digest and root. Then run the step 6 command again, which
   now records that commit and no dirty file, and commit the manifest. Open the PR; CI runs the
   artifact test and the soundness manifest's tests against the new files.

## The CPU and GPU trees

Two trees keygen identical keys exactly when the code that determines them (the riscv AIRs,
the shape tables, the recursion compiler and params) is identical, so:

- while it is, mirror the code change to the GPU tree first, then copy the same two files from
  the CPU tree unchanged;
- while it is not (the GPU tree carries riscv AIR changes the CPU tree does not have yet), build
  the artifact on the GPU tree with the procedure above, and go back to copying once the trees
  agree again;
- never let the trees ship different artifacts for the same code, or the same artifact for
  different code: the change that moved the keys and its artifact travel together;
- verify on a GPU host before merging, with the single-node pipeline: first fib, then one reth
  block whose witness is in `perf/bench_data/rv64/`:

  ```bash
  VK_VERIFICATION=true MLE_VK_MAP=vm/src/mle/shape_vk_bins/mle_vk_map_kb.bin \
  MLE_VK_ROOT="<the root file's MLE_VK_ROOT>" MLE_VERIFY=1 \
  MLE_ELF=fib MLE_N=10 ./single_node_mle.sh
  MLE_ELF=reth MLE_N=<block> ... ./single_node_mle.sh
  ```

  The run passes when the log carries `MLE convert complete: all N convert proof(s) proved +
  verified` and `standalone apex verify` with their check marks: the GPU riscv, convert and
  combine machines proved under the shipped root and the apex accepted it. The GPU tree's CI runs
  no whitelist test, so run the artifact unit test by hand as well
  (`cargo test --release -p pico-vm --lib mle::machine::vk_map`); no CI runs a GPU proof.

## When a proof fails under the whitelist

Two places, two meanings:

- **At shape selection** (`select_riscv_shape` panics: "no MLE core shape holds this chunk" or "no
  MLE shape holds this chunk"): a chunk's natural heights exceed even the catch-all row for some
  air. The guest or workload needs a taller catch-all or a wider enumeration; that is a shape
  table change, followed by a rebuild.
- **At a key check** (the SDK's `KeyNotWhitelisted` at Convert or Combine, or a panic "child VK
  not in the whitelist (vk map)" at the parent of a convert leaf or combine node whose key the
  prover derived): the chunk's shape was selected, but the key the prover derived is not in the
  map: the artifact is stale for this binary (the unit test should have said so; rebuild). An
  artifact whose root is not the pinned one never gets this far: `MleVkMap::load` refuses it
  before proving starts.

A run that is slower with the whitelist on is not a failure: chunks prove at the row's padded
heights, not their natural ones. The cost is bounded by the ladder fit, not by correctness.

## Merkle depth

`MLE_VK_MERKLE_DEPTH` is 15, so the tree holds 32,768 leaves. A ladder row costs one leaf; a new
precompile kind sweeps its whole height enumeration (hundreds of shapes). When the enumeration
approaches the capacity, raise the depth: that invalidates every combine node VK (the depth is
baked into the membership circuit) and the root, so it is a rebuild like any other.

## Downstream of the root

The wrap circuit bakes the root in as a constant. A new root therefore means a new wrap circuit,
a new Groth16 setup and a new on-chain verifier. The artifact PR does not do this; it is a
release step, and the root file's `MLE_VK_ROOT` line is its input. The soundness manifest records
the root the test keys in `contracts/test/dev` were set up under, beside the shipped root.

## Refitting the ladder

Changing the core ladder (`MLE_CORE_LADDER`) is a shape table change and goes through the
procedure above. The fitting itself needs a corpus of natural heights taken with the probe
(`SHAPE_PROBE_NATURAL=1`) on the same emulator chunk-cut rules the prover will run with: a corpus
probed before a change to the chunk split lands chunks on neighbouring rows. The fitting and
accounting tools are not part of this repository.

## Checkpoints

The builder appends one line per finished shape to `MLE_VK_MAP_CKPT` (default `mle_vk_map.ckpt`),
keyed by the shape's content (its sorted `name:height` list), so a build that stopped can resume.
The key says nothing about the code, so on resume the builder keygens the first checkpointed
shape again and refuses the file if the identity differs. That is a safety net for an interrupted
build of the same code, not a way to reuse keys across a code change: a rebuild starts from no
checkpoint.

Every key the builder admits scores at least 100 bits (`docs/soundness/README.md`): each keygen
below that is refused, the probe's included. A resumed shape is not scored again, and need not be:
every convert key has the same recursion AIR set and preset, so the same shape and score, and the
probe has just been admitted under this build's calculator.
