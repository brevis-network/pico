# Deferred proving on the MLE stack

A guest can claim that some other proof exists — "program `vk` produced output `pv`" — and go on
using that fact. `verify_pico_proof(vk_digest, pv_digest)` is how it says so. Nothing is checked
when it says it: the syscall is a no-op in the emulator (`emulator/riscv/syscalls/verify.rs`), and
the guest merely folds the claim into a running digest, which it commits to its public values just
before halting. Making the claim mean something is the recursion layer's job, and that is what this
document describes.

## The chain

The tree carries a hash chain in two recursion public values, `start_reconstruct_deferred_digest`
and `end_reconstruct_deferred_digest`. Laid out across a tree it looks like this:

```
  0
   ├─ deferred node 1 :  start = 0    , end = D₁ = H(0    ‖ sub₁.riscv_vk_digest ‖ sub₁.cvd)
   ├─ deferred node 2 :  start = D₁   , end = D₂
   │  …
   ├─ deferred node k :  start = D_{k-1}, end = D_k
   ├─ convert leaf 1  :  start = end = W       ← every leaf carries the same W
   │  …
   └─ convert leaf m  :  start = end = W
  root : start_reconstruct == 0  ∧  end_reconstruct == deferred_proofs_digest
```

Three things make it close:

- **Deferred nodes advance it.** Each verifies one COMPLETE recursion root of a *sub-program* and
  hashes that proof's identity and output into the chain — the same preimage and sponge as the
  guest's `hash_deferred_proof`, which is what makes the two comparable at all
  (`ConvertVerifierCircuit::build_deferred_program`). A node also requires its child's own
  `deferred_proofs_digest` to be zero: a sub-proof that itself deferred would ride its unverified
  claims into this chain, and nothing below would check them.
- **Leaves are transparent.** A convert leaf witnesses one value and writes it to *both* ends, so
  it neither creates nor consumes a step. Cross-child continuity forces every leaf in one tree to
  the same value.
- **The root closes both ends.** `start_reconstruct == 0` and
  `end_reconstruct == deferred_proofs_digest` (`Builder::assert_root_complete`). Together with the
  chain that means: the digest the guest committed equals the chain the nodes actually built.

A program that defers nothing needs no node: its digest is zero, the leaves carry zero, and the two
ends agree. A program that commits a digest with no node to back it cannot close — which is the
fail-closed property the old per-chunk `deferred_proofs_digest == 0` assert used to provide
directly.

## Where a deferred node may sit, and why

Only at the head. A node publishes `start_chunk == next_chunk == 1`, while every convert leaf sets
`next_chunk = chunk + 1`. Nothing local bounds a leaf's `chunk` from below — the in-circuit range
check only decomposes it into bits — but the root pins `start_chunk == 1` and cross-child
continuity (`next_chunk` of one child against `start_chunk` of the next) numbers the leaves up from
there, so in a tree that can close no leaf leaves the cursor at 1 for a node to follow. A node is
therefore admitted before the chunk-1 leaf or beside another node, and nowhere else.
`CombineMachine::prove_tree` checks the same thing host-side, only so the failure is a sentence
rather than a root proof that does not verify.

The node is otherwise transparent to everything the tree chains: no execution chunk, memory cursors
closed, `exit_code` zero, the neutral GCS point, `flag_complete` zero so it can never pose as a
root. Two of its fields are free witnesses — the main program's `riscv_vk_digest` and entry pc —
and continuity pins both against the execution leaves.

One consequence worth knowing before touching the continuity links: with a node leading the tree,
the root's `start_chunk == 1` and `previous_*_addr == 0` read that node's baked constants rather
than a leaf's trace-bound values. Those asserts become tautologies and the real binding moves onto
continuity. The property survives; continuity is then the only thing holding it.

## Two facts that are easy to get wrong

**The carrier is not one vector.** Two airs declare `RISCV_NUM_PVS` public values — `CpuChip` and
`EcallChip` — and each gets its own vector in the proof, which the verifier observes separately and
never equates. They pin disjoint fields: Cpu takes `execution_chunk` and the pc ends, Ecall takes
`exit_code` and both commit digests. The convert layer ties the (otherwise unconstrained) Global
carrier to *every* present air of that count, and requires Cpu and Ecall to be present together;
tying only the first would leave everything Ecall owns free in the copy the whole tree reads.

**The digest comes from one chunk.** The Ecall air binds `deferred_proofs_digest` only on the
eight COMMIT_DEFERRED_PROOFS rows the SDK's halt runs, and the prover chooses where chunks end — so
every other chunk's copy is free, including a halting chunk cut to hold nothing but HALT, and for
a program that defers nothing a free copy cannot be told apart from an honest zero. Ecall
therefore also publishes how many of those rows its chunk ran and the sum of `2^word_index` over
them. A convert leaf requires the count to be 0 or 8, with all eight indices distinct, and
contributes the chunk's digest only when it is 8; every other chunk contributes zero, whatever its
copy says. The merge sums the contributions. The emulator holds the chunk cut while the run is in flight (the commit-tail
hold in `chunk_split`, up to 2048 clk), so an honest execution has exactly one such chunk.

A guest that halts without the SDK has to commit the same way: all eight words, once, in one run.
One that commits some words, or commits twice, cannot be proved; one that never commits leaves its
`verify_pico_proof` claims unchecked, because a claim binds only once the digest carrying it is
committed.

## Using it

`DeferredMachine::new` takes the **main** program's `RiscvVmVk`, not a sub-proof's: every node
publishes the main program's identity and entry pc, and continuity is what pins them.

```rust
let (nodes, digest) = deferred.prove_chain(&sub_proofs)?;  // one node per sub-proof, in order
convert.set_final_deferred_digest(digest);                 // every leaf carries this
let mut children = nodes;                                  // nodes FIRST
children.extend(convert.prove_with_vks(&riscv_proofs)?);
let root = combine.prove_tree(children)?;
```

The `vk_digest` a guest passes to `verify_pico_proof` is the sub-program's **MLE exe identity** —
`RiscvVmVk::digest()`, i.e. `H(DOMAIN ‖ program_commit ‖ pc_start ‖ initial_gcs)`. The removed FRI
stack hashed a verifying key instead, so a caller porting from it is passing the wrong value. The
`pv_digest` is the SHA-256 the sub-program committed, which is what its root carries in
`committed_value_digest`.

## Under the whitelist

With `vk_verification` on, a node checks its sub-proof the way combine checks its children: it
witnesses the whitelist root into its own `vk_root`, requires the sub-proof's `vk_root` to equal it,
and Merkle-checks the sub-proof's VK identity against it. Membership plus `flag_complete == 1`
admits only the complete-root combine shapes, since every other recursion program bakes the flag
to 0. The parent's `vk_root` agreement then ties the node, and through it the sub-proof, to the
root the apex pins.

The node pads to the combine tier, so to its parent it is one more B-shaped child: the standard
combine shapes already cover every pair it can sit in, and the whitelist gains exactly one leaf, the
node's own VK, after the combine nodes (`DeferredMachine::preregister`).

**A sub-proof must be proved under the same whitelist as the tree that consumes it.** Each rebuild
of the whitelist changes its root, so sub-proofs made before a rebuild have to be proved again
under the new one. `DeferredMachine::prove_chain` refuses one up front — not a member, not
complete, or proved under another root — so the failure is a sentence rather than a node that
does not verify.

## What is not wired yet

- **No production entry point.** `DeferredMachine` has no caller outside the examples; nothing
  ships a deferred tree. The GPU pipeline (`single_node_mle.sh`, the sweep, the distributed
  resident prover) neither builds nor accepts deferred nodes, and the tree it drives runs no
  `check_deferred_prefix`.

## Gates

CI runs none of these on this branch. The deferred examples build with `--features cuda-mle` too,
which proves their riscv chunks on the GPU (the aggregator's then exercise the GPU Ecall tally),
except `test_mle_deferred_split`, which builds its chunk contexts on the host and runs on the CPU
build only.

| | |
|---|---|
| `test_mle_deferred` (by hand) | proves one node over a real root; checks its public values and that its in-circuit chain step equals `hash_deferred_proof` |
| `test_mle_deferred_chain` (by hand) | over fib: a baseline that must prove, plus two cases that must fail at the root — one isolating `end_reconstruct == deferred_proofs_digest`; over the aggregator guest (`perf/bench_data/rv64/aggregator-elf`), claiming fib's root twice: a tree with both nodes must prove, the same leaves carrying no chain must fail, a tree with only the first node must be refused by combine's host-side seam check and, with that check off, fail at the root, while the aggregator claiming fib's root once, one node ahead of its leaves, must prove; a node over the proved two-node tree's root, whose own deferred digest is not zero, must fail to verify, while the same node keygen'd without the zero-digest requirement must prove |
| `test_mle_deferred_split` (by hand) | a halt-only chunk carrying a forged digest behind real nodes, and a cut inside the commit run, must both fail; with the commit-tail hold, the run stays whole across a sweep of chunk sizes and a representative run proves |
| `test_mle_deferred_whitelist` (by hand) | under the whitelist (the shipped artifact via `MLE_VK_MAP`/`MLE_VK_ROOT`, or a self-map): the aggregator tree with two nodes must prove and pass the apex; refused when the sub-proof is unlisted, proved under another root or not complete, when the node's Merkle path is forged or its own VK unlisted, and when the apex pins another root |
| `test_carrier_tie` (by hand) | the tie the chain rests on: a carrier that disagrees with Ecall's copy is rejected |
| `test_mle_e2e` (by hand) | the regression: an honest tree still proves, the chain degenerating to zero |
