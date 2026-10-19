# Examples

Guest programs for the Pico zkVM, with host programs that prove them. The fibonacci and tendermint
hosts run on the host prover crate, `pico-prover`; the aggregator host drives the machines in
`pico-vm` directly, because `pico-prover` has no entry point for deferred proofs. The fibonacci
guest can also be proved from the `cargo pico` CLI, and at the prover's defaults the fibonacci
host's `verify` accepts the RISC-V proof file the CLI writes.

| directory | what it shows |
|---|---|
| `fibonacci/` | the quick start. `app/` is the guest; `lib/` holds `PublicValuesStruct`, the ABI-encoded output a Solidity verifier decodes; `prover/` emulates the guest, proves it to a file, and verifies that file in a separate process |
| `tendermint/` | a light-client update between two real blocks: inputs the host encodes from JSON fixtures, an emulation checked before proving, a proof of the whole run, and an oracle that recomputes all three committed values on the host; `lib/` holds the verification the guest and the oracle share. **Needs a large machine** |
| `aggregator/` | a guest that claims other programs' proofs (`verify_pico_proof`) and recursion that closes those claims. `prover/` proves fibonacci twice, then the aggregator claiming both, and verifies the result in the same process |

The AOT emulation harnesses for fibonacci and reth are in `perf/aot/`, beside the fixtures they run.

## Setup

From the repository root:

```bash
cargo install --path sdk/cli --locked   # the `cargo pico` subcommand
cargo pico install                      # the toolchain guests build with
```

The guest ELFs under `*/app/elf/` are committed, so the provers run without the toolchain (the
aggregator's rv64 ELF is the same file as `perf/bench_data/rv64/aggregator-elf`, which the
deferred-proof tests in `vm/` run).
`cargo pico build` in an `app/` directory rebuilds one. `examples/` has no committed lock, so a
rebuild resolves the newest compatible dependencies and can give a different ELF, and so a
different program id. So can a rebuild from another checkout path: cargo hashes the absolute path
of `sdk/`, which lies outside this workspace, into the guest's symbols.

## Fibonacci from the CLI

In `examples/fibonacci/app`:

```bash
cargo pico build
cargo pico execute --elf elf/riscv64im-pico-zkvm-elf --input u32:100
cargo pico prove   --elf elf/riscv64im-pico-zkvm-elf --input u32:100 --phase riscv
```

`--input u32:100` is what the guest's `read_as::<u32>()` reads. `execute` emulates without keygen
and prints the committed bytes marked as not proved. `prove` proves, verifies the proof, writes
`pico_out/proof-riscv.pico`, and prints the program id.

The CLI has no `verify`. A process that holds the ELF verifies the file through `pico-prover`, and
the fibonacci prover does exactly that. In `examples/fibonacci/prover`:

```bash
cargo run --release -- verify ../app/pico_out/proof-riscv.pico
```

It verifies at the prover's defaults outside whitelist mode, the operating point the `prove` above
used. A file proved at another `--log-stacked-height` or with `VK_VERIFICATION=true` is refused as
an operating-point mismatch: the verifier chooses the operating point, never the file.

## Fibonacci from Rust

In `examples/fibonacci/prover`:

```bash
cargo run --release -- execute 100
cargo run --release -- prove fibonacci.pico 100
cargo run --release -- verify fibonacci.pico
```

Each command decodes the committed bytes as `PublicValuesStruct`, recomputes the sequence from the
`n` inside it, and refuses bytes that are not exactly its encoding; `execute` and `prove` also
refuse an answer for any `n` but the one they gave the guest. On an Apple M4 laptop (10 cores,
24 GB), `execute` takes about a second, `prove` 25 s at a 6.7 GB peak, and `verify` 9 s.

## Tendermint

In `examples/tendermint/prover`:

```bash
cargo run --release
```

The prover checks the guest's three committed values (both header hashes, then the verifier's
verdict) against the same verification run on the host: first on an emulation, then on the proof.

**It needs a large machine.** It proves at the prover's defaults, and on a 124-core, 920 GB server
the run of 19.1 million cycles takes 2 min 28 s at a 206 GB peak. It does not fit a laptop.

A smaller machine can trade proving time for memory through `Prover::builder`. Measured on the same
server with proving limited to 10 threads (`RAYON_NUM_THREADS=10`):

| options | chunks | peak memory | wall clock |
|---|---|---|---|
| the defaults: `log_stacked_height` 23, `concurrency` 4 | 3 | 199 GB | 6 min 42 s |
| `log_stacked_height(21)`, `concurrency(1)` | 10 | 33 GB | 8 min 50 s |
| `log_stacked_height(20)`, `concurrency(1)` | 19 | 26 GB | 10 min 45 s |

A lower stacked height gives more, smaller chunks. Two chunks at a time at height 20 took as long
and peaked at 33 GB. None of these fits in 24 GB.

## Aggregator

In `examples/aggregator/prover`:

```bash
RUST_LOG=info cargo run --release -- prove
```

The guest takes a list of program ids and committed outputs and calls `verify_pico_proof` on each
pair. Inside the guest that only records the claim, in the run's `deferred_proofs_digest`; the
recursion tree is what checks it, with one deferred node per claim verifying a complete proof of the
claimed program. So the prover first proves fibonacci for `n` = 10 and 20 to a combine root each,
then proves the aggregator over those two claims, a deferred node over each root, and finally one
root over the nodes and the aggregator's chunks. It verifies that root, checks that it closes over
the guest's claims folded on the host, and checks the committed outputs against the inputs.
`RUST_LOG=info` shows each step; without it only the summary prints. On a 124-core server the run
takes about a minute at a 6 GB peak.

It runs in dev mode (no whitelist) and verifies only in the process that proved: a combine root
verifies in another process only in whitelist mode, so this example writes no proof file.

## Which proof file another process can verify

A verifier chooses its operating point, the stacked height and the mode, and refuses a file proved
at any other.

| phase | CLI writes | who can verify it |
|---|---|---|
| `riscv` | `proof-riscv.pico` | any process with the ELF, at the file's operating point, because a RISC-V verifying key is derived from the program. In whitelist mode the verifier also needs `vk_map` and `trusted_vk_root`, as every whitelist-mode prover does. The proof covers each chunk of the run, not the run as one execution |
| `combine` | `proof-combine.pico` | another process only in whitelist mode: `VK_VERIFICATION=true`, `MLE_VK_MAP` and `MLE_VK_ROOT` for the CLI, `ProverBuilder::verify_keys(true)` with `vk_map` and `trusted_vk_root` for `pico-prover`. Outside it, `Prover::prove` returns the combine proof already verified, in the process that made it |

These examples run outside whitelist mode, so the program id they print is not the one an on-chain
verifier pins: whitelist mode pads the program table before committing to it, and the same ELF has
a different id there.
