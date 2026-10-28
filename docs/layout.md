# Pico Repo Layout

## Workspace crates

The root workspace (`Cargo.toml`) has these members:

| path | crate | what it is |
|---|---|---|
| `sdk/cli` | `pico-cli` | the `cargo pico` subcommand: `install`, `build`, `execute`, `prove`, `aot`, `new`. It has no `verify`; `prove --evm` runs gnark (`gnark/`) for the Groth16 step |
| `sdk/prover` | `pico-prover` | the host prover: `Prover`, `ProverBuilder`, `Stdin`, `Phase`, `Proof`, `ProofArtifact`, `EvmBundle`. Its crate documentation is the API guide |
| `sdk/sdk` | `pico-sdk` | the guest SDK: `entrypoint!`, `io` (`read_as`, `read_vec`, `commit`, `commit_bytes`), syscalls (`riscv_ecalls`), Poseidon2 hashing |
| `sdk/patch-libs` | `pico-patch-libs` | syscall wrappers used by the patched crates (sha2, keccak, curves, BLS12-381, BN254, ...) |
| `vm` | `pico-vm` | the zkVM: compiler, emulator, chips, and the machines of every phase (see below) |
| `mle-core` | `pico-mle-core` | the MLE/WHIR STARK backend core (KoalaBear only): config, transcript, symbolic AIR, interactions, PCS / sumcheck / LogUp / WHIR prover and verifier, reference device, `StarkEngine`, and the soundness calculator |
| `mle-cpu` | `pico-mle-cpu` | the row-major CPU device backend (`CpuBackend`, `CpuDevice`) for `pico-mle-core` |
| `cuda-mle` | `cuda-mle` | the GPU device backend for `pico-mle-core`: LogUp-GKR, zerocheck, stacked reduction and WHIR on CUDA. Built into `pico-vm` by its `cuda` feature |
| `gpu-api` | `pico-gpu-api` | GPU trace generation for the RISC-V, precompile and recursion chips, and the CUDA bindings `pico-vm` calls. Compiled with `nvcc`, only in a `cuda` build |
| `distributed-vm` | `distributed-vm` | the proving entry points, on the GPU (on the CPU with `PICO_CUDA=0`): `mle-single-node` (one host, one or more cards; also the two-machine split), `mle-ethproofs-single-node` and `mle-ethproofs-vk-bundle`, and the gRPC proving-network and ethproofs clients. See [`distributed-vm/README.md`](../distributed-vm/README.md) |
| `aot-codegen` | `pico-aot-codegen` | ahead-of-time compilation of a guest's RISC-V code to Rust crates (`cargo pico aot`, `bin/generate_crates`) |
| `aot-runtime` | `pico-aot-runtime` | runtime types for running AOT-compiled guests |
| `derive` | `pico-derive` | procedural macros (`aligned_borrow_derive`, from Valida) |
| `gnark/field-ffi` | `field-ffi` | KoalaBear arithmetic exposed to the gnark circuit's hint functions |
| `perf` | `pico-perf` | shared benchmark code, with AOT glue behind its `aot` feature |

`aot-generated` (`pico-aot-dispatch`) is not a member: it is a bootstrap stub that `cargo pico aot`
or `generate_crates` replaces with code generated from a guest's ELF.

The CUDA kernels live in a separate repository, [pico-gpu](https://github.com/brevis-network/pico-gpu),
which `Cargo.toml` pins by commit; `cuda-mle` and `gpu-api` compile them. To build against a local
pico-gpu checkout, pass a `[patch]` on the command line instead of editing `Cargo.toml`:
`--config 'patch."https://github.com/brevis-network/pico-gpu.git".pico-gpu.path="<checkout>/rust"'`.

## `vm`

- `compiler`: compiles RISC-V ELFs and recursion programs into the programs the emulators run.
  `compiler/test_elf` holds test ELFs.
- `emulator`: the RISC-V and recursion emulators, which turn a program and its input into the
  records the machines prove.
- `chips`: the AIRs (chips, gadgets and precompiles) the machines are built from.
- `instances`: the RISC-V and recursion chip-type lists, and the IR and circuit builder that
  recursion programs are written in.
- `machine`: machine-generic building blocks (chips, lookups, witnesses, emulation reports).
- `mle`: the MLE machines of every phase (`riscv`, `convert`, `combine`, `embed`, `wrap`), the
  recursion compiler for them, shape selection, and the verifying-key whitelist (`mle/machine/vk_map.rs`,
  shipped artifact in `mle/shape_vk_bins/`).
- `configs`: field and STARK configurations.
- `primitives`: constants and types shared across the crate.
- `proverchain`: the snapshot-based RISC-V emulation pipeline.
- `iter`, `thread`: parallel-iteration and channel helpers.
- `examples`: developer entry points. `test_mle_e2e.rs` runs the chain and can stop at a given
  phase (`--step`); `mle_build_vk_map.rs` builds the whitelist; `mle_soundness_manifest.rs`
  regenerates the soundness manifest.
- `examples/patch-testing`: a separate workspace with one guest/prover pair per patched crate
  under `patches/`.
- `tests`: integration tests, including the RISC-V constraint parity test.

## Other workspaces and directories

- `examples`: a separate workspace with the fibonacci, tendermint and aggregator examples;
  [`examples/README.md`](../examples/README.md) walks through them from the CLI and from Rust.
- `perf/aot`: a separate workspace of AOT emulation harnesses and record-parity checks against the
  interpreter.
- `perf/bench_apps`: a separate workspace with the benchmark guests (fibonacci, reth, tendermint).
- `perf/bench_data`: the ELFs and block inputs the benchmarks and tests run.
- `gnark`: the Go Groth16 layer for the wrap-phase artifacts (`pico-gnark`), and its Dockerfile;
  see [`gnark/README.md`](../gnark/README.md).
- `contracts`: the Solidity verifier (`PicoVerifier`, `IPicoVerifier`) with Foundry tests and a Groth16
  verifier from a test setup; see [`contracts/README.md`](../contracts/README.md).
- `audits`: third-party security review reports.
- `docs`: project documentation.
- `single_node_mle.sh`, `two_machine_mle.sh`, `ethproofs_single_node_mle.sh`: launchers for the
  `distributed-vm` binaries on a CUDA host; `sweep_reth_mle.sh` proves every block input in a
  directory from one process. `bench-scripts` holds the tools that summarise and draw their logs,
  and `ci/test_*.sh` the launchers' own tests.
- `.github/workflows`: CI, run on pull requests to `main` and `release/v*` and on pushes to `main`.
  `lint.yml` explains how the checks are split across the files there; `build-cuda.yml` and
  `scripts.yml` run only when the paths they check change.
