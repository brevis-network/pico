# Requirements

Pico 3.1.0-gpu.1 (release `v3.1.0-gpu.1`, on the `gpu` branch). For the CPU-only 3.0 release, see
this page at `v3.0.0`.

## Host platform

This branch builds and runs on `x86_64-unknown-linux-gnu` (x86-64 Linux) only. `cargo pico install`
also ships a guest toolchain for `aarch64-apple-darwin`, but no crate that depends on `pico-vm`, the
CLI and the SDK included, builds on macOS: they compile CUDA. See the [support matrix](./support-matrix.md).

## CUDA and GPU

- The [CUDA Toolkit](https://developer.nvidia.com/cuda-downloads), with `nvcc` on `PATH`, to build any
  crate that depends on `pico-vm`, the CLI and the SDK included. CI builds with 12.3 and the GPU
  runs used 12.8; pico-gpu is also tested with 13 on an RTX 5090.
- For the GPU prover's binaries (`distributed-vm`): `protoc` 21.x from an official release, with its
  includes, and `libssl-dev`, `m4` and `google-perftools` (`libtcmalloc.so`).
  [`how-to-setup-gpu-machine.md`](./how-to-setup-gpu-machine.md) walks through a fresh Ubuntu host,
  including generating the AOT crates `single_node_mle.sh` needs.
- An NVIDIA GPU and its driver to run the emulator, which every execute and prove does, on the CPU
  prover as well: its event buffers are CUDA pinned memory. Without a device it stops with
  `Failed to create event buffer: ErrorNoDevice`.
- The GPU prover's memory thresholds are calibrated on 32 GB cards (RTX 5090); `single_node_mle.sh`
  also has a 24 GB tier.

## Always

- [Git](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git)
- [Rust via rustup](https://www.rust-lang.org/tools/install), with the nightly the repository pins in
  [`rust-toolchain`](../rust-toolchain): `nightly-2026-09-27`. The CLI and host code (`pico-prover`)
  build with it. `cargo pico install` installs it as well, with its `rust-src` and `cargo`
  components, because guests build `std` from those sources.

Install the CLI and the guest toolchain:

```bash
rustup toolchain install nightly-2026-09-27
cargo +nightly-2026-09-27 install --git https://github.com/brevis-network/pico --tag v3.1.0-gpu.1 --locked pico-cli
cargo pico install
```

or, from a checkout of the repository at `v3.1.0-gpu.1`:

```bash
cargo install --path sdk/cli --locked
cargo pico install
```

## Only for the EVM path (`cargo pico prove --evm`)

`--evm` runs gnark for the Groth16 proof. Provide **one** of:

- a `pico-gnark` binary (`PICO_GNARK_BIN`): needs [Go](https://go.dev/doc/install) 1.24 or newer
  and the `field-ffi` library built with Cargo; see [`gnark/README.md`](../gnark/README.md);
- a Docker image built from [`gnark/Dockerfile`](../gnark/Dockerfile) (`PICO_GNARK_IMAGE`): needs
  [Docker](https://docs.docker.com/engine/install/). No prebuilt image is published or pulled by
  default.

[Foundry](https://book.getfoundry.sh/getting-started/installation) is needed to build and test the
verifier contracts in [`contracts/`](../contracts).

## Memory

Proving memory depends on the program. The only figures in this repository are measurements of
the examples with the 3.0 CPU prover, not guarantees:

| what | machine | peak memory | wall clock |
|---|---|---|---|
| fibonacci, `prove` (RISC-V phase) | Apple M4 laptop, 10 cores, 24 GB | 6.7 GB | 25 s |
| tendermint, prover defaults (19.1 M cycles) | 124-core server, 920 GB | 206 GB | 2 min 28 s |
| Groth16 setup of the wrap circuit | one machine | 17 GB | 3 min 39 s |
| Groth16 prove of the wrap circuit | one machine | 12 GB | 24 s |

Sources: [`examples/README.md`](../examples/README.md) (including how a lower stacked height
trades time for memory) and [`gnark/README.md`](../gnark/README.md).
