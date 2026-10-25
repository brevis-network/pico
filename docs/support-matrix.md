# Pico 3.1.0-gpu.1 support matrix

For the preview release `v3.1.0-gpu.1` on the `gpu` branch. What is not listed is not supported.
The CPU-only 3.0 release is `v3.0.0` on `main`; its matrix differs from this one in the host
platform, CUDA and prover rows.

| area | 3.1.0-gpu.1 |
|---|---|
| Host platform | `x86_64-unknown-linux-gnu` with the CUDA Toolkit, for every crate that depends on `pico-vm`, the CLI and the SDK included. macOS: not supported on this branch (use `v3.0.0`). Other hosts: not supported |
| CUDA | Toolkit to build (`nvcc`): CI builds with 12.3, the GPU runs used 12.8, and pico-gpu is also tested with 13 on an RTX 5090. An NVIDIA GPU to prove on the GPU; the memory thresholds are calibrated on 32 GB cards (RTX 5090), with a 24 GB tier in `single_node_mle.sh`. The CUDA kernels are [pico-gpu](https://github.com/brevis-network/pico-gpu), licensed under BUSL-1.1 |
| Rust | `nightly-2026-09-27` (the repository's `rust-toolchain`) |
| Guest toolchain | `pico-ae9fd31`, installed by `cargo pico install` |
| Guest target | `riscv64im-pico-zkvm-elf` |
| Field and proof system | KoalaBear only; MLE STARK (LogUp-GKR, ZeroCheck, WHIR) |
| Prover | CPU, through the SDK and `cargo pico prove`, as in 3.0, but on a host with an NVIDIA GPU: the emulator's event buffers are CUDA pinned memory, so executing or proving without a device stops with `ErrorNoDevice`. GPU for the RISCV, CONVERT and COMBINE phases, through `distributed-vm`'s `mle-single-node` (`single_node_mle.sh`, one host and one or more cards, or two hosts) and `mle-ethproofs-single-node` |
| Phases | RISCV, CONVERT, COMBINE (the default), EMBED, WRAP; then Groth16 on BN254 via gnark for EVM verification |
| Verification | every proof is verified in the process that made it before it is returned. In another process: a RISCV proof file verifies from the ELF at the same stacked height and mode; a COMBINE proof file verifies only in whitelist mode |
| EVM / on-chain | whitelist mode only (`VK_VERIFICATION=true`, `MLE_VK_MAP`, `MLE_VK_ROOT`, default stacked height). Verifier: `verifyPicoProof(bytes32, bytes, uint256[12])` in [`contracts/`](../contracts). Groth16 via a `pico-gnark` binary (`PICO_GNARK_BIN`) or an image built from `gnark/Dockerfile` (`PICO_GNARK_IMAGE`) |
| Groth16 keys | keys made with `cargo pico prove --evm --setup` are test keys, and the verifier in `contracts/test/dev` comes from such a test setup. A deployment needs keys from a real setup ceremony |
| AOT emulation | `cargo pico aot`; `--aot` on `cargo pico prove` and `execute` (the CLI builds a helper binary on first use and needs the `v3.1.0-gpu.1` tag, or a checkout named by `PICO_SOURCE`); `ProverBuilder::aot` with the `pico-prover` feature `aot`. One AOT program per process. AOT changes how the witness is produced, not what is proved |
| Coprocessor | `pico-sdk` feature `coprocessor`: available |
| Soundness | Pico 3.0 targets 100 bits of provable round-by-round soundness under the random-oracle model, through the recursion root; the on-chain Groth16 step is held to BN254's security level. This is a computed bound, not a formal verification. |
| Audit | a security review of Pico 2.x by Sherlock is available in [`audits/`](../audits); it predates and does not cover the 3.0 proof system |
| 3.0 compatibility | the same proof system and parameters: the verifying-key whitelist and its root (`vm/src/mle/shape_vk_bins/`), the RISC-V constraint surface, the soundness manifest and the verifier contracts are those of `v3.0.0` |
| 2.x compatibility | none: 2.x proofs, keys and verifier contracts are not usable. See the [migration guide](./migration-2.x-to-3.0.md) |
| Resource figures | only the measurements in [`examples/README.md`](../examples/README.md) and [`gnark/README.md`](../gnark/README.md), summarised in [requirements.md](./requirements.md#memory); no general sizing guidance yet |
