# Pico support matrix

For `main`, where one tree builds the CPU prover (the default) and the GPU prover (the
`cuda` feature). What is not listed is not supported.

| area | `main` |
|---|---|
| Host platform | CPU build: `x86_64-unknown-linux-gnu` and macOS, no CUDA needed. GPU build (`cuda` feature): `x86_64-unknown-linux-gnu` with the CUDA Toolkit. Other hosts: not supported |
| CUDA | Toolkit to build (`nvcc`): CI builds with 12.3, the GPU runs used 12.8, and pico-gpu is also tested with 13 on an RTX 5090. Only the `cuda` feature needs it. `CUDA_ARCH` picks the SM targets; without it the build asks `nvidia-smi`, and builds for sm_89 and sm_120 when no GPU is visible. An NVIDIA GPU to run a `cuda` build, which exits at start without one; the memory thresholds are calibrated on 32 GB cards (RTX 5090), with a 24 GB tier through `PICO_GPU_MEM`. The CUDA kernels are [pico-gpu](https://github.com/brevis-network/pico-gpu), licensed under BUSL-1.1 |
| Rust | `nightly-2026-09-27` (the repository's `rust-toolchain`) |
| Guest toolchain | `pico-ae9fd31`, installed by `cargo pico install` |
| Guest target | `riscv64im-pico-zkvm-elf` |
| Field and proof system | KoalaBear only; MLE STARK (LogUp-GKR, ZeroCheck, WHIR) |
| Prover | CPU, through the SDK and `cargo pico prove`, as in 3.0. GPU (`cuda` feature) for the RISCV, CONVERT and COMBINE phases, through `distributed-vm`'s `mle-single-node` (`single_node_mle.sh`, one host and one or more cards, or two hosts) and `mle-ethproofs-single-node` |
| Phases | RISCV, CONVERT, COMBINE (the default), EMBED, WRAP; then Groth16 on BN254 via gnark for EVM verification |
| Verification | every proof is verified in the process that made it before it is returned. In another process: a RISCV proof file verifies from the ELF at the same stacked height and mode; a COMBINE proof file verifies only in whitelist mode |
| EVM / on-chain | whitelist mode only (`VK_VERIFICATION=true`, `MLE_VK_MAP`, `MLE_VK_ROOT`, default stacked height). Verifier: `verifyPicoProof(bytes32, bytes, uint256[12])` in [`contracts/`](../contracts). Groth16 via a `pico-gnark` binary (`PICO_GNARK_BIN`) or an image built from `gnark/Dockerfile` (`PICO_GNARK_IMAGE`) |
| Groth16 keys | keys made with `cargo pico prove --evm --setup` are test keys, and the verifier in `contracts/test/dev` comes from such a test setup. A deployment needs keys from a real setup ceremony |
| AOT emulation | `cargo pico aot`; `--aot` on `cargo pico prove` and `execute` (the CLI builds a helper binary on first use and needs the release tag of its own version, `v<version>`, or a checkout named by `PICO_SOURCE`); `ProverBuilder::aot` with the `pico-prover` feature `aot`. One AOT program per process. AOT changes how the witness is produced, not what is proved |
| Coprocessor | `pico-sdk` feature `coprocessor`: available |
| Soundness | Pico 3.0 targets 100 bits of provable round-by-round soundness under the random-oracle model, through the recursion root; the on-chain Groth16 step is held to BN254's security level. This is a computed bound, not a formal verification. |
| Audit | a security review of Pico 2.x by Sherlock is available in [`audits/`](../audits); it predates and does not cover the 3.0 proof system |
| 3.0 compatibility | the same proof system and parameters: the verifying-key whitelist and its root (`vm/src/mle/shape_vk_bins/`), the RISC-V constraint surface, the soundness manifest and the verifier contracts are those of `v3.0.0` |
| 2.x compatibility | none: 2.x proofs, keys and verifier contracts are not usable. See the [migration guide](./migration-2.x-to-3.0.md) |
| Resource figures | only the measurements in [`examples/README.md`](../examples/README.md) and [`gnark/README.md`](../gnark/README.md), summarised in [requirements.md](./requirements.md#memory); no general sizing guidance yet |
