# Pico 3.0 support matrix

For release `v3.0.0`. What is not listed is not supported.

| area | 3.0 |
|---|---|
| Host platform | `aarch64-apple-darwin`, `x86_64-unknown-linux-gnu` (the hosts with prebuilt guest toolchains). Other hosts: not supported |
| Rust | `nightly-2026-09-27` (the repository's `rust-toolchain`) |
| Guest toolchain | `pico-ae9fd31`, installed by `cargo pico install` |
| Guest target | `riscv64im-pico-zkvm-elf` |
| Field and proof system | KoalaBear only; MLE STARK (LogUp-GKR, ZeroCheck, WHIR) |
| Prover | CPU |
| Phases | RISCV, CONVERT, COMBINE (the default), EMBED, WRAP; then Groth16 on BN254 via gnark for EVM verification |
| Verification | every proof is verified in the process that made it before it is returned. In another process: a RISCV proof file verifies from the ELF at the same stacked height and mode; a COMBINE proof file verifies only in whitelist mode |
| EVM / on-chain | whitelist mode only (`VK_VERIFICATION=true`, `MLE_VK_MAP`, `MLE_VK_ROOT`, default stacked height). Verifier: `verifyPicoProof(bytes32, bytes, uint256[12])` in [`contracts/`](../contracts). Groth16 via a `pico-gnark` binary (`PICO_GNARK_BIN`) or an image built from `gnark/Dockerfile` (`PICO_GNARK_IMAGE`) |
| Groth16 keys | keys made with `cargo pico prove --evm --setup` are test keys, and the verifier in `contracts/test/dev` comes from such a test setup. A deployment needs keys from a real setup ceremony |
| AOT emulation | `cargo pico aot`; `--aot` on `cargo pico prove` and `execute` (the CLI builds a helper binary on first use and needs the `v3.0.0` tag, or a checkout named by `PICO_SOURCE`); `ProverBuilder::aot` with the `pico-prover` feature `aot`. One AOT program per process. AOT changes how the witness is produced, not what is proved |
| Coprocessor | `pico-sdk` feature `coprocessor`: available |
| Soundness | Pico 3.0 targets 100 bits of provable round-by-round soundness under the random-oracle model, through the recursion root; the on-chain Groth16 step is held to BN254's security level. This is a computed bound, not a formal verification. |
| Audit | a security review of Pico 2.x by Sherlock is available in [`audits/`](../audits); it predates and does not cover the 3.0 proof system |
| 2.x compatibility | none: 2.x proofs, keys and verifier contracts are not usable. See the [migration guide](./migration-2.x-to-3.0.md) |
| Resource figures | only the measurements in [`examples/README.md`](../examples/README.md) and [`gnark/README.md`](../gnark/README.md), summarised in [requirements.md](./requirements.md#memory); no general sizing guidance yet |
