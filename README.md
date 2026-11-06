# Pico

![Pico](docs/pico.png)

Pico is an open-source zero-knowledge virtual machine (zkVM) that transforms how developers build secure, scalable, and high-performance decentralized applications. Drawing on the innovative [Glue-and-Coprocessor](https://vitalik.eth.limo/general/2024/09/02/gluecp.html) architecture, Pico fuses the efficiency of specialized circuits with the adaptability of a general-purpose zkVM. This unique design empowers you to craft tailored proof systems that meet the diverse needs of your applications.

**[Install](https://pico-docs.brevis.network/getting-started/installation)**
| [Docs](https://pico-docs.brevis.network/)
| [Examples](./examples)
| [Telegram](https://t.me/brevisnetwork)
| [Discord](https://discord.com/invite/QTRkjKdZ6A)

## Getting Started

Before you begin, please ensure that you have installed all the [requirements](./docs/requirements.md). For installation and setup instructions, refer to the [Installation Guide](https://pico-docs.brevis.network/getting-started/installation) and follow the steps outlined in [Quick Start](https://pico-docs.brevis.network/getting-started/quick-start) section in [Pico Docs](https://pico-docs.brevis.network/).

## Key Features
Pico's design is rooted in the need for adaptable, high-performance ZK systems that can keep up with the rapidly evolving cryptography research. Rather than relying on a "one size fits all" solution, Pico's modular architecture lets you:

- **Integrate App-Specific Circuits**: Seamlessly incorporate specialized circuits/coprocessors to accelerate domain-specific computations.
- **Customize Proving Workflows**: Assemble and fine-tune proof generation pipelines tailored to your application's specific requirements.

## Proof System
Pico 3.1 proves with a multilinear (MLE) STARK on the KoalaBear field (prime $p = 2^{31} - 2^{24} + 1$), drawing its challenges from the degree-5 extension KoalaBear⁵: LogUp-GKR for lookups, ZeroCheck for constraints and WHIR as the polynomial commitment. The chain is RISCV → CONVERT → COMBINE → COMPRESS (the final compression layer, the final proof) → EMBED → WRAP, the last two for the EVM path. On the EVM path the [WRAP phase](https://pico-docs.brevis.network/writing-apps/advanced/proverchain) output is proved with Groth16 on BN254 for on-chain verification.

Pico 3.1 is a breaking release: the extension field is KoalaBear⁵, and the parameters, the verifying-key whitelist, the soundness manifest and the Groth16 circuit, keys and verifier contract differ from those of 3.0, so their proofs and keys are not accepted. See the [release notes](./docs/release-notes/3.1.md), the [changes on `main` since](./docs/release-notes/unreleased.md) and the [support matrix](./docs/support-matrix.md); from 2.x, see the [3.0 release notes](./docs/release-notes/3.0.md) and the [migration guide](./docs/migration-2.x-to-3.0.md) first.

## GPU Prover
Pico 3.1 adds a GPU prover for the RISCV, CONVERT, COMBINE and COMPRESS phases, through `distributed-vm`'s `mle-single-node` (`single_node_mle.sh`), and its proofs verify with the CPU verifier. In a `cuda` build of `pico-prover`, a whitelist-mode `prove` (to the combine root) runs on the GPU pipeline; any other mode or phase proves CONVERT and COMBINE on the CPU (see the [release notes](./docs/release-notes/3.1.md)).

The default build is the CPU prover and needs no CUDA Toolkit or GPU, on Linux and macOS. The GPU prover is the `cuda` feature (`cargo build --release --features pico-vm/cuda,distributed-vm/cuda`) and needs the CUDA Toolkit on x86-64 Linux to build and an NVIDIA GPU to run; a `cuda` build does not fall back to the CPU. `make build` and `single_node_mle.sh` pick the GPU build when they find `nvcc` and a GPU; `PICO_CUDA=0` or `PICO_CUDA=1` overrides that (see [`detect_cuda.sh`](./detect_cuda.sh)). The `cuda` feature pulls in the CUDA kernels from [pico-gpu](https://github.com/brevis-network/pico-gpu), which is licensed under MIT or Apache-2.0, except code derived from third-party projects, which keeps its original license (see pico-gpu's README). See the [release notes](./docs/release-notes/3.1.md) and the [support matrix](./docs/support-matrix.md).

## Security
Pico targets 128 bits of provable round-by-round soundness under the random-oracle model, through the compress proof (the final proof); the on-chain Groth16 step is held to BN254's security level. The number is computed by the repository's soundness calculator and recorded in its soundness manifest ([docs/soundness](./docs/soundness/README.md)); it is a computed bound, not a formal verification.

The verifier in [`contracts/test/dev`](./contracts/test/dev) comes from a test setup: a deployment needs keys and a verifier from a real setup ceremony.

A security review of Pico 2.x by Sherlock is available in [`audits/`](./audits); it predates and does not cover the 3.x proof system.

## For Contributors

We welcome contributions from developers, researchers, and enthusiasts. Your input is crucial for Pico's evolution, whether you're fixing bugs, enhancing performance, improving documentation, or adding new features.

Before getting started, please review our [Repo Layout](./docs/layout.md) to understand the repository structure. For detailed contribution instructions, see our [Contributing Guidelines](./docs/contributor.md).


## Acknowledgements

Pico draws inspiration from the following projects, each representing cutting-edge advancements in zero-knowledge proof systems. 
- [Plonky3](https://github.com/Plonky3/Plonky3): Pico's proving backend is built on Plonky3's field, hash and matrix primitives.
- [SP1](https://github.com/succinctlabs/sp1): Pico derives significant inspiration from SP1's chip design and their constraints. Its recursion compiler and precompiles originate from SP1.
- [Valida](https://github.com/valida-xyz/valida): Pico's implementation of cross-table lookups is inspired by Valida's pioneering work in this area.
- [RISC0](https://github.com/risc0/risc0): Pico's Rust toolchain is based on the one originally developed by RISC0.
- [OpenVM](https://github.com/openvm-org/openvm): Pico's multilinear proving backend (LogUp-GKR, stacked reduction and WHIR) is based on OpenVM's stark-backend.
