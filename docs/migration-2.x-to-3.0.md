# Migrating from Pico 2.x to 3.0

This guide lists what changes for a project built on Pico 2.x (last release `v2.1.2`) when it moves
to Pico 3.0 (`v3.0.0`). See also the [release notes](./release-notes/3.0.md) and the
[support matrix](./support-matrix.md).

## Overview

Pico 3.0 replaces the proof system. 2.x proved with FRI-based STARKs over BabyBear, KoalaBear or
Mersenne31; 3.0 proves with a multilinear (MLE) STARK over KoalaBear only — LogUp-GKR, ZeroCheck
and WHIR — through five phases: RISCV → CONVERT → COMBINE → EMBED → WRAP.

What follows from that:

- **2.x proofs are not usable in 3.0.** 3.0 neither reads nor verifies them, and its proof files
  have a new format. Re-prove with 3.0.
- **Program ids and verifying keys change.** Anything that pins a 2.x value has to be updated.
- **Redeploy the on-chain verifier.** The wrap circuit, its Groth16 keys and the verifier interface
  are new (`uint256[12]` proofs instead of `uint256[8]`).
- **Host code moves to a new crate.** The prover client left `pico-sdk`; host code uses
  `pico-prover`.
- Guest code mostly builds unchanged, after rebuilding with the new toolchain.

## Upgrade checklist

1. Install the 3.0 toolchain and CLI (see [Toolchain](#toolchain)), then rerun `cargo pico install`.
   Set the project's own `rust-toolchain` file to `nightly-2026-09-27`: `pico-vm`, which the host
   crate builds through `pico-prover`, uses nightly-only features.
2. Point the guest's `pico-sdk` dependency at `v3.0.0` and drop the `bb` / `m31` / `aot` features:
   `pico-sdk = { git = "https://github.com/brevis-network/pico", tag = "v3.0.0" }`.
3. Replace the host's `pico-sdk` client with `pico-prover` (see [Host](#host-pico-sdk-client--pico-prover)).
4. Rebuild the guest ELF with `cargo pico build`. Its program id changes.
5. Update scripts that call `cargo pico prove` (see [CLI](#cli-cargo-pico)).
6. Regenerate proofs. Discard stored 2.x proofs.
7. For on-chain verification: run a Groth16 setup for the 3.0 wrap circuit, deploy the new
   verifier, and update callers to `verifyPicoProof(bytes32, bytes, uint256[12])` (see
   [Outputs and on-chain](#outputs-and-on-chain)).

## Guest (`pico-sdk`)

| 2.x | 3.0 |
|---|---|
| field features `bb`, `kb`, `m31`; exactly one required, `kb` by default | KoalaBear only. `bb` and `m31` are removed. `kb` is kept as a no-op so guests that select it still build |
| feature `aot` | removed from `pico-sdk`. AOT is a host-side option: `ProverBuilder::aot` with `pico-prover`'s `aot` feature, `--aot` on the CLI |
| `pico_sdk::client`, `pico_sdk::m31_client` | removed; see [Host](#host-pico-sdk-client--pico-prover) |
| `pico_sdk::HashableKey` (re-export) | removed. A program's identity is `pico_prover::ProgramId`, with `vkey_hash()` (the on-chain public input) and `as_words()` |
| `syscall_poseidon2_permute(*const [u32; 16], *mut [u32; 16])` | `syscall_poseidon2_permute(*const Poseidon2State, *mut Poseidon2State)`. `Poseidon2State` (in `pico-patch-libs`) is an 8-byte-aligned `repr(C)` wrapper around `[u32; 16]` |
| `pico_sdk::poseidon2_hash` | deprecated: its output is a single field element, so it is not collision-resistant. Use `pico_sdk::poseidon2::hash`, which returns eight elements; it adds no padding, so use it for fixed-length input (or put the length in the input) |
| `entrypoint!`, `io::{read_as, read_vec, commit, commit_bytes}`, `load_elf`, `init_logger`, the other syscalls | unchanged |

The guest target is unchanged: `riscv64im-pico-zkvm-elf`.

## Host (`pico-sdk` client → `pico-prover`)

Host code depends on `pico-prover` instead of `pico-sdk`:

```toml
[dependencies]
pico-prover = { git = "https://github.com/brevis-network/pico", tag = "v3.0.0" }
```

| 2.x (`pico_sdk::client`) | 3.0 (`pico_prover`) |
|---|---|
| `DefaultProverClient`, `KoalaBearProverClient`, `BabyBearProverClient`, `M31RiscvProverClient` | `Prover`, configured through `ProverBuilder` |
| `DefaultProverClient::new(&elf)` | `Prover::new(&elf)?` |
| `new_with_opts(&elf, EmulatorOpts)` | `Prover::builder(&elf)` with setters (`log_stacked_height`, `chunk_size`, `concurrency`, `verify_keys`, `vk_map`, `trusted_vk_root`, ...) then `.build()?` |
| `client.new_stdin_builder()`, `write(&v)`, `write_slice(&bytes)` | `Stdin::new()` with `write(&v)` and `write_bytes(&bytes)`, or `Stdin::from(&v)` for one value |
| `prove(stdin) -> (riscv proof, embed proof)` | `prove(stdin) -> Proof`, which stops at COMBINE, **verifies the proof** and binds the guest's committed bytes to it before returning |
| `prove_combine(stdin)` | `prove(stdin)`, or `prove_to(stdin, Phase::Combine)` |
| `prove_fast(stdin)` | `prove_to(stdin, Phase::Riscv)`. The RISC-V phase is full-security; there is no "fast" mode |
| `verify(&proof)` | no separate call: every returned `Proof` is already verified. To verify in another process: `Proof::write(path)`, then `ProofArtifact::read(path)` and `Prover::verify_artifact(artifact)` |
| `emulate(stdin) -> (reports, public values)` | `execute(stdin) -> Execution` on `Prover`, or on `ProverBuilder` to skip keygen. Its `committed_bytes` are not proved |
| `proof.pv_stream` | `proof.committed()`: `as_bytes()` for the raw bytes, `read::<T>()` per committed value |
| `prove_evm(stdin, need_setup, output, field)`, which ran Groth16 in Docker | `prove_evm(stdin) -> EvmBundle`, in whitelist mode only (`verify_keys(true)`); `EvmBundle::write_to(dir)` writes the gnark inputs. The library runs no Groth16: use `cargo pico prove --evm` or the `pico-gnark` CLI |
| `write_onchain_data(dir, ...)` | `EvmBundle::write_to(dir)`, or `Proof::write_wrap_artifacts(constraints, witness)` on a WRAP proof |
| `riscv_vk()`, `riscv_pk_vk()` | none. Identify a program with `Prover::program_id()` / `Proof::program_id()` |
| options read from the environment (`VK_VERIFICATION`, ...) | `pico-prover` takes its options only from `ProverBuilder` setters. The CLI maps environment variables onto them (see [Environment variables](#environment-variables)) |

Which stored proofs another process can verify: a RISCV proof file verifies in any process that has
the ELF and uses the same stacked height and mode; a COMBINE proof file verifies in another process
only in whitelist mode. See [`examples/README.md`](../examples/README.md).

### Example: proving fibonacci

2.x, with `pico-sdk`'s client:

```rust
use pico_sdk::{client::DefaultProverClient, init_logger, load_elf};

fn main() {
    init_logger();
    let elf = load_elf("../app/elf/riscv64im-pico-zkvm-elf");
    let client = DefaultProverClient::new(&elf);

    let mut stdin = client.new_stdin_builder();
    stdin.write(&100u32);
    let proof = client.prove_fast(stdin).expect("prove");

    let committed: Vec<u8> = proof.pv_stream.unwrap();
    // decode `committed` ...
}
```

3.0, with `pico-prover` (abridged from [`examples/fibonacci/prover`](../examples/fibonacci/prover/src/main.rs)):

```rust
use pico_prover::{Phase, ProofArtifact, Prover, Stdin};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let elf = std::fs::read("../app/elf/riscv64im-pico-zkvm-elf")?;
    let mut prover = Prover::new(&elf)?;

    // Proves the RISC-V phase and verifies it before returning.
    let proof = prover.prove_to(Stdin::from(&100u32), Phase::Riscv)?;
    let committed = proof.committed();
    let bytes: &[u8] = committed.as_bytes();
    // decode `bytes` ...

    // Store it, and verify it again later from the ELF alone.
    proof.write("fibonacci.pico")?;
    let proof = prover.verify_artifact(ProofArtifact::read("fibonacci.pico")?)?;
    println!("program id: {}", proof.program_id());
    Ok(())
}
```

## CLI (`cargo pico`)

Subcommands are `install`, `build`, `execute`, `prove`, `aot` and `new`.

| 2.x | 3.0 |
|---|---|
| `prove` with no `--phase`: proved through EMBED and wrote the gnark inputs | `prove` stops at COMBINE by default and writes `proof-combine.pico`. Use `--phase riscv\|convert\|combine\|embed\|wrap` to choose; `--phase wrap` writes the gnark inputs |
| `prove --fast` | `prove --phase riscv`. `--fast` now fails with that hint |
| `prove --field kb\|bb\|m31` | removed; `--field` now fails (proving is KoalaBear only) |
| `prove` without `--elf` found `elf/riscv64im-pico-zkvm-elf` | `--elf <path>` is required |
| `--input <0x… or file path>`, once | `--input` is repeatable, one value per guest read, in order: `<type>:<value>` (for example `u32:100`, `u64:7`, `bool:true`, `string:abc`), `0x<hex>` (raw bytes) or `file:<path>` (raw bytes). A bare number is refused |
| `--output` defaulted to `pico_out` in the project's target directory | `--output` defaults to `pico_out` in the current directory |
| `prove --evm` ran a fixed Docker image | `prove --evm` runs gnark from `$PICO_GNARK_BIN` (a `pico-gnark` binary) or `$PICO_GNARK_IMAGE` (an image built from `gnark/Dockerfile`), in whitelist mode only, with keys from `--keys DIR` or `$PICO_GROTH16_KEYS` |
| `prove --evm --setup` | still available; it makes **test keys only** (the machine that runs the setup knows its randomness) |
| `build --rustflags` split on commas | `--rustflags` is split on whitespace and may be repeated; commas are kept, as in `-C target-feature=+m,+a` |
| `new` cloned the template's `main` / `evm` branch | `new` clones the template release that matches the CLI: tag `v3.0.0` (basic) or `evm-v3.0.0` (`--template evm`), falling back to the branch with a note if the tag does not exist. `--template-ref REF` picks another tag or branch |
| — | new: `cargo pico execute` (emulate without proving), `cargo pico aot` (generate a guest's AOT crates), `--aot` on `prove` and `execute`, `--log-stacked-height N` |

Typical 3.0 invocations, for a guest that reads one `u32` (as `examples/fibonacci` does):

```bash
cargo pico build
cargo pico execute --elf elf/riscv64im-pico-zkvm-elf --input u32:100
cargo pico prove   --elf elf/riscv64im-pico-zkvm-elf --input u32:100 --phase riscv
cargo pico prove   --elf elf/riscv64im-pico-zkvm-elf --input u32:100 --aot
cargo pico aot     --elf elf/riscv64im-pico-zkvm-elf --out <dir>
```

The CLI has no `verify`; verify a stored proof with `pico-prover` (`Prover::verify_artifact`).

## Environment variables

`pico-prover` reads none of its options from the environment. The CLI maps these onto
`ProverBuilder` setters and echoes each one it reads:

| variable | setter |
|---|---|
| `CHUNK_SIZE` | `chunk_size` |
| `PROVE_CONCURRENCY` | `concurrency` |
| `VK_VERIFICATION` (`true` / `false`) | `verify_keys` |
| `MLE_VK_MAP` (path to `mle_vk_map_kb.bin`) | `vk_map`, read only when `VK_VERIFICATION=true` |
| `MLE_VK_ROOT` (the eight numbers on the `MLE_VK_ROOT=` line of `mle_vk_root.txt`) | `trusted_vk_root`, read only when `VK_VERIFICATION=true` |

Whitelist mode needs all three of `VK_VERIFICATION=true`, `MLE_VK_MAP` and `MLE_VK_ROOT`, at the
default stacked height. The whitelist files ship in `vm/src/mle/shape_vk_bins/`.

The CLI also reads `PICO_GNARK_BIN`, `PICO_GNARK_IMAGE` and `PICO_GROTH16_KEYS` for `--evm`, and
`PICO_AOT_CACHE` (default `~/.pico/aot`) and `PICO_SOURCE` (a Pico checkout to build AOT helpers
against) for `--aot` and `aot`.

From 2.x: `FRI_QUERIES` no longer exists. `CHUNK_BATCH_SIZE` and `SPLIT_THRESHOLD` have no effect on
`pico-prover` or the CLI.

## Outputs and on-chain

| 2.x | 3.0 |
|---|---|
| `proof.json` (the embed proof) and `pv_file` (the committed bytes, hex) | `proof-riscv.pico` / `proof-combine.pico` (`Proof::write`, read back with `ProofArtifact::read`); the committed bytes are inside the proof (`Proof::committed`) and the CLI prints them |
| `constraints.json`, `groth16_witness.json` | `wrap_constraints.json`, `wrap_groth16_witness.json` |
| `proof.data`, `inputs.json` | same names. `inputs.json` holds `riscvVKey`, `publicValues`, `committedValuesDigest` (new) and `proof` (12 words) |
| `Groth16Verifier.sol` from the setup | still written by the setup (`--setup`), into the key directory with `pk`, `vk`, `ccs` and `manifest.json`; `--keys` defaults to `<output>/groth16` with `--setup` |
| `verifyPicoProof(bytes32, bytes, uint256[8])` | `verifyPicoProof(bytes32 riscvVkey, bytes publicValues, uint256[12] proof)`. The extra four words are a Pedersen commitment and its proof of knowledge |
| — | `contracts/` ships `IPicoVerifier` and `PicoVerifier` with Foundry tests; see [`contracts/README.md`](../contracts/README.md) |

The on-chain verifier accepts whitelist-mode proofs only: the wrap circuit bakes in the whitelist
root, so a new whitelist or wrap circuit needs a new Groth16 setup and a new verifier. The verifier
in `contracts/test/dev` comes from a test setup; a deployment needs keys and a verifier from a real
setup ceremony.

## Removed with no replacement

- The BabyBear and Mersenne31 fields, and FRI-based proving.
- The COMPRESS phase.
- `prove --fast` as a separate mode, and `--field`.
- The M31 RISC-V prover client.
- Access to the RISC-V proving and verifying keys from the client (`riscv_vk`, `riscv_pk_vk`).
- A default gnark Docker image: build `pico-gnark` or its image from `gnark/`.

## Toolchain

| | 2.x | 3.0 |
|---|---|---|
| Rust (`rust-toolchain`) | `nightly-2025-08-04` | `nightly-2026-09-27` |
| guest toolchain (`cargo pico install`) | `pico-8bd1f45` | `pico-ae9fd31` |
| prebuilt guest toolchain hosts | per host | `aarch64-apple-darwin`, `x86_64-unknown-linux-gnu` only |
| guest target | `riscv64im-pico-zkvm-elf` | unchanged |

Install:

```bash
rustup toolchain install nightly-2026-09-27
cargo +nightly-2026-09-27 install --git https://github.com/brevis-network/pico --tag v3.0.0 --locked pico-cli
cargo pico install
```

`cargo pico install` checks the downloaded archive's size and SHA-256 against values pinned in the
CLI, and installs `nightly-2026-09-27` with `rust-src` for guest builds.

## Templates

`cargo pico new <name>` (and `--template evm`) clones the release-tagged template that matches the
CLI's version, so a 3.0 CLI creates a 3.0 project. Projects created from a 2.x template need the
dependency, host and CLI changes above.
