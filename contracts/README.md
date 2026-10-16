# Pico verifier contracts

The on-chain end of the EVM path: `cargo pico prove --evm` makes a Groth16 proof of the wrap
circuit, and these contracts check it.

```
src/IPicoVerifier.sol   verifyPicoProof(bytes32 riscvVkey, bytes publicValues, uint256[12] proof)
src/PicoVerifier.sol    hashes the public values and calls a Groth16 verifier for the two inputs
```

`PicoVerifier` holds the address of the Groth16 verifier gnark exports for one setup of the wrap
circuit (`Groth16Verifier.sol`, contract `Verifier`), so nothing in `src/` depends on a setup's
keys. The wrap circuit bakes in the recursion whitelist root: a verifier accepts the proofs made
under the whitelist its setup was made for, and a new whitelist or wrap circuit needs a new setup,
a new `Groth16Verifier.sol` and a `PicoVerifier` pointing at it.

The proof is twelve words where the 2.x interface took eight: the wrap circuit range-checks
with a log-derivative lookup, so every proof carries a Pedersen commitment and its proof of
knowledge besides A, B and C. `inputs.json`'s `proof` holds all twelve, in order.

## The public inputs

- `riscvVkey`: the program's verification key hash in whitelist mode, the program id `cargo pico
  prove` prints. A contract pins the program it accepts by checking this value.
- `publicValues`: the bytes the guest committed. The circuit's input is their SHA-256 with the top
  three bits cleared (`hashPublicValues`), which is what fits one BN254 scalar.

## Tests

```
forge test
```

`test/PicoVerifier.t.sol` runs `PicoVerifier` over the verifier in `test/dev` and the three proofs
in `test/fixtures`, which `cargo pico prove --evm` wrote for fib, poseidon2 and ed25519 with one key
set: the wrap circuit is the same for every program, and one verifier checks all three. Changing the
public values, the program's key or any proof word must make it revert.

**`test/dev` is a test key set, never a deployable one.** It came from `cargo pico prove --evm
--setup`, a local Groth16 setup whose randomness the machine that ran it knew, so anyone holding it
can forge proofs that verify. `test/dev/manifest.json` records the circuit it was made for and the
hash of each file it wrote. The fixtures are proofs under these keys, and they are replaced
together: a new wrap circuit, a new whitelist root or a new setup means rerunning

```
VK_VERIFICATION=true MLE_VK_MAP=... MLE_VK_ROOT=... PICO_GNARK_BIN=... \
  cargo pico prove --elf vm/src/compiler/test_elf/fib-elf --input u32:10 --evm --setup \
  --keys <keys> --output <fib>
```

then `--keys <keys>` without `--setup` for the other two:

```
cargo pico prove --elf perf/bench_data/rv64/poseidon2-elf --input u32:50 --evm --keys <keys> \
  --output <poseidon2>
# The basepoint, its negation and two scalars, as sdk/prover's `ed25519_stdin` writes them.
cargo pico prove --elf perf/bench_data/rv64/ed25519-elf \
  --input 0x5866666666666666666666666666666666666666666666666666666666666666 \
  --input 0x58666666666666666666666666666666666666666666666666666666666666e6 \
  --input 0x0a00000000000000000000000000000000000000000000000000000000000000 \
  --input 0x0a00000001000000000000000000000000000000000000000000000000000000 \
  --evm --keys <keys> --output <ed25519>
```

and copying `<keys>/Groth16Verifier.sol` and `<keys>/manifest.json` to `test/dev/`, and each run's
`inputs.json` to `test/fixtures/<name>.json`. The setup records the whitelist root it pinned into
the circuit in `manifest.json`. Then regenerate the soundness manifest
(`cargo run --release -p pico-vm --example mle_soundness_manifest`): it copies the circuit's hash
and that root from `test/dev/manifest.json`, and `pico-mle-core`'s soundness tests fail until it
does.
