# Pico gnark CLI

The BN254 Groth16 outer layer for the MLE/WHIR pipeline. It takes the `wrap` artifacts that
`pico-vm` emits for an **embed** proof and turns them into a Groth16 proof plus a Solidity
verifier.

This tree is KoalaBear-only: the MLE pipeline commits under BN254-Poseidon2 at the embed layer and
range checks with log-derivative lookups.

## Where this sits

```
pico-vm (Rust, KoalaBear)
  riscv -> convert -> combine        KoalaBear-Poseidon2
    -> embed                         same root re-proved under BN254-Poseidon2
      -> wrap                        wrap_constraints.json + wrap_groth16_witness.json
                                     |
gnark (Go, BN254) ------------------ v
  koalabear_verifier   replays the opcode stream as a circuit
  koalabear            KoalaBear arithmetic in BN254 with lazy reduction
  poseidon2            BN254 width-3 (native) and KoalaBear width-16 (emulated)
  sdk                  setup / prove / verify / solve / exportSolidity
```

The circuit verifies the **embed** proof, not the combine root directly. The embed layer exists
to move the hash domain: a native BN254 width-3 permutation costs ~240 R1CS constraints against
~7,858 for an emulated KoalaBear width-16 one, and verifying a KoalaBear-hashed proof directly
would not fit.

## Build the field FFI

The circuit's hint functions call into Rust for KoalaBear inversion.

```
cargo build --release --package field-ffi        # from the repo root
export CGO_LDFLAGS="-L$(pwd)/target/release"
export LD_LIBRARY_PATH=$(pwd)/target/release:$LD_LIBRARY_PATH     # Linux
export DYLD_LIBRARY_PATH=$(pwd)/target/release:$DYLD_LIBRARY_PATH # macOS
```

`libfield_ffi.so` on Linux, `libfield_ffi.dylib` on macOS.

Note: gnark's `go.mod` needs Go 1.24+. A 1.18 `go` on `PATH` fails to parse it.

## End to end

`cargo pico prove --evm` runs the whole chain: a whitelist-mode proof to wrap, then this CLI for the
Groth16 proof. It finds the CLI as a binary (`PICO_GNARK_BIN`) or as the image below
(`PICO_GNARK_IMAGE`), and the keys as the directory a setup wrote (`--keys`, or `--setup` to make
one). Beside the wrap files it writes `proof.data`, and `inputs.json` with what the verifier
contract is called with; `contracts/` checks both.

```
go build -o pico-gnark ./sdk/main        # here, with the field FFI built as above

VK_VERIFICATION=true MLE_VK_MAP=vm/src/mle/shape_vk_bins/mle_vk_map_kb.bin \
MLE_VK_ROOT="<the eight numbers on the MLE_VK_ROOT= line of mle_vk_root.txt>" PICO_GNARK_BIN=gnark/pico-gnark \
  cargo pico prove --elf <elf> --input u32:10 --evm --setup --keys <keys> --output <out>
```

By hand, with the wrap files from `cargo pico prove --phase wrap` (or `test_mle_e2e --step wrap`):

```
# Groth16 setup: pk, vk, ccs, the verifier contract, and manifest.json
./pico-gnark -cmd setup \
  -constraints ../wrap_constraints.json -witness ../wrap_groth16_witness.json \
  -pk ./data/pk -vk ./data/vk -ccs ./data/ccs -sol ./data/Groth16Verifier.sol \
  -manifest ./data/manifest.json

# prove, with the keys and the ccs the setup saved
./pico-gnark -cmd prove \
  -constraints ../wrap_constraints.json -witness ../wrap_groth16_witness.json \
  -pk ./data/pk -vk ./data/vk -ccs ./data/ccs -manifest ./data/manifest.json \
  -proof ./data/proof.data

# verify a proof file against the verifying key, as the contract does
./pico-gnark -cmd verify -vk ./data/vk -proof ./data/proof.data
```

A setup samples its randomness locally: whoever runs it can forge proofs for its keys, so keys from
`-cmd setup` are for testing, and the keys behind a deployed verifier need a setup whose provenance
is settled.

`setup` (and `setupAndProve`) only takes wrap files proved in whitelist mode. There the wrap
constraints pin the whitelist root in one `AssertVkRoot` op; outside it they pin none, and keys
made from them would verify a wrap of any program with the same layout. The setup reads the
constraints file it compiles: one `AssertVkRoot` is the root the keys attest, more than one is
refused, and none is refused unless `PICO_GNARK_ALLOW_UNPINNED_SETUP=1` is set, which is for tests
only. `prove`, `solve` and `verify` do not check it.

`prove` proves against the ccs the setup saved rather than compiling the constraints file again:
the compile was most of a prove's wall time, and only the saved ccs is certain to be the circuit the
proving key was made for. With a `manifest.json` beside the keys, the `-constraints` file has to be
the circuit they were made for (`circuit_sha256`), or `prove` refuses before loading them; keys with
no manifest are used with a warning. The prover solves the constraint system itself, so no separate
solve runs; `-cmd solve` still runs the circuit in gnark's test engine without proving, which is the
fast way to check that a new opcode stream is satisfiable.

`manifest.json` records the SHA-256 of the constraints file, the constraint and public-input counts,
the gnark version, the SHA-256 of each file the setup wrote (`pk`, `vk`, `ccs`, `solidity`), and
`vk_root`, the eight KoalaBear limbs of the whitelist root the circuit pins (absent when it pins
none), so a published key set can be checked against the circuit and the whitelist it claims to be
for.

`proof.data` is 14 comma-separated 32-byte hex fields:

```
[0:8]    A, B, C            the Groth16 proof
[8:10]   commitment         Pedersen commitment (the log-derivative lookup argument needs it)
[10:12]  commitmentPok      its proof of knowledge
[12:14]  vkey_hash, committed_values_digest    the two public inputs
```

which is exactly the argument order of the exported

```solidity
function verifyProof(uint256[8] proof, uint256[2] commitments,
                     uint256[2] commitmentPok, uint256[2] input) view
```

## The image

`Dockerfile` builds both binaries and the field library from the repository root:

```
docker build -f gnark/Dockerfile -t pico-gnark .        # from the repo root
docker run --rm -v "$PWD/pico_out:/out" pico-gnark -cmd verify \
  -vk /out/groth16/vk -proof /out/proof.data
```

`pico-gnark` is the entrypoint; `pico-gnark-server` is beside it for `--entrypoint`. Every path is
the container's, so mount what a run reads and writes; `cargo pico prove --evm` does that itself
with `PICO_GNARK_IMAGE=pico-gnark`, as the owner of the key directory.

## What the whitelist-mode circuit costs

Measured during 3.0 development on one machine, with the shipped whitelist: the wrap circuit is the
same for every program (fib, poseidon2 and ed25519 give byte-identical constraints files), and

| | |
|---|---|
| R1CS | 7,751,968, 7.6% under 2^23 |
| setup | 3 min 39 s, 17 GB peak |
| prove | 24 s, 12 GB peak (3 s of it the Groth16 prover) |
| pk / ccs / vk | 1.69 GB / 0.64 GB / 560 B |
| `verifyProof` transaction | 347,037 gas |

Past 2^23 constraints the FFT domain doubles to 2^24, and the setup, the prove time and the proving
key with it. `TestCircuitFitsGroth16Domain` checks the circuit beside it against that bound.

## Tests

```
export PATH=/usr/local/go/bin:$PATH        # 1.24+
go test ./koalabear/ ./poseidon2/ ./utils/
```

`koalabear/canonicality_test.go` and its two audit companions cover the felt-to-integer boundary.
They are mutation-tested: deleting the shifted range check in `proveCanonicalBound` while leaving
the tightened bound behind compiles and passes nine of the ten, and `freepath_audit_test.go` is
the one that catches it. That path discharges 64,900 of 64,900 canonicality obligations on a
representative tape, so do not prune it.

`utils` reads a proof file back and verifies it, changing each of its 14 fields in turn. The
`koalabear_verifier` tests read `constraints.json` and `groth16_witness.json` from their own
directory, as CI's Wrap proof job puts them there, and skip without them:
`TestSolveVerifierCircuit` solves the circuit, `TestTamperedWitnessIsUnsatisfiable` changes one
witness value at a time and requires each change to leave it unsatisfiable, and
`TestCircuitFitsGroth16Domain` compiles it and requires at most 2^23 constraints.
