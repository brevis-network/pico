# Pico Gnark CLI

### Build field ffi

From the pico repo directory, run the following command to generate `libfield_ffi.dylib` in `target/release`
```
cargo build --release --package field-ffi
```
Then you will find the field ffi lib file in `./target/release`.
The file name is different on Linux and MacOS.

On linux, it is named as `libfield_ffi.so`

On MacOs, it is named as `libfield_ffi.dylib`

### Load ffi lib to local env
```
export CGO_LDFLAGS="-L$(pwd)/target/release"
export LD_LIBRARY_PATH=$(pwd)/target/release:$LD_LIBRARY_PATH
```
### Run tests

#### Poseidon2 on BabyBear

```
cd gnark/poseidon2

go test -timeout 300000s -run TestPoseidon2BabyBear
```

#### Poseidon2 on BabyBear

```
cd gnark/poseidon2

go test -timeout 300000s -run TestPoseidon2KoalaBear
```

#### Verify Pico EMBED Proof on BabyBear
You need copy the `groth16_witness.json` and `constraints.json` into the dir first.
```
cd gnark/babybear_verifier/

go test -timeout 300000s -run TestSolveVerifierCircuit
```

#### Verify Pico EMBED Proof on KoalaBear
You need copy the `groth16_witness.json` and `constraints.json` into the dir first.
```
cd gnark/koalabear_verifier/

go test -timeout 300000s -run TestSolveVerifierCircuit
```

#### Use Docker to Prove:
```
mkdir data
cp groth16_witness.json ./data/
cp constraints.json ./data/
docker run --rm -v ./data:/data brevishub/pico_gnark_cli:1.0 /pico_gnark_cli -cmd setupAndProve
```
