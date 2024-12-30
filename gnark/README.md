
run this cmd to generate libbabybear_ffi.dylib in target/release
cargo build --release

for mac

```export CGO_LDFLAGS="-L{your_path}/brevis-vm/target/release"```

for ubuntu 

```export CGO_LDFLAGS="-L{your_path}/brevis-vm/target/release" export LD_LIBRARY_PATH={your_path}/brevis-vm/target/release$LD_LIBRARY_PATH```


test poseidon2_babybear

```
cd brevis-vm/gnark/poseidon2

go test -timeout 300000s -run TestPoseidon2BabyBear
```

test verify embed proof

copy the constraints.json and witness.json to brevis-vm/gnark/vm_verifier/
```
cd brevis-vm/gnark/vm_verifier/

go test -timeout 300000s -run TestVerifierCircuit
```
