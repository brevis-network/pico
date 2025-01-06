
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

build docker:
```
docker buildx build --platform linux/amd64,linux/arm64 --secret id=gitcre,src=$HOME/git-read-credentials -t liuxiaobleach657/test_vm:0.02 --push .
```

use docker:

setup pk vk
```
docker run --rm -v ./data:/data {repo_in_docker_hub} /pico_vm_gnark_cli -cmd setup -witness /data/groth16_witness.json -constraints /data/constraints.json -pk /data/vm_pk -vk /data/vm_vk
```

generate proof
```
docker run --rm -v ./data:/data {repo_in_docker_hub} /pico_vm_gnark_cli -cmd setup -witness /data/groth16_witness.json -constraints /data/constraints.json -pk /data/vm_pk -vk /data/vm_vk -proof /data/proof.data
```

set up proof and generate proof
```
docker run --rm -v ./data:/data {repo_in_docker_hub} /pico_vm_gnark_cli -cmd setupAndProve -witness /data/groth16_witness.json -constraints /data/constraints.json -pk /data/vm_pk -vk /data/vm_vk -proof /data/proof.data
```