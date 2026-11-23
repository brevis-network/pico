# How to Set Up a GPU Machine (Ubuntu)

This guide walks you through setting-up a GPU Ubuntu machine for CUDA, NVIDIA drivers, and development tools.

## Install NVIDIA Drivers

First, check available GPU:
```
lspci | grep -i nvidia
```

Install the recommended driver:
```
sudo apt-get update
sudo apt-get install -y nvidia-driver-570
```

If nvidia-driver-570 doesn't work, follow [this link](https://developer.nvidia.com/datacenter-driver-downloads?target_os=Linux&target_arch=x86_64&Distribution=Ubuntu&target_version=24.04&target_type=deb_local) to install nvidia-driver-580.

Reboot and confirm:
```
nvidia-smi
```

### Install CUDA Toolkit

Pico's CI builds with CUDA 12.3 and the GPU runs here used 12.8; pico-gpu is also tested with CUDA 13 on an RTX 5090. To install 12.8, follow [this link](https://developer.nvidia.com/cuda-12-8-0-download-archive?target_os=Linux&target_arch=x86_64&Distribution=Ubuntu&target_version=24.04&target_type=deb_local).

After installing CUDA toolkit, add these lines to `~/.bashrc` or `~/.zshrc`:
```
export PATH=/usr/local/cuda-12.8/bin:$PATH
export LD_LIBRARY_PATH=/usr/local/cuda-12.8/lib64:$LD_LIBRARY_PATH
```

Reload bash configuration:
```
source ~/.bashrc
```

Verify if it could work:
```
nvcc --version
```

## Install Development Tools

```
sudo apt-get install -y build-essential cmake git pkg-config
sudo apt-get install -y libssl-dev
```

And follow [this link](https://www.rust-lang.org/tools/install) to install rustup. The repository's
`rust-toolchain` pins the nightly (`nightly-2026-09-27`), which rustup installs on the first build.

## Install TCMalloc

```
sudo apt-get install google-perftools
sudo ln -s /usr/lib/x86_64-linux-gnu/libtcmalloc.so.4 /usr/lib/x86_64-linux-gnu/libtcmalloc.so
```

## Install m4
```
sudo apt-get update
sudo apt-get install -y m4
```

## Install protoc
```
wget https://github.com/protocolbuffers/protobuf/releases/download/v21.12/protoc-21.12-linux-x86_64.zip
unzip protoc-21.12-linux-x86_64.zip -d protoc21.12
sudo mv protoc21.12/bin/* /usr/local/bin/
sudo mv protoc21.12/include/* /usr/local/include/
protoc --version
```

## Other Tips

### G++ Version
By default, Ubuntu 24.04 uses g++-13, which may cause issues with CUDA. Install g++-11 and gcc-11:
```
sudo apt-get update
sudo apt-get install -y g++-11 gcc-11
/usr/bin/g++-11 --version
```
When running script, specify g++-11 explicitly:
```
CUDAHOSTCXX=/usr/bin/g++-11 ./single_node_mle.sh 8
```

### Generate the AOT crates first

`single_node_mle.sh` builds with the `aot-emulator` feature, which needs the guest's AOT crates.
Generate them once per ELF, from the repository root, before the first run:
```
cargo run -r -p pico-aot-codegen --bin generate_crates -- perf/bench_data/rv64/reth-elf
```

The crates hold one guest's code, and a binary built with them proves that guest only: loading
another ELF stops at once, with the two digests. For the Amsterdam guest
(`MLE_ELF=reth-amsterdam`, see below), generate them from
`perf/bench_data/rv64/reth-amsterdam-elf` and rebuild.

### The two reth guests

`perf/bench_data/rv64/` holds two guests that execute Ethereum blocks:

| `MLE_ELF` | File | What it is | Inputs |
|---|---|---|---|
| `reth` | `reth-elf` | RSP's client on reth 1.9 and revm: mainnet up to the Osaka fork. The default of every script. | `reth-<block>.bin`, a bare `<block>.bin`, or one of the five aliases |
| `reth-amsterdam` | `reth-amsterdam-elf` | RSP's client on reth v2.11.0 and evm2: blocks of the Amsterdam fork, and mainnet before it. | `reth-amsterdam-<block>.bin` or a bare `<block>.bin` |

An input of one is not an input of the other. The fixtures of `reth-amsterdam` are Sepolia block
12125459, which is after the fork, and mainnet block 26403932:
```
MLE_ELF=reth-amsterdam MLE_N=12125459 ./single_node_mle.sh 4
```
`ethproofs_single_node_mle.sh` takes `MLE_ELF=reth-amsterdam` the same way, and then proves the
Sepolia fixture before it opens its port.

### Run the GPU tests

No CI job runs the GPU trace-generation tests or the CPU-vs-GPU benches, so they run only by
hand. Once the toolkit and a card are in place, run them from the repository root:
```
./run_all_tests.sh
```

### Check NUMA

On a host with several NUMA nodes, binding the prover to the node its GPUs hang off avoids
cross-socket memory traffic (`nvidia-smi topo -m` shows the affinity):
```
lscpu
numactl --cpunodebind=<node> --membind=<node> ./single_node_mle.sh 8
```

### Export LD_LIBRARY_PATH

If met errors:
```
target/release/mle-single-node: error while loading shared libraries: libgpu_api.so: cannot open shared object file: No such file or directory
```

Add the repository root, where the build writes `libgpu_api.so`, to `LD_LIBRARY_PATH`:
```
export LD_LIBRARY_PATH=<path to this repository>:$LD_LIBRARY_PATH
```
