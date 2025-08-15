#!/bin/bash

# Run this script from the root of the repository.
# ./scripts/benchmarks/bench_all_with_vk.sh

set -e

# Create a timestamped log folder
LOG_DIR="logs/$(date +'%Y%m%d-%H%M%S')"
mkdir -p "$LOG_DIR"

cargo build --release --bin gnarkctl
cp target/release/gnarkctl gnarkctl

export CHUNK_SIZE=4194304
export CHUNK_BATCH_SIZE=32
export SPLIT_THRESHOLD=1048576
export RUST_LOG=info
export RUSTFLAGS="-C target-cpu=native -C target-feature=+avx512f,+avx512ifma,+avx512vl"
export JEMALLOC_SYS_WITH_MALLOC_CONF="retain:true,background_thread:true,metadata_thp:always,dirty_decay_ms:-1,muzzy_decay_ms:-1,abort_conf:true"
export VK_VERIFICATION=true

PROGRAMS=("fibonacci-300kn" "tendermint" "reth-17106222" "reth-20528709")
FIELDS=("bb" "kb")

for field in "${FIELDS[@]}"; do

  ./gnarkctl setup --field "$field"

  for prog in "${PROGRAMS[@]}"; do
    echo "Benchmarking $prog with field $field"
    cargo run --profile perf --bin bench --features jemalloc --features nightly-features -- --programs "$prog" --field "$field" > "$LOG_DIR/pico-$prog-$field.log"
  done
done

./gnarkctl teardown
rm gnarkctl

echo "pico benchmark (kb and bb, with vk) completed!"