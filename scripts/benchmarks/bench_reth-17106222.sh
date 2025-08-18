#!/bin/bash

# Run this script from the root of the repository.
# ./scripts/benchmarks/bench_reth-17106222.sh

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

PROG="reth-17106222"
FIELD="kb"

RUNS=5

./gnarkctl setup --field $FIELD

for i in $(seq 1 $RUNS); do
  echo "===== Run #$i ====="
  LOG_FILE="bench_reth171_${i}.log"
  cargo run --profile perf --bin bench --features jemalloc,nightly-features -- --programs $PROG --field $FIELD | tee "$LOG_DIR/$LOG_FILE"
done

./gnarkctl teardown
rm gnarkctl

echo "pico benchmark reth-17106222 (kb) completed!"