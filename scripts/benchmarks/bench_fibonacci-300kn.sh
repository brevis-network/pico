#!/bin/bash

# Run this script from the root of the repository.
# ./scripts/benchmarks/bench_fibonacci-300kn.sh

set -e

# Create a timestamped log folder
LOG_DIR="logs/$(date +'%Y%m%d-%H%M%S')"
mkdir -p "$LOG_DIR"

# cargo build --release --bin gnarkctl
# cp target/release/gnarkctl gnarkctl

export CHUNK_SIZE=4194304
export CHUNK_BATCH_SIZE=1
export SPLIT_THRESHOLD=1048576
export RUST_LOG=debug
export RUSTFLAGS="-C target-cpu=native"
export JEMALLOC_SYS_WITH_MALLOC_CONF="retain:true,background_thread:true,metadata_thp:always,dirty_decay_ms:-1,muzzy_decay_ms:-1,abort_conf:true"
export VK_VERIFICATION=false

PROG="pure-fibonacci"
FIELD="kb"

RUNS=1

# ./gnarkctl setup --field $FIELD

for i in $(seq 1 $RUNS); do
  echo "===== Run #$i ====="
  LOG_FILE="bench_reth171_${i}.log"
  DEBUG_MEMORY_EVENTS=1 DEBUG_SNAPSHOT=1 DEBUG_SNAPSHOT_RESTORE=1 cargo run --release --bin bench --features jemalloc,nightly-features -- --programs $PROG --field $FIELD > "$LOG_DIR/$LOG_FILE" 2>&1
done

# ./gnarkctl teardown
# rm gnarkctl

echo "pico benchmark reth-17106222 (kb) completed!"