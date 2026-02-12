#!/bin/bash

# Run this script from the root of the repository.
# ./scripts/benchmarks/bench_custom.sh

set -e

# Create a timestamped log folder
LOG_DIR="logs/$(date +'%Y%m%d-%H%M%S')"
mkdir -p "$LOG_DIR"

# Environment variables setup
export CHUNK_SIZE=4194304
export CHUNK_BATCH_SIZE=1
export SPLIT_THRESHOLD=1048576
export RUST_LOG=debug
export RUSTFLAGS="-C target-cpu=native"
export JEMALLOC_SYS_WITH_MALLOC_CONF="retain:true,background_thread:true,metadata_thp:always,dirty_decay_ms:-1,muzzy_decay_ms:-1,abort_conf:true"
export VK_VERIFICATION=false
export NUM_THREADS=8

FIELD="kb"

# --- Define Function---
run_benchmark() {
    local PROG=$1
    local RUNS=$2

    echo ">>> Starting benchmark for $PROG (Running $RUNS times)"

    for i in $(seq 1 $RUNS); do
        echo "===== $PROG: Run #$i of $RUNS ====="
        
        LOG_FILE="bench_${PROG}_run${i}.log"
        # DEBUG_MEMORY_CHIPS=1 DEBUG_LOCAL_MEMORY=1 DEBUG_MEMORY_EVENTS=1 RUST_BACKTRACE=1 
        # mmap-memory feature is much slower than box-memory
        # cargo run --release --bin bench --features jemalloc,nightly-features,bigint-rug \
            # -- --programs $PROG --field $FIELD --noprove --snapshot > "$LOG_DIR/$LOG_FILE" 2>&1
        cargo run --release --bin bench --features jemalloc,nightly-features,bigint-rug \
            -- --programs $PROG --field $FIELD > "$LOG_DIR/$LOG_FILE" 2>&1
    done
}

# ---Execute Tasks---
run_benchmark "pure-fibonacci" 1
run_benchmark "bn" 3
run_benchmark "bls12381" 3

run_benchmark "fibonacci-300kn" 1
# run_benchmark "reth-18884864" 1
run_benchmark "reth-17106222" 1

run_benchmark "reth-23993050" 1

echo "All benchmarks (reth-17106222 & reth-23993050) completed!"
