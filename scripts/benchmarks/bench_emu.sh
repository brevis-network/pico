#!/bin/bash

# Run this script from the root of the repository.
# ./scripts/benchmarks/bench_emu.sh

set -e

# Create a timestamped log folder
LOG_DIR="logs/$(date +'%Y%m%d-%H%M%S')"
mkdir -p "$LOG_DIR"

#cargo build --release --bin gnarkctl
#cp target/release/gnarkctl gnarkctl

export CHUNK_SIZE=2097152
export CHUNK_BATCH_SIZE=1
export SPLIT_THRESHOLD=1048576
export RUST_LOG=info
#export RUSTFLAGS="-C target-cpu=native -C target-feature=+avx512f,+avx512ifma,+avx512vl"
export RUSTFLAGS="-C target-cpu=native"
export JEMALLOC_SYS_WITH_MALLOC_CONF="retain:true,background_thread:true,metadata_thp:always,dirty_decay_ms:-1,muzzy_decay_ms:-1,abort_conf:true"
export VK_VERIFICATION=false
export NUM_THREADS=6
#export FRI_QUERIES=1
export RUST_BACKTRACE=full

# PROG="reth-17106222"
PROGRAMS=("reth-17106222")
#PROGRAMS=("fibonacci-300kn" "tendermint" "reth-17106222" "reth-22528700" "reth-18884864" "reth-22059900" "reth-20528709" "reth-22515566" "reth-22745330")

FIELD="kb"

RUNS=5

#./gnarkctl setup --field $FIELD
for PROG in "${PROGRAMS[@]}"; do
  for i in $(seq 1 $RUNS); do
    echo "===== Run #$i ====="
    LOG_FILE_SIMPLE="bench_emu_${PROG}_${i}_simple.log"
    LOG_FILE_SNAPSHOT="bench_emu_${PROG}_${i}_snapshot.log"
    LOG_FILE_PROVE="bench_emu_${PROG}_${i}_prove.log"
  #  RUST_LOG=info RUSTFLAGS="-Cforce-frame-pointers=yes" cargo run --release --bin bench --features jemalloc,nightly-features -- --programs $PROG --field $FIELD --noprove | tee "$LOG_DIR/$LOG_FILE"
  #  RUST_LOG=info cargo run --release --bin bench -- --programs $PROG --field $FIELD --noprove | tee "$LOG_DIR/$LOG_FILE"
  #  RUST_LOG=info cargo run --release --bin bench --features jemalloc,nightly-features -- --programs $PROG --field $FIELD | tee "$LOG_DIR/$LOG_FILE"
#    export RUSTFLAGS="-C target-cpu=native -C force-frame-pointers=yes"
#    cargo run --profile flamegraph --bin bench --features jemalloc,nightly-features,bigint-rug -- --programs $PROG --field $FIELD --noprove --simple | tee "$LOG_DIR/$LOG_FILE_SIMPLE"
    export RUSTFLAGS="-C target-cpu=native"
    cargo run --release --bin bench --features jemalloc,nightly-features,bigint-rug -- --programs $PROG --field $FIELD --noprove --snapshot | tee "$LOG_DIR/$LOG_FILE_SNAPSHOT"
#    cargo run --release --bin bench --features jemalloc,nightly-features,bigint-rug -- --programs $PROG --field $FIELD 2>&1 | tee "$LOG_DIR/$LOG_FILE_PROVE"
  done
done

#./gnarkctl teardown
#rm gnarkctl

echo "pico benchmark fibonacci (kb) completed!"