#!/bin/bash

# Run this script from the root of the repository.
# ./scripts/benchmarks/bench_fibonacci-300kn.sh

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

./gnarkctl setup --field kb
cargo run --profile perf --bin bench --features jemalloc --features nightly-features -- --programs fibonacci-300kn --field kb | tee "$LOG_DIR/fibonacci-300kn-kb.log"

./gnarkctl setup --field bb
cargo run --profile perf --bin bench --features jemalloc --features nightly-features -- --programs fibonacci-300kn --field bb | tee "$LOG_DIR/fibonacci-300kn-bb.log"

./gnarkctl teardown
rm gnarkctl

echo "pico benchmark fibonacci-300kn (kb and bb) completed!"