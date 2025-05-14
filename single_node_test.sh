export CHUNK_SIZE=4194304
export CHUNK_BATCH_SIZE=32
export SPLIT_THRESHOLD=1048576
export RUSTFLAGS="-C target-cpu=native -C target-feature=+avx512f,+avx512ifma,+avx512vl"
export JEMALLOC_SYS_WITH_MALLOC_CONF="retain:true,background_thread:true,metadata_thp:always,dirty_decay_ms:-1,muzzy_decay_ms:-1,abort_conf:true"

export RUST_LOG=debug
export RUST_LOGGER=forest

export RUST_BACKTRACE=full

export PROVER_COUNT=32
export RUST_MIN_STACK=16777216
export PROGRAM="reth-17106222"

# ulimit -s unlimited

RUNS=3

for i in $(seq 1 $RUNS); do
    /usr/bin/time -v cargo run --profile perf --bin single-node --features jemalloc,nightly-features > logs/compare_refactor/test_monitor_${i}.log
done