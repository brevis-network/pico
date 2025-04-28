export CHUNK_SIZE=4194304
export CHUNK_BATCH_SIZE=32
export SPLIT_THRESHOLD=1048576
export RUSTFLAGS="-C target-cpu=native -C target-feature=+avx512f,+avx512ifma,+avx512vl"
export JEMALLOC_SYS_WITH_MALLOC_CONF="retain:true,background_thread:true,metadata_thp:always,dirty_decay_ms:-1,muzzy_decay_ms:-1,abort_conf:true"

# export RUST_LOG=debug
export RUST_LOG=info

export RUST_BACKTRACE=full

export PROVER_COUNT=32
export RUST_MIN_STACK=16777216
export PROGRAM="reth-17106222"

# ulimit -s unlimited

cargo run -r --bin single-node
