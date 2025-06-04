# export CHUNK_SIZE=4194304
# export CHUNK_BATCH_SIZE=32
# export SPLIT_THRESHOLD=1048576

export CHUNK_SIZE=524288
export CHUNK_BATCH_SIZE=4
export SPLIT_THRESHOLD=131072

# export SPLIT_THRESHOLD=32768
# export CHUNK_SIZE=2097152
# export CHUNK_BATCH_SIZE=4

export RUSTFLAGS="-C target-cpu=native -C target-feature=+avx512f,+avx512ifma,+avx512vl"
export JEMALLOC_SYS_WITH_MALLOC_CONF="retain:true,background_thread:true,metadata_thp:always,dirty_decay_ms:-1,muzzy_decay_ms:-1,abort_conf:true"

# export RUST_LOG=debug
export RUST_LOG=info

export RUST_BACKTRACE=full
export PROVER_COUNT=2
export RUST_MIN_STACK=16777216
export PROGRAM="reth-18884864"
# export PROGRAM="fibonacci-300kn"

export VK_VERIFICATION=false
# ulimit -s unlimited

cargo test -r -- --nocapture test_byte_chip_trace_benchmark
