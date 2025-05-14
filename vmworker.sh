# export CHUNK_SIZE=4194304
# export CHUNK_BATCH_SIZE=32
# export SPLIT_THRESHOLD=1048576

export SPLIT_THRESHOLD=32768
export CHUNK_SIZE=2097152
export CHUNK_BATCH_SIZE=4

export RUST_LOG=debug,tower=info,tonic=info,hyper=info,h2=info
export RUST_LOG=info
# export RUST_LOG=debug

# export RUSTFLAGS="-C target-cpu=native -C target-feature=+avx512f,+avx512ifma,+avx512vl"
export JEMALLOC_SYS_WITH_MALLOC_CONF="retain:true,background_thread:true,metadata_thp:always,dirty_decay_ms:-1,muzzy_decay_ms:-1,abort_conf:true"

export RUST_BACKTRACE=full
export PROVER_COUNT=4
export RUST_MIN_STACK=16777216
export PROGRAM="reth-18884864"

export VK_VERIFICATION=false
# ulimit -s unlimited
export LIC_PATH="pico-gpu.lic"

export COORDINATOR_GRPC_ADDR="http://0.0.0.0:50051"
export WORKER_NAME="zan-1"

# export COORDINATOR_GRPC_ADDR="http://10.60.212.100:50051"
# export WORKER_NAME="zan-2"

cargo run -r --bin worker
