#!/usr/bin/env bash
# EthProofs single-node MLE/WHIR prover (KoalaBear, GPU via cuda-mle).
#
# A LONG-RUNNING SERVICE, not a benchmark run: it binds the PicoProver gRPC port and proves
# whatever RSP sends, one block at a time, until killed. Run from the repo root on a CUDA box;
# non-interactive ssh: invoke via `bash -lc ./ethproofs_single_node_mle.sh`.
#
#   ./ethproofs_single_node_mle.sh 4            # 4 cards
#   CUDA_VISIBLE_DEVICES=4,5,6,7 ./ethproofs_single_node_mle.sh 4
#
# The proving knobs below are `single_node_mle.sh`'s, verbatim and for the same reasons -- an
# operating point tuned there transfers here unchanged. Only the service settings at the bottom and
# the three marked differences are new. Read `single_node_mle.sh` for the full rationale of each
# proving knob; it is not duplicated here, so the two cannot drift into two explanations.
set -xe

# ── Card count ──────────────────────────────────────────────────────────────────────────────────
if [[ "${1:-}" =~ ^[0-9]+$ ]]; then
    export PROVER_COUNT="$1"
    shift
else
    export PROVER_COUNT="${PROVER_COUNT:-1}"
fi

if [ -n "${CUDA_VISIBLE_DEVICES:-}" ]; then
    visible_gpus=$(tr ',' '\n' <<< "$CUDA_VISIBLE_DEVICES" | grep -c .)
else
    visible_gpus=$(nvidia-smi --query-gpu=index --format=csv,noheader 2>/dev/null | grep -c . || echo 0)
fi
if [ "${visible_gpus:-0}" -gt 0 ] && [ "$PROVER_COUNT" -gt "$visible_gpus" ]; then
    echo "PROVER_COUNT=$PROVER_COUNT exceeds the $visible_gpus visible GPU(s)" >&2
    exit 1
fi
echo "[ethproofs_mle] PROVER_COUNT=$PROVER_COUNT (visible GPUs: ${visible_gpus:-unknown})"

export RUSTFLAGS="${RUSTFLAGS:--C target-cpu=native -C opt-level=3 -C codegen-units=1}"
export RUST_BACKTRACE="${RUST_BACKTRACE:-1}"
export RUST_MIN_STACK="${RUST_MIN_STACK:-16777216}"

# ⚠️ DIFFERENCE 1 vs single_node_mle.sh: this log is a forensic record of a service that is meant to
# run for days, not the output of one run someone is watching. `distributed_vm::mle::ethproofs` is
# added at info so every accepted block, every rejection and every stored result is on the record.
export RUST_LOG="${RUST_LOG:-warn,bench=info,distributed_vm::mle=info,mle_soundness=info}"

# ── Proving knobs (see single_node_mle.sh for the reasoning behind each) ─────────────────────────
export CHUNK_SIZE="${CHUNK_SIZE:-8388608}"
export MLE_LOG_STACKED_HEIGHT="${MLE_LOG_STACKED_HEIGHT:-23}"
export RS_STREAM_BLOCKS="${RS_STREAM_BLOCKS:-8}"
export SPLIT_THRESHOLD="${SPLIT_THRESHOLD:-32768}"
export CHUNK_BATCH_SIZE="${CHUNK_BATCH_SIZE:-1}"
export MLE_EVENT_POOL_SIZE="${MLE_EVENT_POOL_SIZE:-64}"
export MLE_PACKED_EVENTS="${MLE_PACKED_EVENTS:-1}"

# ⚠️ DIFFERENCE 2: pinned EXPLICITLY, not left to follow MLE_EVENT_POOL_SIZE.
# The slots are pre-pinned host memory at ~1.4 GB each, so the binary's own default of 256 is
# ~358 GiB per process. A benchmark run that dies on that is an afternoon; a service that dies on
# it is missed blocks and a liveness penalty, and it would die on the FIRST block after a config
# change nobody connected to this knob.
export MLE_PACKED_POOL_SIZE="${MLE_PACKED_POOL_SIZE:-16}"

export MEMORY_POOL_SIZE="${MEMORY_POOL_SIZE:-140}"
export MEMORY_RECYCLER_THREADS="${MEMORY_RECYCLER_THREADS:-4}"
export MLE_PREWARM="${MLE_PREWARM:-1}"
export MLE_HEAP_PREWARM_GB="${MLE_HEAP_PREWARM_GB:-6}"
export TCMALLOC_RELEASE_RATE="${TCMALLOC_RELEASE_RATE:-0}"
export NUM_THREADS="${NUM_THREADS:-8}"
export RAYON_NUM_THREADS="${RAYON_NUM_THREADS:-32}"
export PICO_GPU_MEM="${PICO_GPU_MEM:-5090}"
export MEM_POOL_RESERVE_SIZE="${MEM_POOL_RESERVE_SIZE:-28000000000}"
export G1_JIT="${G1_JIT:-1}"
export Z1_JIT="${Z1_JIT:-1}"
export G1_JIT_MAX_RULES="${G1_JIT_MAX_RULES:-2000}"
export Z1_JIT_MAX_RULES="${Z1_JIT_MAX_RULES:-11000}"
export Z1_JIT_SEG_RULES="${Z1_JIT_SEG_RULES:-400}"
export MLE_JIT_MAXRREG_Z1="${MLE_JIT_MAXRREG_Z1:-128}"
export MLE_JIT_CACHE_DIR="${MLE_JIT_CACHE_DIR:-$HOME/.mle_jit_cache}"
export MLE_CONVERT_PREBUILD_PK="${MLE_CONVERT_PREBUILD_PK:-1}"
export MLE_COMBINE_OVERLAP_KEYGEN="${MLE_COMBINE_OVERLAP_KEYGEN:-1}"

# ── Service settings ────────────────────────────────────────────────────────────────────────────
export MLE_ELF="${MLE_ELF:-reth}"

# ⚠️ DIFFERENCE 3: forced, not defaulted. `--step riscv` and `--step convert` produce no root, so a
# prover started on either would answer every GetProveResult with "no proof" forever while looking
# perfectly healthy. There is no legitimate ethproofs run below combine, so this is not a knob.
if [ -n "${MLE_STEP:-}" ] && [ "$MLE_STEP" != "combine" ]; then
    echo "MLE_STEP=$MLE_STEP: ethproofs needs a combine root; refusing to start" >&2
    exit 1
fi
export MLE_STEP=combine

# Where RSP connects (its WITNESS_GETAWAY_ENDPOINT). 50051 matches the FRI ethproofs node, so RSP
# needs no change to point at this one.
export GRPC_ADDR="${GRPC_ADDR:-0.0.0.0:50051}"
export AUTH_METHOD="${AUTH_METHOD:-none}"
export MAX_GRPC_MSG_SIZE="${MAX_GRPC_MSG_SIZE:-629145600}"
export MLE_RT_THREADS="${MLE_RT_THREADS:-2}"
export MLE_ETHPROOFS_RESULT_CAPACITY="${MLE_ETHPROOFS_RESULT_CAPACITY:-64}"

# SKIP_BUILD=1 runs the binary that is already there. systemd sets it: a service that compiles
# on every start turns a broken tree into a restart loop, and turns a cold build into what looks
# like a hang. Interactive runs still build by default, so the two cannot drift.
FEATURES="${FEATURES:-bigint-rug tcmalloc mmap-memory aot-emulator cuda-mle}"
if [ -z "${SKIP_BUILD:-}" ]; then
    CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-8}" \
        cargo build --bin mle-ethproofs-single-node --release --features "$FEATURES"
elif [ ! -x ./target/release/mle-ethproofs-single-node ]; then
    echo "SKIP_BUILD set but ./target/release/mle-ethproofs-single-node is not there" >&2
    exit 1
fi

export LD_LIBRARY_PATH="$PWD:$LD_LIBRARY_PATH"

current_time=$(date "+%Y-%m-%d_%H-%M-%S")
log_dir="logs/ethproofs_mle_${PROVER_COUNT}card_${current_time}"
mkdir -p "$log_dir"
log_file="$log_dir/ethproofs-mle.txt"
echo "[ethproofs_mle] logging to $log_file"

# Rotation, because this process is expected to outlive any one log file. 2 GB x 5 is a ~10 GB
# forensic window -- whether that is enough for a 48h incident has not been measured; if a soak
# needs longer, raise the count here rather than discovering the gap afterwards.
# Needs apache2-utils (Debian/Ubuntu) / httpd-tools (RHEL); without it the run still works, the log
# just goes to one unbounded file.
if command -v rotatelogs > /dev/null; then
    ./target/release/mle-ethproofs-single-node "$@" 2>&1 | rotatelogs -n 5 "$log_file" 2G
else
    echo "[ethproofs_mle] rotatelogs not found; writing one unbounded log" >&2
    ./target/release/mle-ethproofs-single-node "$@" 2>&1 | tee "$log_file"
fi
