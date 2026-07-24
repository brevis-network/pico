#!/bin/bash
#
# Run the reth-24600825 AOT proof end-to-end via perf/bench.
# Run this script from the ROOT of the repository:
#     bash scripts/benchmarks/aot_gate.sh
#
# Steps:
#   1. (re)generate the AOT dispatch + chunk crates for the reth ELF into ./aot-generated,
#      overwriting the bootstrap stub with reth-specific COMPILED chunks. In-tree codegen
#      uses the default relative `../aot-runtime` runtime spec (no env needed).
#   2. Prove reth-24600825 through the AOT snapshot pipeline (bench --features aot --aot).
#
# Prereqs (must exist): ./perf/bench_data/reth-elf and ./perf/bench_data/reth-24600825.bin
#
# Notes:
#   - reth is large -> generate_crates can emit MANY chunk crates; step 1 codegen and the
#     step 2 `--features aot` build can both take a while / a lot of RAM the first time.
#   - Step 1 overwrites the tracked ./aot-generated stub locally (+ untracked chunk dirs).
#     This is a build artifact — do NOT commit it. `git checkout -- aot-generated` restores
#     the stub if a later `git merge --ff-only` ever complains about it.
#   - Set SKIP_AOT_CODEGEN=1 to reuse an already-generated ./aot-generated (repeat runs).

set -e

# Create a timestamped log folder
LOG_DIR="logs/$(date +'%Y%m%d-%H%M%S')"
mkdir -p "$LOG_DIR"

export CHUNK_SIZE=4194304
export CHUNK_BATCH_SIZE=1
export SPLIT_THRESHOLD=1048576
export RUST_LOG=debug
export RUSTFLAGS="-C target-cpu=native"
export JEMALLOC_SYS_WITH_MALLOC_CONF="retain:true,background_thread:true,metadata_thp:always,dirty_decay_ms:-1,muzzy_decay_ms:-1,abort_conf:true"
export VK_VERIFICATION=true

PROG="reth-24600825"
FIELD="kb"
RETH_ELF="./perf/bench_data/reth-elf"
RETH_INPUT="./perf/bench_data/${PROG}.bin"
AOT_OUT="./aot-generated"

RUNS=1

# ---- sanity: required inputs present ----
[ -f "$RETH_ELF" ]   || { echo "ERROR: missing reth ELF at $RETH_ELF"; exit 1; }
[ -f "$RETH_INPUT" ] || { echo "ERROR: missing block input at $RETH_INPUT (need $PROG.bin)"; exit 1; }

# ---- Step 1: (re)generate AOT crates for the reth ELF into ./aot-generated ----
if [ "${SKIP_AOT_CODEGEN:-0}" = "1" ]; then
  echo "===== [1/2] SKIP_AOT_CODEGEN=1 -> reusing existing $AOT_OUT ====="
else
  echo "===== [1/2] generate_crates: $RETH_ELF -> $AOT_OUT ====="
  cargo run -r -p pico-aot-codegen --bin generate_crates -- "$RETH_ELF" "$AOT_OUT" \
    2>&1 | tee "$LOG_DIR/generate_crates.log"
fi

# ---- Step 2: prove reth-24600825 with the AOT snapshot pipeline ----
echo "===== [2/2] prove $PROG ($FIELD) with AOT ====="
for i in $(seq 1 $RUNS); do
  echo "===== Run #$i ====="
  LOG_FILE="aot_reth246_${i}.log"
  DEBUG_MEMORY_EVENTS=1 DEBUG_SNAPSHOT=1 DEBUG_SNAPSHOT_RESTORE=1 \
    cargo run --release --bin bench --features jemalloc,nightly-features,aot -- \
    --programs "$PROG" --field "$FIELD" --aot \
    > "$LOG_DIR/$LOG_FILE" 2>&1
  echo "  log: $LOG_DIR/$LOG_FILE"
done

echo "pico aot $PROG ($FIELD) completed! logs: $LOG_DIR"
