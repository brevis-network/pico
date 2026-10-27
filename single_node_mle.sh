#!/usr/bin/env bash
# Single-node MLE/WHIR prover (KoalaBear, GPU via cuda-mle). Run from the repo root on a CUDA box;
# non-interactive ssh: invoke via `bash -lc ./single_node_mle.sh`. Operating point: CHUNK_SIZE=2^23,
# MLE_LOG_STACKED_HEIGHT=23.
set -xe

# ── Card count ──────────────────────────────────────────────────────────────────────────────────
# `PROVER_COUNT` is a clap field with an env binding, but nothing here ever set it, so every run
# through this script silently used the default of 1 card.
#
# Take it from `$1`, but only when `$1` is a bare number, and `shift` it off. That keeps the
# `"$@"` pass-through at the bottom working, so all three of these behave:
#   ./single_node_mle.sh                 # 1 card (unchanged default)
#   ./single_node_mle.sh 4               # 4 cards
#   ./single_node_mle.sh 4 --step combine
#   ./single_node_mle.sh --step combine  # still parsed as a flag, not a card count
#
# The default stays 1 so this change is behaviour-preserving; picking a different default is a
# policy call for whoever drives it, not for this entry point.
if [[ "${1:-}" =~ ^[0-9]+$ ]]; then
    export PROVER_COUNT="$1"
    shift
else
    export PROVER_COUNT="${PROVER_COUNT:-1}"
fi

# One card = two prover lanes (riscv, recursion) + its own machine set, and every lane binds its
# own device, so asking for more cards than are visible would bind a device that is not there.
# `CUDA_VISIBLE_DEVICES` wins when set, because that is how the two-machine shape splits an 8-card
# host into two 4-card processes.
#
# The lane count comes from the tree (two per card; `MLE_RECURSION_LANE=0` collapses them to the
# single lane the split was carved out of). Deliberately not defaulted here: a second source for
# it would drift from the prover's own default and hide which one is in force.
if [ -n "${CUDA_VISIBLE_DEVICES:-}" ]; then
    visible_gpus=$(tr ',' '\n' <<< "$CUDA_VISIBLE_DEVICES" | grep -c .)
else
    visible_gpus=$(nvidia-smi --query-gpu=index --format=csv,noheader 2>/dev/null | grep -c . || echo 0)
fi
if [ "${visible_gpus:-0}" -gt 0 ] && [ "$PROVER_COUNT" -gt "$visible_gpus" ]; then
    echo "PROVER_COUNT=$PROVER_COUNT exceeds the $visible_gpus visible GPU(s)" >&2
    exit 1
fi
echo "[single_node_mle] PROVER_COUNT=$PROVER_COUNT (visible GPUs: ${visible_gpus:-unknown})"

export RUSTFLAGS="${RUSTFLAGS:--C target-cpu=native -C opt-level=3 -C codegen-units=1}"
# warn + the targets that carry the `MLE bench:` headline, the per-chunk lines, and the per-machine
# provable-bits reading. info everywhere floods the disk on long reth runs.
export RUST_LOG="${RUST_LOG:-warn,bench=info,distributed_vm::mle=info,mle_soundness=info}"
export RUST_BACKTRACE="${RUST_BACKTRACE:-1}"
export RUST_MIN_STACK="${RUST_MIN_STACK:-16777216}"

# Emulator knobs (read by EmulatorOpts::bench_riscv_ops() — the snapshot/sequencer pipeline).
# CHUNK_SIZE=2^23. Requires RS_STREAM_BLOCKS below: the monolithic rs_code_matrix would need a
# single ~16GiB codeword buffer here and OOM on a 32GB card; the streaming commit/open keep the
# peak to one column-block. MLE_LOG_STACKED_HEIGHT must be >= log2(largest trace), track
# log2(CHUNK_SIZE), and is baked into the VK.
export CHUNK_SIZE="${CHUNK_SIZE:-8388608}"
export MLE_LOG_STACKED_HEIGHT="${MLE_LOG_STACKED_HEIGHT:-23}"
# Streaming column-block RS commit+open (cuda-mle stacked_pcs / whir): split the RS codeword
# matrix into N column-blocks so its peak GPU memory is ~one block instead of the whole
# codeword_height x width buffer. Required at CHUNK_SIZE=2^23 (see above); N=8 keeps each block
# ~2GiB. Set RS_STREAM_BLOCKS= (empty) to force the monolithic path (only fits at <=2^22).
export RS_STREAM_BLOCKS="${RS_STREAM_BLOCKS:-8}"
# Precompile-split threshold; sets how many tail chunks the precompile remainders split into.
export SPLIT_THRESHOLD="${SPLIT_THRESHOLD:-32768}"
export CHUNK_BATCH_SIZE="${CHUNK_BATCH_SIZE:-1}"

# Event buffer pools (cpu + alu): pinned host memory pre-allocated before keygen. Streaming only
# needs >= in-flight chunks (backpressure), so a modest pool keeps setup cheap.
export MLE_EVENT_POOL_SIZE="${MLE_EVENT_POOL_SIZE:-64}"

# Pack the RISC-V events for the H2D upload (CpuEvent 304B -> 80B + a 24B side stream). Flat on wall
# clock with one card, where those copies already hid behind the prove kernels, so this is for hosts
# where several provers share a bus. A chunk whose events break a packing invariant silently uses
# the unpacked path instead, which costs the saving for that whole chunk — reth-171 packs all 16 of
# its chunks, and the `fell back to fat path` lines name the cause if a workload stops doing so. The
# packed kernels live in pico-gpu.
export MLE_PACKED_EVENTS="${MLE_PACKED_EVENTS:-1}"

# Snapshot-pipeline memory pool: a CAP, not a count. The
# pool seeds MEMORY_POOL_EAGER entries and tops up in the background while below
# MEMORY_POOL_LOW_WATER, so this number alone no longer keeps the blocking recv from starving.
export MEMORY_POOL_SIZE="${MEMORY_POOL_SIZE:-140}"
export MEMORY_RECYCLER_THREADS="${MEMORY_RECYCLER_THREADS:-4}"

# First-iteration warmup. Without these, the FIRST `e2e=` of a fresh process is 419±52 ms slower
# than the warm ones, purely from host-side first-touch page faults in the pipeline's head (the
# prove lane is the critical path but idle, so the bubble passes straight into `prove(wall)`).
# Prewarming before the `e2e=` window opens drops that to 42±107 ms — i.e. the first run's number is
# usable. Costs ~1.1s of setup (outside `e2e=`, inside `total=`) and ~1.2GB of peak RSS; the warm
# iterations are unchanged. Both are needed: `MLE_PREWARM` alone recovers ~1/3, because tcmalloc
# hands the pre-faulted pages back to the kernel unless the release is disabled. Two knobs that
# look related but are not: MEMORY_POOL_PRETOUCH is a measured no-op (its faults are off the
# critical path) and CUDA_MODULE_LOADING=EAGER is harmful (the eager load lands inside `e2e=`).
# Turn the whole thing off with `MLE_PREWARM=0`.
export MLE_PREWARM="${MLE_PREWARM:-1}"
export MLE_HEAP_PREWARM_GB="${MLE_HEAP_PREWARM_GB:-6}"
export TCMALLOC_RELEASE_RATE="${TCMALLOC_RELEASE_RATE:-0}"

# Emulator trace / snapshot worker threads (vm/src/proverchain/riscv.rs), NOT prover_count.
# Held at 1 while parallel emulation produced invalid proofs; that is fixed (chunks are stamped
# with the record's own index, not its arrival order). 8 is where emulate saturates — 1/2/8/12 all
# verified through combine, with e2e flat across them, since emulate runs behind prove.
export NUM_THREADS="${NUM_THREADS:-8}"

# Global rayon pool; rayon otherwise sizes it from num_cpus (124 on the box measured here).
# 32 is worth -3.3% e2e, and it lands in the riscv and convert phases -- combine goes +4.0% the
# other way and the tail does not move at all, so read the win on the phases, not the whole run.
# Do not go much lower: at 8 the dispatcher stops being fed and the run dies on GlobalScheduler's
# 300s "system is broken" timeout. Measured at four cards only; scale it with the card count.
# Per process, so a box running both halves of two_machine_mle.sh gets two of these pools.
export RAYON_NUM_THREADS="${RAYON_NUM_THREADS:-32}"

# CPU preparer pools come from the tree (one per kind on a single card); set MLE_*_PREPARERS to override.

# GPU memory tier for precompile-split thresholds (record.rs get_prover_hardware_config): 5090 =>
# Tier32GB. Leaving it unset drops to the smaller (24GB) thresholds, which produce more tail
# chunks.
export PICO_GPU_MEM="${PICO_GPU_MEM:-5090}"

# CUDA mem-pool warm reserve (mem_pool.rs create_ctx; code default 29e9). Not pre-paying pool
# growth -- the pool neither shrinks nor grows during prove: at 1e9 the 16 GiB gkr_leaves buffer
# asks for ~95% of free pool space and the driver coalesces the whole free list (~26ms/chunk),
# while a larger reserve leaves exact-fit blocks. Set 1000000000 for the old nvidia-smi reading.
export MEM_POOL_RESERVE_SIZE="${MEM_POOL_RESERVE_SIZE:-28000000000}"

# --- Zerocheck constraint-eval JIT (cuda-mle nvrtc codegen; replaces the buffer interpreter). ---
# G1 = interaction eval (GKR input / logup MLE rounds); Z1 = round-0 zerocheck. Both warmed at
# keygen (see RiscvMachine::new -> warmup_jit_kernels) so nvrtc does not run mid-proof; concurrent
# keygens are held apart by a lock inside compile_kernel, which is what the libnvrtc deadlock
# actually needs. The MAX_RULES
# gates keep the hot-path core AIRs JIT-ed while leaving the optional-precompile giants
# (Weierstrass/Fp2, up to ~72k rules) on the interpreter — compiling those never finishes nvrtc.
# Z1_JIT_SEG_RULES segments rule lists > Z1_JIT_SEG_MIN (default 2000) into __noinline__ functions
# so the compile-infeasible monsters become compilable. Cubin disk cache: MLE_JIT_CACHE_DIR.
# NOTE: the MAX_RULES defaults below mirror `JitKind::default_max_rules` (cuda-mle/src/cuda/jit.rs);
# the binary applies the same values when these are unset — keep the two in sync.
# Z1's gate has headroom on purpose: an AIR over it drops to the rule interpreter -- correct, just
# slower -- so any value between the largest admitted AIR and the smallest gated-out one admits the
# same set, and the high end of that range is the safe one. Both counts move at every upstream bump,
# so they are not quoted here; the binary warns once per AIR when one actually crosses.
# `{G1,Z1}_JIT=0` DISABLES that family; it used to enable it.
export G1_JIT="${G1_JIT:-1}"
export Z1_JIT="${Z1_JIT:-1}"
export G1_JIT_MAX_RULES="${G1_JIT_MAX_RULES:-2000}"
export Z1_JIT_MAX_RULES="${Z1_JIT_MAX_RULES:-11000}"
export Z1_JIT_SEG_RULES="${Z1_JIT_SEG_RULES:-400}"
export MLE_JIT_MAXRREG_Z1="${MLE_JIT_MAXRREG_Z1:-128}"
# Compiled-cubin disk cache. Default under $HOME so it is shared across worktrees and outside the
# repo (never $PWD, which would land ~hundreds of MB of .cubin in the worktree). Override to isolate
# per user on a shared host.
export MLE_JIT_CACHE_DIR="${MLE_JIT_CACHE_DIR:-$HOME/.mle_jit_cache}"

# --- Recursion key pre-building (both default ON; `=0` restores the pre-change path). ---
# Together they take the recursion keygen off the proof tree's serial chain, measured at -2.15 %
# E2E over fourteen paired runs on the p99 blocks, with peak VRAM unchanged.
# MLE_CONVERT_PREBUILD_PK: the convert pre-build warms the device proving key as well as the
# program, on the card that will prove the chunk. Those workers then bind a card and do device
# work, which the program-only form avoids -- `=0` if that matters more than the time.
# MLE_COMBINE_OVERLAP_KEYGEN: a combine node's keygen runs against its recursion emulation instead
# of before it. Its keygen then has no span lane, so it stops appearing in the span record.
export MLE_CONVERT_PREBUILD_PK="${MLE_CONVERT_PREBUILD_PK:-1}"
export MLE_COMBINE_OVERLAP_KEYGEN="${MLE_COMBINE_OVERLAP_KEYGEN:-1}"

# Default: reth block 18884864 (selector 188). Override with MLE_ELF / MLE_N.
ELF="${MLE_ELF:-reth}"
N="${MLE_N:-188}"

# Prove the whole chain by default: stopping at riscv leaves the recursion layers unmeasured. `:-` so
# an explicit MLE_STEP wins.
export MLE_STEP="${MLE_STEP:-combine}"

# Default GPU path (`cuda`) + `aot-emulator`. Override FEATURES for
# CPU-only. NOTE: aot-emulator requires the per-ELF AOT dispatch crate to be generated first:
#   cargo run -r -p pico-aot-codegen --bin generate_crates -- perf/bench_data/rv64/reth-elf
# (run once per ELF; without it the `aot-generated` crate is a stub and the build fails).
FEATURES="${FEATURES:-bigint-rug tcmalloc mmap-memory aot-emulator cuda}"

CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-8}" cargo build --bin mle-single-node --release --features "$FEATURES"

export LD_LIBRARY_PATH="$PWD:$LD_LIBRARY_PATH"

# Raw spans (vm/src/mle/spans) for the timeline figures below. Defaulted, not forced: the bench
# harness sets `MLE_SPANS` to its own artefact path and that must win.
current_time=$(date "+%Y-%m-%d_%H-%M-%S")
export MLE_SPANS="${MLE_SPANS:-logs/mle_${ELF}${N}_${current_time}/run.spans.csv}"
mkdir -p "$(dirname "$MLE_SPANS")"

# `MLE_REPEAT=N` makes the prover export one CSV per iteration, named `<MLE_SPANS>.iterK` by
# `csv_path_for_iteration` in `vm/src/mle/spans/record.rs`; a single run writes the named path itself.
#
# The count is read the way the prover reads it (`usize::from_str`, then `>= 1` or fall back to one),
# because the two have to agree on how many files exist. A leading `+` parses there; leading zeros do
# too, and here they have to go before the digits are counted, or `0000100` would be read as a typo.
n_iters="${MLE_REPEAT:-1}"
case "$n_iters" in +[0-9]*) n_iters="${n_iters#+}" ;; esac
case "$n_iters" in
    '' | *[!0-9]*) n_iters=1 ;;
    *)
        n_iters="${n_iters#"${n_iters%%[!0]*}"}"
        # A ceiling the prover does not have: the list below holds one entry per iteration, so a
        # mistyped count would spend the run building that instead of proving (2.4 s at 10^6 entries).
        # Nothing proves 10^5 blocks in one process; raise this if that ever stops being true.
        if [ -z "$n_iters" ] || [ "${#n_iters}" -gt 5 ]; then
            n_iters=1
        else
            n_iters=$((10#$n_iters))
        fi
        ;;
esac
if [ "${MLE_TIMELINE:-0}" != "0" ]; then want_figures=1; else want_figures=0; fi

# What this run is expected to write. Built once: the clear below and the drawing further down both
# need it, and two copies of the rule could drift.
if [ "$n_iters" -gt 1 ]; then
    spans_expected=()
    for ((k = 1; k <= n_iters; k++)); do spans_expected+=("$MLE_SPANS.iter$k"); done
else
    spans_expected=("$MLE_SPANS")
fi

# Clear them, so a file still there afterwards is one this run wrote rather than one an earlier run
# left at the same path -- which the drawing would otherwise present as this run's. Reachable when
# MLE_SPANS is given explicitly and a run is repeated at it; the default path carries a timestamp.
#
# Only when figures were asked for: this is destructive and the drawing block is its sole beneficiary.
# `|| true` because a failure here -- a directory sitting at the name, a read-only log directory --
# must not take a 40-minute proving run down with it.
if [ "$want_figures" = 1 ]; then
    rm -f -- "${spans_expected[@]}" || true
fi

# Extra args pass through, so `./single_node_mle.sh --step combine` works alongside MLE_STEP.
#
# The exit code is carried by hand rather than left to `set -e`, so a failed run still reaches the
# drawing below — which then finds a CSV only if the prover got as far as writing one, since the export
# is the last thing its report does.
# stdout stays untouched -- callers redirect it themselves, so capturing it here would take the log
# away from them.
rc=0
./target/release/mle-single-node --elf "$ELF" --n "$N" "$@" || rc=$?

# Timeline figures beside the spans CSV, same prefix. Opt-in with `MLE_TIMELINE=1`: a proving run should
# not grow side effects, and the CSV is written either way, so any run can be drawn afterwards.
if [ "$want_figures" = 1 ]; then
    # `-f` as well as `-s`: a directory's own size is never zero, so `-s` alone accepts one.
    fresh() { [ -f "$1" ] && [ -s "$1" ]; }
    last_expected="${spans_expected[${#spans_expected[@]} - 1]}"
    spans_csvs=()
    for f in "${spans_expected[@]}"; do
        if fresh "$f"; then spans_csvs+=("$f"); fi
    done

    # Each branch says something: silence here is indistinguishable from "drawing is switched off".
    if ! command -v python3 > /dev/null 2>&1; then
        echo "[single_node_mle] python3 not found; skipping timeline figures" >&2
    elif [ ${#spans_csvs[@]} -eq 0 ]; then
        echo "[single_node_mle] none of the ${#spans_expected[@]} expected spans CSV(s) exist" \
             "(first: ${spans_expected[0]}); nothing to draw" >&2
    else
        if ! fresh "$last_expected"; then
            # Only the last iteration lines up with the log's last `MLE bench:` / `MLE lane:` lines,
            # so without it every figure takes its window from its own last span and skips the checks.
            echo "[single_node_mle] iteration $n_iters wrote no spans CSV;" \
                 "drawing the rest without --log" >&2
        fi
        for spans_csv in "${spans_csvs[@]}"; do
            # `--log` adds the window, the run's shape and the checks against the prover's own
            # figures, and this script does not own its own stdout, so the caller names the log
            # through MLE_TIMELINE_LOG when it has one.
            #
            # It goes to the LAST iteration only: the log covers the whole process and the drawing
            # script keeps the last match it finds. Hand it to an earlier one and those checks run
            # against another iteration's numbers, fail, and return before anything is drawn.
            log_arg=()
            if [ "$spans_csv" = "$last_expected" ] \
               && [ -f "${MLE_TIMELINE_LOG:-}" ] && [ -r "${MLE_TIMELINE_LOG}" ]; then
                log_arg=(--log "$MLE_TIMELINE_LOG")
            fi
            python3 bench-scripts/draw-mle-timeline.py "$spans_csv" "${log_arg[@]}" || true
        done
    fi
fi

exit $rc
