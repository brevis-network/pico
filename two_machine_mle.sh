#!/usr/bin/env bash
# MLE two-machine launcher: N cards each side, real gRPC.
#
#   ./two_machine_mle.sh primary   4          # cards 4..7, serves the scheduler
#   ./two_machine_mle.sh secondary 4          # cards 0..3, connects to PRIMARY_IP
#
# Both halves are the SAME binary and the same pipeline as `single_node_mle.sh`; only the role and
# the visible cards differ. Run them in two shells (or two `nohup`s) on one host, primary first.
#
# The card count is per side, not total, and is deliberately a parameter rather than a hardcoded 4:
# 2+2 exercises the identical path on half a box, which is the difference between validating this
# on a busy machine and waiting for eight free cards.
set -xe

ROLE="${1:?usage: two_machine_mle.sh <primary|secondary> <cards-per-side> [extra args...]}"
CARDS="${2:?usage: two_machine_mle.sh <primary|secondary> <cards-per-side> [extra args...]}"
shift 2

case "$ROLE" in
    primary | secondary) ;;
    *)
        echo "role must be 'primary' or 'secondary', got '$ROLE'" >&2
        exit 1
        ;;
esac

# `CUDA_VISIBLE_DEVICES` is mandatory, not tidiness: the prover assumes device ids start at 0 and
# binds 0..prover_count, so each process must see its own cards AS 0..N-1.
#
# Two layouts, because the two halves may or may not share a box:
#
#   MLE_TWO_HOST=1  each half is on its OWN machine and takes that machine's cards.
#   (unset)         both halves share one box, so the cards are split — primary takes the top half
#                   so a partially-busy box can still host the secondary on the low cards.
#
# The distinction is load-bearing for the numbers, not just for the launch: on one box the two
# halves contend for CPU and memory bandwidth, which is most of the measured two-process cost.
total_gpus=$(nvidia-smi --query-gpu=index --format=csv,noheader 2>/dev/null | grep -c . || echo 0)
if [ -n "${MLE_TWO_HOST:-}" ]; then
    if [ "$CARDS" -gt "${total_gpus:-0}" ]; then
        echo "need $CARDS GPUs on this host, it has ${total_gpus}" >&2
        exit 1
    fi
    export CUDA_VISIBLE_DEVICES="${CUDA_VISIBLE_DEVICES:-$(seq -s, 0 $((CARDS - 1)))}"
    # Pointing at 127.0.0.1 with MLE_TWO_HOST set would silently run both halves against a local
    # scheduler that only one of them fills — a hang, not an error. Refuse it.
    if [ "$ROLE" = "secondary" ] && [ "${PRIMARY_IP:-127.0.0.1}" = "127.0.0.1" ]; then
        echo "MLE_TWO_HOST=1 needs PRIMARY_IP set to the primary's address, not loopback" >&2
        exit 1
    fi
else
    if [ "$((CARDS * 2))" -gt "${total_gpus:-0}" ]; then
        echo "need $((CARDS * 2)) GPUs for ${CARDS}+${CARDS} on one box, it has ${total_gpus}" >&2
        exit 1
    fi
    if [ "$ROLE" = "primary" ]; then
        export CUDA_VISIBLE_DEVICES="${CUDA_VISIBLE_DEVICES:-$(seq -s, "$CARDS" $((CARDS * 2 - 1)))}"
    else
        export CUDA_VISIBLE_DEVICES="${CUDA_VISIBLE_DEVICES:-$(seq -s, 0 $((CARDS - 1)))}"
    fi
fi

# Selects the mode inside the pipeline; without it the single-node pin stays in force and this
# would silently run two independent single-node provers (see `mle_two_machine_requested`).
export MLE_TWO_MACHINE=1
export MACHINE_ROLE="$ROLE"
# The scheduler reads the runtime mode from USECASE; MACHINE_ROLE alone is not enough.
export USECASE="${USECASE:-two_machine_${ROLE}}"
# Role-labelled worker ids: `worker_index_for_id` matches the id string against
# ["primary","secondary"] and falls back to `unwrap_or(0)`, which would make every worker on both
# machines the leader. The pipeline prefixes `get_worker_label()` itself; this pins what it returns.
export WORKER_LABEL="${WORKER_LABEL:-$ROLE}"
# Secondary only. Loopback still traverses the network stack, so this is real gRPC.
export PRIMARY_IP="${PRIMARY_IP:-127.0.0.1}"

# Event buffer pools. `single_node_mle.sh` defaults these to 64 on the reasoning that streaming
# only needs ">= in-flight chunks", since a chunk's pooled buffer comes back when a worker proves
# it and drops its record. A split run needs more than that, and 64 against reth-239's 95 chunks
# measures badly on both sides of the pipeline:
#
#   - Before the preparer learned to drop chunks it cannot prove, the other machine's half stayed
#     pinned until the peer proved it and said so, so the emulator blocked in `get_buffer` waiting
#     on the network: emulate 61.7s against single-node's 6.6s.
#   - That is fixed in the pipeline now, and emulate at 64 is healthy (6.0s). But the run is still
#     roughly 2x worse end to end (21.9s vs 10.7s), because the prove lanes starve instead:
#     occupancy 21% against 50% at 128. The mechanism there is NOT established — the emulator
#     finishing early does not by itself explain provers idling 137 lane-seconds — so treat 128 as
#     an empirical floor, not a derived one, and do not "optimise" it back down on the strength of
#     the first bullet having been fixed.
#
# The buffers are pinned host memory pre-allocated before keygen at ~0.95s each, so 64 -> 128 costs
# 43s -> 121s of startup: a one-time process cost amortised over every block the process serves,
# against a per-block stall. Raise it for blocks with more than ~128 chunks.
export MLE_EVENT_POOL_SIZE="${MLE_EVENT_POOL_SIZE:-128}"

# The packed staging pools follow the line above by default — at 128 that is twice the ~88 GiB
# `single_node_mle.sh` pays, per process. Pin them at the 16 every measurement above was taken
# at; past 16 in-flight chunks events upload unpacked and bitwise/shift_left go pageable on the
# prove thread.
export MLE_PACKED_POOL_SIZE="${MLE_PACKED_POOL_SIZE:-16}"

# NUMA: do not assume 0-3 -> node 0. Check `nvidia-smi topo -m` and set NUMA_NODE to
# bind; left unset the run is correct but pays cross-socket memory traffic on a two-socket box.
NUMACTL=""
if [ -n "${NUMA_NODE:-}" ] && command -v numactl > /dev/null; then
    NUMACTL="numactl --cpunodebind=${NUMA_NODE} --membind=${NUMA_NODE}"
fi

echo "[two_machine_mle] role=$ROLE cards=$CARDS CUDA_VISIBLE_DEVICES=$CUDA_VISIBLE_DEVICES"

# Print the resolved configuration and stop, without touching a GPU. Two uses: an operator can
# check which cards a side will take before committing a long run, and the card split becomes
# testable -- getting it wrong is silent, because each side would simply see the wrong cards and
# still run.
if [ -n "${TWO_MACHINE_DRY_RUN:-}" ]; then
    set +x
    echo "DRY_RUN role=$ROLE cards=$CARDS devices=$CUDA_VISIBLE_DEVICES role_env=$MACHINE_ROLE usecase=$USECASE label=$WORKER_LABEL two_machine=$MLE_TWO_MACHINE two_host=${MLE_TWO_HOST:-0} primary_ip=${PRIMARY_IP:-127.0.0.1}"
    exit 0
fi

exec $NUMACTL ./single_node_mle.sh "$CARDS" "$@"
