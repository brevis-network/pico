#!/usr/bin/env bash
# Tests for two_machine_mle.sh's card split and role plumbing. Runs anywhere -- no GPU, no build.
#
# Worth testing rather than eyeballing: a wrong split is SILENT. Each side would simply see the
# wrong cards and run anyway, either overlapping (two processes sizing their pools for a card each,
# with no shared accounting between them) or leaving cards idle while the run looks healthy.
#
#   ./ci/test_two_machine_launcher.sh
set -uo pipefail
cd "$(dirname "$0")/.."

PASS=0
FAIL=0

# Stub nvidia-smi so the GPU count is an input rather than whatever the host happens to have.
STUB_DIR="$(mktemp -d)"
trap 'rm -rf "$STUB_DIR"' EXIT
cat > "$STUB_DIR/nvidia-smi" << 'STUB'
#!/usr/bin/env bash
# Emits FAKE_GPUS index lines, matching `--query-gpu=index --format=csv,noheader`.
seq 0 $((${FAKE_GPUS:-8} - 1))
STUB
chmod +x "$STUB_DIR/nvidia-smi"

run_launcher() { # role cards [fake_gpus]
    FAKE_GPUS="${3:-8}" PATH="$STUB_DIR:$PATH" TWO_MACHINE_DRY_RUN=1 \
        CUDA_VISIBLE_DEVICES= NUMA_NODE= \
        ./two_machine_mle.sh "$1" "$2" 2>/dev/null | grep '^DRY_RUN' || true
}

check() { # description expected_substring actual
    if [[ "$3" == *"$2"* ]]; then
        PASS=$((PASS + 1))
        printf 'ok   %s\n' "$1"
    else
        FAIL=$((FAIL + 1))
        printf 'FAIL %s\n     want: %s\n     got:  %s\n' "$1" "$2" "$3"
    fi
}

check_fails() { # description role cards fake_gpus
    if FAKE_GPUS="$4" PATH="$STUB_DIR:$PATH" TWO_MACHINE_DRY_RUN=1 CUDA_VISIBLE_DEVICES= \
        ./two_machine_mle.sh "$2" "$3" > /dev/null 2>&1; then
        FAIL=$((FAIL + 1))
        printf 'FAIL %s (expected non-zero exit)\n' "$1"
    else
        PASS=$((PASS + 1))
        printf 'ok   %s\n' "$1"
    fi
}

# --- The split itself. The halves must be disjoint and cover exactly 2*cards devices. ---
out=$(run_launcher secondary 4 8)
check "4+4 secondary takes the low half" "devices=0,1,2,3" "$out"
out=$(run_launcher primary 4 8)
check "4+4 primary takes the high half" "devices=4,5,6,7" "$out"

# 2+2 is the configuration that makes this validatable on a busy box, so it is a first-class case.
out=$(run_launcher secondary 2 8)
check "2+2 secondary takes 0,1" "devices=0,1" "$out"
out=$(run_launcher primary 2 8)
check "2+2 primary takes 2,3" "devices=2,3" "$out"

out=$(run_launcher secondary 1 2)
check "1+1 secondary takes 0" "devices=0" "$out"
out=$(run_launcher primary 1 2)
check "1+1 primary takes 1" "devices=1" "$out"

# --- Role plumbing. Each of these is load-bearing on its own. ---
out=$(run_launcher primary 4 8)
check "primary sets MACHINE_ROLE" "role_env=primary" "$out"
check "primary sets a two_machine usecase" "usecase=two_machine_primary" "$out"
# Without a role-labelled worker id, `worker_index_for_id` falls through to `unwrap_or(0)` and every
# worker on BOTH machines becomes the leader -- partitioning collapses and the root pin lapses.
check "primary sets WORKER_LABEL" "label=primary" "$out"
check "the two-machine switch is on" "two_machine=1" "$out"

out=$(run_launcher secondary 4 8)
check "secondary sets MACHINE_ROLE" "role_env=secondary" "$out"
check "secondary sets a two_machine usecase" "usecase=two_machine_secondary" "$out"
check "secondary sets WORKER_LABEL" "label=secondary" "$out"

# --- Refusals. Over-subscribing cards is the failure that would otherwise be silent. ---
check_fails "refuses 4+4 on a 4-GPU box" primary 4 4
check_fails "refuses 8+8 on an 8-GPU box" secondary 8 8
check_fails "refuses an unknown role" tertiary 4 8

# --- Two-host mode: each half is on its own machine and takes that machine's cards. ---
run_two_host() { # role cards fake_gpus primary_ip
    FAKE_GPUS="${3:-8}" PATH="$STUB_DIR:$PATH" TWO_MACHINE_DRY_RUN=1 MLE_TWO_HOST=1 \
        PRIMARY_IP="${4:-10.0.0.5}" CUDA_VISIBLE_DEVICES= NUMA_NODE= \
        ./two_machine_mle.sh "$1" "$2" 2>/dev/null | grep '^DRY_RUN' || true
}

out=$(run_two_host primary 8 8)
check "two-host primary takes all 8 of its own cards" "devices=0,1,2,3,4,5,6,7" "$out"
out=$(run_two_host secondary 8 8)
check "two-host secondary also takes all 8 of its own" "devices=0,1,2,3,4,5,6,7" "$out"
check "two-host mode is flagged" "two_host=1" "$out"
check "two-host secondary records the primary's address" "primary_ip=10.0.0.5" "$out"

# 8+8 is impossible on one box but correct across two -- the guard must be per-host in this mode.
out=$(run_two_host primary 8 8)
check "8+8 is allowed when each half has its own host" "cards=8" "$out"

# Loopback with MLE_TWO_HOST would run both halves against a scheduler only one of them fills:
# a hang rather than an error, so it is refused up front.
if FAKE_GPUS=8 PATH="$STUB_DIR:$PATH" TWO_MACHINE_DRY_RUN=1 MLE_TWO_HOST=1 PRIMARY_IP=127.0.0.1 \
    CUDA_VISIBLE_DEVICES= ./two_machine_mle.sh secondary 8 > /dev/null 2>&1; then
    FAIL=$((FAIL + 1)); printf 'FAIL two-host refuses a loopback PRIMARY_IP\n'
else
    PASS=$((PASS + 1)); printf 'ok   two-host refuses a loopback PRIMARY_IP\n'
fi
check_fails "two-host refuses more cards than the host has" primary 16 8

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
