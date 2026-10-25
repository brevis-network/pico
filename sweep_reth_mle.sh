#!/usr/bin/env bash
# MLE directory sweep — prove every reth input in a directory from ONE resident process.
#
#   ./sweep_reth_mle.sh 4 ~/inputs                 # 4 cards, sweep every *.bin in ~/inputs
#   SWEEP_DRY_RUN=1 ./sweep_reth_mle.sh 4 ~/inputs # print the resolved plan, touch no GPU
#
# Third entry point beside `single_node_mle.sh` and `two_machine_mle.sh`, and the same shape as
# those: a thin shell that resolves and validates, then execs the single-node script. Everything
# expensive lives in the prover.
#
# Why an entry point at all: `single_node_mle.sh` proves one block per process, and setup is larger
# than the proof it wraps -- 18.0s of keygen and warmup against a 10.7s window on four cards -- so a
# per-block process spends most of a sweep rebuilding state that never changes. Worse for the
# numbers than for the clock: the pipeline's worker threads spawn *after* the measurement window
# opens, so a per-block process leaves every window carrying first-touch costs (stream creation, the
# leaked per-thread-per-device copy-sync events) that a long-running prover does not pay. Resident
# is the only shape whose per-block `e2e` means what production means.
set -uo pipefail

CARDS="${1:?usage: sweep_reth_mle.sh <1|4|8> [input-dir] [-- extra args...]}"
shift
# `--` in the input-dir slot means "no input dir, extra args follow". Without this test the
# directory is taken to be literally `--` and the run dies at the -d check below, which made the
# documented `<1|4|8> [-- extra args...]` form unusable.
# An EMPTY argument falls back to the default, because `${2:-...}` did and a driver written as
# `./sweep_reth_mle.sh 4 "$INPUT_DIR" -- ...` with INPUT_DIR unset used to run. It must still be
# SHIFTED off, or the empty string and the `--` are both forwarded to the prover.
INPUT_DIR="perf/bench_data/rv64"
if [ $# -gt 0 ] && [ "$1" != "--" ]; then
    [ -n "$1" ] && INPUT_DIR="$1"
    shift
fi
[ "${1:-}" = "--" ] && shift

die() { echo "sweep: $*" >&2; exit 1; }

# One sweep per tree. Two in the same worktree give both provers the same cwd -- which is how the
# steady sampler tells its own prover from a neighbour's -- race for the same cards, and, started in
# the same second at the same card count, share `logs/sweep_${CARDS}card_${TS}` so both tee into one
# run.log. `exec 9>` before `flock -n 9`, or fd 9 does not exist and flock fails with EBADF while
# blaming an instance that is not there.
if command -v flock > /dev/null; then
    # In the git dir, not the working tree: a lock file in the tree is untracked, is not covered by
    # .gitignore, and shows up in `git status` and in a `plannotator review --git` of an unrelated
    # change. `git rev-parse --git-dir` is per-worktree, so linked worktrees still get their own.
    lockdir=$(git rev-parse --git-dir 2> /dev/null || echo .)
    exec 9> "$lockdir/sweep.lock" || die "cannot open $lockdir/sweep.lock -- is it writable?"
    flock -n 9 || die "another sweep is running in this tree"
fi

# ---------------------------------------------------------------------------------------------
# 1. Card count and which cards
# ---------------------------------------------------------------------------------------------
# Only 1/4/8. Not "other counts cannot run" -- this entry point does not promise anything about
# other groupings' topology, and a silently-accepted 6 would produce numbers nobody can compare.
# Any four cards other than {0,1,2,3} or {4,5,6,7} span the interconnect: card-to-card drops from
# PHB to SYS, which moves the figures this sweep exists to produce.
case "$CARDS" in
    1 | 4 | 8) ;;
    *) die "cards must be 1, 4 or 8 (got '$CARDS'); other groupings span the interconnect" ;;
esac

pick_cards() {
    case "$CARDS" in
        # Ascending first-free, not a hardcoded 0: on a box whose card 0 hosts a long-lived service an
        # unchecked `0` collides with it every time, while the four-card path right below has always
        # checked.
        1)
            local i
            for i in 0 1 2 3 4 5 6 7; do
                group_free "$i" && { echo "$i"; return; }
            done
            echo ""
            ;;
        8) group_free 0 1 2 3 4 5 6 7 && seq -s, 0 7 || echo "" ;;
        4)
            # Prefer the high group so a partially-busy box can still host this on {4,5,6,7};
            # fall back to the low group. Only these two -- see above.
            if group_free 4 5 6 7; then echo "4,5,6,7"
            elif group_free 0 1 2 3; then echo "0,1,2,3"
            else echo ""
            fi
            ;;
    esac
}

# A card is free if it has < 1 GiB in use and no compute process. Anything unreadable is "cannot
# tell" and refuses, rather than assuming free — including a non-numeric reading such as `[N/A]`,
# which used to make the integer test *error* instead of match and so let the card through as free.
#
# The process check is not redundant with the memory one: a process that has just attached, or one
# holding only a context, shows up here well before it shows up as a gibibyte.
group_free() {
    command -v nvidia-smi > /dev/null || return 1
    local idx used procs
    for idx in "$@"; do
        used=$(nvidia-smi --query-gpu=memory.used --format=csv,noheader,nounits -i "$idx" 2> /dev/null)
        case "$used" in
            '' | *[!0-9]*) return 1 ;;
        esac
        [ "$used" -ge 1024 ] && return 1
        # `|| return 1`, not `|| true`: a query that fails prints nothing, and `grep -c` turns that
        # into a `0` indistinguishable from "idle" -- so a driver error handed out a busy card. An
        # idle card returns EMPTY here, never `0`.
        procs=$(nvidia-smi --query-compute-apps=pid --format=csv,noheader -i "$idx" 2> /dev/null) || return 1
        [ -z "$procs" ] || return 1
    done
    return 0
}

# ---------------------------------------------------------------------------------------------
# 2. Discovery, alias expansion, dedup
# ---------------------------------------------------------------------------------------------
# Block number = the file's basename with an optional `reth-` prefix and the `.bin` suffix removed,
# and it must be all digits. Anything else is skipped and named rather than silently dropped.
#
# ⚠️ Dedup must happen AFTER alias expansion. `load_reth_input` (distributed-vm/src/mle/mod.rs)
# maps five small numbers onto real blocks:
#
#     171 -> 17106222   188 -> 18884864   239 -> 23993050   240 -> 24000020   246 -> 24600825
#
# so `240.bin` and `reth-24000020.bin` are the SAME input under two names. They parse to 240 and
# 24000020, pass a naive dedup, and produce two rows for one block -- which then disagree with each
# other on timing and look like variance. Expand first, dedup on the expansion, and refuse a
# collision by name rather than silently keeping one.
# The five aliases, in ONE place. `load_reth_input` (distributed-vm/src/mle/mod.rs) maps five small
# numbers onto real blocks, so `240.bin` and `reth-24000020.bin` are the same witness under two
# names: they parse to 240 and 24000020, pass a naive dedup, and produce two rows for one block that
# then disagree on timing and read as variance. Expand first, dedup on the expansion, and refuse a
# collision by name.
#
# Written once and checked against the Rust below, because the failure mode of a drifted copy is
# silent: discovery would resolve a name to a block the prover never loads.
ALIAS_MAP="171:17106222 188:18884864 239:23993050 240:24000020 246:24600825"

# The source of truth is the prover's own table. Parse it and compare, so an alias added or changed
# on either side fails here rather than in a report that names the wrong block.
#
# Anchored on the const array, not on the function body: a range covering the whole function picks
# up any other `N => M,` arm someone adds to it and dies blaming an alias disagreement that does not
# exist. And the count is required, because "parsed nothing" must be a failure — a table restructured
# into some other shape is the likeliest way it gets touched, and a gate that passes silently then
# is a gate that never fires when it matters.
alias_gate() {
    local src="distributed-vm/src/mle/mod.rs" from_rust
    [ -r "$src" ] || return 0        # a tree without the prover source genuinely cannot be checked
    from_rust=$(sed -n '/^const RETH_ALIASES/,/^];/p' "$src" \
        | sed -nE 's/^[[:space:]]*\(([0-9]+),[[:space:]]*([0-9]+)\),.*/\1:\2/p' | sort | paste -sd' ' -)
    [ "$(printf '%s\n' $from_rust | grep -c .)" -eq 5 ] \
        || die "cannot parse the five aliases out of $src (got '${from_rust:-nothing}') -- this gate needs updating against the source"
    if [ "$from_rust" != "$(printf '%s\n' $ALIAS_MAP | sort | paste -sd' ' -)" ]; then
        die "the alias table here ($ALIAS_MAP) disagrees with $src ($from_rust) -- discovery would resolve a name to a block the prover does not load"
    fi
}
alias_gate

[ -d "$INPUT_DIR" ] || die "input dir not found: $INPUT_DIR"

# BLOCKS is deliberately NOT pre-initialised: it is derived after the resume prune below, and an
# empty default would turn "used before it is set" from a `set -u` error into a silently empty list.
SKIPPED=""
declare -a SEEN_BLOCK=() SEEN_FILE=()

# One awk pass, then one sort. The obvious shape -- a shell loop with the alias lookup in a
# command substitution and a nested scan of what has been seen -- is a fork per file and O(n^2)
# comparisons, which is 9 s at 2,400 blocks and 81 s at 7,200, paid again on every restart before
# a card is touched. This is the sweep's own scale, so it is not a micro-optimisation.
#
# The dedup below depends on this sort: drop it and duplicate blocks stop being adjacent, and the
# alias-collision check silently stops catching anything.
while IFS=' ' read -r blk name; do
    [ -z "$blk" ] && continue
    case "$blk" in
        SKIP) SKIPPED="$SKIPPED $name"; continue ;;
    esac
    SEEN_BLOCK+=("$blk"); SEEN_FILE+=("$name")
done < <(
    find "$INPUT_DIR" -maxdepth 1 -name '*.bin' 2> /dev/null \
    | awk -F/ -v aliases="$ALIAS_MAP" '
      BEGIN { n = split(aliases, a, " "); for (i = 1; i <= n; i++) { split(a[i], kv, ":"); m[kv[1]] = kv[2] } }
      {
        f = $NF; base = f; sub(/\.bin$/, "", base); sub(/^reth-/, "", base)
        if (base !~ /^[0-9]+$/) { print "SKIP " f; next }
        b = (base in m) ? m[base] : base
        printf "%d %s\n", b + 0, f
      }' \
    | sort -k1,1n -k2,2
)

[ "${#SEEN_BLOCK[@]}" -eq 0 ] && die "no usable *.bin inputs in $INPUT_DIR"

# Dedup on the EXPANDED block, so `240.bin` and `reth-24000020.bin` are caught as one input under
# two names rather than producing two rows that then disagree on timing and read as variance.
# The list is sorted, so duplicates are adjacent.
for i in "${!SEEN_BLOCK[@]}"; do
    [ "$i" -eq 0 ] && continue
    if [ "${SEEN_BLOCK[$i]}" = "${SEEN_BLOCK[$((i - 1))]}" ]; then
        die "two files resolve to block ${SEEN_BLOCK[$i]}: '${SEEN_FILE[$((i - 1))]}' and '${SEEN_FILE[$i]}' (alias collision) -- remove one"
    fi
done

# ---------------------------------------------------------------------------------------------
# 2b. Resume
# ---------------------------------------------------------------------------------------------
# `SWEEP_RESUME=<previous outdir>` drops blocks that directory already proved, so a sweep killed on
# block 40 of 200 restarts as the remaining 160 rather than from scratch.
#
# Resume-by-restart rather than resume-in-process, deliberately: a bad input takes the whole process
# down (the panic hook), so the recovery path has to survive the process dying. It keys on
# `summary.csv` rc=0 -- the block finished and its row is complete -- so a block that started and
# crashed (rc=1) is retried rather than skipped, which is the behaviour you want when the reason it
# crashed was transient.
# Resume PRUNES THE ARRAYS, and runs before the format gate below rather than after it. Filtering
# only the block list left the gate iterating every discovered file, so a resume at block 7,000 of
# 7,200 still re-hashed all 7,200 inputs -- tens of gigabytes of reading to validate blocks it had
# already decided to skip, on every restart.
if [ -n "${SWEEP_RESUME:-}" ]; then
    prev="$SWEEP_RESUME/summary.csv"
    # summary.csv is written by the teardown, so a launcher killed with its process group leaves
    # nothing to resume from: kill the prover, not the launcher.
    [ -r "$prev" ] || die "SWEEP_RESUME=$SWEEP_RESUME has no summary.csv to resume from"
    done_list=$(mktemp) || die "cannot create a temp file for the resume list"
    awk -F, 'NR>1 && $5 == 0 {print $2}' "$prev" | sort -u > "$done_list"

    # One awk over the pairs and one grep for the log line -- no per-block forks. The obvious shape,
    # `printf "$done_blocks" | grep -qx "$b"` inside the loop, is two forks and a full scan per
    # block: 20 s at 7,200 discovered against 7,000 done, which after the discovery rewrite would be
    # the largest thing left before a card is touched.
    declare -a KEEP_BLOCK=() KEEP_FILE=()
    while IFS=' ' read -r b f; do
        [ -n "$b" ] || continue
        KEEP_BLOCK+=("$b"); KEEP_FILE+=("$f")
    done < <(
        paste -d' ' <(printf '%s\n' "${SEEN_BLOCK[@]}") <(printf '%s\n' "${SEEN_FILE[@]}") \
        | awk -v dl="$done_list" 'BEGIN { while ((getline l < dl) > 0) d[l] = 1 } !($1 in d)'
    )
    skipped_done=$(printf '%s\n' "${SEEN_BLOCK[@]}" | grep -Fxf "$done_list" | paste -sd' ' - || true)
    rm -f "$done_list"

    [ "${#KEEP_BLOCK[@]}" -eq 0 ] && { echo "sweep: every block already proved in $SWEEP_RESUME — nothing to do"; exit 0; }
    SEEN_BLOCK=("${KEEP_BLOCK[@]}"); SEEN_FILE=("${KEEP_FILE[@]}")
    # Count AND list. A count alone makes "the resume skipped the wrong set" undiagnosable from the
    # log, which is the one thing this line exists to let someone check.
    n_skipped=$(printf '%s' "$skipped_done" | wc -w | tr -d ' ')
    echo "[sweep] resume: skipping ${skipped_done:-nothing} ($n_skipped block(s) already proved in $SWEEP_RESUME)"
fi

# Comma-separated, expanded, deduped, ascending -- and derived HERE, below the prune, so it can
# never describe blocks a resume dropped. Do not hoist it above the resume block.
BLOCKS=$(printf '%s\n' "${SEEN_BLOCK[@]}" | paste -sd, -)

# ---------------------------------------------------------------------------------------------
# 3. Format gate
# ---------------------------------------------------------------------------------------------
# The witness format has changed below the guest at least three times and the guest ELF has been
# rebuilt repeatedly, so "is this file current" is a property of a (file, guest) PAIR, not of a
# file. A file from the wrong generation halts the guest with exit code 1 in well under a second --
# and the panic hook takes the process down, so ONE stale file ends the whole sweep and discards
# the resident setup with it. That is the whole reason this gate runs before the GPU is touched.
#
# Keyed on sha256, not mtime: a copy or a checkout moves mtime independently of content.
# Not overridable. `load_elf` builds `{RV64_DIR}/{name}-elf` from a fixed const and the launcher
# never exports a path, so an override here would hash one guest while the prover proved against
# another -- and the manifest's whole premise is that "current format" is a property of the
# (witness, guest) PAIR. An ELF the prover does not load cannot stand in for the one it does.
ELF="perf/bench_data/rv64/reth-elf"
MANIFEST="${SWEEP_MANIFEST:-$INPUT_DIR/inputs.manifest}"
ELF_SHA=""
if [ -r "$ELF" ]; then
    ELF_SHA=$( { sha256sum "$ELF" 2> /dev/null || shasum -a 256 "$ELF"; } | cut -c1-12)
fi

# The pico-gpu commit the CUDA kernels come from, as Cargo.lock pins it, so a run stays attributable.
# A `[patch]` to a local checkout bypasses the pin and is not visible here.
PPG_SHA=$(sed -n 's|^source = "git+https://github.com/brevis-network/pico-gpu.git?rev=[0-9a-f]*#\([0-9a-f]\{9\}\).*|\1|p' \
    Cargo.lock 2> /dev/null | head -1)

# Manifest format, one row per input, whitespace-separated:
#
#     <sha256-of-input>  <elf_sha12-it-was-validated-against>  <filename>
#
# Both keys are load-bearing. The sha256 is what makes this a statement about content rather than
# about a path -- a copy or a checkout moves mtime independently of the bytes. The elf hash is what
# makes it a statement about a (file, guest) PAIR, which is the only thing "current format" can
# mean here.
sha_of() { { sha256sum "$1" 2> /dev/null || shasum -a 256 "$1"; } | awk '{print $1}'; }

if [ -z "${SWEEP_SKIP_MANIFEST:-}" ]; then
    [ -r "$MANIFEST" ] || die "no manifest at $MANIFEST (set SWEEP_SKIP_MANIFEST=1 to bypass, at your own risk)"
    # One awk to read the manifest and classify every discovered file, instead of an awk that
    # rescans the whole manifest once per file: at 7,200 blocks that was 7,200 forks each scanning
    # up to 7,200 lines. The sha itself still costs a fork per file -- that is the hashing, not the
    # lookup, and it is what SWEEP_SKIP_MANIFEST exists to bypass.
    rejects=""
    n_verdicts=0
    while IFS=' ' read -r verdict name want; do
        n_verdicts=$((n_verdicts + 1))
        [ -n "$verdict" ] || continue
        case "$verdict" in
            ABSENT) rejects="$rejects $name(absent)" ;;
            ELF)    rejects="$rejects $name(elf:$want!=$ELF_SHA)" ;;
            SHA)
                # Skipped for a zero-byte placeholder so the launcher stays testable without real
                # witnesses.
                if [ -s "$INPUT_DIR/$name" ] && [ -n "$want" ]; then
                    got_sha=$(sha_of "$INPUT_DIR/$name")
                    [ "$got_sha" != "$want" ] && rejects="$rejects $name(sha:${want:0:8}!=${got_sha:0:8})"
                fi
                ;;
        esac
    done < <(
        printf '%s\n' "${SEEN_FILE[@]}" \
        | awk -v elf="$ELF_SHA" -v man="$MANIFEST" '
            # Leading blanks stripped, because an explicit regex FS -- unlike awk\047s default --
            # leaves an empty first field and shifts every column, turning a manifest that used to
            # work into "absent" for every row. First row wins on a duplicate filename, which is
            # what the old per-file `$3 == n {print; exit}` did.
            BEGIN {
              while ((getline l < man) > 0) {
                sub(/^[ \t]+/, "", l)
                n = split(l, f, /[ \t]+/)
                if (n >= 3 && !(f[3] in ws)) { ws[f[3]] = f[1]; we[f[3]] = f[2] }
              }
            }
            {
              if (!($0 in ws)) { print "ABSENT " $0; next }
              if (elf != "" && we[$0] != "" && we[$0] != elf) { print "ELF " $0 " " we[$0]; next }
              print "SHA " $0 " " ws[$0]
            }'
    )
    # One verdict per discovered file, or the classifier died and an empty reject list means
    # "everything passed" -- the opposite of the old shape, where any awk failure turned into
    # `(absent)` and a refusal.
    [ "$n_verdicts" -eq "${#SEEN_FILE[@]}" ] \
        || die "the manifest check produced $n_verdicts verdicts for ${#SEEN_FILE[@]} inputs -- refusing rather than assuming they passed"
    [ -n "$rejects" ] && die "manifest rejects:$rejects"
fi

# ---------------------------------------------------------------------------------------------
# 4. Output dir, and clearing stale span exports
# ---------------------------------------------------------------------------------------------
# ⚠️ The sweep must clear these itself. `single_node_mle.sh`'s own cleanup only runs under
# MLE_TIMELINE=1, which step 6 sets to 0 (this script draws the figures instead, so it can name
# them per block), and that cleanup derives the expected filenames from MLE_REPEAT -- which cannot
# produce the names a block list implies. Left behind, a resume or a re-run draws the PREVIOUS
# run's `iterK` as this one's.
TS=$(date "+%Y-%m-%d_%H-%M-%S")
OUTDIR="${SWEEP_OUTDIR:-logs/sweep_${CARDS}card_${TS}}"
SPANS="$OUTDIR/run.spans.csv"

# ⚠️ A preset CUDA_VISIBLE_DEVICES short-circuits pick_cards, so it also skips the gate above. That
# is deliberate -- a caller with its own gate, or one deliberately sharing a card, must be able to
# say so -- but it means the gate protects only the runs that let the sweep choose.
DEVICES="${CUDA_VISIBLE_DEVICES:-$(pick_cards)}"
if [ -z "$DEVICES" ]; then
    # Count-specific, because the groups differ: the old text named {4,5,6,7} and {0,1,2,3} for
    # every count, and once 1 and 8 became gateable it sent readers to inspect cards nothing tried.
    case "$CARDS" in
        1) die "no free group of 1 cards (tried 0-7 ascending)" ;;
        4) die "no free group of 4 cards (tried {4,5,6,7} then {0,1,2,3})" ;;
        8) die "no free group of 8 cards (needs all of 0-7)" ;;
    esac
fi

NBLOCKS=$(printf '%s' "$BLOCKS" | tr ',' '\n' | grep -c .)

if [ -n "${SWEEP_DRY_RUN:-}" ]; then
    echo "DRY_RUN cards=$CARDS devices=$DEVICES blocks=$BLOCKS n=$NBLOCKS dir=$INPUT_DIR elf_sha=${ELF_SHA:-none} ppg=${PPG_SHA:-unknown} outdir=$OUTDIR skipped=${SKIPPED:-none}"
    exit 0
fi

mkdir -p "$OUTDIR"
rm -f "$SPANS".iter*

# manifest.csv maps the span export's `.iterK` suffix back to a block number. The suffix itself
# must NOT be renamed: mle-gate-metrics.py and the drawing script both strip the base name from it.
# The two arrays are aligned and in the same order as BLOCKS, so this is one pass. Looking each
# block up by scanning the array was the same O(n^2) the discovery had.
{
    echo "epoch,block,input"
    for i in "${!SEEN_BLOCK[@]}"; do
        echo "$((i + 1)),${SEEN_BLOCK[$i]},${SEEN_FILE[$i]}"
    done
} > "$OUTDIR/manifest.csv"

{
    echo "cards=$CARDS devices=$DEVICES elf_sha=${ELF_SHA:-none} ppg=${PPG_SHA:-unknown}"
    echo "blocks=$BLOCKS"
    echo "input_dir=$INPUT_DIR manifest=$MANIFEST"
} > "$OUTDIR/env.txt"

export CUDA_VISIBLE_DEVICES="$DEVICES"
# The sweep is what the census exists for: every block boundary, per card. On by default HERE and
# nowhere else -- a caller running `single_node_mle.sh` directly never sees this.
#
# On by default rather than opt-in when something breaks, because the evidence it produces is a
# TREND: when a block finally fails you need the fifty before it, and those rows do not exist
# retroactively. Recovering them means re-running the whole sweep, which for the heaviest set is
# tens of minutes on a four-card box and is not guaranteed to reproduce.
#
# This is the BOUNDARY census only. The prover's in-block probes sit behind their own
# `MLE_VRAM_PROBE`, which nothing sets, because eleven of their thirteen points are inside the
# window `e2e=` measures while the boundary census runs outside it. Switched on here, what a block's
# measured window pays is eleven cached flag loads.
#
# What the census itself costs, stated so the default can be argued with: ~205 us per block per
# card, plus one primary-context creation per card at the first `pre` (~341 ms measured). That
# creation lands in `total=`, not in `e2e=`, and NOT in these columns -- they are read at `post`, by
# which point the prover has bound every card itself, so row 1 is comparable with row 2.
#
# It replaces one `nvidia-smi` fork per boundary that took a driver lock exactly as the next block
# began, so the block-to-block wall clock is roughly a wash. One asymmetry to know when comparing a
# censused sweep against an uncensused one: `post` synchronises each card, absorbing a drain that
# would otherwise have overlapped the NEXT block's window, so the next `e2e=` comes out marginally
# faster and less variable. The cost does not leave the sweep's wall clock, only that window.
#
# `:-` and not a bare assignment: a caller who says `MLE_VRAM_CENSUS=0` means it.
export MLE_VRAM_CENSUS="${MLE_VRAM_CENSUS:-1}"
export MLE_BLOCKS="$BLOCKS"
export MLE_INPUT_DIR="$INPUT_DIR"
export MLE_SPANS="$SPANS"
# This script draws the figures itself (per block, with block names), so the launcher's own
# drawing -- and the cleanup bound to it -- stays off. See the stale-span note above.
export MLE_TIMELINE=0


# --------------------------------------------------------------------------------------------
# steady.csv — one row per block boundary
# --------------------------------------------------------------------------------------------
# Nobody has run this prover over more than a handful of blocks in one process, and there is no
# per-block teardown anywhere in it, so the first long sweep is the first evidence either way about
# whether anything grows. Nothing here should climb monotonically.
#
# VRAM comes from the prover's own per-block census (`MLE_VRAM_CENSUS=1`), not from `nvidia-smi`.
# Two reasons, and the second is why the columns changed shape:
#
#  1. A boundary `nvidia-smi` sample reads the whole card at whatever phase the NEXT block has
#     reached, so the same card came back anywhere from 20 to 32 GiB and a real trend hid inside
#     the swing (measured: R^2 <= 0.08 against block index on one card). The census reads at the
#     quiescent point, after `run_pipeline` has joined every thread it spawned.
#  2. It removes the index-space trap this comment used to carry. The prover binds logical ordinals
#     inside the `CUDA_VISIBLE_DEVICES` filter -- with cards 4-7 selected it calls `set_device(0..3)`
#     -- so asking `nvidia-smi` for 0-3 recorded a neighbour's job as ours. The census reports the
#     prover's own ordinals, so there is only one index space left.
#
# `out_of_pool` is the column that would catch a recurrence of the per-thread leak: it is the device
# total minus what both memory pools have reserved, i.e. the memory no `cudaMemPoolTrimTo` can reach.
# `dev_used` is kept beside it as the continuation of the old column, and `pool_used_high` because
# an OOM is a PEAK event: a resting pair cannot see a block whose peak crept to the ceiling while
# its resting figure stayed flat, which is what the heaviest blocks do. Read the peak from row 2
# onwards -- the first `pre` runs before `init_mle_gpu_pool`, so row 1's mark may predate the reset.
#
# Column count follows `$DEVICES`, the census follows the prover's card count. An explicit
# `CUDA_VISIBLE_DEVICES` wider than the prover uses leaves the trailing triples empty for the whole
# run, and the all-empty check below will not fire on it because the leading ones are filled.
#
# ⚠️ The census rides `target: "bench"` at info, which `single_node_mle.sh` enables by default --
# but only as a default. A caller who exports a `RUST_LOG` without `bench=info` filters the lines
# out and every census column comes back EMPTY, with nothing else looking wrong. The teardown says
# so rather than leaving a blank column to be read as "the prover held nothing".
steady_sampler() {
    local out="$OUTDIR/steady.csv" i d ours cwd
    # Resolved in here, not by the caller, so the fix cannot be broken by moving the `&` above an
    # assignment. Empty is fatal: see the match below.
    ours="$(readlink -f .)"
    [ -n "$ours" ] || { echo "sweep: cannot resolve this tree's path — refusing to sample by pid" >&2; return 1; }
    {
        printf 'epoch,block,rss_gb,fds'
        i=0
        for d in $(printf '%s' "$DEVICES" | tr ',' ' '); do
            printf ',dev_used_post_card%s_phys%s_mib' "$i" "$d"
            printf ',out_of_pool_post_card%s_phys%s_mib' "$i" "$d"
            printf ',pool_used_high_post_card%s_phys%s_mib' "$i" "$d"
            i=$((i + 1))
        done
        printf '\n'
    } > "$out"

    # Per-card census values for the block being assembled. Captured as the lines stream past
    # rather than grepped out of run.log at each boundary: this loop already reads every line, and
    # one grep per block over a log that grows all sweep is quadratic on a 7,200-block run. The
    # prover emits its `post` lines BEFORE the block's `done` marker, so they are always in hand by
    # the time the row is written.
    local -a du oop puh
    local c
    du=() oop=() puh=()
    tail -n +1 -F "$OUTDIR/run.log" 2>/dev/null | while IFS= read -r line; do
        case "$line" in
            *"vram_census: phase=post"*)
                # `-n ... p`, not a bare `s///`: a substitution that does not match prints the line
                # UNCHANGED, so the plain form would have put a whole log line into a CSV cell the
                # first time the log format or the census's field list moved. Empty is the honest
                # answer, and the teardown notices a column that is empty all the way down.
                c=$(printf '%s' "$line" | sed -nE 's/.* card=([0-9]+) .*/\1/p')
                # And the subscript is guarded, because in bash it is an ARITHMETIC context: a bare
                # word silently evaluates to 0 and would overwrite card 0's cell with another card's
                # figures, which is the kind of wrong number that never looks wrong. `set -u` cannot
                # catch it either -- the sampler runs under `setsid bash -c`, which does not inherit
                # shell options.
                case "$c" in '' | *[!0-9]*) continue ;; esac
                du[$c]=$(printf '%s' "$line" | sed -nE 's/.* dev_used_mib=([0-9.]+).*/\1/p')
                oop[$c]=$(printf '%s' "$line" | sed -nE 's/.* out_of_pool_mib=([0-9.]+).*/\1/p')
                puh[$c]=$(printf '%s' "$line" | sed -nE 's/.* pool_used_high_mib=([0-9.]+).*/\1/p')
                continue
                ;;
            *"MLE block: "*" done"*) ;;
            *) continue ;;
        esac
        epoch=$(printf '%s' "$line" | sed -E 's/.*MLE block: ([0-9]+)\/[0-9]+ block=([0-9]+) done.*/\1/')
        blk=$(printf '%s' "$line" | sed -E 's/.*MLE block: ([0-9]+)\/[0-9]+ block=([0-9]+) done.*/\2/')
        # Resolved once and cached. The final block's `done` line and the process exit race, and
        # looking the pid up per sample loses that race often enough that the last row -- the one a
        # growth check cares about most -- comes back empty.
        #
        # Matched on cwd, not on `-u <uid>` plus `head -1`. These boxes are shared through one
        # account, pgrep emits ascending pids, and this sampler starts BEFORE its own prover -- so
        # any neighbour's prover already running had the lower pid and won, and every RSS, fd and
        # VRAM row in the report was theirs. Our prover is the one whose cwd is this run's tree.
        if [ -z "${PROVER_PID:-}" ]; then
            for cand in $(pgrep -x mle-single-node 2> /dev/null); do
                cwd=$(readlink -f "/proc/$cand/cwd" 2> /dev/null)
                # Both sides must be non-empty. A process whose cwd we cannot read also yields the
                # empty string, so an empty `ours` would match the first foreign candidate and
                # reinstate exactly the misattribution this test exists to prevent.
                [ -n "$cwd" ] && [ "$cwd" = "$ours" ] && PROVER_PID="$cand" && break
            done
        fi
        # `:-` because the search above can find nothing -- no prover yet, or a cwd that cannot be
        # read -- and this sampler runs under `set -u` on the no-`setsid` fallback path, where an
        # unbound expansion kills the subshell at the first block boundary and leaves steady.csv
        # with nothing but its header for the rest of the sweep. Silently: the sweep itself carries
        # on proving.
        pid="${PROVER_PID:-}"
        rss=$(awk '/VmRSS/{printf "%.1f", $2/1048576}' "/proc/${pid:-0}/status" 2> /dev/null)
        # `ls`, not `find`: `find <dir> -maxdepth 1` counts the directory itself, so every fd count
        # this ever reported was one too high. And guarded, because `grep -c` prints `0` before it
        # exits 1 -- so a pid that has gone away used to record `fds=0` beside an empty `rss`, which
        # reads as "the prover closed everything" rather than "there was nothing to read".
        fds=""
        if [ -d "/proc/${pid:-0}/fd" ]; then
            fds=$(ls "/proc/${pid:-0}/fd" 2> /dev/null | wc -l | tr -d ' ')
            # The last block's `done` line races the process exit, and a zombie keeps /proc/<pid>/fd
            # as an EMPTY directory while /proc/<pid>/status loses VmRSS. Recording that as `0`
            # alongside a blank rss reads as "the prover closed everything" on the very row a growth
            # check cares about most. No fds means no reading, not zero fds.
            [ "$fds" = "0" ] && fds=""
        fi
        # No `nvidia-smi` here any more. It was one fork per block boundary taking a driver lock
        # exactly as the next block started -- a measurement that disturbed what it measured -- and
        # it read the whole card at an arbitrary phase of that next block. The census values were
        # already collected above, at the prover's own quiescent point.
        printf '%s,%s,%s,%s' "$epoch" "$blk" "${rss:-}" "${fds:-}" >> "$out"
        i=0
        for _ in $(printf '%s' "$DEVICES" | tr ',' ' '); do
            printf ',%s,%s,%s' "${du[$i]:-}" "${oop[$i]:-}" "${puh[$i]:-}" >> "$out"
            i=$((i + 1))
        done
        printf '\n' >> "$out"
        # Cleared per row. A card the census skipped -- `set_device` failing leaves a
        # `vram_census_note:` line and no figures -- must record an empty cell rather than the
        # previous block's number, which is the kind of wrong value that never looks wrong.
        du=() oop=() puh=()
    done
}

echo "[sweep] $NBLOCKS block(s) on cards $DEVICES -> $OUTDIR"
# Its own process group, so the teardown can take the `tail -F` and the `while read` with it.
# `kill "$SAMPLER"` alone kills the function's subshell and orphans both, and they hold run.log
# open -- which matters now that a soak restarts this script many times in one tree.
# ⚠️ `9>&-` on every child. The tree lock lives on fd 9 without close-on-exec -- it has to, or the
# external `flock` could not see it -- so every child inherits it, and a `flock` lock is released
# only when the LAST inherited descriptor closes. An orphaned `tail -F` holding fd 9 refuses the next
# sweep in this tree with nothing actually running. `9>&-` is a no-op when fd 9 was never opened.
#
# And the child announces its own process group rather than the parent guessing it: `setsid` forks
# when its caller is already a group leader, so `$!` is not reliably the leader -- and probing with
# `ps` right after `$!` races the child's own `setsid()` call and loses about half the time, which
# silently downgrades the teardown to a single kill and leaks exactly the descriptor above.
PGID_FILE="$OUTDIR/.sampler.pgid"
if command -v setsid > /dev/null; then
    setsid bash -c "$(declare -f steady_sampler); echo \$\$ > '$PGID_FILE'; OUTDIR='$OUTDIR' DEVICES='$DEVICES' steady_sampler" 9>&- &
    SAMPLER=$!
else
    steady_sampler & SAMPLER=$!
fi

# A blank census column is indistinguishable from a prover that held nothing, so it is said out
# loud once rather than left in the CSV. Checked on the assembled rows: field 5 onwards is the
# per-card block, and every one of them empty across every row means the lines never arrived.
warn_if_census_empty() {
    # Not when the census was switched off on purpose: the columns are then legitimately empty and
    # blaming `RUST_LOG` would send the reader after a filter that is doing nothing wrong.
    case "${MLE_VRAM_CENSUS:-1}" in 0 | false | no | off) return 0 ;; esac
    local f="$OUTDIR/steady.csv"
    [ -s "$f" ] || return 0
    awk -F, 'NR > 1 { for (i = 5; i <= NF; i++) if ($i != "") { found = 1 } rows++ }
        END {
            if (rows > 0 && !found) {
                print "sweep: every census column in steady.csv is empty — the prover'"'"'s " \
                      "`vram_census:` lines never reached the log. Check that RUST_LOG still " \
                      "carries `bench=info`." > "/dev/stderr"
            }
        }' "$f"
}

# Teardown on every exit, not only the happy one. There was no trap at all: a Ctrl-C went to the
# launcher's foreground group, the setsid'd sampler is in another session and never saw it, and the
# script exited before the kill below -- leaving the sampler, and the lock, forever.
stop_sampler() {
    local pg
    pg=$(cat "$PGID_FILE" 2> /dev/null)
    case "$pg" in
        # No pgid file means the no-setsid fallback ran, and killing the subshell alone leaves its
        # `tail -F` and the while-read holding whatever stdout it inherited -- which hangs any
        # caller that wrapped this in a command substitution, not just leaks a process.
        '' | 0 | *[!0-9]*) pkill -P "$SAMPLER" 2> /dev/null; kill "$SAMPLER" 2> /dev/null ;;
        *) kill -- -"$pg" 2> /dev/null ;;
    esac
    rm -f "$PGID_FILE"
}
trap stop_sampler EXIT INT TERM

# The whole pipeline with fd 9 closed, not just its left side: `tee` inherits it too, and a `tee`
# that outlives a TERMed launcher goes on holding the tree lock -- which reads as "another sweep is
# running in this tree" when nothing is.
{ ./single_node_mle.sh "$CARDS" "$@" 2>&1 | tee "$OUTDIR/run.log"; } 9>&-
rc=${PIPESTATUS[0]}

# Teardown. The CSVs are derived from the log, so they are written even when the run died: a sweep
# that crashed on block 7 still has six blocks of measurements worth keeping, and `summary.csv`
# marks the block that did not finish with `rc=1` rather than dropping it. That matters here more
# than usual -- one stale input takes the whole resident process down (see the format gate above),
# and re-running to recover the earlier blocks would cost the setup all over again.
stop_sampler
# Only on this path: a Ctrl-C teardown has no complete CSV to judge. `stop_sampler` signals the
# group without waiting for it, so the final row may still be in flight -- which is fine for a
# check that asks whether EVERY row is empty.
warn_if_census_empty

if command -v python3 > /dev/null; then
    SWEEP_ELF_SHA="$ELF_SHA" SWEEP_PPG_SHA="$PPG_SHA" python3 bench-scripts/sweep-csv.py \
        "$OUTDIR/run.log" "$OUTDIR" --manifest "$OUTDIR/manifest.csv" --spans-base "$SPANS" || true

    # One set of figures per block. The suffix `.iterK` is what the drawing script and
    # mle-gate-metrics.py strip the base name from, so it is NOT renamed -- manifest.csv carries
    # the epoch -> block mapping instead.
    #
    # ⚠️ `--log` goes to the LAST block only. The drawing script scans the whole log and keeps the
    # last match it finds for the window, `chunks`, `prover_count` and each `MLE lane:` role, so
    # handing it to an earlier block gives that block another block's numbers, fails its checks,
    # and draws nothing.
    last_epoch=$(awk -F, 'NR>1{e=$1} END{print e}' "$OUTDIR/manifest.csv" 2> /dev/null)
    # SWEEP_NO_FIGURES=1 keeps the CSVs and skips the drawing entirely -- the whole loop, so it
    # cannot read as a per-block switch. Three SVGs per block is minutes at a handful of blocks and
    # hours at soak scale, per attempt, for pictures nobody opens.
    while IFS=, read -r epoch blk _input; do
        [ -n "${SWEEP_NO_FIGURES:-}" ] && break
        [ "$epoch" = "epoch" ] && continue
        [ -f "$SPANS.iter$epoch" ] || continue
        logarg=""
        [ "$epoch" = "$last_epoch" ] && logarg="--log $OUTDIR/run.log"
        # shellcheck disable=SC2086
        python3 bench-scripts/draw-mle-timeline.py "$SPANS.iter$epoch" \
            --lane "$OUTDIR/block-$blk.lane.svg" \
            --chunk "$OUTDIR/block-$blk.chunk.svg" \
            --overview "$OUTDIR/block-$blk.overview.svg" $logarg > /dev/null 2>&1 || true
    done < "$OUTDIR/manifest.csv"
fi
echo "[sweep] rc=$rc — artefacts in $OUTDIR"
exit "$rc"
