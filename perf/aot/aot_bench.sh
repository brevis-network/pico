#!/usr/bin/env bash
# The AOT measurement: one guest's arms, one per process, interleaved across repeats.
#
# Generates the guest's AOT crates into aot-generated/, builds aot-bench against them, then runs
# every arm once per repeat, never A A B B. Repeats go in pairs: the first of a pair runs the arm
# list rotated one place further than the previous pair did (A B C, then B C A, then C A B), and
# the second runs that same order reversed (C B A). So with an even repeat count, every two arms
# that run back to back do so equally often in each order, and every arm's mean position is the
# middle. What it does not give: arms that are not neighbours in the list's cyclic order (A and C
# in A B C D) never run back to back, and the arm that ends a pair's first repeat also starts the
# second, so it runs twice in a row there. An odd repeat count leaves the last repeat without its
# reverse, and the run warns. Each repeat's order is written as an AOT_BENCH_ORDER line. Each arm
# runs under /usr/bin/time for its peak resident memory. aot-bench prints one AOT_BENCH line per arm (perf/aot/bench/src/main.rs
# says what each field means); this script appends rep, pos (the arm's place in that repeat),
# peak_rss_kib and exit, and writes every line to a results file. An arm that printed no line is
# written as AOT_BENCH_FAIL. RUST_LOG defaults to info, so each arm's log holds the prover's own
# lines. The committed aot-generated/ stub is restored on every exit, error paths included, and the
# run refuses to start when aot-generated/ is anything but that stub.
#
# An arm written ARM@LABEL runs ARM under the command prefix `-e LABEL='PREFIX'` names: an `env`
# assignment list, a `numactl` binding, or both, with {out}, {rep}, {arm} and {label} replaced per
# run; a label with no -e is refused, and `-e LABEL=` runs it with no prefix. It rotates with the
# other arms like any arm, so two arms that differ only in their environment or binding interleave
# in one call and one build:
#   -a pipeline-aot@off,pipeline-aot@on -e off='numactl --cpunodebind=1 --membind=1 --' \
#   -e on='env MLE_LEDGER={out}/{rep}-{arm}@{label}.jsonl numactl --cpunodebind=1 --membind=1 --'
# A run is named by its arm as written, ARM or ARM@LABEL: that name, the repeat and the warm-up
# flag go to aot-bench, which hands them to the stage ledger's envelope. Each run's line gains
# label= (that name) and prefix= (spaces as +), the CPU list, memory list and memory policy read
# under that same prefix, whether MLE_LEDGER was set, and the host's lock: the last line of the
# file BENCH_LOCK_FILE names, read (never written) before and after the run as lock_before= and
# lock_after= (spaces as +), and lock_held=true only when both name the holder BENCH_LOCK_HOLDER
# gives, as that line writes it (lock_holder=). With the file unset the two reads say unknown, with
# the holder unset lock_holder= does, and lock_held=false either way. The arm's process gets
# MLE_LEDGER_LOCK_HELD=1, the ledger's lock flag, only when the read before the run names the
# holder, and never inherits that variable or GPUBENCH_LOCK_HELD_BY otherwise; a prefix that sets
# either is refused. This is the pinning evidence for an arm that writes no stage ledger. The
# script itself is not pinned; a binding lives in its arm's prefix, so an arm without one runs
# unpinned.
# It exports MLE_LEDGER_BRANCH, MLE_LEDGER_COMMIT and MLE_LEDGER_DIRTY from the tree before it
# regenerates aot-generated/, unless the caller set them.
#
# With MLE_LEDGER set on Linux, the ledger
# resets the process's peak RSS when emulation ends, to report the two halves apart; the peak this
# script reads from /usr/bin/time is the kernel's at exit and may hold the second half's alone, so the
# envelope's peak_rss_kib is the process peak. The AOT_BENCH_RUN line shows only the driver's own
# values, `-` for one set per arm: each run's own line is the record.
#
# -W runs every arm once, in list order, before the first repeat, and records those runs as
# AOT_BENCH_WARMUP lines: the first run after a build pays for page cache and allocator state the
# others do not, and is not one of the repeats.
#
# -L builds aot-bench without its default stage-ledger feature (--no-default-features --features
# jemalloc), so the stage ledger and the span recorder compile out as they do in a shipped build:
# the build for an arm that measures what they cost. The run line says stage_ledger=off. MLE_LEDGER
# and MLE_SPANS would write nothing then, so the run refuses them, set in its environment or in a
# -e prefix. The two builds take two calls, so their arms do not interleave with each other.
#
# -T builds aot-bench with the feature set single_node_mle.sh and ethproofs_single_node_mle.sh build
# with: rug for the curve precompiles' big integers (bigint-rug), tcmalloc in place of jemalloc, and
# the guest memory mmap-backed (mmap-memory); under -L too. Each arm's line says bigint=, alloc= and
# mem= as the binary was built, not as this script asked.
#
# history-census writes its capacity table to PICO_BENCH_CENSUS_OUT and folds in the one
# PICO_BENCH_CENSUS_FOLD names, both set in its -e prefix, so a second block's run folds in the
# first's:
#   -a history-census@c \
#   -e c='env PICO_BENCH_CENSUS_FOLD=<dir>/capacity.json PICO_BENCH_CENSUS_OUT={out}/capacity.json'
# Each block is recorded with the tree MLE_LEDGER_COMMIT and MLE_LEDGER_DIRTY name, so a run on a
# copied tree, a fresh one-commit repository, sets both to the commit it was extracted from. A fold
# onto blocks of another tree is refused unless PICO_BENCH_CENSUS_REPLACE=1 is in the same prefix.
#
# history-arena pins MLE_HISTORY_SLOTS history slots (64 unset) at the committed census's
# capacities and needs a card: device 0 of what CUDA_VISIBLE_DEVICES leaves.
#
# Exits non-zero if any arm did.

set -euo pipefail

ARMS_ALL="emulate-opts pipeline-interp pipeline-aot pipeline-aot-workers execute-default execute-aot execute-serial prove-default prove-aot prove-serial prove-aot-workers tracegen-aot replay-chunk retained-rows history-census history-arena"

usage() {
  echo "usage: perf/aot/aot_bench.sh -g ELF -i INPUT [-i INPUT]... -w WORKERS -a ARM[@LABEL][,ARM[@LABEL]]... [-e LABEL=PREFIX]... [-p PHASE] [-r REPEATS] [-W] [-L] [-T] [-o DIR]" >&2
  echo "  ELF      a path, or a name under perf/bench_data/rv64/ without its -elf suffix" >&2
  echo "  INPUT    a file (passed raw, as cargo pico's file:<path>), or u32:<n>, u64:<n>, file:<path>" >&2
  echo "  WORKERS  interpreter workers for every arm that has them, or default: the core count for the" >&2
  echo "           pipeline arms, and no emulation_workers call (the builder's default) for the default and" >&2
  echo "           AOT prover arms; the serial arms have none" >&2
  echo "  ARM      one of: $ARMS_ALL; ARM@LABEL runs it under LABEL's prefix." >&2
  echo "           execute-default and prove-default emulate as the SDK does by default, on the snapshot" >&2
  echo "           pipeline with the interpreter on its snapshot thread; execute-serial and prove-serial are" >&2
  echo "           the prover's one-interpreter arms (serial_emulation)" >&2
  echo "  PREFIX   a command prefix for LABEL's arms, e.g. 'env K=V numactl --cpunodebind=1 --membind=1 --';" >&2
  echo "           {out}, {rep}, {arm} and {label} are replaced per run" >&2
  echo "  PHASE    the phase the prove arms prove to; default combine. tracegen-aot stops inside riscv and takes no PHASE" >&2
  echo "  REPEATS  how many times each arm runs, interleaved; default 1" >&2
  echo "  -W       one unrecorded warm-up run of each arm first" >&2
  echo "  -L       build aot-bench without stage-ledger: the ledger and span recorder compile out, as in a" >&2
  echo "           shipped build, and the run line says stage_ledger=off" >&2
  echo "  -T       build aot-bench with rug, tcmalloc and mmap-backed guest memory, as the production" >&2
  echo "           scripts do" >&2
  echo "  DIR      where results.txt and each run's log go; default perf/aot/target/aot-bench/<guest>-<time>" >&2
  exit 2
}

ROOT=$(git -C "$(dirname "$0")" rev-parse --show-toplevel)
AOT_DIR="$ROOT/perf/aot"

guest_arg="" workers="" arms="" phase="" repeats=1 out="" warmup=0 stage_ledger=on memory=jemalloc
inputs=()
prefixes=()
while getopts "g:i:w:a:e:p:r:o:WLTh" opt; do
  case "$opt" in
    g) guest_arg="$OPTARG" ;;
    i)
      if [ -f "$OPTARG" ]; then
        inputs+=("file:$(cd "$(dirname "$OPTARG")" && pwd)/$(basename "$OPTARG")")
      else
        inputs+=("$OPTARG")
      fi
      ;;
    w) workers="$OPTARG" ;;
    a) arms="$OPTARG" ;;
    p) phase="$OPTARG" ;;
    r) repeats="$OPTARG" ;;
    W) warmup=1 ;;
    L) stage_ledger=off ;;
    T) memory="bigint-rug tcmalloc mmap-memory" ;;
    e)
      case "$OPTARG" in
        *=*) prefixes+=("$OPTARG") ;;
        *) echo "-e takes LABEL=PREFIX, not '$OPTARG'" >&2; exit 2 ;;
      esac
      ;;
    o) out="$OPTARG" ;;
    *) usage ;;
  esac
done
shift $((OPTIND - 1))
[ "$#" -eq 0 ] && [ -n "$guest_arg" ] && [ -n "$workers" ] && [ -n "$arms" ] || usage
case "$workers" in default) ;; '' | *[!0-9]* | 0) echo "WORKERS must be a positive integer or default, not '$workers'" >&2; exit 2 ;; esac
case "$repeats" in '' | *[!0-9]* | 0) echo "REPEATS must be a positive integer, not '$repeats'" >&2; exit 2 ;; esac

if [ -f "$guest_arg" ]; then
  elf="$(cd "$(dirname "$guest_arg")" && pwd)/$(basename "$guest_arg")"
elif [ -f "$ROOT/perf/bench_data/rv64/$guest_arg-elf" ]; then
  elf="$ROOT/perf/bench_data/rv64/$guest_arg-elf"
else
  echo "no ELF at '$guest_arg' or perf/bench_data/rv64/$guest_arg-elf" >&2
  exit 2
fi
guest=$(basename "$elf")

arm_list=$(echo "$arms" | tr ',' ' ')
for arm in $arm_list; do
  case " $ARMS_ALL " in
    *" ${arm%@*} "*) ;;
    *) echo "unknown arm '$arm'" >&2; usage ;;
  esac
  case "$arm" in
    *@*)
      found=0
      for entry in ${prefixes[@]+"${prefixes[@]}"}; do
        [ "${entry%%=*}" = "${arm#*@}" ] && found=1
      done
      if [ "$found" -eq 0 ]; then
        echo "arm '$arm' has no -e ${arm#*@}=PREFIX (write -e ${arm#*@}= for none)" >&2
        exit 2
      fi
      ;;
  esac
done

if [ "$stage_ledger" = off ]; then
  inert=""
  [ -z "${MLE_LEDGER+set}" ] || inert="$inert MLE_LEDGER"
  [ -z "${MLE_SPANS+set}" ] || inert="$inert MLE_SPANS"
  for entry in ${prefixes[@]+"${prefixes[@]}"}; do
    case "${entry#*=}" in *MLE_LEDGER=* | *MLE_SPANS=*) inert="$inert -e ${entry%%=*}" ;; esac
  done
  if [ -n "$inert" ]; then
    echo "-L compiles the stage ledger and the span recorder out, so these would write nothing:$inert" >&2
    exit 2
  fi
fi

for entry in ${prefixes[@]+"${prefixes[@]}"}; do
  case "${entry#*=}" in
    *MLE_LEDGER_LOCK_HELD* | *GPUBENCH_LOCK_HELD_BY*)
      echo "-e ${entry%%=*} sets the lock flag by hand; the script reads it from the lock file" >&2
      exit 2
      ;;
  esac
done
LOCK_FILE=${BENCH_LOCK_FILE:-}
lock_holder=${BENCH_LOCK_HOLDER:-}
# The lock's state is its last line: "USING:" alone is free, "USING: <holder> <since>" is held.
lock_state() {
  local last
  [ -n "$LOCK_FILE" ] || { echo unknown; return 0; }
  last=$(tail -n 1 "$LOCK_FILE" 2>/dev/null || true)
  echo "${last:--}" | tr ' ' '+'
}
lock_ours() {
  [ -n "$lock_holder" ] || return 1
  case "$1" in "USING:+$lock_holder" | "USING:+$lock_holder+"*) return 0 ;; esac
  return 1
}

if /usr/bin/time -v true >/dev/null 2>&1; then
  time_flag=-v # GNU: "Maximum resident set size (kbytes): N"
elif /usr/bin/time -l true >/dev/null 2>&1; then
  time_flag=-l # BSD: "N  maximum resident set size", in bytes
else
  echo "/usr/bin/time reports no peak resident memory here" >&2
  exit 2
fi
peak_rss_kib() {
  local kib=""
  if [ -f "$1" ]; then
    if [ "$time_flag" = -v ]; then
      kib=$(awk -F': ' '/Maximum resident set size/ { print $2 }' "$1")
    else
      kib=$(awk '/maximum resident set size/ { printf "%d", $1 / 1024 }' "$1")
    fi
  fi
  echo "${kib:--}"
}

now() { perl -MTime::HiRes=time -e 'printf "%.2f", time'; }
since() { perl -e 'printf "%.1f", $ARGV[1] - $ARGV[0]' "$1" "$(now)"; }

# Anything but the tracked stub (the bootstrap script's sentinel aside) is someone's generated code.
leftovers=$(git -C "$ROOT" status --porcelain --ignored -- aot-generated \
  | grep -v '^!! aot-generated/\.aot-bootstrap-stub$' || true)
if [ -n "$leftovers" ]; then
  echo "aot-generated/ is not the committed stub, and this run would overwrite it:" >&2
  echo "$leftovers" >&2
  echo "restore it with: rm -rf aot-generated && git checkout -- aot-generated" >&2
  exit 2
fi

restore() {
  local status=$?
  rm -rf "${ROOT:?}/aot-generated"
  if git -C "$ROOT" checkout -- aot-generated \
    && [ -z "$(git -C "$ROOT" status --porcelain --ignored -- aot-generated)" ]; then
    echo "restored the committed aot-generated/ stub"
  else
    echo "FAILED to restore the committed aot-generated/ stub" >&2
    [ "$status" -ne 0 ] || status=1
  fi
  exit "$status"
}
trap restore EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

[ -n "$out" ] || out="$AOT_DIR/target/aot-bench/${guest}-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$out"
results="$out/results.txt"
: >"$results"

record() {
  echo "$1"
  echo "$1" >>"$results"
}

dirty=""
[ -z "$(git -C "$ROOT" status --porcelain --untracked-files=no)" ] || dirty="-dirty"
# Before aot-generated/ is regenerated, which would read as a dirty tree to the run's own check.
export MLE_LEDGER_BRANCH="${MLE_LEDGER_BRANCH:-$(git -C "$ROOT" rev-parse --abbrev-ref HEAD)}"
export MLE_LEDGER_COMMIT="${MLE_LEDGER_COMMIT:-$(git -C "$ROOT" rev-parse --short=9 HEAD)}"
export MLE_LEDGER_DIRTY="${MLE_LEDGER_DIRTY:-$([ -z "$dirty" ] && echo 0 || echo 1)}"
sha256() {
  local sum
  if command -v sha256sum >/dev/null; then sum=$(sha256sum "$1"); else sum=$(shasum -a 256 "$1"); fi
  echo "${sum%% *}"
}
input_sha256=""
for input in ${inputs[@]+"${inputs[@]}"}; do
  case "$input" in
    file:*) input_sha256="$input_sha256,$(sha256 "${input#file:}")" ;;
    *) input_sha256="$input_sha256,-" ;;
  esac
done
export RUST_LOG="${RUST_LOG:-info}"
# What the prover and the pipeline read from the environment, beyond what the line already names.
env_values=""
for name in MLE_SPLIT_REPLAY MLE_SPLIT_CHUNKS MLE_SPLIT_FROM_CHUNK PROVER_COUNT NUM_THREADS \
  MEMORY_POOL_SIZE CHUNK_SIZE PROVE_CONCURRENCY RUST_LOG RAYON_NUM_THREADS CHUNK_BATCH_SIZE \
  MLE_LOG_STACKED_HEIGHT MLE_LEDGER MLE_SPANS MLE_EVENT_POOL_SIZE MLE_PREWARM \
  MLE_HEAP_PREWARM_GB TCMALLOC_RELEASE_RATE PICO_BENCH_CENSUS_OUT PICO_BENCH_CENSUS_FOLD \
  PICO_BENCH_CENSUS_REPLACE MLE_HISTORY_SLOTS MLE_REPLAY_WORKERS; do
  value=$(printenv "$name" | tr -s ' \t' '_' || true)
  env_values="$env_values $name=${value:--}"
done
record "AOT_BENCH_RUN guest=$guest elf_sha256=$(sha256 "$elf") \
inputs=$(IFS=,; echo "${inputs[*]+${inputs[*]}}" | sed 's|file:[^,]*/|file:|g') \
input_sha256=${input_sha256#,} workers=$workers arms=$arms repeats=$repeats phase=${phase:--} \
stage_ledger=$stage_ledger memory_features=${memory// /+}\
$env_values host=$(hostname -s) commit=$(git -C "$ROOT" rev-parse --short HEAD)$dirty"

echo "==> building generate_crates"
(cd "$ROOT" && cargo build --release -p pico-aot-codegen --bin generate_crates)
root_target=$(cd "$ROOT" && cargo metadata --format-version 1 --no-deps \
  | python3 -c 'import json, sys; print(json.load(sys.stdin)["target_directory"])')
aot_target=$(cd "$AOT_DIR" && cargo metadata --format-version 1 --no-deps \
  | python3 -c 'import json, sys; print(json.load(sys.stdin)["target_directory"])')
bench="$aot_target/release/aot-bench"
# jemalloc stays under -L unless -T: it is the allocator a user's prover build gets.
bench_features=()
if [ "$stage_ledger" = off ]; then
  bench_features=(--no-default-features --features "$memory")
elif [ "$memory" != jemalloc ]; then
  bench_features=(--no-default-features --features "$memory stage-ledger")
fi
# The history-arena arm's round trip through a card needs `cuda`: build it where the machine has one.
# shellcheck source=../../detect_cuda.sh
. "$ROOT/detect_cuda.sh"
pico_cuda_detect
if [ "$PICO_BACKEND" = cuda ]; then
  if [ "${#bench_features[@]}" -eq 0 ]; then
    bench_features=(--features cuda)
  else
    bench_features[2]="${bench_features[2]} cuda"
  fi
fi

# Against the stub first, so the build time below is the generated crates' alone.
echo "==> building aot-bench's dependencies against the stub"
start=$(now)
(cd "$AOT_DIR" && cargo build --release -p aot-bench ${bench_features[@]+"${bench_features[@]}"})
deps_build_s=$(since "$start")

echo "==> $guest: generating"
start=$(now)
"$root_target/release/generate_crates" "$elf" "$ROOT/aot-generated"
generate_s=$(since "$start")
size=$(du -sh "$ROOT/aot-generated" | cut -f1 | tr -d ' ')
size_kib=$(du -sk "$ROOT/aot-generated" | cut -f1)
crates=$(find "$ROOT/aot-generated" -name Cargo.toml | wc -l | tr -d ' ')

echo "==> $guest: building"
start=$(now)
(cd "$AOT_DIR" && cargo build --release -p aot-bench ${bench_features[@]+"${bench_features[@]}"})
build_s=$(since "$start")
record "AOT_BENCH_BUILD guest=$guest generate_s=$generate_s size=$size size_kib=$size_kib \
crates=$crates build_s=$build_s deps_build_s=$deps_build_s"

# shellcheck disable=SC2206 # arm names are single words
arm_array=($arm_list)
arm_count=${#arm_array[@]}
runs=0
failed=0
if [ "$arm_count" -ge 2 ] && [ $((repeats % 2)) -eq 1 ]; then
  record "AOT_BENCH_WARN repeats=$repeats is odd: the last repeat runs without its reverse, so its \
back-to-back pairs run once more in one order than in the other"
fi
# LABEL's prefix as given to -e, empty when there is none.
prefix_of() {
  local entry
  for entry in ${prefixes[@]+"${prefixes[@]}"}; do
    if [ "${entry%%=*}" = "$1" ]; then
      echo "${entry#*=}"
      return 0
    fi
  done
  return 0
}

# One arm, once: REP names the run's files, KIND is the line's record type.
run_arm() {
  local rep=$1 pos=$2 arm=$3 kind=$4
  local name=${arm%@*} label=${arm} raw=""
  case "$arm" in *@*) label=${arm#*@}; raw=$(prefix_of "$label") ;; esac
  raw=${raw//\{out\}/$out}
  raw=${raw//\{rep\}/$rep}
  raw=${raw//\{label\}/$label}
  raw=${raw//\{arm\}/$name}
  local prefix=()
  read -r -a prefix <<<"$raw"
  local log="$out/$rep-$arm.log" timing="$out/$rep-$arm.time"
  local args=(--arm "$name" --elf "$elf" --workers "$workers" --label "$arm" --rep "$rep")
  [ "$kind" != AOT_BENCH_WARMUP ] || args+=(--warmup)
  for input in ${inputs[@]+"${inputs[@]}"}; do args+=(--input "$input"); done
  case "$name" in prove-*) [ -z "$phase" ] || args+=(--phase "$phase") ;; esac
  # Read under the arm's own prefix, so it describes the process the arm ran in.
  local placement
  placement=$(${prefix[@]+"${prefix[@]}"} sh -c '
    c=$(sed -n "s/^Cpus_allowed_list:[[:space:]]*//p" /proc/self/status 2>/dev/null)
    m=$(sed -n "s/^Mems_allowed_list:[[:space:]]*//p" /proc/self/status 2>/dev/null)
    p=$(cut -d" " -f2 /proc/self/numa_maps 2>/dev/null | sort | uniq -c | awk "{printf \"%s%s:%s\", (NR>1?\",\":\"\"), \$2, \$1}")
    l=n; [ -n "${MLE_LEDGER:-}" ] && l=y
    echo "cpus_allowed_list=${c:--} mems_allowed_list=${m:--} mempolicy=${p:--} ledger_set=$l"')
  echo "==> rep $rep/$repeats: $arm"
  local lock_before lock_after held=false
  local lock_env=(env -u MLE_LEDGER_LOCK_HELD -u GPUBENCH_LOCK_HELD_BY)
  lock_before=$(lock_state)
  if lock_ours "$lock_before"; then lock_env+=(MLE_LEDGER_LOCK_HELD=1); fi
  local code=0
  "${lock_env[@]}" ${prefix[@]+"${prefix[@]}"} /usr/bin/time "$time_flag" -o "$timing" "$bench" \
    "${args[@]}" >"$log" 2>&1 || code=$?
  lock_after=$(lock_state)
  if lock_ours "$lock_before" && lock_ours "$lock_after"; then held=true; fi
  local line
  line=$(grep '^AOT_BENCH ' "$log" | tail -n 1 || true)
  local tail_keys="label=$arm prefix=$(echo "${raw:--}" | tr ' ' '+') $placement \
lock_held=$held lock_before=$lock_before lock_after=$lock_after \
lock_holder=${lock_holder:-unknown} rep=$rep pos=$pos"
  if [ -n "$line" ]; then
    record "${kind}${line#AOT_BENCH} $tail_keys peak_rss_kib=$(peak_rss_kib "$timing") exit=$code"
  else
    record "AOT_BENCH_FAIL arm=$name $tail_keys peak_rss_kib=$(peak_rss_kib "$timing") exit=$code log=$log"
  fi
  if [ "$code" -ne 0 ]; then
    failed=$((failed + 1))
    tail -n 5 "$log" >&2
  fi
}

if [ "$warmup" -eq 1 ]; then
  pos=0
  for arm in "${arm_array[@]}"; do
    runs=$((runs + 1))
    pos=$((pos + 1))
    run_arm w "$pos" "$arm" AOT_BENCH_WARMUP
  done
fi
for rep in $(seq 1 "$repeats"); do
  rotation=$(((rep - 1) / 2))
  order=""
  for i in $(seq 0 $((arm_count - 1))); do
    arm=${arm_array[$(((i + rotation) % arm_count))]}
    if [ $((rep % 2)) -eq 0 ]; then order="$arm $order"; else order="$order $arm"; fi
  done
  record "AOT_BENCH_ORDER rep=$rep arms=$(echo $order | tr ' ' ',')"
  pos=0
  for arm in $order; do
    runs=$((runs + 1))
    pos=$((pos + 1))
    run_arm "$rep" "$pos" "$arm" AOT_BENCH
  done
done

echo "OVERALL: $((runs - failed))/$runs run(s) exited 0, results in $results, EXIT=$((failed > 0 ? 1 : 0))"
[ "$failed" -eq 0 ]
