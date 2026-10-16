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
# Exits non-zero if any arm did.

set -euo pipefail

ARMS_ALL="emulate-opts pipeline-interp pipeline-aot execute-default execute-aot prove-default prove-aot"

usage() {
  echo "usage: perf/aot/aot_bench.sh -g ELF -i INPUT [-i INPUT]... -w WORKERS -a ARM[,ARM]... [-p PHASE] [-r REPEATS] [-o DIR]" >&2
  echo "  ELF      a path, or a name under perf/bench_data/rv64/ without its -elf suffix" >&2
  echo "  INPUT    a file (passed raw, as cargo pico's file:<path>), or u32:<n>, u64:<n>, file:<path>" >&2
  echo "  WORKERS  interpreter workers for every arm that has them, or default: the core count for the" >&2
  echo "           pipeline arms, and no emulation_workers call (the builder's default) for the AOT prover arms" >&2
  echo "  ARM      one of: $ARMS_ALL" >&2
  echo "  PHASE    the phase the prove arms prove to; default combine" >&2
  echo "  REPEATS  how many times each arm runs, interleaved; default 1" >&2
  echo "  DIR      where results.txt and each run's log go; default perf/aot/target/aot-bench/<guest>-<time>" >&2
  exit 2
}

ROOT=$(git -C "$(dirname "$0")" rev-parse --show-toplevel)
AOT_DIR="$ROOT/perf/aot"

guest_arg="" workers="" arms="" phase="" repeats=1 out=""
inputs=()
while getopts "g:i:w:a:p:r:o:h" opt; do
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
    *" $arm "*) ;;
    *) echo "unknown arm '$arm'" >&2; usage ;;
  esac
done

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
for name in MLE_SPLIT_REPLAY PROVER_COUNT NUM_THREADS MEMORY_POOL_SIZE CHUNK_SIZE PROVE_CONCURRENCY \
  RUST_LOG; do
  value=$(printenv "$name" | tr -s ' \t' '_' || true)
  env_values="$env_values $name=${value:--}"
done
record "AOT_BENCH_RUN guest=$guest elf_sha256=$(sha256 "$elf") \
inputs=$(IFS=,; echo "${inputs[*]+${inputs[*]}}" | sed 's|file:[^,]*/|file:|g') \
input_sha256=${input_sha256#,} workers=$workers arms=$arms repeats=$repeats phase=${phase:--}\
$env_values host=$(hostname -s) commit=$(git -C "$ROOT" rev-parse --short HEAD)$dirty"

echo "==> building generate_crates"
(cd "$ROOT" && cargo build --release -p pico-aot-codegen --bin generate_crates)
root_target=$(cd "$ROOT" && cargo metadata --format-version 1 --no-deps \
  | python3 -c 'import json, sys; print(json.load(sys.stdin)["target_directory"])')
aot_target=$(cd "$AOT_DIR" && cargo metadata --format-version 1 --no-deps \
  | python3 -c 'import json, sys; print(json.load(sys.stdin)["target_directory"])')
bench="$aot_target/release/aot-bench"

# Against the stub first, so the build time below is the generated crates' alone.
echo "==> building aot-bench's dependencies against the stub"
start=$(now)
(cd "$AOT_DIR" && cargo build --release -p aot-bench)
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
(cd "$AOT_DIR" && cargo build --release -p aot-bench)
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
    log="$out/$rep-$arm.log"
    timing="$out/$rep-$arm.time"
    args=(--arm "$arm" --elf "$elf" --workers "$workers")
    for input in ${inputs[@]+"${inputs[@]}"}; do args+=(--input "$input"); done
    case "$arm" in prove-*) [ -z "$phase" ] || args+=(--phase "$phase") ;; esac
    echo "==> rep $rep/$repeats: $arm"
    code=0
    /usr/bin/time "$time_flag" -o "$timing" "$bench" "${args[@]}" >"$log" 2>&1 || code=$?
    line=$(grep '^AOT_BENCH ' "$log" | tail -n 1 || true)
    if [ -n "$line" ]; then
      record "$line rep=$rep pos=$pos peak_rss_kib=$(peak_rss_kib "$timing") exit=$code"
    else
      record "AOT_BENCH_FAIL arm=$arm rep=$rep pos=$pos peak_rss_kib=$(peak_rss_kib "$timing") exit=$code log=$log"
    fi
    if [ "$code" -ne 0 ]; then
      failed=$((failed + 1))
      tail -n 5 "$log" >&2
    fi
  done
done

echo "OVERALL: $((runs - failed))/$runs run(s) exited 0, results in $results, EXIT=$((failed > 0 ? 1 : 0))"
[ "$failed" -eq 0 ]
