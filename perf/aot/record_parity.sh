#!/usr/bin/env bash
# The AOT snapshot thread and the AOT replay workers against the interpreter's, record by record,
# one guest at a time.
#
# First, against the committed stub, the two positive controls: the stub's code under fib's digest
# on the AOT core's own records, and in the replay workers (perf/aot/record_parity/src/lib.rs,
# `check_stub_code` and `check_stub_replay`). Then, for each guest: generate its AOT crates into
# aot-generated/, build the aot-record-parity test against them, and run it (perf/aot/record_parity/
# src/lib.rs says what it compares). A process holds one AOT program and every generated crate is
# named pico-aot-dispatch, so each guest gets its own build. The committed aot-generated/ stub is
# restored on every exit, error paths included; the run refuses to start when aot-generated/ is
# anything but that stub, rather than overwrite it.
#
# The replay workers' pass, its control included, runs the AOT workers on the recording bodies:
# their ledger lines have to show the recording bodies and the fallback covering every cycle.
#
# -c builds the test with recorder-check: each step whose rows a recording block writes directly is
# also closed by the shared writer's generic code, and a layout mismatch, or an instruction constant
# that is not the program's at its pc, fails the run. It checks layout, not values; the record
# comparison catches a wrong value. A run in which no block wrote rows directly fails, having
# checked nothing.
#
# Prints each control's EXIT=<n>, then the generate time, the generated tree's size and crate count,
# the build time and EXIT=<n> for each guest, then an overall line. Exits non-zero if a control or
# any guest failed.

set -euo pipefail

GUESTS_ALL="fib ed25519 poseidon2 aggregator bls12381-fp sha2 sha3 tiny-keccak k256 bn254-fp bls12381-ws bn254-ws"

usage() {
  echo "usage: perf/aot/record_parity.sh [-w WORKERS] [-e ENGINE] [-c] GUEST... | all" >&2
  echo "  GUEST    one of: $GUESTS_ALL (the ELF is perf/bench_data/rv64/<GUEST>-elf, but see elf_of)" >&2
  echo "  WORKERS  replay workers in the pipeline, every arm; default 4, or the core count if lower" >&2
  echo "  ENGINE   what the AOT replay workers run: aot, the recording bodies (the default and only one)" >&2
  echo "  -c       the checking build, every direct row checked as it is written" >&2
  exit 2
}

workers=""
engine=aot
check=""
while getopts "w:e:ch" opt; do
  case "$opt" in
    w) workers="$OPTARG" ;;
    e) engine="$OPTARG" ;;
    c) check=1 ;;
    *) usage ;;
  esac
done
case "$engine" in
  aot) ;;
  aot-recorder)
    echo "-e aot-recorder is refused: the AOT replay workers run the recording bodies as aot; use -e aot or leave -e out" >&2
    exit 2
    ;;
  *) echo "ENGINE must be aot, not '$engine'" >&2; exit 2 ;;
esac
features=()
[ -z "$check" ] || features+=(--features recorder-check)
export AOT_PARITY_REPLAY="$engine"
shift $((OPTIND - 1))
[ "$#" -gt 0 ] || usage
if [ -n "$workers" ]; then
  case "$workers" in
    '' | *[!0-9]* | 0) echo "WORKERS must be a positive integer, not '$workers'" >&2; exit 2 ;;
  esac
fi

ROOT=$(git -C "$(dirname "$0")" rev-parse --show-toplevel)
AOT_DIR="$ROOT/perf/aot"

guests=""
for guest in "$@"; do
  if [ "$guest" = all ]; then
    guests="$guests $GUESTS_ALL"
    continue
  fi
  case " $GUESTS_ALL " in
    *" $guest "*) guests="$guests $guest" ;;
    *) echo "unknown guest '$guest'" >&2; usage ;;
  esac
done

now() { perl -MTime::HiRes=time -e 'printf "%.2f", time'; }
since() { perl -e 'printf "%.1f", $ARGV[1] - $ARGV[0]' "$1" "$(now)"; }

# Anything but the tracked stub (the bootstrap script's sentinel aside) is someone's generated code.
# Checked apart from the filter: a failed git status prints nothing, which would pass for the stub
# and let the exit trap delete whatever aot-generated/ holds.
if ! generated=$(git -C "$ROOT" status --porcelain --ignored -- aot-generated); then
  echo "git status failed on aot-generated/, so the run cannot tell it is the committed stub" >&2
  exit 2
fi
leftovers=$(printf '%s\n' "$generated" \
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

echo "==> building generate_crates"
(cd "$ROOT" && cargo build --release -p pico-aot-codegen --bin generate_crates)
target_dir=$(cd "$ROOT" && cargo metadata --format-version 1 --no-deps \
  | python3 -c 'import json, sys; print(json.load(sys.stdin)["target_directory"])')
generate_crates="$target_dir/release/generate_crates"

# Against the stub first, so a guest's build time below is its generated crates' alone.
echo "==> building the test's dependencies against the stub"
start=$(now)
(cd "$AOT_DIR" && cargo test --release -p aot-record-parity ${features[@]+"${features[@]}"} --test aot_against_interpreter --no-run)
echo "dependencies built in $(since "$start")s"

echo "==> the stub's code under fib's digest, emitting"
control=0
(
  cd "$AOT_DIR"
  if [ -n "$workers" ]; then export AOT_PARITY_WORKERS="$workers"; fi
  cargo test --release -p aot-record-parity ${features[@]+"${features[@]}"} --test stub_code_against_interpreter -- --nocapture
) || control=$?
control_line="[stub code] EXIT=$control"
echo "$control_line"

echo "==> the stub's code under fib's digest, in the replay workers"
workers_control=0
(
  cd "$AOT_DIR"
  if [ -n "$workers" ]; then export AOT_PARITY_WORKERS="$workers"; fi
  cargo test --release -p aot-record-parity ${features[@]+"${features[@]}"} --test stub_workers_against_interpreter -- --nocapture
) || workers_control=$?
workers_control_line="[stub workers] EXIT=$workers_control"
echo "$workers_control_line"

# The two curve guests' ELFs keep the names they were shipped under.
elf_of() {
  case "$1" in
    bls12381-ws) echo "$ROOT/perf/bench_data/rv64/bls12381-elf-ws-add-double-decompress" ;;
    bn254-ws) echo "$ROOT/perf/bench_data/rv64/bn254-elf-ws-add-double" ;;
    *) echo "$ROOT/perf/bench_data/rv64/$1-elf" ;;
  esac
}

run_guest() {
  local guest=$1 elf start code
  elf=$(elf_of "$guest")

  echo "==> $guest: generating from $elf"
  start=$(now)
  "$generate_crates" "$elf" "$ROOT/aot-generated" || return $?
  generate_s=$(since "$start")
  size_kib=$(du -sk "$ROOT/aot-generated" | cut -f1)
  crates=$(find "$ROOT/aot-generated" -name Cargo.toml | wc -l | tr -d ' ')
  rust_lines=$(find "$ROOT/aot-generated" -name '*.rs' -exec cat {} + | wc -l | tr -d ' ')

  echo "==> $guest: building"
  start=$(now)
  (cd "$AOT_DIR" && cargo test --release -p aot-record-parity ${features[@]+"${features[@]}"} --test aot_against_interpreter --no-run) \
    || return $?
  build_s=$(since "$start")

  echo "==> $guest: comparing"
  code=0
  (
    cd "$AOT_DIR"
    if [ -n "$workers" ]; then export AOT_PARITY_WORKERS="$workers"; fi
    cargo test --release -p aot-record-parity ${features[@]+"${features[@]}"} --test aot_against_interpreter -- --nocapture
  ) || code=$?
  return "$code"
}

summary=""
failed=0
total=0
for guest in $guests; do
  total=$((total + 1))
  generate_s="-" size_kib="-" crates="-" rust_lines="-" build_s="-"
  code=0
  run_guest "$guest" || code=$?
  [ "$code" -eq 0 ] || failed=$((failed + 1))
  line="[$guest] generate ${generate_s}s, ${size_kib} KiB in ${crates} crate(s) (${rust_lines} lines of Rust), build ${build_s}s, EXIT=$code"
  echo "$line"
  summary="$summary$line"$'\n'
done

echo "$control_line"
echo "$workers_control_line"
printf '%s' "$summary"
echo "OVERALL: $((total - failed))/$total guest(s) passed, replay workers on $engine${check:+, checking build}, \
control EXIT=$control, workers control EXIT=$workers_control, \
EXIT=$((failed > 0 || control != 0 || workers_control != 0 ? 1 : 0))"
[ "$failed" -eq 0 ] && [ "$control" -eq 0 ] && [ "$workers_control" -eq 0 ]
