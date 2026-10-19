#!/usr/bin/env bash
# The AOT snapshot thread against the interpreter's, record by record, one guest at a time.
#
# For each guest: generate its AOT crates into aot-generated/, build the aot-record-parity test
# against them, and run it (perf/aot/record_parity/src/lib.rs says what it compares). A process
# holds one AOT program and every generated crate is named pico-aot-dispatch, so each guest gets
# its own build. The committed aot-generated/ stub is restored on every exit, error paths included;
# the run refuses to start when aot-generated/ is anything but that stub, rather than overwrite it.
#
# Prints the generate time, the generated tree's size and crate count, the build time and EXIT=<n>
# for each guest, then an overall line. Exits non-zero if any guest failed.

set -euo pipefail

GUESTS_ALL="fib ed25519 poseidon2 aggregator bls12381-fp"

usage() {
  echo "usage: perf/aot/record_parity.sh [-w WORKERS] GUEST... | all" >&2
  echo "  GUEST    one of: $GUESTS_ALL (the ELF is perf/bench_data/rv64/<GUEST>-elf)" >&2
  echo "  WORKERS  interpreter workers in the pipeline, both arms; default 4, or the core count if lower" >&2
  exit 2
}

workers=""
while getopts "w:h" opt; do
  case "$opt" in
    w) workers="$OPTARG" ;;
    *) usage ;;
  esac
done
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

echo "==> building generate_crates"
(cd "$ROOT" && cargo build --release -p pico-aot-codegen --bin generate_crates)
target_dir=$(cd "$ROOT" && cargo metadata --format-version 1 --no-deps \
  | python3 -c 'import json, sys; print(json.load(sys.stdin)["target_directory"])')
generate_crates="$target_dir/release/generate_crates"

# Against the stub first, so a guest's build time below is its generated crates' alone.
echo "==> building the test's dependencies against the stub"
start=$(now)
(cd "$AOT_DIR" && cargo test --release -p aot-record-parity --test aot_against_interpreter --no-run)
echo "dependencies built in $(since "$start")s"

run_guest() {
  local guest=$1 elf="$ROOT/perf/bench_data/rv64/$1-elf" start code

  echo "==> $guest: generating from $elf"
  start=$(now)
  "$generate_crates" "$elf" "$ROOT/aot-generated" || return $?
  generate_s=$(since "$start")
  size_kib=$(du -sk "$ROOT/aot-generated" | cut -f1)
  crates=$(find "$ROOT/aot-generated" -name Cargo.toml | wc -l | tr -d ' ')
  rust_lines=$(find "$ROOT/aot-generated" -name '*.rs' -exec cat {} + | wc -l | tr -d ' ')

  echo "==> $guest: building"
  start=$(now)
  (cd "$AOT_DIR" && cargo test --release -p aot-record-parity --test aot_against_interpreter --no-run) \
    || return $?
  build_s=$(since "$start")

  echo "==> $guest: comparing"
  code=0
  (
    cd "$AOT_DIR"
    if [ -n "$workers" ]; then export AOT_PARITY_WORKERS="$workers"; fi
    cargo test --release -p aot-record-parity --test aot_against_interpreter -- --nocapture
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

printf '%s' "$summary"
echo "OVERALL: $((total - failed))/$total guest(s) passed, EXIT=$((failed > 0 ? 1 : 0))"
[ "$failed" -eq 0 ]
