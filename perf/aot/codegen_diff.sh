#!/usr/bin/env bash
# Checks that the code generator writes each GUEST's crates, ordinary blocks and recording bodies,
# on this tree byte for byte as at BASE, but for the codegen stamp in the dispatch crate's `AOT`
# when a runtime contract change moved it. Any other difference changes what the AOT snapshot
# thread or replay workers run. Exits non-zero if a guest differs in more than the stamp.
#
# BASE's generate_crates is built from `git archive` under perf/aot/target/codegen-diff/, kept per
# commit so a rerun builds nothing; aot-generated/ is not touched. A BASE from before the recording
# bodies were always generated writes them only under PICO_AOT_RECORDER=1, so its run sets it.

set -euo pipefail

usage() {
  echo "usage: perf/aot/codegen_diff.sh BASE GUEST..." >&2
  echo "  BASE   a revision of this repository, e.g. the branch the change is stacked on" >&2
  echo "  GUEST  an ELF path, or a name under perf/bench_data/rv64/ without its -elf suffix" >&2
  exit 2
}
[ "$#" -ge 2 ] || usage
base=$1
shift

ROOT=$(git -C "$(dirname "$0")" rev-parse --show-toplevel)
base_commit=$(git -C "$ROOT" rev-parse --verify "$base^{commit}") || usage
work="$ROOT/perf/aot/target/codegen-diff"
base_tree="$work/base-${base_commit:0:12}"

stamp_of() {
  sed -n 's/^pub const AOT_CODEGEN_STAMP: u32 = \([0-9][0-9]*\);$/\1/p' "$1/vm/src/lib.rs"
}

if [ ! -x "$base_tree/target/release/generate_crates" ]; then
  echo "==> building generate_crates at $base (${base_commit:0:12})"
  rm -rf "$base_tree"
  mkdir -p "$base_tree"
  git -C "$ROOT" archive "$base_commit" | tar -x -C "$base_tree"
  # The GPU line's workspace has the untracked private kernel checkout as a path dependency, which
  # the archive lacks; link this tree's in. The diff means something only if BASE pins the same one.
  if [ -e "$ROOT/private-pico-gpu" ] && [ ! -e "$base_tree/private-pico-gpu" ]; then
    ln -s "$(cd "$ROOT/private-pico-gpu" && pwd -P)" "$base_tree/private-pico-gpu"
  fi
  (cd "$base_tree" && cargo build --release -p pico-aot-codegen --bin generate_crates \
    --target-dir "$base_tree/target")
fi
echo "==> building generate_crates on this tree"
(cd "$ROOT" && cargo build --release -p pico-aot-codegen --bin generate_crates)
tree_target=$(cd "$ROOT" && cargo metadata --format-version 1 --no-deps \
  | python3 -c 'import json, sys; print(json.load(sys.stdin)["target_directory"])')

base_stamp=$(stamp_of "$base_tree")
tree_stamp=$(stamp_of "$ROOT")
echo "stamp: $base_stamp at $base, $tree_stamp on this tree"

failed=0
for guest in "$@"; do
  if [ -f "$guest" ]; then
    elf=$guest
  else
    elf="$ROOT/perf/bench_data/rv64/$guest-elf"
  fi
  [ -f "$elf" ] || { echo "no ELF for '$guest'" >&2; exit 2; }
  name=$(basename "$elf")
  out="$work/$name"
  rm -rf "$out"
  mkdir -p "$out"
  env -u PICO_AOT_SAVE_METRICS PICO_AOT_RECORDER=1 "$base_tree/target/release/generate_crates" "$elf" "$out/base" >/dev/null
  env -u PICO_AOT_SAVE_METRICS "$tree_target/release/generate_crates" "$elf" "$out/tree" >/dev/null
  code=0
  (cd "$out" && diff -ru base tree) >"$out/diff.txt" || code=$?
  [ "$code" -le 1 ] || { echo "diff failed on $name" >&2; exit 2; }
  echo "==> $name: diff -ru base tree"
  cat "$out/diff.txt"
  # stamp-only iff the one changed line is the dispatch crate's, equal once BASE's stamp is swapped
  # for this tree's.
  verdict=$(python3 - "$out/diff.txt" "$base_stamp" "$tree_stamp" <<'PY'
import re, sys
text = open(sys.argv[1]).read()
base, tree = sys.argv[2], sys.argv[3]
files = re.findall(r"^diff -ru base/(\S+) tree/\S+$", text, re.M)
# A file on one side only shows as an "Only in" line, with no +/- lines: it differs too.
files += re.findall(r"^Only in (.+)$", text, re.M)
removed = [l[1:] for l in text.splitlines() if l.startswith("-") and not l.startswith("---")]
added = [l[1:] for l in text.splitlines() if l.startswith("+") and not l.startswith("+++")]
only_dispatch = files == ["src/lib.rs"]
one_line = len(removed) == 1 and len(added) == 1
stamp = rf"\b{base}u32\b"
same_but_stamp = one_line and base != tree and re.search(stamp, removed[0]) is not None \
    and re.sub(stamp, f"{tree}u32", removed[0]) == added[0]
identical = base == tree and not files and not removed and not added
print("stamp-only" if (only_dispatch and same_but_stamp) or identical else
      f"DIFFERS files={files} removed={len(removed)} added={len(added)}")
PY
)
  files=$(find "$out/tree" -type f | wc -l | tr -d ' ')
  echo "[$name] $files generated file(s); diff against $base: $verdict"
  [ "$verdict" = stamp-only ] || failed=$((failed + 1))
done
echo "OVERALL: $failed guest(s) differ in more than the stamp, EXIT=$((failed > 0 ? 1 : 0))"
[ "$failed" -eq 0 ]
