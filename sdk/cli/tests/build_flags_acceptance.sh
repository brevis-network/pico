#!/usr/bin/env bash
# Real guest builds through `cargo pico build`: the cargo flags it forwards, `--bin` selection, and
# its errors. It needs the pico guest toolchain (`cargo pico install`), which no CI job installs, so
# it is run by hand rather than as a cargo test.
#
# The fixture guest is written to a temporary directory rather than committed: a guest package
# needs its own `[workspace]`, which would make it another workspace root for the fmt loop and the
# lock checks to cover.
#
# Usage: sdk/cli/tests/build_flags_acceptance.sh <cargo-pico binary>
# Export CARGO_TARGET_DIR to keep the guest build between runs.
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <cargo-pico binary>" >&2
  exit 2
fi
PICO_BIN="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
if [[ ! -x "$PICO_BIN" ]]; then
  echo "not an executable: $1" >&2
  exit 2
fi
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"

TMP_ROOT="${TMPDIR:-/tmp}"
WORK="$(mktemp -d "${TMP_ROOT%/}/pico-build-flags.XXXXXX")"
FIXTURE="$WORK/fixture"
GUEST="$FIXTURE/guest"
NEWER="$FIXTURE/newer"
LOGS="$WORK/logs"
mkdir -p "$GUEST/src/bin" "$NEWER/src" "$WORK/empty" "$LOGS"
echo "fixture and logs: $WORK"

cat >"$FIXTURE/Cargo.toml" <<'EOF'
[workspace]
members = ["guest", "newer"]
resolver = "2"
EOF
# The versions this tree's own `pico-sdk` is built and tested with, not whatever resolves today.
cp "$ROOT/Cargo.lock" "$FIXTURE/Cargo.lock"

cat >"$GUEST/Cargo.toml" <<EOF
[package]
name = "flags-guest"
version = "0.1.0"
edition = "2021"

[dependencies]
pico-sdk = { path = "$ROOT/sdk/sdk" }

[features]
default = ["marker"]
marker = []
EOF

cat >"$GUEST/src/bin/first.rs" <<'EOF'
#![no_main]

pico_sdk::entrypoint!(main);

pub fn main() {
    let byte: u8 = if cfg!(feature = "marker") { 0xaa } else { 0xbb };
    pico_sdk::io::commit_bytes(&[byte]);
}
EOF

cat >"$GUEST/src/bin/second.rs" <<'EOF'
#![no_main]

pico_sdk::entrypoint!(main);

pub fn main() {
    pico_sdk::io::commit_bytes(&[0xcc]);
}
EOF

# Above any guest compiler's version (the toolchain moves with each nightly bump), so only
# `--ignore-rust-version` builds it.
cat >"$NEWER/Cargo.toml" <<EOF
[package]
name = "newer-guest"
version = "0.1.0"
edition = "2021"
rust-version = "1.999"

[dependencies]
pico-sdk = { path = "$ROOT/sdk/sdk" }
EOF

cat >"$NEWER/src/main.rs" <<'EOF'
#![no_main]

pico_sdk::entrypoint!(main);

pub fn main() {
    pico_sdk::io::commit_bytes(&[0xdd]);
}
EOF

# pico <log> <args...>: `cargo pico <args...>`, its output in $LOGS/<log>.{out,err}.
pico() {
  local log="$1"
  shift
  "$PICO_BIN" pico "$@" >"$LOGS/$log.out" 2>"$LOGS/$log.err"
}

# The hex the guest commits, as `cargo pico execute` reports it.
committed() {
  "$PICO_BIN" pico execute --elf "$1" 2>/dev/null |
    sed -n 's/^committed ([0-9]* byte(s), not proved): //p'
}

# Each check prints why it failed on stdout and returns non-zero.
expect_build() {
  local log="$1" code=0
  shift
  pico "$log" build "$@" || code=$?
  [[ $code -eq 0 ]] || {
    echo "build $* exited $code, see $LOGS/$log.err"
    return 1
  }
}

expect_commit() {
  local elf="$1" want="$2" got
  [[ -f $elf ]] || {
    echo "no ELF at $elf"
    return 1
  }
  got="$(committed "$elf")" || {
    echo "execute failed on $elf"
    return 1
  }
  [[ $got == "$want" ]] || {
    echo "$elf commits '$got', expected '$want'"
    return 1
  }
}

# Refused by `cargo pico` itself: non-zero, the message on stderr, and cargo never started.
expect_refused_before_cargo() {
  local log="$1"
  shift
  local code=0
  pico "$log" build --path "$GUEST" "$@" || code=$?
  [[ $code -ne 0 ]] || {
    echo "exited 0"
    return 1
  }
  if grep -qF "Building guest package" "$LOGS/$log.out"; then
    echo "cargo ran before the refusal"
    return 1
  fi
}

default_feature() {
  expect_build default --path "$GUEST" --bin first || return 1
  expect_build no-default --path "$GUEST" --bin first --no-default-features \
    --elf-name first-no-default || return 1
  if cmp -s "$GUEST/elf/first" "$GUEST/elf/first-no-default"; then
    echo "the two ELFs are identical"
    return 1
  fi
  expect_commit "$GUEST/elf/first" aa || return 1
  expect_commit "$GUEST/elf/first-no-default" bb
}

second_bin() {
  expect_build second --path "$GUEST" --bin second || return 1
  expect_commit "$GUEST/elf/second" cc
}

unknown_bin() {
  expect_refused_before_cargo unknown --bin nope || return 1
  grep -qF "no bin target \`nope\` in package \`flags-guest\`; its bins: first, second" \
    "$LOGS/unknown.err" || {
    echo "stderr does not name the bins: $(tail -n 1 "$LOGS/unknown.err")"
    return 1
  }
}

two_bins_unnamed() {
  expect_refused_before_cargo unnamed || return 1
  grep -qF "first, second; pass \`--bin <name>\`" "$LOGS/unnamed.err" || {
    echo "stderr does not name both bins: $(tail -n 1 "$LOGS/unnamed.err")"
    return 1
  }
}

ignore_rust_version() {
  local code=0
  pico newer-refused build --path "$NEWER" || code=$?
  [[ $code -ne 0 ]] || {
    echo "built without --ignore-rust-version"
    return 1
  }
  grep -qF "requires rustc 1.999" "$LOGS/newer-refused.err" || {
    echo "refused, but not for its rust-version: see $LOGS/newer-refused.err"
    return 1
  }
  expect_build newer --path "$NEWER" --ignore-rust-version || return 1
  expect_commit "$NEWER/elf/riscv64im-pico-zkvm-elf" dd
}

no_manifest() {
  local code=0
  (cd "$WORK/empty" && "$PICO_BIN" pico build) >"$LOGS/no-manifest.out" \
    2>"$LOGS/no-manifest.err" || code=$?
  [[ $code -eq 1 ]] || {
    echo "exited $code, expected 1"
    return 1
  }
  local lines
  lines="$(wc -l <"$LOGS/no-manifest.err" | tr -d ' ')"
  if [[ $lines -ne 1 ]] || ! grep -qF "no Cargo.toml in" "$LOGS/no-manifest.err"; then
    echo "stderr is $lines line(s), expected the one error: $(head -n 3 "$LOGS/no-manifest.err")"
    return 1
  fi
}

bare() {
  local code=0
  "$PICO_BIN" pico >"$LOGS/bare.out" 2>"$LOGS/bare.err" || code=$?
  if [[ $code -eq 101 ]] || grep -q "panicked" "$LOGS/bare.out" "$LOGS/bare.err"; then
    echo "panicked (exit $code)"
    return 1
  fi
  cat "$LOGS/bare.out" "$LOGS/bare.err" | grep -q "^Usage: cargo pico" || {
    echo "no help printed (exit $code)"
    return 1
  }
}

# The user's cargo settings must reach the nested cargo. Offline, with an empty cargo home, the build
# can only fail for being offline: had either variable been dropped, it would fetch or reuse
# ~/.cargo and succeed.
cargo_settings_offline() {
  local home="$WORK/empty-cargo-home" code=0
  mkdir -p "$home"
  CARGO_HOME="$home" CARGO_NET_OFFLINE=true pico offline build --path "$GUEST" --bin second \
    --elf-name second-offline || code=$?
  [[ $code -ne 0 ]] || {
    echo "built offline from an empty cargo home"
    return 1
  }
  grep -qi "offline" "$LOGS/offline.err" || {
    echo "failed, but not for being offline: see $LOGS/offline.err"
    return 1
  }
}

cargo_home_moved() {
  local home="$WORK/cargo-home"
  mkdir -p "$home"
  CARGO_HOME="$home" expect_build moved-home --path "$GUEST" --bin second \
    --elf-name second-moved-home || return 1
  expect_commit "$GUEST/elf/second-moved-home" cc || return 1
  [[ -n "$(ls -A "$home/registry" 2>/dev/null)" ]] || {
    echo "nothing was fetched into the moved cargo home"
    return 1
  }
}

failures=0
row() {
  local name="$1" reason
  shift
  if reason="$("$@")"; then
    echo "PASS  $name"
  else
    echo "FAIL  $name: $reason"
    failures=$((failures + 1))
  fi
}

row "with and without --no-default-features: the ELFs differ, committing aa and bb" default_feature
row "--bin second: the second bin's ELF, committing cc" second_bin
row "--bin nope: refused before cargo runs, non-zero exit" unknown_bin
row "two bins, no --bin: refused, naming both" two_bins_unnamed
row "rust-version 1.999: builds with --ignore-rust-version, refused without" ignore_rust_version
row "no Cargo.toml: a one-line error, exit 1" no_manifest
row "bare cargo pico: help, no panic" bare
row "CARGO_HOME empty and CARGO_NET_OFFLINE: refused for being offline" cargo_settings_offline
row "CARGO_HOME moved: the build fetches into it, committing cc" cargo_home_moved

if [[ $failures -ne 0 ]]; then
  echo "$failures of 9 rows failed; logs in $LOGS"
  exit 1
fi
rm -rf "$WORK"
echo "all 9 rows pass"
