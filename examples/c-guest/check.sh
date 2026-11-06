#!/usr/bin/env bash
# Runs one build of the C guest through every case of main.c with the outcome each must have,
# then proves the successful case to the combine root. Needs `cargo pico` on PATH.
#
#   ./check.sh guest-lld.elf
set -euo pipefail

ELF=$1

# A successful run commits its input followed by the C++ destructor's "bye".
expect_success() {
    local out
    out=$(cargo pico execute --elf "$ELF" --input "$1" 2>&1) || {
        echo "FAIL $ELF input $1: the run failed: $out" >&2
        exit 1
    }
    grep -qF "committed (4 byte(s), not proved): $2" <<<"$out" || {
        echo "FAIL $ELF input $1: expected to commit $2: $out" >&2
        exit 1
    }
    echo "ok   $ELF input $1: committed $2"
}

expect_failure() {
    local out
    if out=$(cargo pico execute --elf "$ELF" --input "$1" 2>&1); then
        echo "FAIL $ELF input $1: the run succeeded, expected: $2" >&2
        exit 1
    fi
    grep -qF "$2" <<<"$out" || {
        echo "FAIL $ELF input $1: expected '$2': $out" >&2
        exit 1
    }
    echo "ok   $ELF input $1: $2"
}

expect_success 0x00 00627965
expect_failure 0x01 "the guest exited with a non-zero code (exit code 1)"
expect_failure 0x02 "the guest exited with a non-zero code (exit code 256)"
expect_failure 0x03 "the guest aborted (exit code 134)"
expect_failure 0x04 "the guest aborted (exit code 134)"

out=$(cargo pico prove --elf "$ELF" --input 0x00 --phase combine --output "$(mktemp -d)" 2>&1) || {
    echo "FAIL $ELF: prove: $out" >&2
    exit 1
}
grep -qF "committed (4 byte(s)): 00627965" <<<"$out" || {
    echo "FAIL $ELF: the proof does not commit 00627965: $out" >&2
    exit 1
}
echo "ok   $ELF: proved and verified to combine"
