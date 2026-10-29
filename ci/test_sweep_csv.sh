#!/usr/bin/env bash
# Tests for bench-scripts/sweep-csv.py. No GPU, no build.
#
# The fixture's log lines are copied from the format strings in `distributed-vm/src/mle/mod.rs`,
# not from memory of a run, so a change to the headline breaks these tests rather than silently
# producing empty columns.
#
# What is worth testing here is entirely about NOT reading the wrong block: every extractor in the
# script is a last-match or a count, and run over an unsliced log every one of them returns the
# last block's numbers under the first block's name. The numbers look plausible either way.
#
#   ./ci/test_sweep_csv.sh
set -uo pipefail
cd "$(dirname "$0")/.."

PASS=0
FAIL=0
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

eq() { # description actual expected  -- exact match, and an empty actual is a failure
    if [ -n "$2" ] && [ "$2" = "$3" ]; then
        PASS=$((PASS + 1)); printf 'ok   %s\n' "$1"
    else
        FAIL=$((FAIL + 1)); printf 'FAIL %s\n     want: %s\n     got:  %s\n' "$1" "$3" "${2:-<empty>}"
    fi
}

field() { printf '%s' "$1" | awk -F, -v n="$2" '{print $n}'; }

# Look a column up by NAME rather than position. Positional indices have broken these tests twice
# now -- once passing vacuously against a column that did not exist, once silently shifting when a
# column was inserted ahead of them.
col() { # file header-name [row]
    awk -F, -v want="$2" -v row="${3:-2}" '
        NR==1 { for (i = 1; i <= NF; i++) if ($i == want) c = i; next }
        NR==row { print (c ? $c : "") }' "$1"
}

check() { # description expected actual
    if [[ "$3" == *"$2"* ]]; then
        PASS=$((PASS + 1)); printf 'ok   %s\n' "$1"
    else
        FAIL=$((FAIL + 1)); printf 'FAIL %s\n     want: %s\n     got:  %s\n' "$1" "$2" "$3"
    fi
}

# Two blocks of very different size in one resident process -- the shape the sweep produces, and
# the shape that breaks a naive reader. Setup lines appear ONCE, before the first delimiter.
cat > "$WORK/run.log" << 'LOG'
INFO MLE prover lanes: 2 per card (4 card(s))
INFO MLE riscv preparers: 6 (4 card(s))
INFO MLE convert preparers: 12 (4 card(s))
INFO MLE combine preparers: 7 (4 card(s))
INFO MLE event pools pre-sized to 64 buffers in 46.029s
INFO packed event pools initialized: 16 x (cpu 8388608 + mem 8388608)
INFO MLE program compile done in 0.036s
INFO MLE keygen done in 22.082s (4 card(s))
INFO MLE convert warmup keygen done in 6.311s (4 card(s))
INFO MLE prewarm done in 1.204s
INFO MLE block: 1/2 block=18884864 starting
INFO cross-chunk global cumulative sum == 0 ✓
INFO [primary-mle-prover-0] combine [0,1]: OK (is_final=false)
INFO [bench] MLE combine shapes: block keygens=5 hits=0 evictions=0
INFO MLE bench: chunks=6 prover_count=4 lanes=2 | sum(prove)=2.957s avg/chunk=0.493s | prove(wall)=4.781s | keygen=22.082s | emulate=1.346s cycles=24512003 prepare=1.402s | e2e=4.785s | root-accept=0.310s | total=95.100s
INFO MLE block: 1/2 block=18884864 done
INFO MLE block: 2/2 block=24000020 starting
INFO cross-chunk global cumulative sum == 0 ✓
INFO [primary-mle-prover-1] combine [0,1]: OK (is_final=false)
INFO [primary-mle-prover-2] combine [2,3]: OK (is_final=false)
INFO [bench] MLE combine shapes: block keygens=21 hits=4 evictions=0
INFO MLE bench: chunks=26 prover_count=4 lanes=2 | sum(prove)=16.003s avg/chunk=0.615s | prove(wall)=7.865s | keygen=22.082s | emulate=2.857s cycles=108773449 prepare=2.901s | e2e=7.868s | root-accept=0.402s | total=103.900s
INFO MLE block: 2/2 block=24000020 done
LOG

printf 'epoch,block,input\n1,18884864,reth-18884864.bin\n2,24000020,reth-24000020.bin\n' > "$WORK/manifest.csv"

out=$(python3 bench-scripts/sweep-csv.py "$WORK/run.log" "$WORK/out" --manifest "$WORK/manifest.csv" 2>&1)
check "processes both blocks" "2 block(s)" "$out"

sum="$WORK/out/summary.csv"
row1=$(awk -F, 'NR==2' "$sum")
row2=$(awk -F, 'NR==3' "$sum")

# --- the per-block figures must be THIS block's, not the last block's ------------------------
check "block 1 keeps its own chunks"   ",18884864," "$row1"
eq "block 1 chunks are its own"   "$(col "$sum" chunks 2)"  "6"
eq "block 2 chunks are its own"   "$(col "$sum" chunks 3)"  "26"
eq "block 1 e2e is its own"       "$(col "$sum" e2e 2)"  "4.785"
eq "block 2 e2e is its own"       "$(col "$sum" e2e 3)"  "7.868"
eq "block 1 cycles are its own"   "$(col "$sum" cycles 2)"  "24512003"
eq "block 2 cycles are its own"   "$(col "$sum" cycles 3)"  "108773449"
eq "block 1 sum_prove is its own" "$(col "$sum" sum_prove 2)" "2.957"
eq "block 2 sum_prove is its own" "$(col "$sum" sum_prove 3)" "16.003"

# --- shape statistics are per-block deltas, and the cross-block hit survives -----------------
eq "block 1 shape keygens" "$(col "$sum" shape_keygens 2)" "5"
eq "block 1 shape hits"    "$(col "$sum" shape_hits 2)" "0"
eq "block 2 shape keygens" "$(col "$sum" shape_keygens 3)" "21"
eq "block 2 records the cross-block hits" "$(col "$sum" shape_hits 3)" "4"

# --- correctness counters are per block, not run totals --------------------------------------
eq "block 1 gcs closed once"    "$(col "$sum" gcs_ok 2)" "1"
eq "block 2 gcs closed once"    "$(col "$sum" gcs_ok 3)" "1"
eq "block 1 counts its combines" "$(col "$sum" combine_ok 2)" "1"
eq "block 2 counts its combines" "$(col "$sum" combine_ok 3)" "2"

# --- the first block is marked, and inputs are joined ----------------------------------------
eq "first block marked as warmup"     "$(col "$sum" warmup 2)" "1"
eq "later block not marked as warmup" "$(col "$sum" warmup 3)" "0"
check "input file joined from manifest"  "reth-18884864.bin" "$row1"

# --- setup figures appear once, and process-wide ones stay out of the per-block table ---------
setup="$WORK/out/setup.csv"
check "setup keygen recorded once"     "22.082" "$(cat "$setup")"
check "setup program compile recorded" "0.036"  "$(cat "$setup")"
check "setup records the card count"   "4"      "$(cat "$setup")"
check "setup records the lane count"   "2"      "$(cat "$setup")"
eq "setup_total is derived from block 1, not the last block" \
   "$(col "$setup" setup_total_s)" "90.005"
check "summary.csv has no run_total column" "" "$(head -1 "$sum" | grep -o 'run_total' || true)"
check "summary.csv has no total column" "" "$(head -1 "$sum" | grep -o ',total,' || true)"
check "summary.csv has no keygen column" "" "$(head -1 "$sum" | grep -o ',keygen,' || true)"

# --- a crashed block is reported, not dropped -------------------------------------------------
sed '$ d' "$WORK/run.log" > "$WORK/crash.log"   # drop the final 'done' (portable; head -n -1 is GNU-only)
python3 bench-scripts/sweep-csv.py "$WORK/crash.log" "$WORK/out2" > /dev/null 2>&1
check "an unfinished block still gets a row" "24000020" "$(awk 'NR==3' "$WORK/out2/summary.csv")"
eq "an unfinished block is marked rc=1"   "$(awk -F, 'NR==3{print $5}' "$WORK/out2/summary.csv")" "1"

# --- a log from before `cycles=` existed still parses ------------------------------------------
# The headline regex matches the whole line, so a field added to the middle of it would otherwise
# turn every older run log into a table of empty columns -- which reads as a failed run, not as a
# missing field. Only the new field is allowed to come back empty.
sed 's/ cycles=[0-9]*//' "$WORK/run.log" > "$WORK/nocycles.log"
python3 bench-scripts/sweep-csv.py "$WORK/nocycles.log" "$WORK/out3" > /dev/null 2>&1
eq "a pre-cycles log still yields e2e"    "$(col "$WORK/out3/summary.csv" e2e 2)" "4.785"
# Two assertions, because `col` returns empty for a missing COLUMN and for an empty CELL alike:
# the header check is what makes the second one mean "the cell is empty" rather than "the column
# is gone". `eq` counts an empty actual as a failure, hence the sentinel.
check "a pre-cycles log still has a cycles column" "cycles" "$(head -1 "$WORK/out3/summary.csv")"
eq "a pre-cycles log leaves the cycles cell empty" \
   "$(col "$WORK/out3/summary.csv" cycles 2 | sed 's/^$/<none>/')" "<none>"

# --- the fixture has to stay the prover's headline ----------------------------------------------
# Everything above reads a hand-typed heredoc, so this suite is green by construction when the
# format string the heredoc was copied from changes -- which is the one drift that empties these
# columns on a real run. Compare the field names, in order, against the prover's own line.
names() { printf '%s' "$1" | grep -oE '[a-z_()/-]+=' | tr '\n' ' '; }
prover=$(names "$(grep -o 'MLE bench: chunks=.*' distributed-vm/src/mle/mod.rs | head -1)")
i=0
while IFS= read -r ln; do
    i=$((i + 1))
    eq "fixture headline $i carries the prover's fields, in order" "$(names "$ln")" "$prover"
done < <(grep -o 'MLE bench: chunks=.*' "$WORK/run.log")

# --- the two columns another script reads by position -------------------------------------------
# `sweep_reth_mle.sh`'s SWEEP_RESUME does `awk -F, '$5 == 0 {print $2}'`, so these two are a
# contract with it rather than a layout choice: a column added ahead of either one silently
# resumes the wrong blocks.
eq "block is still column 2, where the resume path reads it" \
   "$(head -1 "$sum" | awk -F, '{print $2}')" "block"
eq "rc is still column 5, where the resume path reads it" \
   "$(head -1 "$sum" | awk -F, '{print $5}')" "rc"

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
