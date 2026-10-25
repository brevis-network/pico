#!/usr/bin/env bash
# Tests for sweep_reth_mle.sh's discovery, alias dedup, card selection and format gate.
# Runs anywhere -- no GPU, no build.
#
# Worth testing rather than eyeballing, because every one of these failures is SILENT:
#
#   - an alias collision produces two rows for one input, which then disagree on timing and read
#     as variance rather than as the same block measured twice;
#   - a wrong four-card group still runs, just across the interconnect, moving the figures the
#     sweep exists to produce;
#   - a stale-generation input halts the guest in under a second and, via the panic hook, takes
#     the whole resident process down -- discarding the setup the sweep is built to amortise.
#
#   ./ci/test_sweep_launcher.sh
set -uo pipefail
cd "$(dirname "$0")/.."

PASS=0
FAIL=0

STUB_DIR="$(mktemp -d)"
WORK="$(mktemp -d)"
trap 'rm -rf "$STUB_DIR" "$WORK"' EXIT

# Stub nvidia-smi so card occupancy is an input rather than whatever the host happens to have.
# BUSY_CARDS reports 8 GiB used; PROC_CARDS reports a compute process with no memory to speak of.
#
# ⚠️ The two queries must answer differently. Real nvidia-smi prints NOTHING for
# --query-compute-apps on an idle card, and the gate reads a `0` as one process — so a stub that
# echoes 0 for every query makes every card look busy. That is not hypothetical: this stub did, and
# it turned three passing gate tests red the moment the process check was added.
cat > "$STUB_DIR/nvidia-smi" << 'STUB'
#!/usr/bin/env bash
idx=""; query=""
for a in "$@"; do
    case "$a" in --query-gpu=*) query=gpu ;; --query-compute-apps=*) query=apps ;; esac
    case "$prev" in -i) idx="$a";; esac; prev="$a"
done
if [ "$query" = apps ]; then
    for b in ${PROC_CARDS:-}; do [ "$b" = "$idx" ] && { echo 4242; exit 0; }; done
    exit 0                    # idle: no output, not a zero
fi
for b in ${BUSY_CARDS:-}; do [ "$b" = "$idx" ] && { echo 8192; exit 0; }; done
echo 0
STUB
chmod +x "$STUB_DIR/nvidia-smi"

mkinputs() { # dir file...
    local d="$WORK/$1"; shift
    rm -rf "$d"; mkdir -p "$d"
    for f in "$@"; do touch "$d/$f"; done
    echo "$d"
}

sweep() { # cards dir [env assignments handled by caller]
    PATH="$STUB_DIR:$PATH" SWEEP_DRY_RUN=1 ./sweep_reth_mle.sh "$@" 2>&1
}

check() { # description expected_substring actual
    if [[ "$3" == *"$2"* ]]; then
        PASS=$((PASS + 1)); printf 'ok   %s\n' "$1"
    else
        FAIL=$((FAIL + 1)); printf 'FAIL %s\n     want: %s\n     got:  %s\n' "$1" "$2" "$3"
    fi
}

# `check` matches a SUBSTRING, so `check "..." "" "$out"` asserts nothing at all: every string
# contains the empty string. These two are for the cases where the expected answer IS emptiness or
# an exact row, and a mutation review found four assertions that were silently vacuous without them.
check_empty() { # description actual
    if [ -z "$2" ]; then
        PASS=$((PASS + 1)); printf 'ok   %s\n' "$1"
    else
        FAIL=$((FAIL + 1)); printf 'FAIL %s\n     want: (empty)\n     got:  %s\n' "$1" "$2"
    fi
}

check_eq() { # description expected actual
    if [ "$2" = "$3" ]; then
        PASS=$((PASS + 1)); printf 'ok   %s\n' "$1"
    else
        FAIL=$((FAIL + 1)); printf 'FAIL %s\n     want: %s\n     got:  %s\n' "$1" "$2" "$3"
    fi
}

# --- discovery -------------------------------------------------------------------------------
d=$(mkinputs disco reth-24006677.bin 24006790.bin junk.bin reth-abc.bin)
out=$(SWEEP_SKIP_MANIFEST=1 CUDA_VISIBLE_DEVICES=0,1,2,3 sweep 4 "$d")
check "accepts both filename conventions" "blocks=24006677,24006790" "$out"
check "skips non-numeric names"           "skipped= junk.bin reth-abc.bin" "$out"
check "counts the blocks it found"        "n=2" "$out"

d=$(mkinputs empty)
out=$(SWEEP_SKIP_MANIFEST=1 sweep 4 "$d")
check "refuses an empty directory" "no usable *.bin inputs" "$out"

out=$(SWEEP_SKIP_MANIFEST=1 sweep 4 "$WORK/does-not-exist")
check "refuses a missing directory" "input dir not found" "$out"

# --- alias expansion and dedup ---------------------------------------------------------------
# The five aliases in load_reth_input: 171/188/239/240/246 name real blocks.
d=$(mkinputs alias 240.bin)
out=$(SWEEP_SKIP_MANIFEST=1 CUDA_VISIBLE_DEVICES=0,1,2,3 sweep 4 "$d")
check "expands an alias to its real block" "blocks=24000020" "$out"

d=$(mkinputs collide 240.bin reth-24000020.bin)
out=$(SWEEP_SKIP_MANIFEST=1 CUDA_VISIBLE_DEVICES=0,1,2,3 sweep 4 "$d")
check "refuses an alias collision"      "two files resolve to block 24000020" "$out"
check "names both colliding files"      "reth-24000020.bin" "$out"

d=$(mkinputs allalias 171.bin 188.bin 239.bin 246.bin)
out=$(SWEEP_SKIP_MANIFEST=1 CUDA_VISIBLE_DEVICES=0,1,2,3 sweep 4 "$d")
check "expands every alias in the table" "blocks=17106222,18884864,23993050,24600825" "$out"

# --- card count parsing and refusals ---------------------------------------------------------
d=$(mkinputs cards reth-24006677.bin)
for n in 2 3 6 7 0 -1 abc; do
    out=$(SWEEP_SKIP_MANIFEST=1 sweep "$n" "$d")
    check "refuses cards=$n" "cards must be 1, 4 or 8" "$out"
done
for n in 1 4 8; do
    out=$(SWEEP_SKIP_MANIFEST=1 CUDA_VISIBLE_DEVICES=0 sweep "$n" "$d")
    check "accepts cards=$n" "cards=$n" "$out"
done

# --- card group selection --------------------------------------------------------------------
# Four cards must be {4,5,6,7} or {0,1,2,3} and nothing else: any other four span the interconnect.
out=$(SWEEP_SKIP_MANIFEST=1 CUDA_VISIBLE_DEVICES= BUSY_CARDS="" sweep 4 "$d")
check "four cards prefers the high group" "devices=4,5,6,7" "$out"

out=$(SWEEP_SKIP_MANIFEST=1 CUDA_VISIBLE_DEVICES= BUSY_CARDS="5" sweep 4 "$d")
check "falls back to the low group when the high one is busy" "devices=0,1,2,3" "$out"

out=$(SWEEP_SKIP_MANIFEST=1 CUDA_VISIBLE_DEVICES= BUSY_CARDS="1 5" sweep 4 "$d")
check "refuses when neither group is free" "no free group of 4 cards" "$out"

out=$(SWEEP_SKIP_MANIFEST=1 CUDA_VISIBLE_DEVICES=2,3,4,5 sweep 4 "$d")
check "an explicit CUDA_VISIBLE_DEVICES wins" "devices=2,3,4,5" "$out"

out=$(SWEEP_SKIP_MANIFEST=1 CUDA_VISIBLE_DEVICES= BUSY_CARDS="" sweep 8 "$d")
check "eight cards takes all of them" "devices=0,1,2,3,4,5,6,7" "$out"

# --- format gate -----------------------------------------------------------------------------
# Keyed on sha256 + the elf hash it was validated against, because "current format" is a property
# of a (file, guest) pair, not of a file.
d=$(mkinputs gate reth-24006677.bin)
elf_sha=$( { sha256sum perf/bench_data/rv64/reth-elf 2>/dev/null || shasum -a 256 perf/bench_data/rv64/reth-elf 2>/dev/null; } | cut -c1-12)

out=$(CUDA_VISIBLE_DEVICES=0,1,2,3 sweep 4 "$d")
check "refuses to start with no manifest" "no manifest at" "$out"

# Rows are: <sha256-of-input>  <elf_sha12>  <filename>
printf 'aaaa deadbeef1234 reth-24006677.bin\n' > "$d/inputs.manifest"
out=$(CUDA_VISIBLE_DEVICES=0,1,2,3 sweep 4 "$d")
check "rejects a row whose elf hash does not match" "elf:deadbeef1234" "$out"

if [ -n "$elf_sha" ]; then
    printf 'aaaa %s reth-24006677.bin\n' "$elf_sha" > "$d/inputs.manifest"
    out=$(CUDA_VISIBLE_DEVICES=0,1,2,3 sweep 4 "$d")
    check "accepts a row matching the current elf" "blocks=24006677" "$out"

    # sha256 is checked against content, so a file whose bytes changed is rejected even though its
    # name and elf hash still line up -- the case mtime-keyed checks miss.
    printf 'not-the-real-sha %s reth-24006677.bin\n' "$elf_sha" > "$d/inputs.manifest"
    echo "changed" > "$d/reth-24006677.bin"
    out=$(CUDA_VISIBLE_DEVICES=0,1,2,3 sweep 4 "$d")
    check "rejects a row whose sha256 does not match the bytes" "sha:not-the-" "$out"
    : > "$d/reth-24006677.bin"

    printf 'aaaa %s reth-24006677.bin\n' "$elf_sha" > "$d/inputs.manifest"
    touch "$d/reth-24006790.bin"
    out=$(CUDA_VISIBLE_DEVICES=0,1,2,3 sweep 4 "$d")
    check "rejects an input absent from the manifest" "reth-24006790.bin(absent)" "$out"
fi

# --- resume ----------------------------------------------------------------------------------
# Keys on rc=0 in a previous summary.csv: a finished block is skipped, a block that started and
# crashed is retried. Resume-by-restart because a bad input takes the whole process down.
d=$(mkinputs resume reth-24006677.bin reth-24006790.bin reth-24006610.bin)
prev="$WORK/prevrun"; mkdir -p "$prev"
{
  echo "epoch,block,input,warmup,rc,chunks"
  echo "1,24006610,reth-24006610.bin,1,0,100"   # finished -> skip
  echo "2,24006677,reth-24006677.bin,0,1,0"     # crashed  -> retry
} > "$prev/summary.csv"

out=$(SWEEP_SKIP_MANIFEST=1 CUDA_VISIBLE_DEVICES=0,1,2,3 SWEEP_RESUME="$prev" sweep 4 "$d")
check "resume skips a block that finished"      "skipping 24006610" "$out"
check "resume retries a block that crashed"     "24006677" "$(printf '%s' "$out" | grep -o 'blocks=[0-9,]*')"
check "resume keeps a block never attempted"    "24006790" "$(printf '%s' "$out" | grep -o 'blocks=[0-9,]*')"

{
  echo "epoch,block,input,warmup,rc,chunks"
  echo "1,24006610,x,1,0,1"
  echo "2,24006677,x,0,0,1"
  echo "3,24006790,x,0,0,1"
} > "$prev/summary.csv"
out=$(SWEEP_SKIP_MANIFEST=1 CUDA_VISIBLE_DEVICES=0,1,2,3 SWEEP_RESUME="$prev" sweep 4 "$d")
check "resume stops when everything is done" "nothing to do" "$out"

out=$(SWEEP_SKIP_MANIFEST=1 CUDA_VISIBLE_DEVICES=0,1,2,3 SWEEP_RESUME="$WORK/nope" sweep 4 "$d")
check "resume refuses a directory with no summary.csv" "no summary.csv to resume from" "$out"

# --- steady_sampler: the census parsing path ----------------------------------------------------
# Untested until now, and every case above is blind to it: they all run with SWEEP_DRY_RUN=1, which
# exits before the sampler exists. What breaks here breaks silently -- a `sed` that does not match
# prints the whole log line into a CSV cell, a bare-word array subscript evaluates to 0 and
# overwrites card 0 with another card's figures, and a card the census skipped inherits the previous
# block's number.
#
# The function is extracted and eval'd, which is how the sweep itself hands it to its child
# (`declare -f steady_sampler`) -- so this also fails if it stops being self-contained.
sampler_body="$(awk '/^steady_sampler\(\) \{/,/^\}/' sweep_reth_mle.sh)"
[ -n "$sampler_body" ] || { echo "FAIL could not extract steady_sampler"; FAIL=$((FAIL + 1)); }

run_sampler() { # devices want_rows  (run.log content on stdin) -> steady.csv on stdout
    local devices="$1" want="$2" dir pid i n
    dir="$WORK/s$RANDOM$RANDOM"
    mkdir -p "$dir"
    cat > "$dir/run.log"
    # stdout and stderr redirected AWAY from the caller's command substitution. Without this the
    # `$(...)` around `run_sampler` waits for every writer of its pipe to close, and the `tail -F`
    # this leaves behind holds that descriptor -- so the test hangs instead of failing.
    ( cd "$dir" && eval "$sampler_body" && OUTDIR="$dir" DEVICES="$devices" steady_sampler ) \
        > /dev/null 2>&1 &
    pid=$!
    # Disowned so the shell does not print `Terminated: 15` for it when the kill below lands. That
    # notice comes from job control, not from the killed process, so redirecting the kill cannot
    # silence it.
    disown "$pid" 2> /dev/null || true
    # Bounded poll, not `sleep N`: `timeout` is not portable and a fixed sleep is either flaky or
    # slow. Header plus the wanted rows is the finish line.
    for i in $(seq 1 80); do
        # `{ ...; } 2>/dev/null`: a failed REDIRECTION is reported by the shell, not by `wc`, so
        # the redirect has to be inside the silenced group or the poll prints an error per turn.
        n=$({ wc -l < "$dir/steady.csv"; } 2> /dev/null || echo 0)
        [ "${n:-0}" -ge "$((want + 1))" ] && break
        sleep 0.1
    done
    kill "$pid" 2> /dev/null
    # The `tail -F` is a child of that subshell and outlives the kill -- the same descriptor leak the
    # sweep documents at its own teardown. `pkill` never matches its own pid, and the pattern carries
    # this test's unique directory, so it cannot reach another test's sampler.
    # Matched on this test's unique directory alone. `pkill -f` takes an ERE, so a pattern
    # carrying the literal `+` of `-n +1` never matches -- which is how five consecutive runs left
    # twenty `tail` processes polling directories the EXIT trap had already deleted.
    pkill -f "$dir/run.log" 2> /dev/null
    cat "$dir/steady.csv" 2> /dev/null
}

CEN='INFO vram_census: phase=post epoch=1 block=24004465 card=%s tracked_live_mib=1.00 tracked_peak_mib=2.00 pool_used_mib=3.00 pool_used_high_mib=%s pool_reserved_mib=5.00 pool_reserved_high_mib=6.00 dev_used_mib=%s out_of_pool_mib=%s ext_pool=1 bufcache_mib=7.00 air_entries=21 jit_modules=14 jit_kernels=310 streams_created=8 streams_recycled=328 pk_convert=1/8 pk_combine=3/8 comb_keygens=3 comb_evictions=0\n'

out=$({
    printf "$CEN" 0 1111.00 27412.50 2743.25
    printf "$CEN" 1 2222.00 27000.00 2000.00
    echo "INFO MLE block: 1/2 block=24004465 done"
} | run_sampler 4,5 1)
check "sampler writes three census columns per card" "27412.50,2743.25,1111.00,27000.00,2000.00,2222.00" "$out"
check "sampler header names the phase and the physical card" "dev_used_post_card0_phys4_mib" "$out"
check "sampler header carries the peak column" "pool_used_high_post_card1_phys5_mib" "$out"

# A card the census skipped must leave an EMPTY cell, not the previous block's number.
out=$({
    printf "$CEN" 0 1111.00 27412.50 2743.25
    printf "$CEN" 1 2222.00 27000.00 2000.00
    echo "INFO MLE block: 1/2 block=24004465 done"
    printf "$CEN" 0 3333.00 28000.00 3000.00
    echo "INFO vram_census_note: phase=post epoch=2 block=24004505 card=1 skipped=set_device"
    echo "INFO MLE block: 2/2 block=24004505 done"
} | run_sampler 4,5 2)
check "a skipped card records an empty cell, not a stale one" "28000.00,3000.00,3333.00,,," "$(printf '%s' "$out" | tail -1)"

# A census line the patterns cannot read must yield empty cells -- never the log line itself.
out=$({
    echo "INFO vram_census: phase=post epoch=1 block=24004465 card=0 dev_used_mib=oops out_of_pool_mib=nope"
    echo "INFO MLE block: 1/1 block=24004465 done"
} | run_sampler 4 1)
check_eq "an unreadable census line leaves empty cells, not the line" "1,24004465,,,,," "$(printf '%s' "$out" | tail -1)"

# A non-numeric card must not become subscript 0 and overwrite card 0.
out=$({
    printf "$CEN" 0 1111.00 27412.50 2743.25
    echo "INFO vram_census: phase=post epoch=1 block=24004465 card=abc dev_used_mib=9.99 out_of_pool_mib=9.99 pool_used_high_mib=9.99"
    echo "INFO MLE block: 1/1 block=24004465 done"
} | run_sampler 4 1)
check "a non-numeric card does not overwrite card 0" "27412.50,2743.25,1111.00" "$(printf '%s' "$out" | tail -1)"

# --- warn_if_census_empty ----------------------------------------------------------------------
warn_body="$(awk '/^warn_if_census_empty\(\) \{/,/^\}/' sweep_reth_mle.sh)"
warn_on() { # csv-body  -> stderr
    local dir="$WORK/w$RANDOM$RANDOM"
    mkdir -p "$dir"
    cat > "$dir/steady.csv"
    ( eval "$warn_body" && OUTDIR="$dir" MLE_VRAM_CENSUS="${1:-1}" warn_if_census_empty ) 2>&1
}
out=$(printf 'epoch,block,rss_gb,fds,a,b,c\n1,24004465,,,,,\n2,24004505,,,,,\n' | warn_on 1)
check "an all-empty census column is said out loud" "never reached the log" "$out"
out=$(printf 'epoch,block,rss_gb,fds,a,b,c\n1,24004465,,,27412.50,2743.25,1111.00\n' | warn_on 1)
check_empty "a populated census column is silent" "$out"
# One populated cell is enough. Without this row the awk's starting field could move by one and
# nothing would notice.
out=$(printf 'epoch,block,rss_gb,fds,a,b,c\n1,24004465,,,27412.50,,\n' | warn_on 1)
check_empty "a single populated census cell is enough to stay silent" "$out"
out=$(printf 'epoch,block,rss_gb,fds,a,b,c\n1,24004465,,,,,\n' | warn_on 0)
check_empty "census switched off on purpose is not blamed on RUST_LOG" "$out"
out=$(printf 'epoch,block,rss_gb,fds,a,b,c\n' | warn_on 1)
check_empty "a header-only csv does not fire the warning" "$out"

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
