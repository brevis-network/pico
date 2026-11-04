#!/usr/bin/env python3
"""Compare two runs' execution histories chunk by chunk, from the `history_digest` each replay worker
writes on its `worker.replay` stage-ledger line.

Each input is one run's stage ledger, as `MLE_LEDGER=<path>` writes it (`perf/ledger/summarise.py`
describes the format): the reference, whose replay workers are expected to be interpreters, and the
candidate, whose workers are expected to be AOT cores. The digest is on the line only when the
workers ran with `MLE_LEDGER_DIGESTS=1` set. aot_bench.sh writes one ledger per run with a prefix such as

  -e h='env MLE_LEDGER_DIGESTS=1 MLE_LEDGER={out}/{rep}-{arm}@{label}.jsonl'

Each ledger must hold one run whose envelope says it completed. The comparison passes only if the
two runs emulated the same ELF on the same input (the envelopes' digests), no chunk has more than
one replay line, every replay line carries a digest, the two runs' replay lines name the same
chunks, each chunk's digest and byte count agree, each chunk was replayed by the expected engine,
at least `--min-chunks` chunks were compared, and a candidate of AOT workers entered a compiled
block somewhere in its run. A split chunk's replay writes one line per segment and a history per
segment, which is not the chunk's, so it fails here. A chunk neither run wrote a line for is not
seen.

Prints each differing chunk, then one `HISTORY_DIGEST` line with the verdict.

Exit status: 0 the histories agree; 1 they do not, or a check above failed; 2 bad input (not one
run in a file, a run with no complete envelope, another schema version, a replay line with no
chunk).

Deliberately stdlib-only, so it runs as-is on any host a ledger comes from.
"""

from __future__ import annotations

import argparse
import json
import sys

SCHEMA_VERSION = 2


class BadInput(Exception):
    pass


def load(path: str) -> dict:
    """The run in `path`: its last envelope, and its replay lines keyed by chunk."""
    runs, envelope, replays = set(), None, {}
    with open(path, encoding="utf-8") as lines:
        for number, raw in enumerate(lines, 1):
            if not raw.strip():
                continue
            try:
                line = json.loads(raw)
            except json.JSONDecodeError:
                print(f"warning: {path}:{number} is not JSON, the torn end of a killed run",
                      file=sys.stderr)
                continue
            if line.get("v") != SCHEMA_VERSION:
                raise BadInput(f"{path}:{number}: schema version {line.get('v')!r}, "
                               f"not {SCHEMA_VERSION}")
            runs.add(line.get("run"))
            if line.get("kind") == "envelope":
                envelope = line
                continue
            if line.get("stage") != "worker.replay" or line.get("skipped"):
                continue
            chunk = line.get("chunk")
            if not isinstance(chunk, int):
                raise BadInput(f"{path}:{number}: a worker.replay line with no chunk")
            replays.setdefault(chunk, []).append(line.get("facts") or {})
    if len(runs) != 1:
        raise BadInput(f"{path}: {len(runs)} runs; give one ledger per run")
    # The opening envelope says `"complete": false`; only the driver's finish writes a complete one.
    if envelope is None or envelope.get("complete") is not True:
        raise BadInput(f"{path}: the run has no complete envelope, so it did not finish")
    return {"path": path, "envelope": envelope, "replays": replays}


def digest_of(envelope: dict, field: str):
    """The sha256 the envelope names for its `elf` or `input`; none when it names none."""
    named = envelope.get(field)
    return named.get("sha256") if isinstance(named, dict) else None


def check_run(run: dict, kind: str, problems: list[str]) -> dict:
    """Each chunk's (digest, bytes) in `run`, adding to `problems` what makes a chunk unusable."""
    side = run["path"]
    chunks = {}
    for chunk, lines in sorted(run["replays"].items()):
        if len(lines) != 1:
            problems.append(f"{side}: chunk {chunk} has {len(lines)} replay lines; "
                            f"split replay writes a history per segment")
            continue
        facts = lines[0]
        if facts.get("worker_kind") != kind:
            problems.append(f"{side}: chunk {chunk} was replayed by {facts.get('worker_kind')!r}, "
                            f"not {kind!r}")
        digest = facts.get("history_digest")
        if digest is None:
            problems.append(f"{side}: chunk {chunk} carries no history_digest; set "
                            f"MLE_LEDGER_DIGESTS=1")
            continue
        chunks[chunk] = (digest, facts.get("history_bytes"))
    return chunks


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("reference", help="the reference run's stage ledger")
    parser.add_argument("candidate", help="the candidate run's stage ledger")
    parser.add_argument("--reference-kind", default="interpreter",
                        help="the engine the reference's workers must be (default interpreter)")
    parser.add_argument("--candidate-kind", default="aot",
                        help="the engine the candidate's workers must be (default aot)")
    parser.add_argument("--min-chunks", type=int, default=2,
                        help="the fewest chunks a passing comparison compares (default 2)")
    args = parser.parse_args()

    try:
        reference, candidate = load(args.reference), load(args.candidate)
    except (BadInput, OSError) as err:
        print(f"error: {err}", file=sys.stderr)
        return 2

    problems: list[str] = []
    for field in ("elf", "input"):
        ours = digest_of(reference["envelope"], field)
        theirs = digest_of(candidate["envelope"], field)
        if ours != theirs:
            problems.append(f"the runs' {field} differs: {ours} in the reference, {theirs} in the "
                            f"candidate")
    if digest_of(reference["envelope"], "elf") is None:
        problems.append("the reference's envelope names no ELF, so nothing says what it ran")
    left = check_run(reference, args.reference_kind, problems)
    right = check_run(candidate, args.candidate_kind, problems)
    for chunk in sorted(set(left) ^ set(right)):
        problems.append(f"chunk {chunk} is in only the "
                        f"{'reference' if chunk in left else 'candidate'}")
    common = sorted(set(left) & set(right))
    differing = [chunk for chunk in common if left[chunk] != right[chunk]]
    for chunk in differing:
        print(f"DIFFERS chunk={chunk} reference={left[chunk][0]} candidate={right[chunk][0]} "
              f"reference_bytes={left[chunk][1]} candidate_bytes={right[chunk][1]}")
    if differing:
        problems.append(f"{len(differing)} chunk(s) differ")
    if len(common) < args.min_chunks:
        problems.append(f"{len(common)} chunk(s) compared, fewer than {args.min_chunks}")
    dispatches = sum(lines[0].get("dispatches") or 0
                     for lines in candidate["replays"].values() if len(lines) == 1)
    if args.candidate_kind == "aot" and dispatches == 0:
        problems.append("the candidate's AOT workers entered no compiled block, so they interpreted")

    for problem in problems:
        print(f"FAIL: {problem}")
    print(f"HISTORY_DIGEST reference={reference['path']} "
          f"reference_label={reference['envelope'].get('label')} "
          f"candidate={candidate['path']} "
          f"candidate_label={candidate['envelope'].get('label')} "
          f"chunks={len(common)} equal={len(common) - len(differing)} differing={len(differing)} "
          f"candidate_dispatches={dispatches} verdict={'FAIL' if problems else 'PASS'}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
