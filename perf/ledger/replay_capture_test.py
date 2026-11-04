#!/usr/bin/env python3
"""Tests of `replay_capture.py` on fixture ledgers.

Stdlib only: `python3 -I perf/ledger/replay_capture_test.py`.
"""

import contextlib
import importlib.util
import io
import json
import os
import tempfile
import unittest

_spec = importlib.util.spec_from_file_location(
    "replay_capture", os.path.join(os.path.dirname(os.path.abspath(__file__)), "replay_capture.py"))
rc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rc)

CALIBRATION = {
    "clock": "Instant (CLOCK_MONOTONIC)",
    "pairs": 4096,
    "timer.precompile_event_path.empty_pair_ns": 50,
    "timer.precompile_event_path.enclosed_pair_ns": 60.0,
    "timer.precompile_compute.empty_pair_ns": 30,
    "timer.precompile_compute.enclosed_pair_ns": 40.0,
    "timer.drain_cpu_window.empty_pair_ns": 20,
    "timer.drain_cpu_window.enclosed_pair_ns": 40.0,
    "timer.deferred_extend.empty_pair_ns": 100,
    "timer.deferred_extend.enclosed_pair_ns": 120.0,
    "timer.deferred_memory_extend.empty_pair_ns": 1000,
    "timer.deferred_memory_extend.enclosed_pair_ns": 1100.0,
    "timer.split_last.empty_pair_ns": 1000,
    "timer.split_last.enclosed_pair_ns": 1000.0,
}
ANCHORS = {4: 212.9, 5: 146.6, 6: 115.0, 7: 89.3, 8: 73.3}
NO_GROWTH = ",".join(f"t{i}:0" for i in range(16)) + ",cpu_pool:0,alu_pool:0"
GROWTH = "t0:3," + ",".join(f"t{i}:0" for i in range(1, 16)) + ",cpu_pool:0,alu_pool:0"


def envelope(run, label, rep, arm="pipeline-aot-pooled", worker_kind="interpreter", warmup=False,
             cpus="62-123", mems="0-1", mempolicy=None, lock=True, timers=False, elf="e1"):
    return {
        "v": 2, "kind": "envelope", "run": run, "complete": True, "arm": arm, "label": label,
        "rep": rep, "warmup": warmup, "snapshot_main": "aot", "worker_kind": worker_kind,
        "cpus_allowed_list": cpus, "mems_allowed_list": mems,
        "mempolicy": {"bind:1": 450} if mempolicy is None else mempolicy, "lock_held": lock,
        "knobs": {"MLE_LEDGER_PRECOMPILE_TIMERS": "1" if timers else None},
        "timer_calibration": CALIBRATION if timers else None,
        "elf": {"path": "reth-elf", "sha256": elf}, "input": {"path": "in", "sha256": "i1"},
    }


def stage(run, name, chunk, dur_us, lane="emulate", **facts):
    return {"v": 2, "run": run, "stage": name, "chunk": chunk, "lane": {"role": lane, "idx": 0},
            "t0_us": 0, "t1_us": dur_us, "dur_us": dur_us, "facts": facts}


def snapshot_line(run, chunk, extra_us=0, **facts):
    """Chunks 4-8 at their anchors, the rest at 70 ms."""
    dur = int(ANCHORS.get(chunk, 70.0) * 1000) + extra_us
    return stage(run, "snapshot.emulate", chunk, dur, lane="snapshot", dispatches_delta=5,
                 cycles_delta=1000, **facts)


def replay_run(run, label, rep, replay_ms, sink="legacy", chunks=range(0, 39), **env):
    lines = [envelope(run, label, rep, **env)]
    for chunk in chunks:
        lines.append(snapshot_line(run, chunk))
        bytes_fact = {"history_bytes": 10} if sink == "history" else {"record_bytes": 10}
        lines.append(stage(run, "worker.replay", chunk, int(replay_ms * 1000), sink=sink,
                           dispatches=3, **bytes_fact))
    return lines


def bench_line(label, rep, arm="pipeline-aot-pooled", **over):
    fields = {"arm": arm, "alloc": "tcmalloc", "mem": "mmap", "bigint": "rug", "storage": "pooled",
              "aot_dispatches": "9", "realloc": NO_GROWTH, "minor_faults": "7",
              "major_faults": "0", "label": label, "rep": rep, "exit": "0", "lock_held": "true",
              "lock_before": "USING:+someone+t0", "lock_after": "USING:+someone+t0"}
    fields.update({k: str(v) for k, v in over.items()})
    return "AOT_BENCH " + " ".join(f"{k}={v}" for k, v in fields.items())


def pricing_run(run, rep, keccak_worker=100, keccak_snapshot=100, sink="legacy", anchor_extra=0,
                chunks=range(0, 39), drain_calls=1000, drain_words=1000):
    """A pricing run whose facts give X = 278 us and assembly = 199 us (see test_x).

    `drain_calls` None leaves the key out, as a ledger from before the drain counted calls does.
    """
    lines = [envelope(run, "p@price", rep, arm="pipeline-aot-workers-pooled", worker_kind="aot",
                      timers=True)]
    for chunk in chunks:
        facts = {}
        extra = anchor_extra if chunk == 6 else 0
        if chunk == 4 and keccak_snapshot:
            facts = {"role": "snapshot", "precompile.keccak_permute.count": keccak_snapshot,
                     "precompile.keccak_permute.compute_us": 600.0}
            # The compute timers' enclosed cost, 100 x 40 ns, sits in snapshot.emulate.
            extra += 4
        lines.append(snapshot_line(run, chunk, extra, **facts))
        worker = {"sink": sink, "dispatches": 3, "record_bytes": 10, "history_bytes": 10}
        if chunk == 4:
            worker |= {"role": "worker", "drain.cpu_window_us": 100.0, "drain.words": drain_words}
            if drain_calls is not None:
                worker["drain.calls"] = drain_calls
            if keccak_worker:
                worker |= {"precompile.keccak_permute.count": keccak_worker,
                           "precompile.keccak_permute.event_path_us": 1000.0}
        if chunk == 5:
            worker |= {"deferred.extend_us": 200.0, "deferred.extends": 10,
                       "deferred.memory_extend_us": 50.0, "deferred.memory_extends": 1,
                       "faults.minor": 3,
                       "pool.blocked_gets": 2, "pool.blocked_us": 9.0}
        lines.append(stage(run, "worker.replay", chunk, 500_000, **worker))
    lines.append(stage(run, "sequencer.finalize", 38, 9_000, lane="sequencer",
                       **{"split.last.extract_us": 3.0, "split.last.sort_us": 4.0,
                          "split.last.records_us": 5.0, "split.last.memory_us": 6.0,
                          "split.last.wall_us": 9.0, "split.last.splits": 1}))
    return lines


def pricing_bench(rep):
    return bench_line("p@price", rep, arm="pipeline-aot-workers-pooled")


class Summarise(unittest.TestCase):
    def run_on(self, ledger_lines, bench_lines=(), *extra, more_bench=None):
        with tempfile.TemporaryDirectory() as tmp:
            ledger = os.path.join(tmp, "l.jsonl")
            with open(ledger, "w") as fh:
                fh.writelines(json.dumps(line) + "\n" for line in ledger_lines)
            argv = [ledger]
            for n, lines in enumerate([bench_lines] + ([more_bench] if more_bench else [])):
                path = os.path.join(tmp, f"results{n}.txt")
                with open(path, "w") as fh:
                    fh.writelines(line + "\n" for line in lines)
                argv += ["--bench", path]
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = rc.main(argv + list(extra))
        return code, out.getvalue() + err.getvalue()

    def line(self, text, prefix, *must):
        found = [l for l in text.splitlines() if l.startswith(prefix) and all(m in l for m in must)]
        self.assertTrue(found, f"no {prefix} line with {must} in:\n{text}")
        return found[0]

    def assertVacuous(self, lines, bench, why, *extra, more_bench=None):
        code, out = self.run_on(lines, bench, *extra, more_bench=more_bench)
        self.assertEqual(code, 1, out)
        self.line(out, "VACUOUS", why)

    # -- the replay ---------------------------------------------------------------------------

    def test_the_band_check_prints_inside_and_outside(self):
        lines, bench = [], []
        for rep, ms in enumerate((600.0, 610.0, 620.0), start=1):
            lines += replay_run(f"in{rep}", "p@legacy", str(rep), ms)
            bench.append(bench_line("p@legacy", rep))
            lines += replay_run(f"out{rep}", "p@slow", str(rep), ms + 100)
            bench.append(bench_line("p@slow", rep))
        code, out = self.run_on(lines, bench)
        self.assertEqual(code, 0, out)
        self.line(out, "BAND", "label=p@legacy", "median_of_medians_ms=610.000", "inside")
        self.line(out, "BAND", "label=p@slow", "outside")

    def test_the_band_check_needs_pooled_storage(self):
        lines = replay_run("a", "g@legacy", "1", 600.0, arm="pipeline-aot")
        code, out = self.run_on(lines, [bench_line("g@legacy", 1, arm="pipeline-aot",
                                                   storage="growable")])
        self.assertEqual(code, 0, out)
        self.assertNotIn("BAND", out)

    def test_the_shrink_names_its_regime_and_each_pairs_difference(self):
        lines = (replay_run("a1", "p@legacy", "1", 600.0) + replay_run("a2", "p@legacy", "2", 620.0)
                 + replay_run("b1", "p@history", "1", 450.0, sink="history")
                 + replay_run("b2", "p@history", "2", 460.0, sink="history"))
        reserved = [bench_line("p@legacy", 1), bench_line("p@legacy", 2),
                    bench_line("p@history", 1), bench_line("p@history", 2)]
        code, out = self.run_on(lines, reserved)
        self.assertEqual(code, 0, out)
        self.assertNotIn("BAND label=p@history", out)
        self.line(out, "SHRINK", "streams_ms=610.000", "history_ms=455.000",
                  "pair_deltas_ms=1:-150.000,2:-160.000", "pair_range_ms=-160.000..-150.000",
                  "regime=reserved")
        grown = reserved[:3] + [bench_line("p@history", 2, realloc=GROWTH)]
        code, out = self.run_on(lines, grown)
        self.line(out, "SHRINK", "regime=growth")

    def test_faults_are_printed_per_run(self):
        code, out = self.run_on(replay_run("a", "p@legacy", "1", 600.0),
                                [bench_line("p@legacy", 1, minor_faults=11, major_faults=2)])
        self.line(out, "FAULTS", "label=p@legacy", "minor_faults=11", "major_faults=2")

    def test_a_warm_up_and_a_discarded_rep_are_read_nowhere(self):
        lines = (replay_run("w", "p@legacy", "w", 900.0, warmup=True)
                 + replay_run("d", "p@legacy", "1", 900.0) + replay_run("a", "p@legacy", "2", 600.0))
        code, out = self.run_on(lines, [bench_line("p@legacy", 1), bench_line("p@legacy", 2)],
                                "--discard-reps", "1")
        self.assertEqual(code, 0, out)
        self.line(out, "REPLAY", "label=p@legacy", "runs=1", "pooled_median_ms=600.000")

    # -- vacuity ------------------------------------------------------------------------------

    def test_a_vacuous_run_exits_1(self):
        run = replay_run("a", "p@legacy", "1", 600.0)
        cases = [
            ([bench_line("p@legacy", 1, alloc="jemalloc")], "alloc=jemalloc"),
            ([bench_line("p@legacy", 1, mem="heap")], "mem=heap"),
            ([bench_line("p@legacy", 1, bigint="default")], "bigint=default"),
            ([bench_line("p@legacy", 1, storage="growable")], "storage=growable"),
            ([], "no AOT_BENCH line"),
            ([bench_line("p@legacy", 1, aot_dispatches=0)], "aot_dispatches=0"),
            ([bench_line("p@legacy", 1, lock_held="false", lock_after="USING:")],
             "the lock file was not read held"),
        ]
        for bench, why in cases:
            self.assertVacuous(run, bench, why)

    def test_an_unpinned_run_is_vacuous(self):
        bench = [bench_line("p@legacy", 1)]
        self.assertVacuous(replay_run("a", "p@legacy", "1", 600.0, cpus="0-123"), bench,
                           "cpus_allowed_list=0-123")
        # The cpuset's node list proves nothing: only the policy on every mapping does.
        self.assertVacuous(replay_run("a", "p@legacy", "1", 600.0, mems="1",
                                      mempolicy={"default": 9}),
                           bench, "memory not bound to node 1")
        self.assertVacuous(replay_run("a", "p@legacy", "1", 600.0, lock=False), bench,
                           "the envelope's lock_held=false")

    def test_runs_of_another_workload_are_vacuous(self):
        bench = [bench_line("p@legacy", 1), bench_line("p@legacy", 2)]
        short = replay_run("a", "p@legacy", "1", 600.0) + replay_run("b", "p@legacy", "2", 600.0,
                                                                       chunks=range(0, 38))
        self.assertVacuous(short, bench, "chunks=38")
        other = replay_run("a", "p@legacy", "1", 600.0) + replay_run("b", "p@legacy", "2", 600.0,
                                                                       elf="e2")
        self.assertVacuous(other, bench, "elf_sha256=e2")
        self.assertVacuous(replay_run("a", "p@legacy", "1", 600.0), bench[:1], "cycles=39000",
                           "--expect-cycles", "40000")

    # -- the capture --------------------------------------------------------------------------

    def priced(self, reps=("3", "4"), **kw):
        lines = []
        for rep in reps:
            lines += pricing_run(f"x{rep}", rep, **kw)
        return lines, [pricing_bench(rep) for rep in reps]

    def test_x_is_computed_from_known_facts(self):
        lines, bench = self.priced(reps=("3",))
        code, out = self.run_on(lines, bench, "--rows-ms", "0.5", "--expect-events", "100")
        # event path 1000 - 100 x 0.05 = 995; compute 600 - 100 x 0.03 = 597; the drain's timer
        # inside the event path 1000 x 0.04 = 40; the drain 100 - 1000 x 0.02 = 80;
        # X = 995 - 597 - 40 - 80 = 278 us. Assembly 200 - 10 x 0.1 = 199 us, the memory extend
        # beside it and not in it: 50 - 1 x 1.0 = 49 us.
        self.line(out, "CAPTURE", "kind=keccak_permute", "count_worker=100", "count_snapshot=100",
                  "event_path_ms=0.995", "compute_ms=0.597")
        self.line(out, "CAPTURE", "drain_ms=0.080", "drain_brackets=1000", "drain_words=1000",
                  "drain_timer_in_event_path_ms=0.040")
        self.line(out, "CAPTURE", "X_ms=0.278", "assembly_ms=0.199", "memory_extend_ms=0.049",
                  "memory_extends=1",
                  "extract:0.002,sort:0.003,records:0.004,memory:0.005,wall:0.008", "splits=1")
        self.line(out, "FAULTS", "label=p@price", "faults.minor=3", "pool.blocked_gets=2",
                  "pool.blocked_us=9")

    def test_the_drain_is_priced_per_call_and_not_per_word(self):
        # Four words a call. Priced per word the drain would read 100 - 4000 x 0.02 = 20 us, and
        # the timer inside the event path 4000 x 0.04 = 160 us.
        lines, bench = self.priced(reps=("3",), drain_words=4000)
        code, out = self.run_on(lines, bench, "--rows-ms", "0.5", "--expect-events", "100")
        self.line(out, "CAPTURE", "drain_ms=0.080", "drain_brackets=1000", "drain_words=4000",
                  "drain_timer_in_event_path_ms=0.040")
        self.line(out, "CAPTURE", "X_ms=0.278", "assembly_ms=0.199")

    def test_reads_pair_the_counted_reps_and_name_the_worst_and_best(self):
        lines, bench = self.priced(reps=("1", "2", "3", "4", "5", "6"))
        code, out = self.run_on(lines, bench, "--rows-ms", "0.5", "--expect-events", "100",
                                "--discard-reps", "1,2")
        self.assertEqual(code, 0, out)
        self.line(out, "READ", "read=1", "reps=3,4", "X_ms=0.278", "rows_ms=0.500",
                  "assembly_ms=0.199", "X_plus_rows_plus_assembly_ms=0.977", "anchor=within")
        self.line(out, "READ", "read=2", "reps=5,6")
        self.assertNotIn("reps=1,2", out)
        self.line(out, "READS", "reads=2", "worst_X_plus_rows_plus_assembly_ms=0.977",
                  "best_X_ms=0.278")

    def test_rows_are_the_slowest_writer_line_of_any_bench_file(self):
        lines, bench = self.priced()
        writers = [bench_line("retained-rows@pinned", r, arm="retained-rows", retained_rows_us=v)
                   for r, v in ((1, "400.0"), (2, "500.0"))]
        code, out = self.run_on(lines, bench, "--expect-events", "100", more_bench=writers)
        self.assertEqual(code, 0, out)
        self.line(out, "READ", "rows_ms=0.500", "X_plus_rows_plus_assembly_ms=0.977")

    def test_the_timers_need_the_expected_event_count(self):
        lines, bench = self.priced()
        code, out = self.run_on(lines, bench)
        self.assertEqual(code, 2, out)
        self.assertIn("--expect-events", out)

    def test_a_vacuous_capture_exits_1(self):
        cases = [
            (self.priced(), "counted 100 precompile events, not 101", ("--expect-events", "101")),
            (self.priced(keccak_worker=90), "counted 90 in the worker role and 100 in the snapshot",
             ("--expect-events", "90")),
            (self.priced(keccak_worker=0, keccak_snapshot=0), "no precompile kind counted",
             ("--expect-events", "0")),
            (self.priced(sink="history"), "the pricing arm writes sink=history",
             ("--expect-events", "100")),
            (self.priced(drain_calls=0), "the drain counted no call", ("--expect-events", "100")),
            (self.priced(drain_calls=None), "the drain counted no call",
             ("--expect-events", "100")),
            (self.priced(reps=("3", "4", "5")), "a read without its pair",
             ("--expect-events", "100")),
            (self.priced(anchor_extra=20_000), "anchor outside", ("--expect-events", "100")),
            (self.priced(chunks=range(0, 6)), "anchor missing", ("--expect-events", "100")),
        ]
        for (lines, bench), why, extra in cases:
            self.assertVacuous(lines, bench, why, *extra)

    # -- the anchor ---------------------------------------------------------------------------

    def test_the_anchor_check_flags_a_chunk_outside_ten_percent_and_keeps_the_pool_wait(self):
        run = "s"
        lines = [envelope(run, "p@legacy", "1")]
        for chunk, snap_ms in {4: 212.9, 5: 150.0, 6: 140.0, 7: 89.3, 8: 70.0}.items():
            lines.append(stage(run, "snapshot.emulate", chunk, int(snap_ms * 1000),
                               lane="snapshot", dispatches_delta=5, cycles_delta=1000))
            lines.append(stage(run, "snapshot.pool_wait", chunk, 30_000, lane="snapshot"))
            lines.append(stage(run, "worker.replay", chunk, 600_000, sink="legacy", dispatches=3,
                               record_bytes=10))
        code, out = self.run_on(lines, [bench_line("p@legacy", 1)])
        self.assertEqual(code, 0, out)
        self.line(out, "ANCHOR", "chunk=4", "snapshot_ms=212.900", "pool_wait_ms=30.000",
                  "within")
        self.line(out, "ANCHOR", "chunk=5", "within")
        self.line(out, "ANCHOR", "chunk=6", "snapshot_ms=140.000", "outside")
        self.line(out, "ANCHOR", "chunk=8", "within")

    def test_bad_input_exits_2(self):
        with tempfile.TemporaryDirectory() as tmp:
            ledger = os.path.join(tmp, "l.jsonl")
            with open(ledger, "w") as fh:
                fh.write(json.dumps({"v": 1, "run": "a"}) + "\n")
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(rc.main([ledger]), 2)


if __name__ == "__main__":
    unittest.main()
