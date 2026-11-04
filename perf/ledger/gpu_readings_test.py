#!/usr/bin/env python3
"""Fixture tests for gpu_readings.py: python3 -I perf/ledger/gpu_readings_test.py"""

import contextlib
import io
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gpu_readings  # noqa: E402


def tracegen(chunk, device, cpu=True, idle=2000, waits=20, wait_us=9000, unread=0, kernels=600):
    return (
        f"2026-10-28T05:00:00.000Z  INFO [gpu-tracegen] chunk={chunk} cpu={str(cpu).lower()} "
        f"device={device} wall_us=50000 device.idle_us={idle} device.busy_us=40000 "
        f"device.span_us={40000 + idle} events_unread={unread} h2d.exposed_us=300 "
        f"host_wait_final_us=null host_wait_us={wait_us} host_waits={waits} "
        f"kernel.Cpu.us=30000 kernel.global_poseidon2_local_memory.us={kernels}"
    )


def brackets(chunk, device, cpu=True, global_ms=4.0, union_ms=45.0):
    return (
        f"2026-10-28T05:00:00.000Z  INFO [gpu-tracegen-brackets] chunk={chunk} "
        f"cpu={str(cpu).lower()} device={device} wall_us=50000 chip.Cpu_ms=20.5 "
        f"chip.Global_ms={global_ms} step.Global.memset_ms=0.25 step.Global.between_ms=1.5 "
        f"copy.cpu_slices_ms=6.0 sum_ms=70.0 union_ms={union_ms} span_ms=50.0 events_unread=0"
    )


def wait(chunk, site, us, cpu=True, final=False):
    tail = " final=true" if final else ""
    return (
        f"2026-10-28T05:00:00.000Z DEBUG [host-wait] chunk={chunk} cpu={str(cpu).lower()} "
        f"site={site} us={us}{tail}"
    )


def proved(chunk):
    return (
        f"2026-10-28T05:00:00.000Z  INFO [bench][p-0](chunk-{chunk}) "
        "mle-gpu-prover: running=40 ms"
    )


# Two cards, CPU chunks 0-5 and one deferred record. Chunk 0 is card 0's first, chunk 1 card 1's,
# chunk 5 the last CPU chunk, chunk 3 has an unread event: chunks 2 and 4 are kept.
RUN = [
    tracegen(0, 0, idle=90000),
    tracegen(1, 1, idle=90000),
    tracegen(2, 0, idle=1000, wait_us=8000, kernels=500),
    tracegen(3, 1, idle=70000, unread=1),
    tracegen(4, 0, idle=3000, wait_us=12000, kernels=700),
    tracegen(5, 1, idle=50000),
    tracegen(5, 0, cpu=False, idle=4000),
    brackets(2, 0, global_ms=3.0, union_ms=40.0),
    brackets(3, 1, global_ms=90.0, union_ms=10.0),
    brackets(4, 0, global_ms=5.0, union_ms=50.0),
    brackets(5, 0, cpu=False, global_ms=70.0),
    wait(2, "vm/src/machine/prover.rs:151", 5000),
    wait(2, "vm/src/machine/prover.rs:151", 1000, final=True),
    wait(4, "vm/src/machine/prover.rs:151", 7000),
    wait(5, "vm/src/machine/prover.rs:151", 99000, cpu=False),
    "2026-10-28T05:00:00.000Z  INFO [gpu-air-prove] chunk=2 air.Cpu.prove_us=4000 "
    "air_events_unread=0",
    "2026-10-28T05:00:00.000Z DEBUG [jit-gate] air=KeccakPermuteChip family=z1jit rules=33420 "
    "gate=(built-in default 11000) on=true forced=false admitted=false",
    "2026-10-28T05:00:00.000Z  INFO [queue-pickup] chunk=2 pv_chunk=2 lane=p-0 queue.depth=1 "
    "queue.scheduler_depth=0 queue.kind=cpu cost=10 wait_us=150",
] + [proved(i) for i in range(7)]


class GpuReadingsTest(unittest.TestCase):
    def test_the_statistic_keeps_only_the_steady_cpu_chunks(self):
        run = gpu_readings.parse(RUN)
        kept, dropped = gpu_readings.kept_cpu_chunks(run)
        self.assertEqual([s["chunk"] for s in kept], [2, 4])
        self.assertEqual(
            dropped,
            {"first chunk on its card": 2, "last CPU chunk": 1, "events unread": 1},
        )

    def test_medians_and_sites_read_the_kept_chunks(self):
        summary = gpu_readings.summarise(gpu_readings.parse(RUN))
        figures = summary["figures"]
        self.assertEqual(figures["device idle ms per CPU chunk"], 2.0)
        self.assertEqual(
            figures["host-blocked ms per CPU chunk (includes queued kernel time)"], 10.0
        )
        self.assertEqual(
            figures["Global + Poseidon2 + local memory kernel ms (upper bound)"], 0.6
        )
        self.assertEqual(figures["host waits per CPU chunk"], 20)
        self.assertEqual(summary["sites"], {"vm/src/machine/prover.rs:151": [2, 12000]})

    def test_brackets_read_the_kept_chunks_only(self):
        found = gpu_readings.summarise(gpu_readings.parse(RUN))["brackets"]
        self.assertEqual(found["chip.Global_ms"], 4.0)
        self.assertEqual(found["chip.Cpu_ms"], 20.5)
        self.assertEqual(found["step.Global.between_ms"], 1.5)
        self.assertEqual(found["union_ms"], 45.0)
        self.assertEqual(found["union_over_span"], 0.9)
        self.assertNotIn("events_unread", found)

    def test_a_run_without_brackets_reads_as_before(self):
        run = gpu_readings.parse([line for line in RUN if "brackets]" not in line])
        self.assertEqual(run["tracegen"], gpu_readings.parse(RUN)["tracegen"])
        self.assertEqual(gpu_readings.summarise(run)["brackets"], {})

    def test_a_readable_run_is_not_vacuous(self):
        self.assertEqual(gpu_readings.vacuity(gpu_readings.parse(RUN)), [])

    def test_vacuous_runs_are_named(self):
        self.assertEqual(
            gpu_readings.vacuity(gpu_readings.parse([proved(0)])), ["no [gpu-tracegen] line"]
        )
        no_waits = [tracegen(0, 0, waits=0), proved(0)]
        self.assertIn("reports no host wait", gpu_readings.vacuity(gpu_readings.parse(no_waits))[0])
        unread = [tracegen(0, 0, unread=2), proved(0)]
        self.assertIn("events_unread", gpu_readings.vacuity(gpu_readings.parse(unread))[0])
        short = [tracegen(0, 0), proved(0), proved(1)]
        self.assertIn("proved records", gpu_readings.vacuity(gpu_readings.parse(short))[0])

    def test_main_exits_one_on_a_vacuous_run_and_zero_otherwise(self):
        with tempfile.TemporaryDirectory() as directory:
            good = os.path.join(directory, "good.log")
            bad = os.path.join(directory, "bad.log")
            with open(good, "w", encoding="utf-8") as f:
                f.write("\n".join(RUN) + "\n")
            with open(bad, "w", encoding="utf-8") as f:
                f.write(proved(0) + "\n")
            with contextlib.redirect_stdout(io.StringIO()) as out:
                self.assertEqual(gpu_readings.main([good, good, good]), 0)
                self.assertEqual(gpu_readings.main([good, bad]), 1)
            self.assertIn("median of 3 runs' medians", out.getvalue())
            self.assertIn("VACUOUS", out.getvalue())


if __name__ == "__main__":
    unittest.main()
