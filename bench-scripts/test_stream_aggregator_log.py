#!/usr/bin/env python3
import argparse
import signal
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

# For inactivity simulation, call the streaming function directly
from stream_aggregator_log import stream_analyze_file


def _diff_lines(a: list[str], b: list[str], max_lines: int = 20) -> list[str]:
    diffs: list[str] = []
    for i, (la, lb) in enumerate(zip(a, b)):
        if la != lb:
            diffs.append(f"line {i+1}:")
            diffs.append(f"  stream: {la}")
            diffs.append(f"  batch : {lb}")
            if len(diffs) >= max_lines:
                break
    if len(a) != len(b):
        diffs.append(f"lengths differ: stream={len(a)} batch={len(b)}")
    return diffs


def run_demo(
    sample_log: Path, poll_interval: float = 0.05, feed_sleep: float = 0.001
) -> int:
    root = Path(__file__).parent
    stream_script = root / "stream_aggregator_log.py"
    batch_script = root / "analyze_aggregator_log.py"

    if not sample_log.exists():
        print(f"Error: sample log not found: {sample_log}")
        return 2

    with tempfile.TemporaryDirectory() as td:
        td_path = Path(td)
        temp_log = td_path / "live.log"
        stream_csv = td_path / "live_analysis.csv"
        batch_csv = td_path / "batch_analysis.csv"

        print(f"Temporary working directory: {td_path}")
        print(f"Feeding from: {sample_log}")
        print(f"Streaming into: {temp_log}")
        print(f"Stream CSV: {stream_csv}")
        print(f"Batch CSV : {batch_csv}")

        # Start streaming analyzer
        proc = subprocess.Popen(
            [
                sys.executable,
                str(stream_script),
                str(temp_log),
                str(stream_csv),
                "--poll-interval-secs",
                str(poll_interval),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )

        progress_seen = {"lines": 0, "progress_events": 0}

        def reader_thread() -> None:
            assert proc.stdout is not None
            for line in proc.stdout:
                sys.stdout.write(f"[stream] {line}")
                sys.stdout.flush()
                if line.strip().startswith("progress: block "):
                    progress_seen["progress_events"] += 1
                progress_seen["lines"] += 1

        t = threading.Thread(target=reader_thread, daemon=True)
        t.start()

        # Feed the log incrementally
        total_lines = 0
        with open(sample_log, "r", encoding="utf-8", errors="replace") as src, open(
            temp_log, "w", encoding="utf-8"
        ) as dst:
            for line in src:
                dst.write(line)
                dst.flush()
                total_lines += 1
                if total_lines % 500 == 0:
                    print(f"[feeder] wrote {total_lines} lines...")
                time.sleep(feed_sleep)

        print("[feeder] done writing. waiting for streamer to settle...")
        time.sleep(0.25)

        if proc.poll() is None:
            print("[ctrlc] sending SIGINT to streamer...")
            proc.send_signal(getattr(signal, "SIGINT", 2))

        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            print("[error] streamer did not exit in time; killing...")
            proc.kill()
            return 3

        # Batch analyze the same temp log
        print("[batch] analyzing temp log for ground truth...")
        subprocess.run(
            [sys.executable, str(batch_script), str(temp_log), str(batch_csv)],
            check=True,
        )

        # Load and compare
        if not stream_csv.exists() or not batch_csv.exists():
            print("[error] CSV(s) missing: stream or batch not generated")
            return 4

        s1 = stream_csv.read_text(encoding="utf-8").strip().splitlines()
        s2 = batch_csv.read_text(encoding="utf-8").strip().splitlines()

        if s1 == s2:
            print("[ok] Streaming CSV matches batch CSV")
        else:
            print(
                "[mismatch] Streaming CSV differs from batch CSV. Showing first diffs:"
            )
            for ln in _diff_lines(s1, s2, max_lines=40):
                print(ln)
            return 5

        print(
            f"[stats] progress_lines={progress_seen['lines']} events={progress_seen['progress_events']}"
        )
        if progress_seen["progress_events"] == 0:
            print("[warn] no progress lines observed from streaming analyzer")

    return 0


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Streaming analyzer demos (no pytest).",
    )
    sub = parser.add_subparsers(dest="cmd")

    p1 = sub.add_parser(
        "compare",
        help="Feed a sample log and compare streaming vs batch CSV outputs",
    )
    p1.add_argument(
        "--log",
        dest="sample_log",
        default=str(
            Path(__file__).parent.parent / "logs/aggregator-b23290391-g10000000.txt"
        ),
        help="Path to sample log to feed (default: logs/aggregator-b23290391-g10000000.txt)",
    )
    p1.add_argument(
        "--poll-interval",
        type=float,
        default=0.05,
        help="Streaming analyzer poll interval in seconds (default: 0.05)",
    )
    p1.add_argument(
        "--feed-sleep",
        type=float,
        default=0.001,
        help="Delay between feeding lines, seconds (default: 0.001)",
    )

    p2 = sub.add_parser(
        "inactivity",
        help="Simulate inactivity and assert Slack notification callback is triggered",
    )
    p2.add_argument(
        "--timeout",
        type=float,
        default=0.2,
        help="Inactivity timeout seconds for the test (default: 0.2)",
    )
    p2.add_argument(
        "--stop-after",
        type=float,
        default=0.35,
        help="Stop-after idle seconds to end the stream loop (default: 0.35)",
    )
    p2.add_argument(
        "--poll-interval",
        type=float,
        default=0.05,
        help="Polling interval seconds (default: 0.05)",
    )

    p3 = sub.add_parser(
        "stuck",
        help="Simulate a stuck block and assert the alert includes the block number",
    )
    p3.add_argument(
        "--timeout",
        type=float,
        default=0.2,
        help="Inactivity timeout seconds for the test (default: 0.2)",
    )
    p3.add_argument(
        "--stop-after",
        type=float,
        default=0.35,
        help="Stop-after idle seconds to end the stream loop (default: 0.35)",
    )
    p3.add_argument(
        "--poll-interval",
        type=float,
        default=0.05,
        help="Polling interval seconds (default: 0.05)",
    )

    args = parser.parse_args()

    if args.cmd == "inactivity":
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            temp_log = td_path / "idle.log"
            # Do not create or write to temp_log to simulate no new data/results
            out_csv = td_path / "idle_analysis.csv"

            messages: list[str] = []

            def on_notify(msg: str) -> None:
                messages.append(msg)

            start = time.time()
            stream_analyze_file(
                log_file=str(temp_log),
                output_csv=str(out_csv),
                tag="inactivity-test",
                poll_interval_secs=float(args.poll_interval),
                on_progress=None,
                quiet=True,
                stop_when_idle_secs=float(args.stop_after),
                inactivity_timeout_secs=float(args.timeout),
                slack_webhook_url=None,
                slack_token=None,
                slack_channel=None,
                notification_callback=on_notify,
            )
            elapsed = time.time() - start
            print(f"[inactivity] elapsed={elapsed:.3f}s notifications={len(messages)}")
            if len(messages) >= 1:
                print("[ok] Inactivity notification was triggered")
                sys.exit(0)
            print("[fail] Inactivity notification was NOT triggered")
            sys.exit(6)
    elif args.cmd == "stuck":
        # Simulate a stuck block by feeding a partial block: we write lines that
        # start a block and cycles but never write an E2E_total, then idle.
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            temp_log = td_path / "stuck.log"
            out_csv = td_path / "stuck_analysis.csv"

            messages: list[str] = []

            def on_notify(msg: str) -> None:
                messages.append(msg)

            # Write a minimal partial block
            temp_log.write_text(
                """
2025-01-01T00:00:00Z INFO [emulator] block-123456: chunk_num=1
2025-01-01T00:00:01Z INFO Total Cycles: 424242
                """.strip()
            )

            start = time.time()
            stream_analyze_file(
                log_file=str(temp_log),
                output_csv=str(out_csv),
                tag="stuck-test",
                poll_interval_secs=float(args.poll_interval),
                on_progress=None,
                quiet=True,
                stop_when_idle_secs=float(args.stop_after),
                inactivity_timeout_secs=float(args.timeout),
                slack_webhook_url=None,
                slack_token=None,
                slack_channel=None,
                notification_callback=on_notify,
            )
            elapsed = time.time() - start
            print(f"[stuck] elapsed={elapsed:.3f}s notifications={len(messages)}")
            # Expect an inactivity message mentioning stuck on block 123456
            hit = any("stuck on block 123456" in m for m in messages)
            if hit:
                print(
                    "[ok] Stuck block inactivity notification was triggered and contains block number"
                )
                sys.exit(0)
            print("[fail] Stuck block notification missing or not triggered")
            sys.exit(7)
    else:
        code = run_demo(Path(args.sample_log), args.poll_interval, args.feed_sleep)
        sys.exit(code)


if __name__ == "__main__":
    main()
