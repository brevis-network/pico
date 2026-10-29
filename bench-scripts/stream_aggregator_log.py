#!/usr/bin/env python3
"""
Streaming Aggregator Log Analyzer

Continuously tails an aggregator log file and emits incremental CSV snapshots
that converge to the same results as the batch analyzer when the log is complete.

Features:
- Robust file tailing (partial lines, truncation, rotation)
- Low overhead polling with configurable interval
- Atomic (temp+rename) CSV writes, idempotent results
- Console progress for current block

Usage:
    python stream_aggregator_log.py <log_file> [output_csv]

Options:
    --poll-interval-secs N  Polling interval in seconds (default: 1.0)
    --tag TAG               Optional tag to include in CSV
    --quiet                 Suppress console progress output

Notes:
- This module reuses the parsing logic from analyze_aggregator_log.AggregatorLogAnalyzer
  without modifying it, to ensure result equivalence.
"""

from __future__ import annotations

import argparse
import io
import os
import signal
import sys
import time
from dataclasses import dataclass
import logging
from pathlib import Path
from typing import Callable, Optional
import json
import urllib.request
import socket
from typing import Iterable

# Local import (same directory)
from analyze_aggregator_log import AggregatorLogAnalyzer


ProgressCallback = Callable[[int, int, str, Optional[int], Optional[float]], None]


@dataclass
class _TailState:
    file_obj: Optional[io.TextIOBase]
    inode: Optional[int]
    position: int
    buffer: str


def _open_text(log_path: Path) -> io.TextIOBase:
    # Open in text mode with replace to tolerate partial/invalid utf-8 fragments
    return open(log_path, "r", encoding="utf-8", errors="replace")


def _stat_inode(path: Path) -> Optional[int]:
    try:
        return path.stat().st_ino
    except FileNotFoundError:
        return None


def _fstat_inode(f: io.IOBase) -> Optional[int]:
    try:
        return os.fstat(f.fileno()).st_ino
    except Exception:
        return None


def _write_csv_atomically(
    analyzer: AggregatorLogAnalyzer, results_out: Path, src_log: str, tag: str
) -> None:
    # Write to temp file in the same directory then rename, ensuring atomic snapshot
    tmp_path = results_out.with_suffix(results_out.suffix + ".tmp")
    analyzer.write_csv_output(analyzer.block_results, str(tmp_path), src_log, tag)
    os.replace(tmp_path, results_out)


def _load_env_file(env_file: Optional[str]) -> None:
    # Lightweight .env loader: key=value lines, ignore comments and blanks.
    # Precedence: existing environment vars are NOT overridden.
    path: Optional[Path] = None
    try:
        if env_file:
            p = Path(env_file)
            if p.exists() and p.is_file():
                path = p
        else:
            p = Path.cwd() / ".env"
            if p.exists() and p.is_file():
                path = p
    except Exception:
        path = None

    if not path:
        return

    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fp:
            for raw in fp:
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" not in line:
                    continue
                key, val = line.split("=", 1)
                key = key.strip()
                val = val.strip().strip('"').strip("'")
                if key and key not in os.environ:
                    os.environ[key] = val
    except Exception:
        pass


def stream_analyze_file(
    log_file: str,
    output_csv: Optional[str] = None,
    tag: str = "",
    poll_interval_secs: float = 1.0,
    on_progress: Optional[ProgressCallback] = None,
    quiet: bool = False,
    stop_when_idle_secs: Optional[float] = None,
    inactivity_timeout_secs: Optional[float] = 120.0,
    slack_webhook_url: Optional[str] = None,
    slack_token: Optional[str] = None,
    slack_channel: Optional[str] = None,
    slack_username: str = "aggregator-monitor",
    slack_emoji: Optional[str] = None,
    notification_callback: Optional[Callable[[str], None]] = None,
) -> None:
    """Continuously tail a log file and write incremental CSV snapshots.

    Args:
        log_file: Path to the aggregator log to tail
        output_csv: Destination CSV path; defaults to <logdir>/<logstem>_analysis.csv
        tag: Optional tag to include in CSV rows
        poll_interval_secs: Polling interval for new data
        on_progress: Optional callback receiving (block_number, execution_id, status, cycles, e2e_s)
        quiet: If True, suppress console progress lines
        stop_when_idle_secs: If set, exit after this many seconds with no new data
    """
    src_path = Path(log_file)
    out_path = (
        Path(output_csv)
        if output_csv
        else src_path.parent / f"{src_path.stem}_analysis.csv"
    )

    analyzer = AggregatorLogAnalyzer()

    # tail state
    state = _TailState(file_obj=None, inode=None, position=0, buffer="")

    # Track last printed/progress state to avoid flooding
    last_progress_signature: Optional[tuple] = None
    # Track last CSV snapshot signature to avoid redundant/empty writes
    last_snapshot_key: Optional[tuple] = None

    def _compute_snapshot_key() -> tuple:
        if not analyzer.block_results:
            return (0,)
        r = analyzer.block_results[-1]
        return (
            len(analyzer.block_results),
            r.block_number,
            r.execution_id,
            r.status,
            r.cycles,
            r.e2e_s,
        )

    # Setup signal handling for graceful termination
    terminate = {"flag": False}

    def _handle_sig(signum, frame):  # noqa: ARG001
        terminate["flag"] = True

    try:
        signal.signal(signal.SIGINT, _handle_sig)
        signal.signal(signal.SIGTERM, _handle_sig)
    except Exception:
        # Not all environments allow installing signal handlers (e.g., Windows, threads)
        pass

    last_activity_time = time.time()
    last_result_activity_time = time.time()
    notification_sent_for_current_idle = False

    # Resolve Slack configuration from env if not provided
    slack_webhook_url = slack_webhook_url or os.environ.get("SLACK_WEBHOOK_URL")
    slack_token = slack_token or os.environ.get("SLACK_BOT_TOKEN")
    slack_channel = slack_channel or os.environ.get("SLACK_CHANNEL")

    def _send_slack_message(text: str) -> bool:
        # Prefer webhook if provided
        try:
            if slack_webhook_url:
                payload: dict[str, object] = {"text": text}
                if slack_channel:
                    payload["channel"] = slack_channel
                if slack_username:
                    payload["username"] = slack_username
                # Ensure an alert emoji icon unless explicitly disabled
                payload["icon_emoji"] = (
                    slack_emoji if slack_emoji else ":rotating_light:"
                )
                data = json.dumps(payload).encode("utf-8")
                req = urllib.request.Request(
                    slack_webhook_url,
                    data=data,
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=5) as resp:  # nosec B310
                    return 200 <= (resp.status or 0) < 300
            elif slack_token and slack_channel:
                api_url = "https://slack.com/api/chat.postMessage"
                payload = {"channel": slack_channel, "text": text}
                data = json.dumps(payload).encode("utf-8")
                req = urllib.request.Request(
                    api_url,
                    data=data,
                    headers={
                        "Content-Type": "application/json; charset=utf-8",
                        "Authorization": f"Bearer {slack_token}",
                    },
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=5) as resp:  # nosec B310
                    return 200 <= (resp.status or 0) < 300
        except Exception:
            pass
        return False

    def _build_inactivity_message(
        idle_for_s: float, timeout_s: float, file_exists_flag: bool
    ) -> str:
        host = socket.gethostname()
        reason_lines = []
        # Determine a human-friendly reason/context
        if not file_exists_flag:
            reason_lines.append("reason: log file not found yet")
        elif not analyzer.block_results:
            reason_lines.append("reason: no blocks detected yet")
        else:
            # There is at least one result
            curr = analyzer.block_results[-1]
            # Prefer the truly problematic (currently in-progress) block if any
            if analyzer.current_block is not None:
                stuck_block = analyzer.current_block
                # Find the most recent result for that stuck block to get details
                stuck: Optional[type(curr)] = None
                for r in reversed(analyzer.block_results):
                    if r.block_number == stuck_block:
                        stuck = r
                        break
                # Fallback to last if not found for any reason
                ref = stuck if stuck is not None else curr
                cycles_str = str(ref.cycles) if ref.cycles is not None else "NA"
                e2e_str = f"{ref.e2e_s:.3f}s" if ref.e2e_s is not None else "Pending"
                stuck_line = (
                    f"reason: stuck on block {stuck_block} (exec {ref.execution_id})\n"
                    f"        status={ref.status} cycles={cycles_str} e2e={e2e_str}"
                )
                reason_lines.append(stuck_line)
                if ref.status == "FAIL" and ref.error_message:
                    err = ref.error_message.replace("\n", " ")[:200]
                    reason_lines.append(f"        last error: {err}")
            else:
                # No current block: last completed or finalized
                cycles_str = str(curr.cycles) if curr.cycles is not None else "NA"
                e2e_str = f"{curr.e2e_s:.3f}s" if curr.e2e_s is not None else "Pending"
                reason_lines.append(
                    f"reason: no progress after last block {curr.block_number} (exec {curr.execution_id})"
                )
                reason_lines.append(
                    f"        status={curr.status} cycles={cycles_str} e2e={e2e_str}"
                )
        header = f":rotating_light: Aggregator streaming monitor idle for {int(idle_for_s)}s (>= {int(timeout_s)}s)"
        meta = f"log: {src_path}\ncsv: {out_path}\ntag: {tag or '-'}\nhost: {host}"
        return "\n".join([header, meta, *reason_lines])

    while True:
        if terminate["flag"]:
            # Graceful termination requested: finalize and break
            break

        inode_now = _stat_inode(src_path)
        file_exists = inode_now is not None

        opened_inode = _fstat_inode(state.file_obj) if state.file_obj else None

        # Handle open/rotation
        if file_exists and (state.file_obj is None or opened_inode != inode_now):
            # Open or reopen (rotation)
            try:
                if state.file_obj is not None:
                    try:
                        state.file_obj.close()
                    except Exception:
                        pass
                state.file_obj = _open_text(src_path)
                state.inode = _fstat_inode(state.file_obj)
                # If reopening due to rotation, start from beginning
                state.position = 0
                state.buffer = ""
            except FileNotFoundError:
                state.file_obj = None
                state.inode = None
                state.position = 0
                state.buffer = ""

        if not state.file_obj:
            # File not yet present; still honor inactivity and idle-stop semantics
            if stop_when_idle_secs is not None:
                if (time.time() - last_activity_time) >= stop_when_idle_secs:
                    break
            if inactivity_timeout_secs is not None and inactivity_timeout_secs > 0:
                idle_for = time.time() - last_result_activity_time
                if (
                    idle_for >= inactivity_timeout_secs
                    and not notification_sent_for_current_idle
                ):
                    message = _build_inactivity_message(
                        idle_for, inactivity_timeout_secs, file_exists_flag=False
                    )
                    try:
                        if notification_callback is not None:
                            notification_callback(message)
                    except Exception:
                        pass
                    _send_slack_message(message)
                    notification_sent_for_current_idle = True
            time.sleep(poll_interval_secs)
            continue

        # Detect truncation
        try:
            current_size = src_path.stat().st_size
        except FileNotFoundError:
            # Rotated between stat calls; loop to reopen
            time.sleep(poll_interval_secs)
            continue

        if state.position > current_size:
            # Truncated
            try:
                state.file_obj.seek(0)
                state.position = 0
                state.buffer = ""
            except Exception:
                pass

        # Read any new data
        state.file_obj.seek(state.position)
        data = state.file_obj.read()

        if data:
            last_activity_time = time.time()
            state.position = state.file_obj.tell()
            state.buffer += data

            # Process complete lines; keep last partial in buffer
            lines = state.buffer.splitlines(keepends=True)
            # If last line does not end with newline, keep it buffered
            if lines and (not lines[-1].endswith("\n")):
                state.buffer = lines[-1]
                lines = lines[:-1]
            else:
                state.buffer = ""

            made_progress = False
            for raw in lines:
                line = raw.rstrip("\r\n")
                analyzer._process_line(line)  # type: ignore[attr-defined]
                made_progress = True

                # Console progress for current block
                if analyzer.current_block is not None and analyzer.block_results:
                    curr = analyzer.block_results[-1]
                    signature = (
                        curr.block_number,
                        curr.execution_id,
                        curr.status,
                        curr.cycles,
                        curr.e2e_s,
                    )
                    if signature != last_progress_signature:
                        last_progress_signature = signature
                        if not quiet:
                            # Concise, human-readable progress line (not CSV-like)
                            cycles_str = (
                                str(curr.cycles) if curr.cycles is not None else "NA"
                            )
                            if curr.e2e_s is not None:
                                e2e_str = f"{curr.e2e_s:.3f}s"
                            else:
                                e2e_str = "Pending"
                            print(
                                f"progress: block {curr.block_number} exec {curr.execution_id} {curr.status} "
                                f"cycles={cycles_str} e2e={e2e_str}",
                                flush=True,
                            )
                        if on_progress is not None:
                            try:
                                on_progress(
                                    curr.block_number,
                                    curr.execution_id,
                                    curr.status,
                                    curr.cycles,
                                    curr.e2e_s,
                                )
                            except Exception:
                                pass

            # After processing a batch of lines, emit an atomic CSV snapshot
            if made_progress:
                # Only write when we have at least one result and something changed
                if analyzer.block_results:
                    snap_key = _compute_snapshot_key()
                    if snap_key != last_snapshot_key:
                        _write_csv_atomically(analyzer, out_path, str(src_path), tag)
                        last_snapshot_key = snap_key
                        last_result_activity_time = time.time()
                        notification_sent_for_current_idle = False

        else:
            # No new data; optionally exit if idle for long
            if stop_when_idle_secs is not None:
                if (time.time() - last_activity_time) >= stop_when_idle_secs:
                    break

            # Inactivity notification if configured
            if inactivity_timeout_secs is not None and inactivity_timeout_secs > 0:
                idle_for = time.time() - last_result_activity_time
                if (
                    idle_for >= inactivity_timeout_secs
                    and not notification_sent_for_current_idle
                ):
                    message = _build_inactivity_message(
                        idle_for, inactivity_timeout_secs, file_exists_flag=True
                    )
                    try:
                        if notification_callback is not None:
                            notification_callback(message)
                    except Exception:
                        pass
                    _send_slack_message(message)
                    notification_sent_for_current_idle = True

            time.sleep(poll_interval_secs)

    # Finalize any in-progress block and write a last snapshot
    try:
        analyzer._finalize_current_block()  # type: ignore[attr-defined]
    except Exception:
        pass
    if analyzer.block_results:
        _write_csv_atomically(analyzer, out_path, str(src_path), tag)

    # Print analysis summary to console upon exit
    try:
        analyzer.print_summary(analyzer.block_results)
    except Exception:
        pass


def _configure_logging_passthrough() -> None:
    # Configure a simple stdout logger so analyzer.print_summary logs are visible
    logger = logging.getLogger(__name__)
    if logger.handlers:
        return
    logger.setLevel(logging.INFO)
    stdout_handler = logging.StreamHandler(stream=sys.stdout)
    stdout_handler.setLevel(logging.INFO)
    formatter = logging.Formatter("%(message)s")
    stdout_handler.setFormatter(formatter)
    logger.addHandler(stdout_handler)
    # Also configure the analyzer module logger to print to stdout
    a_logger = logging.getLogger("analyze_aggregator_log")
    if not a_logger.handlers:
        a_logger.setLevel(logging.INFO)
        a_stdout = logging.StreamHandler(stream=sys.stdout)
        a_stdout.setLevel(logging.INFO)
        a_stdout.setFormatter(formatter)
        a_logger.addHandler(a_stdout)


def main() -> None:
    _configure_logging_passthrough()

    parser = argparse.ArgumentParser(
        description="Stream and analyze an aggregator log file, writing incremental CSV snapshots",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python stream_aggregator_log.py logs/aggregator-b23290391-g10000000.txt
    python stream_aggregator_log.py logs/aggregator-b23290391-g10000000.txt --poll-interval-secs 0.5 --tag run1
        """,
    )

    parser.add_argument("log_file", help="Path to the aggregator log file to tail")
    parser.add_argument("output_csv", nargs="?", help="Output CSV file path (optional)")
    parser.add_argument(
        "--poll-interval-secs",
        type=float,
        default=1.0,
        help="Polling interval in seconds (default: 1.0)",
    )
    parser.add_argument("--tag", default="", help="Tag to include in CSV output")
    parser.add_argument(
        "--quiet", action="store_true", help="Suppress console progress output"
    )
    parser.add_argument(
        "--env-file",
        help="Path to .env file to load (default: ./.env if present)",
    )
    parser.add_argument(
        "--inactivity-timeout-secs",
        type=float,
        default=120.0,
        help="Send Slack notification if no new results for this many seconds (default: 120)",
    )
    # Slack config (either webhook or token+channel)
    parser.add_argument("--slack-webhook-url", help="Slack incoming webhook URL")
    parser.add_argument("--slack-token", help="Slack bot token for Web API")
    parser.add_argument("--slack-channel", help="Slack channel or conversation ID")
    parser.add_argument(
        "--slack-username",
        default="aggregator-monitor",
        help="Slack username when using webhook (default: aggregator-monitor)",
    )
    parser.add_argument("--slack-emoji", help=":emoji: for webhook icon (optional)")

    args = parser.parse_args()

    # Load .env before reading env-based Slack config
    _load_env_file(args.env_file)

    # Validate input path existence is optional; we can start waiting for file to appear.
    out_csv = args.output_csv if args.output_csv else None

    stream_analyze_file(
        log_file=args.log_file,
        output_csv=out_csv,
        tag=args.tag,
        poll_interval_secs=float(args.poll_interval_secs),
        on_progress=None,
        quiet=bool(args.quiet),
        stop_when_idle_secs=None,
        inactivity_timeout_secs=float(args.inactivity_timeout_secs),
        slack_webhook_url=args.slack_webhook_url,
        slack_token=args.slack_token,
        slack_channel=args.slack_channel,
        slack_username=args.slack_username,
        slack_emoji=args.slack_emoji,
    )


if __name__ == "__main__":
    main()
