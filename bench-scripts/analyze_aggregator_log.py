#!/usr/bin/env python3
"""
Aggregator Log Analysis Tool

This script analyzes aggregator log files to extract performance metrics for each block.
It efficiently processes logs containing 10,000+ blocks and outputs results in CSV format.

Usage:
    python analyze_aggregator_log.py <log_file> [output_csv]

Output CSV columns:
    tag, kind, block, idx, status, cycles, e2e_s, log_file
"""

import argparse
import csv
import logging
import re
import sys
import os
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple
from datetime import datetime


@dataclass
class BlockResult:
    """Represents the analysis result for a single block execution."""

    block_number: int
    execution_id: int  # Unique ID for each execution of the same block
    status: str  # "OK" or "FAIL"
    cycles: Optional[int] = None
    e2e_s: Optional[float] = None
    error_message: Optional[str] = None
    start_timestamp: Optional[str] = None  # When block execution started
    end_timestamp: Optional[str] = None  # When block execution ended
    has_cycles: bool = False  # Whether cycles metric was found
    has_e2e: bool = False  # Whether E2E metric was found


class AggregatorLogAnalyzer:
    """Efficient analyzer for aggregator log files."""

    def __init__(self):
        # Regex patterns for parsing log entries
        # Detect the earliest indication of a new block on emulator lines, not only chunk_num=1
        # Example matches:
        #   [emulator] block-23290000: chunk_num=1
        #   [emulator-0] ... block-23290000 ...
        self.block_start_pattern = re.compile(r"\[emulator(?:-\d+)?\].*?block-(\d+)\b")
        self.total_cycles_pattern = re.compile(r"Total Cycles:\s*(\d+)")
        self.e2e_total_pattern = re.compile(r"E2E_total\s*=\s*([\d.]+)\s*s")
        self.timestamp_pattern = re.compile(
            r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2}))"
        )

        # Enhanced error patterns for better failure detection
        self.error_patterns = [
            re.compile(r"ERROR", re.IGNORECASE),
            re.compile(r"FATAL", re.IGNORECASE),
            re.compile(r"panic", re.IGNORECASE),
            re.compile(r"failed", re.IGNORECASE),
            re.compile(r"timeout", re.IGNORECASE),
            re.compile(r"connection.*refused", re.IGNORECASE),
            re.compile(r"network.*error", re.IGNORECASE),
            re.compile(r"out of memory", re.IGNORECASE),
            re.compile(r"segmentation fault", re.IGNORECASE),
            re.compile(r"abort", re.IGNORECASE),
            re.compile(r"killed", re.IGNORECASE),
            re.compile(r"terminated", re.IGNORECASE),
        ]

        # Warning patterns that might indicate issues
        self.warning_patterns = [
            re.compile(r"WARN", re.IGNORECASE),
            re.compile(r"warning", re.IGNORECASE),
            re.compile(r"retry", re.IGNORECASE),
            re.compile(r"timeout", re.IGNORECASE),
        ]

        # Track current block being processed
        self.current_block: Optional[int] = None
        self.current_execution_id: int = 0
        self.block_results: List[BlockResult] = []
        self.pending_cycles: Optional[int] = None
        self.pending_e2e: Optional[float] = None

        # Track seen block numbers to detect duplicates or gaps
        self.seen_blocks: Set[int] = set()
        self.duplicate_blocks: Set[int] = set()

        # Statistics for validation
        self.total_lines_processed: int = 0
        self.malformed_lines: int = 0
        self.warning_count: int = 0

    def analyze_log_file(self, log_file_path: str) -> List[BlockResult]:
        """
        Analyze a log file and extract block results.

        Args:
            log_file_path: Path to the aggregator log file

        Returns:
            List of BlockResult objects for each block found
        """
        self.current_block = None
        self.current_execution_id = 0
        self.block_results = []

        logger = logging.getLogger(__name__)
        logger.info(f"Analyzing log file: {log_file_path}")

        try:
            with open(log_file_path, "r", encoding="utf-8", errors="replace") as f:
                line_count = 0
                for line in f:
                    line_count += 1
                    if line_count % 10000 == 0:
                        logger.info(f"Processed {line_count:,} lines...")

                    self._process_line(line.strip())

                logger.info(f"Completed processing {line_count:,} lines")

        except FileNotFoundError:
            logging.getLogger(__name__).error(
                f"Error: Log file not found: {log_file_path}"
            )
            sys.exit(1)
        except Exception as e:
            logging.getLogger(__name__).error(f"Error reading log file: {e}")
            sys.exit(1)

        # Finalize any incomplete blocks
        self._finalize_current_block()

        return self.block_results

    def _find_coordinator_started_line(self, log_file_path: str) -> Optional[str]:
        """Return the first line containing 'coordinator started' (with timestamp) if any."""
        try:
            with open(log_file_path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    if "coordinator started" in line:
                        return line.rstrip("\n")
        except Exception:
            return None
        return None

    def split_log_by_block(
        self,
        log_file_path: str,
        output_dir: Path,
        blocks_filter: Optional[Set[int]] = None,
    ) -> List[Tuple[int, int, Path]]:
        """
        Split a big aggregator log into per-block files, one file per execution occurrence.

        - Segments are created starting from "coordinator started" lines, ensuring complete
          execution cycles from start to finish.
        - Each segment includes the full execution from coordinator start to E2E completion.
        - Returns a list of tuples: (block_number, execution_index, split_file_path)
        """
        output_dir.mkdir(parents=True, exist_ok=True)

        # Universal segmentation logic: works for both single-block and multi-block logs
        # Segment by coordinator started -> E2E_total pattern for complete execution cycles
        segments: List[Tuple[int, int, Path]] = []
        per_block_counts: Dict[int, int] = {}
        buffer_lines: List[str] = []
        current_block: Optional[int] = None
        coordinator_started_rx = re.compile(r"coordinator started")
        e2e_total_rx = re.compile(r"E2E_total\s*=\s*([0-9.]+)\s*s")
        block_num_rx = re.compile(r"block-(\d+)")

        def flush_buffer_as_exec():
            nonlocal buffer_lines, current_block
            if not buffer_lines or current_block is None:
                return

            # Determine block number from buffer content if not already set
            if current_block is None:
                for line in buffer_lines:
                    match = block_num_rx.search(line)
                    if match:
                        try:
                            current_block = int(match.group(1))
                            break
                        except (ValueError, IndexError):
                            continue

            if current_block is None:
                # Fallback: try to extract from filename
                try:
                    stem = Path(log_file_path).stem
                    mfile = re.search(r"aggregator-b(\d+)-g\d+", stem)
                    if mfile:
                        current_block = int(mfile.group(1))
                except Exception:
                    pass

            if current_block is None:
                # Skip if we can't determine block number
                buffer_lines = []
                return

            # Check if this block should be exported
            if blocks_filter is not None and current_block not in blocks_filter:
                buffer_lines = []
                return

            per_block_counts[current_block] = per_block_counts.get(current_block, 0) + 1
            exec_idx = per_block_counts[current_block]

            # Only add exec-* layer if there are multiple executions of the same block
            if per_block_counts[current_block] == 1:
                # Single execution - no exec-* layer needed
                per_dir = output_dir / f"block-{current_block}"
                out_path = per_dir / f"block-{current_block}.txt"
            else:
                # Multiple executions - use exec-* layer
                per_dir = output_dir / f"block-{current_block}" / f"exec-{exec_idx}"
                out_path = per_dir / f"block-{current_block}-{exec_idx}.txt"

            per_dir.mkdir(parents=True, exist_ok=True)

            # Write segment with proper coordinator started line
            with open(out_path, "w", encoding="utf-8") as fp:
                # Check if buffer already contains a coordinator started line
                has_coordinator_line = any(
                    coordinator_started_rx.search(line) for line in buffer_lines
                )

                if has_coordinator_line:
                    # Buffer already has coordinator line, write as-is
                    fp.writelines(buffer_lines)
                else:
                    # No coordinator line found, add synthetic one using first timestamp
                    coordinator_ts = None
                    for line in buffer_lines:
                        ts_match = self.timestamp_pattern.search(line)
                        if ts_match:
                            coordinator_ts = ts_match.group(1)
                            break

                    # Write synthetic coordinator line if we have a timestamp
                    if coordinator_ts:
                        fp.write(f"{coordinator_ts} INFO coordinator started\n")

                    fp.writelines(buffer_lines)

            segments.append((current_block, exec_idx, out_path))
            buffer_lines = []
            current_block = None

        with open(log_file_path, "r", encoding="utf-8", errors="replace") as f:
            for line_num, line in enumerate(f, 1):
                try:
                    buffer_lines.append(line)

                    # Check for coordinator started - start new segment
                    if coordinator_started_rx.search(line):
                        # Flush previous segment if exists
                        if (
                            buffer_lines and len(buffer_lines) > 1
                        ):  # More than just this line
                            # Remove the coordinator line from buffer temporarily
                            coordinator_line = buffer_lines.pop()
                            flush_buffer_as_exec()
                            # Start new buffer with coordinator line
                            buffer_lines = [coordinator_line]
                        current_block = None  # Will be determined from buffer content

                    # Check for E2E completion - end current segment
                    elif e2e_total_rx.search(line):
                        flush_buffer_as_exec()

                    # Try to detect block number from emulator lines
                    elif current_block is None:
                        match = self.block_start_pattern.search(line)
                        if match:
                            try:
                                current_block = int(match.group(1))
                            except (ValueError, IndexError):
                                pass

                except Exception as e:
                    # Handle corrupted lines gracefully
                    logging.getLogger(__name__).warning(
                        f"Error processing line {line_num}: {e}. Skipping line."
                    )
                    continue

        # Flush any remaining buffer (incomplete execution)
        if buffer_lines:
            # Only flush if we have substantial content (more than just coordinator line)
            if (
                len(buffer_lines) > 10
            ):  # Arbitrary threshold for incomplete but substantial content
                flush_buffer_as_exec()

        return segments

    def generate_timeline_for_blocks(
        self,
        block_segments: List[Tuple[int, int, Path]],
        charts_dir: Path,
        chart_workers: int = 1,
    ) -> None:
        """For each per-block execution file, emit CSV and two SVG charts using existing scripts.

        If chart_workers > 1, runs generation concurrently using a thread pool.
        """
        charts_dir.mkdir(parents=True, exist_ok=True)
        root = Path(__file__).parent
        extract_script = root / "extract_time_info.py"
        draw_script = root / "draw-timeline.py"

        def _generate_one(item):
            block_num, exec_idx, log_path = item
            # Use the same directory structure as the log file
            dest_dir = log_path.parent
            dest_dir.mkdir(parents=True, exist_ok=True)

            # Generate file names based on the log file name
            log_stem = log_path.stem  # e.g., "block-23290396" or "block-23290396-1"
            tmp_csv = dest_dir / f"{log_stem}.timeline.csv"
            result_txt = dest_dir / f"{log_stem}.timeline.result.txt"
            svg_chunk = dest_dir / f"{log_stem}-chunk.svg"
            svg_gpuid = dest_dir / f"{log_stem}-gpuid.svg"
            try:
                with open(tmp_csv, "w", encoding="utf-8") as out_csv, open(
                    result_txt, "w", encoding="utf-8"
                ) as err_txt:
                    subprocess.run(
                        [sys.executable, str(extract_script), str(log_path)],
                        stdout=out_csv,
                        stderr=err_txt,
                        check=False,
                    )
                subprocess.run(
                    [
                        sys.executable,
                        str(draw_script),
                        str(tmp_csv),
                        str(svg_chunk),
                        str(svg_gpuid),
                    ],
                    check=False,
                )
            except Exception as e:
                logging.getLogger(__name__).warning(
                    f"Timeline generation failed for block {block_num}: {e}"
                )

        items = sorted(block_segments, key=lambda t: (t[0], t[1]))
        workers = max(1, int(chart_workers or 1))
        if workers == 1 or len(items) <= 1:
            for it in items:
                _generate_one(it)
        else:
            with ThreadPoolExecutor(max_workers=workers) as ex:
                futures = [ex.submit(_generate_one, it) for it in items]
                for _ in as_completed(futures):
                    pass

    def _process_line(self, line: str) -> None:
        """Process a single log line and update current block state."""
        self.total_lines_processed += 1

        # Extract timestamp if present
        timestamp_match = self.timestamp_pattern.search(line)
        timestamp = timestamp_match.group(1) if timestamp_match else None

        # Check for block start
        block_match = self.block_start_pattern.search(line)
        if block_match:
            # Finalize previous block if exists
            self._finalize_current_block()

            # Start new block execution
            try:
                block_num = int(block_match.group(1))
            except (ValueError, IndexError) as e:
                self.malformed_lines += 1
                logging.getLogger(__name__).warning(
                    f"Malformed block number in line: {line[:100]}..."
                )
                return

            # Track duplicate blocks
            if block_num in self.seen_blocks:
                self.duplicate_blocks.add(block_num)
            else:
                self.seen_blocks.add(block_num)

            self.current_block = block_num
            self.current_execution_id += 1

            new_result = BlockResult(
                block_number=block_num,
                execution_id=self.current_execution_id,
                status="OK",  # Default to OK, will be updated if errors found
                start_timestamp=timestamp,
            )

            # If we have pending metrics, assign them to this new block
            if self.pending_cycles is not None:
                new_result.cycles = self.pending_cycles
                new_result.has_cycles = True
                self.pending_cycles = None

            if self.pending_e2e is not None:
                new_result.e2e_s = self.pending_e2e
                new_result.has_e2e = True
                self.pending_e2e = None

            self.block_results.append(new_result)
            return

        # Check for Total Cycles (can appear before block start)
        cycles_match = self.total_cycles_pattern.search(line)
        if cycles_match:
            try:
                cycles_value = int(cycles_match.group(1))
            except (ValueError, IndexError) as e:
                self.malformed_lines += 1
                logging.getLogger(__name__).warning(
                    f"Malformed cycles value in line: {line[:100]}..."
                )
                return

            if self.current_block is not None and self.block_results:
                # If we're in a block, check if current result already has cycles
                current_result = self.block_results[-1]
                if not current_result.has_cycles:
                    # Assign to current block if it doesn't have cycles yet
                    current_result.cycles = cycles_value
                    current_result.has_cycles = True
                else:
                    # Current block already has cycles, store as pending for next block
                    self.pending_cycles = cycles_value
            else:
                # If no current block, store as pending for the next block
                self.pending_cycles = cycles_value

        # Check for E2E total time (can appear before block start)
        e2e_match = self.e2e_total_pattern.search(line)
        if e2e_match:
            try:
                e2e_value = float(e2e_match.group(1))
            except (ValueError, IndexError) as e:
                self.malformed_lines += 1
                logging.getLogger(__name__).warning(
                    f"Malformed E2E value in line: {line[:100]}..."
                )
                return

            if self.current_block is not None and self.block_results:
                current_result = self.block_results[-1]
                if not current_result.has_e2e:
                    current_result.e2e_s = e2e_value
                    current_result.has_e2e = True
                    current_result.end_timestamp = timestamp
                else:
                    # Current block already has E2E, store as pending for next block
                    self.pending_e2e = e2e_value
            else:
                # If no current block, store as pending for the next block
                self.pending_e2e = e2e_value

        # If we're in a block, check for errors and warnings
        if self.current_block is not None and self.block_results:
            current_result = self.block_results[-1]

            # Check for errors
            if any(pattern.search(line) for pattern in self.error_patterns):
                current_result.status = "FAIL"
                if current_result.error_message is None:
                    current_result.error_message = line[
                        :200
                    ]  # Truncate long error messages

            # Check for warnings (don't fail the block, but track them)
            if any(pattern.search(line) for pattern in self.warning_patterns):
                self.warning_count += 1
                if current_result.error_message is None:
                    current_result.error_message = f"Warning detected: {line[:150]}"

    def _finalize_current_block(self) -> None:
        """Finalize the current block being processed."""
        if self.current_block is not None and self.block_results:
            result = self.block_results[-1]

            # Determine final status with enhanced validation
            if result.status == "OK":
                missing_metrics = []

                # Check if we have required metrics
                if not result.has_cycles:
                    missing_metrics.append("cycles")
                if not result.has_e2e:
                    missing_metrics.append("e2e_s")

                # Validate metric values if present
                if result.cycles is not None and result.cycles <= 0:
                    result.status = "FAIL"
                    result.error_message = f"Invalid cycles value: {result.cycles}"
                elif result.e2e_s is not None and result.e2e_s <= 0:
                    result.status = "FAIL"
                    result.error_message = f"Invalid E2E time value: {result.e2e_s}"
                elif missing_metrics:
                    result.status = "FAIL"
                    result.error_message = (
                        f"Missing required metrics: {', '.join(missing_metrics)}"
                    )

                # Check for suspicious patterns
                if (
                    result.cycles is not None and result.cycles > 1_000_000_000
                ):  # > 1B cycles seems suspicious
                    if result.error_message is None:
                        result.error_message = (
                            f"Unusually high cycles: {result.cycles:,}"
                        )

                if (
                    result.e2e_s is not None and result.e2e_s > 3600
                ):  # > 1 hour seems suspicious
                    if result.error_message is None:
                        result.error_message = (
                            f"Unusually long E2E time: {result.e2e_s:.1f}s"
                        )

            self.current_block = None

    def write_csv_output(
        self,
        results: List[BlockResult],
        output_path: str,
        log_file_path: str,
        tag: str = "",
    ) -> None:
        """
        Write results to CSV file in the required format.

        Args:
            results: List of BlockResult objects
            output_path: Path for output CSV file
            log_file_path: Original log file path for reference
            tag: Optional tag to include in results
        """
        # Ensure output directory exists
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)

        # Sort results by block number, then by execution ID (do not mutate caller list)
        sorted_results: List[BlockResult] = sorted(
            results, key=lambda x: (x.block_number, x.execution_id)
        )

        # Precompute count of executions per block to avoid O(n^2)
        per_block_counts: Dict[int, int] = {}
        for r in sorted_results:
            per_block_counts[r.block_number] = (
                per_block_counts.get(r.block_number, 0) + 1
            )

        logging.getLogger(__name__).info(
            f"Writing {len(sorted_results)} results to: {output_path}"
        )

        with open(output_path, "w", newline="", encoding="utf-8") as csvfile:
            writer = csv.writer(csvfile)

            # Write header
            writer.writerow(
                ["tag", "kind", "block", "idx", "status", "cycles", "e2e_s", "log_file"]
            )

            # Write data rows
            for result in sorted_results:
                # Only add execution ID if there are multiple executions of the same block
                block_identifier = str(result.block_number)
                if per_block_counts.get(result.block_number, 0) > 1:
                    block_identifier = f"{result.block_number}-{result.execution_id}"

                writer.writerow(
                    [
                        tag,  # tag
                        "aggregator",  # kind
                        block_identifier,  # block (with execution ID only if multiple executions)
                        "",  # idx (empty for aggregator)
                        result.status,  # status
                        result.cycles if result.cycles is not None else "NA",  # cycles
                        (
                            f"{result.e2e_s:.3f}" if result.e2e_s is not None else "NA"
                        ),  # e2e_s
                        log_file_path,  # log_file
                    ]
                )

        logging.getLogger(__name__).info(
            f"Successfully wrote CSV with {len(sorted_results)} entries"
        )

    def print_summary(self, results: List[BlockResult]) -> None:
        """Print a summary of the analysis results."""
        total_blocks = len(results)
        successful_blocks = sum(1 for r in results if r.status == "OK")
        failed_blocks = total_blocks - successful_blocks

        logger = logging.getLogger(__name__)
        logger.info(f"\n=== Analysis Summary ===")
        logger.info(f"Total blocks found: {total_blocks}")
        logger.info(f"Successful blocks: {successful_blocks}")
        logger.info(f"Failed blocks: {failed_blocks}")
        logger.info(f"Total lines processed: {self.total_lines_processed:,}")
        logger.info(f"Malformed lines: {self.malformed_lines}")
        logger.info(f"Warnings detected: {self.warning_count}")

        if self.duplicate_blocks:
            logger.info(f"Duplicate block executions: {sorted(self.duplicate_blocks)}")

        # Check for block number gaps
        if len(self.seen_blocks) > 1:
            min_block = min(self.seen_blocks)
            max_block = max(self.seen_blocks)
            expected_blocks = set(range(min_block, max_block + 1))
            missing_blocks = expected_blocks - self.seen_blocks
            if missing_blocks:
                logger.info(f"Missing block numbers: {sorted(missing_blocks)}")

        if successful_blocks > 0:
            cycles_values = [r.cycles for r in results if r.cycles is not None]
            e2e_values = [r.e2e_s for r in results if r.e2e_s is not None]

            if cycles_values:
                logger.info(
                    f"Cycles range: {min(cycles_values):,} - {max(cycles_values):,}"
                )
                logger.info(
                    f"Average cycles: {sum(cycles_values) / len(cycles_values):,.0f}"
                )
            if e2e_values:
                logger.info(
                    f"E2E time range: {min(e2e_values):.3f}s - {max(e2e_values):.3f}s"
                )
                logger.info(
                    f"Average E2E time: {sum(e2e_values) / len(e2e_values):.3f}s"
                )

        if failed_blocks > 0:
            logger.info(f"\nFailed blocks (showing first 10):")
            failed_count = 0
            for result in results:
                if result.status == "FAIL" and failed_count < 10:
                    logger.info(
                        f"  Block {result.block_number}-{result.execution_id}: {result.error_message}"
                    )
                    failed_count += 1
            if failed_blocks > 10:
                logger.info(f"  ... and {failed_blocks - 10} more failed blocks")


def _configure_logging() -> None:
    """Configure logging to preserve original stdout/stderr behavior and messages."""
    logger = logging.getLogger(__name__)
    if logger.handlers:
        return

    logger.setLevel(logging.INFO)

    stdout_handler = logging.StreamHandler(stream=sys.stdout)
    stdout_handler.setLevel(logging.INFO)

    formatter = logging.Formatter("%(message)s")
    stdout_handler.setFormatter(formatter)

    logger.addHandler(stdout_handler)


def main() -> None:
    """Main entry point for the script."""
    _configure_logging()

    parser = argparse.ArgumentParser(
        description="Analyze aggregator log files and extract block performance metrics",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python analyze_aggregator_log.py logs/aggregator-b23290390-g10000000.txt
    python analyze_aggregator_log.py logs/aggregator-b23290390-g10000000.txt output/results.csv
        """,
    )

    parser.add_argument("log_file", help="Path to the aggregator log file")
    parser.add_argument("output_csv", nargs="?", help="Output CSV file path (optional)")
    # Compatibility shim: also accept --output/-o like the batch analyzer and the shell wrapper
    parser.add_argument("--output", "-o", help="Output CSV file path (optional)")
    parser.add_argument("--tag", default="", help="Tag to include in CSV output")
    # New: per-block split + charts
    parser.add_argument(
        "--split-block-logs",
        action="store_true",
        help="Split the input log into per-block files",
    )
    parser.add_argument(
        "--split-dir",
        help="Directory to write per-block logs (defaults to <logdir>/<logstem>.blocks)",
    )
    parser.add_argument(
        "--charts",
        action="store_true",
        help="Generate timeline charts for each block (uses split logs)",
    )
    parser.add_argument(
        "--charts-dir", help="Directory to write charts (defaults to split-dir)"
    )
    parser.add_argument(
        "--include-failed",
        action="store_true",
        help="Also generate split logs/charts for failed blocks",
    )
    parser.add_argument(
        "--chart-workers",
        type=int,
        default=4,
        help="Concurrent workers for chart generation (default: 4)",
    )

    args = parser.parse_args()

    # Validate input file
    log_path = Path(args.log_file)
    if not log_path.exists():
        logging.getLogger(__name__).error(f"Error: Log file not found: {args.log_file}")
        sys.exit(1)

    if not log_path.is_file():
        logging.getLogger(__name__).error(f"Error: Path is not a file: {args.log_file}")
        sys.exit(1)

    if log_path.stat().st_size == 0:
        logging.getLogger(__name__).error(f"Error: Log file is empty: {args.log_file}")
        sys.exit(1)

    # Determine output path
    output_path: Path
    if args.output:
        output_path = Path(args.output)
    elif args.output_csv:
        output_path = Path(args.output_csv)
    else:
        # Generate output path based on input file
        log_path = Path(args.log_file)
        output_path = log_path.parent / f"{log_path.stem}_analysis.csv"

    # Create analyzer and process log
    analyzer = AggregatorLogAnalyzer()
    results = analyzer.analyze_log_file(args.log_file)

    if not results:
        logging.getLogger(__name__).info("No blocks found in the log file.")
        sys.exit(1)

    # Write CSV output
    analyzer.write_csv_output(results, str(output_path), args.log_file, args.tag)

    # Optional: split per-block logs and generate charts
    if args.split_block_logs or args.charts:
        # Filter which blocks to export
        if args.include_failed:
            blocks_to_export = {r.block_number for r in results}
        else:
            blocks_to_export = {r.block_number for r in results if r.status == "OK"}

        log_path = Path(args.log_file)
        default_split_dir = log_path.parent / f"{log_path.stem}.blocks"
        split_dir = Path(args.split_dir) if args.split_dir else default_split_dir
        segments = analyzer.split_log_by_block(
            str(log_path), split_dir, blocks_to_export
        )

        if args.charts:
            charts_dir = Path(args.charts_dir) if args.charts_dir else split_dir
            analyzer.generate_timeline_for_blocks(
                segments, charts_dir, chart_workers=args.chart_workers
            )

    # Print summary
    analyzer.print_summary(results)

    logging.getLogger(__name__).info(
        f"\nAnalysis complete. Results saved to: {output_path}"
    )
    if args.split_block_logs:
        logging.getLogger(__name__).info("Per-block logs written.")
    if args.charts:
        logging.getLogger(__name__).info("Per-block timeline charts written.")


if __name__ == "__main__":
    main()
