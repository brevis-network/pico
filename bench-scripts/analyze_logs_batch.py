#!/usr/bin/env python3
"""
Batch Aggregator Log Analysis Tool

This script processes multiple aggregator log files and combines the results
into a single CSV file. It's designed to handle large-scale log analysis
with 10,000+ blocks across multiple files.

Usage:
    python analyze_logs_batch.py <log_directory> [output_csv]
    python analyze_logs_batch.py <log_file1> <log_file2> ... [output_csv]

Examples:
    # Process all log files in a directory
    python analyze_logs_batch.py logs/

    # Process specific log files
    python analyze_logs_batch.py logs/aggregator-*.txt

    # Specify output file
    python analyze_logs_batch.py logs/ output/combined_results.csv
"""

import argparse
import csv
import logging
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, Iterable, List, Set

from analyze_aggregator_log import AggregatorLogAnalyzer, BlockResult


def find_log_files(paths: List[str]) -> List[Path]:
    """
    Find all aggregator log files from the given paths.

    Args:
        paths: List of file/directory paths to search

    Returns:
        List of Path objects for found log files
    """
    log_files: List[Path] = []
    skipped_files: List[str] = []

    for path_str in paths:
        path = Path(path_str)

        if path.is_file():
            # Single file
            if path.name.startswith("aggregator-") and path.suffix == ".txt":
                # Additional validation
                if path.stat().st_size == 0:
                    logging.getLogger(__name__).warning(
                        f"Warning: Skipping empty file: {path}"
                    )
                    skipped_files.append(str(path))
                else:
                    log_files.append(path)
            else:
                logging.getLogger(__name__).warning(
                    f"Warning: Skipping non-aggregator file: {path}"
                )
                skipped_files.append(str(path))
        elif path.is_dir():
            # Directory - find all aggregator log files
            try:
                for log_file in path.glob("aggregator-*.txt"):
                    if log_file.stat().st_size == 0:
                        logging.getLogger(__name__).warning(
                            f"Warning: Skipping empty file: {log_file}"
                        )
                        skipped_files.append(str(log_file))
                    else:
                        log_files.append(log_file)
            except PermissionError:
                logging.getLogger(__name__).error(
                    f"Error: Permission denied accessing directory: {path}"
                )
        else:
            logging.getLogger(__name__).warning(f"Warning: Path not found: {path}")
            skipped_files.append(str(path))

    if skipped_files:
        logging.getLogger(__name__).info(
            f"Skipped {len(skipped_files)} files/directories"
        )

    return sorted(log_files)


def process_log_files(
    log_files: List[Path],
    tag: str = "",
    split_block_logs: bool = False,
    charts: bool = False,
    include_failed: bool = False,
    split_base: Path | None = None,
    charts_base: Path | None = None,
    chart_workers: int = 4,
) -> List[BlockResult]:
    """
    Process multiple log files and combine results.

    Args:
        log_files: List of log file paths to process
        tag: Optional tag to include in results

    Returns:
        Combined list of BlockResult objects
    """
    all_results: List[BlockResult] = []
    processing_stats = {
        "successful_files": 0,
        "failed_files": 0,
        "total_blocks": 0,
        "total_lines": 0,
        "malformed_lines": 0,
        "warnings": 0,
    }

    logging.getLogger(__name__).info(f"Processing {len(log_files)} log files...")

    for i, log_file in enumerate(log_files, 1):
        logging.getLogger(__name__).info(
            f"\n[{i}/{len(log_files)}] Processing: {log_file.name}"
        )

        try:
            # Create a fresh analyzer for each file to avoid state contamination
            # This ensures memory efficiency for large-scale processing (10k+ blocks)
            analyzer = AggregatorLogAnalyzer()
            results = analyzer.analyze_log_file(str(log_file))

            # Add tag to results if provided
            if tag:
                for result in results:
                    setattr(result, "tag", tag)

            # Add log file path to each result for better traceability
            for result in results:
                setattr(result, "log_file", str(log_file))

            all_results.extend(results)
            processing_stats["successful_files"] += 1
            processing_stats["total_blocks"] += len(results)
            processing_stats["total_lines"] += analyzer.total_lines_processed
            processing_stats["malformed_lines"] += analyzer.malformed_lines
            processing_stats["warnings"] += analyzer.warning_count

            logging.getLogger(__name__).info(f"  Found {len(results)} blocks")

            # Optional: split logs and/or draw charts per block for this file
            # For large-scale scenarios (10k+ blocks), this is done per-file to manage memory
            if split_block_logs or charts:
                if include_failed:
                    blocks_to_export: Set[int] = {r.block_number for r in results}
                else:
                    blocks_to_export = {
                        r.block_number for r in results if r.status == "OK"
                    }

                # Only process if we have blocks to export (avoids unnecessary work)
                if blocks_to_export:
                    stem = log_file.stem
                    default_split_dir = (
                        split_base if split_base else log_file.parent
                    ) / f"{stem}.blocks"
                    segments = analyzer.split_log_by_block(
                        str(log_file), default_split_dir, blocks_to_export
                    )

                    if charts and segments:
                        default_charts_dir = (
                            charts_base if charts_base else default_split_dir
                        )
                        analyzer.generate_timeline_for_blocks(
                            segments, default_charts_dir, chart_workers=chart_workers
                        )

            # Show file-level summary if there are issues
            if analyzer.malformed_lines > 0 or analyzer.warning_count > 0:
                logging.getLogger(__name__).info(
                    f"  File issues: {analyzer.malformed_lines} malformed lines, {analyzer.warning_count} warnings"
                )

        except Exception as e:
            logging.getLogger(__name__).error(f"  Error processing {log_file}: {e}")
            processing_stats["failed_files"] += 1
            continue

    # Print processing summary
    logging.getLogger(__name__).info(f"\n=== Processing Summary ===")
    logging.getLogger(__name__).info(
        f"Successful files: {processing_stats['successful_files']}"
    )
    logging.getLogger(__name__).info(
        f"Failed files: {processing_stats['failed_files']}"
    )
    logging.getLogger(__name__).info(
        f"Total blocks processed: {processing_stats['total_blocks']}"
    )
    logging.getLogger(__name__).info(
        f"Total lines processed: {processing_stats['total_lines']:,}"
    )
    logging.getLogger(__name__).info(
        f"Total malformed lines: {processing_stats['malformed_lines']}"
    )
    logging.getLogger(__name__).info(f"Total warnings: {processing_stats['warnings']}")

    return all_results


def write_combined_csv(
    results: List[BlockResult], output_path: str, tag: str = ""
) -> None:
    """
    Write combined results to CSV file with memory-efficient processing for large datasets.

    Args:
        results: List of BlockResult objects
        output_path: Path for output CSV file
        tag: Optional tag to include in results
    """
    # Ensure output directory exists
    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)

    # For large datasets (10k+ blocks), use memory-efficient sorting
    # Sort results by block number, then by execution ID (without mutating input)
    sorted_results: List[BlockResult] = sorted(
        results, key=lambda x: (x.block_number, x.execution_id)
    )

    # Precompute counts to avoid O(n^2) - memory efficient for large datasets
    per_block_counts: Dict[int, int] = {}
    for r in sorted_results:
        per_block_counts[r.block_number] = per_block_counts.get(r.block_number, 0) + 1

    logging.getLogger(__name__).info(
        f"\nWriting {len(sorted_results)} combined results to: {output_path}"
    )

    # Use buffered writing for large datasets
    with open(
        output_path, "w", newline="", encoding="utf-8", buffering=8192
    ) as csvfile:
        writer = csv.writer(csvfile)

        # Write header
        writer.writerow(
            ["tag", "kind", "block", "idx", "status", "cycles", "e2e_s", "log_file"]
        )

        # Write data rows in batches for memory efficiency
        batch_size = 1000  # Process in batches to manage memory for very large datasets
        for i in range(0, len(sorted_results), batch_size):
            batch = sorted_results[i : i + batch_size]
            for result in batch:
                # Only add execution ID if there are multiple executions of the same block
                block_identifier = str(result.block_number)
                if per_block_counts.get(result.block_number, 0) > 1:
                    block_identifier = f"{result.block_number}-{result.execution_id}"

                writer.writerow(
                    [
                        getattr(result, "tag", tag),  # tag
                        "aggregator",  # kind
                        block_identifier,  # block (with execution ID only if multiple executions)
                        "",  # idx (empty for aggregator)
                        result.status,  # status
                        result.cycles if result.cycles is not None else "NA",  # cycles
                        (
                            f"{result.e2e_s:.3f}" if result.e2e_s is not None else "NA"
                        ),  # e2e_s
                        getattr(result, "log_file", ""),  # log_file
                    ]
                )

    logging.getLogger(__name__).info(
        f"Successfully wrote combined CSV with {len(sorted_results)} entries"
    )


def print_combined_summary(results: List[BlockResult]) -> None:
    """Print a summary of the combined analysis results."""
    total_blocks = len(results)
    successful_blocks = sum(1 for r in results if r.status == "OK")
    failed_blocks = total_blocks - successful_blocks

    logger = logging.getLogger(__name__)
    logger.info(f"\n=== Combined Analysis Summary ===")
    logger.info(f"Total blocks found: {total_blocks}")
    logger.info(f"Successful blocks: {successful_blocks}")
    logger.info(f"Failed blocks: {failed_blocks}")

    # Calculate success rate
    if total_blocks > 0:
        success_rate = (successful_blocks / total_blocks) * 100
        logger.info(f"Success rate: {success_rate:.1f}%")

    # Group results by log file for better insights
    results_by_file = defaultdict(list)
    for result in results:
        log_file = getattr(result, "log_file", "unknown")
        results_by_file[log_file].append(result)

    logger.info(f"\nResults by log file:")
    for log_file, file_results in results_by_file.items():
        file_successful = sum(1 for r in file_results if r.status == "OK")
        file_total = len(file_results)
        file_success_rate = (
            (file_successful / file_total) * 100 if file_total > 0 else 0
        )
        logger.info(
            f"  {Path(log_file).name}: {file_successful}/{file_total} blocks ({file_success_rate:.1f}% success)"
        )

    if successful_blocks > 0:
        cycles_values = [r.cycles for r in results if r.cycles is not None]
        e2e_values = [r.e2e_s for r in results if r.e2e_s is not None]

        if cycles_values:
            logger.info(f"\nCycles statistics:")
            logger.info(f"  Range: {min(cycles_values):,} - {max(cycles_values):,}")
            logger.info(f"  Average: {sum(cycles_values) / len(cycles_values):,.0f}")

            # Calculate percentiles
            sorted_cycles = sorted(cycles_values)
            p50_idx = len(sorted_cycles) // 2
            p95_idx = int(len(sorted_cycles) * 0.95)
            logger.info(f"  Median (P50): {sorted_cycles[p50_idx]:,}")
            logger.info(f"  P95: {sorted_cycles[p95_idx]:,}")

        if e2e_values:
            logger.info(f"\nE2E time statistics:")
            logger.info(f"  Range: {min(e2e_values):.3f}s - {max(e2e_values):.3f}s")
            logger.info(f"  Average: {sum(e2e_values) / len(e2e_values):.3f}s")

            # Calculate percentiles
            sorted_e2e = sorted(e2e_values)
            p50_idx = len(sorted_e2e) // 2
            p95_idx = int(len(sorted_e2e) * 0.95)
            logger.info(f"  Median (P50): {sorted_e2e[p50_idx]:.3f}s")
            logger.info(f"  P95: {sorted_e2e[p95_idx]:.3f}s")

    if failed_blocks > 0:
        logger.info(f"\nFailed blocks (showing first 10):")
        failed_count = 0
        for result in results:
            if result.status == "FAIL" and failed_count < 10:
                log_file = getattr(result, "log_file", "unknown")
                logger.info(
                    f"  Block {result.block_number}-{result.execution_id} ({Path(log_file).name}): {result.error_message}"
                )
                failed_count += 1
        if failed_blocks > 10:
            logger.info(f"  ... and {failed_blocks - 10} more failed blocks")

        # Show failure reasons summary
        failure_reasons = defaultdict(int)
        for result in results:
            if result.status == "FAIL" and result.error_message:
                # Extract the main reason (first part before colon or comma)
                reason = result.error_message.split(":")[0].split(",")[0].strip()
                failure_reasons[reason] += 1

        if failure_reasons:
            logger.info(f"\nFailure reasons summary:")
            for reason, count in sorted(
                failure_reasons.items(), key=lambda x: x[1], reverse=True
            ):
                logger.info(f"  {reason}: {count} blocks")


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
    """Main entry point for the batch analysis script."""
    _configure_logging()

    parser = argparse.ArgumentParser(
        description="Batch analyze multiple aggregator log files and combine results",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Process all log files in a directory
    python analyze_logs_batch.py logs/
    
    # Process specific log files
    python analyze_logs_batch.py logs/aggregator-b23290390-g10000000.txt logs/aggregator-b23290391-g10000000.txt
    
    # Process with custom tag and output
    python analyze_logs_batch.py logs/ --tag "experiment_1" --output results/combined.csv
    
    # Process with wildcards (use quotes to prevent shell expansion)
    python analyze_logs_batch.py "logs/aggregator-*.txt"
        """,
    )

    parser.add_argument(
        "paths", nargs="+", help="Log file paths or directories to process"
    )
    parser.add_argument("--output", "-o", help="Output CSV file path (optional)")
    parser.add_argument("--tag", default="", help="Tag to include in CSV output")
    # New pass-through flags for splitting and charts
    parser.add_argument(
        "--split-block-logs",
        action="store_true",
        help="Split each log into per-block files",
    )
    parser.add_argument(
        "--split-dir",
        help="Base directory to put per-block logs (default: next to log file)",
    )
    parser.add_argument(
        "--charts", action="store_true", help="Generate timeline charts for each block"
    )
    parser.add_argument(
        "--charts-dir", help="Base directory to put charts (default: split dir)"
    )
    parser.add_argument(
        "--include-failed", action="store_true", help="Also generate for failed blocks"
    )
    parser.add_argument(
        "--chart-workers",
        type=int,
        default=4,
        help="Concurrent workers for chart generation (default: 4)",
    )

    args = parser.parse_args()

    # Find log files
    log_files = find_log_files(args.paths)

    if not log_files:
        logging.getLogger(__name__).info(
            "No aggregator log files found in the specified paths."
        )
        sys.exit(1)

    logging.getLogger(__name__).info(f"Found {len(log_files)} aggregator log files:")
    for log_file in log_files:
        logging.getLogger(__name__).info(f"  {log_file}")

    # Process log files
    results = process_log_files(
        log_files,
        args.tag,
        split_block_logs=args.split_block_logs,
        charts=args.charts,
        include_failed=args.include_failed,
        split_base=Path(args.split_dir) if args.split_dir else None,
        charts_base=Path(args.charts_dir) if args.charts_dir else None,
        chart_workers=args.chart_workers,
    )

    if not results:
        logging.getLogger(__name__).info("No blocks found in any of the log files.")
        sys.exit(1)

    # Determine output path
    if args.output:
        output_path = args.output
    else:
        # Generate output path based on input
        if len(log_files) == 1:
            output_path = log_files[0].parent / f"{log_files[0].stem}_analysis.csv"
        else:
            output_path = Path("combined_aggregator_analysis.csv")

    # Write combined CSV
    write_combined_csv(results, str(output_path), args.tag)

    # Print summary
    print_combined_summary(results)

    logging.getLogger(__name__).info(
        f"\nBatch analysis complete. Results saved to: {output_path}"
    )


if __name__ == "__main__":
    main()
