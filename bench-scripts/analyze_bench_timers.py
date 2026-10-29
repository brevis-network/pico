#!/usr/bin/env python3
"""
Analyze [bench-timer] logs from the distributed prover pipeline.
Groups timing data by block number, with per-block and overall summaries.

Usage:
    python3 analyze_bench_timers.py <log_file> [block_list_file]

If block_list_file is not provided, blocks are auto-detected from log lines
matching "Begin block NNNNNN".
"""

import sys
import re
from collections import defaultdict, OrderedDict


def parse_logs(file_path, block_list=None):
    timer_pattern = re.compile(r"\[bench-timer\] (.*?): ([\d.]+) ms")
    block_begin_pattern = re.compile(r"Begin block (\d+)")
    e2e_pattern = re.compile(r"E2E_total\s*=\s*([\d.]+)\s*s")

    # Data: block_number -> label -> [times]
    block_data = OrderedDict()
    current_block = "__init__"  # timers before any block starts (setup phase)
    block_data[current_block] = defaultdict(list)
    e2e_times = {}

    with open(file_path, "r") as f:
        for line in f:
            # Detect block transitions
            bm = block_begin_pattern.search(line)
            if bm:
                current_block = bm.group(1)
                if current_block not in block_data:
                    block_data[current_block] = defaultdict(list)
                continue

            # Detect E2E total
            em = e2e_pattern.search(line)
            if em:
                e2e_times[current_block] = float(em.group(1))
                continue

            # Parse bench-timer lines
            tm = timer_pattern.search(line)
            if tm:
                label = tm.group(1)
                time_ms = float(tm.group(2))
                # Normalize: strip (chunk-N) / (deferred-N) for grouping
                base_label = re.sub(r"\(.*?\)", "", label).strip()
                block_data[current_block][base_label].append(time_ms)

    return block_data, e2e_times


def print_block_summary(block_id, data, e2e=None):
    if not data:
        return

    title = f"Block {block_id}" if block_id != "__init__" else "Initialization (before any block)"
    print(f"\n{'='*110}")
    print(f"  {title}")
    if e2e is not None:
        print(f"  E2E_total = {e2e:.3f} s")
    print(f"{'='*110}")
    print(f"  {'Label':<55} | {'Count':>5} | {'Total(ms)':>10} | {'Avg(ms)':>10} | {'Min(ms)':>10} | {'Max(ms)':>10}")
    print(f"  {'-'*55}-+-{'-'*5}-+-{'-'*10}-+-{'-'*10}-+-{'-'*10}-+-{'-'*10}")

    chip_prefix = "BaseProver.gpu_generate_extra_record_and_main."
    for label in sorted(data.keys()):
        if label.startswith(chip_prefix):
            continue
        times = data[label]
        count = len(times)
        total = sum(times)
        avg = total / count
        mn = min(times)
        mx = max(times)
        print(f"  {label:<55} | {count:>5} | {total:>10.1f} | {avg:>10.3f} | {mn:>10.3f} | {mx:>10.3f}")


def print_overall_summary(block_data, e2e_times):
    """Print a cross-block comparison table."""
    # Collect all labels
    all_labels = set()
    block_ids = [b for b in block_data if b != "__init__"]
    for bid in block_ids:
        all_labels.update(block_data[bid].keys())
    all_labels = sorted(all_labels)

    if not block_ids or not all_labels:
        return

    print(f"\n{'#'*110}")
    print(f"  CROSS-BLOCK COMPARISON (Avg ms per label)")
    print(f"{'#'*110}")

    # Header
    header = f"  {'Label':<45}"
    for bid in block_ids:
        header += f" | {bid:>10}"
    print(header)
    print(f"  {'-'*45}" + ("-+-" + "-" * 10) * len(block_ids))

    chip_prefix = "BaseProver.gpu_generate_extra_record_and_main."
    for label in all_labels:
        if label.startswith(chip_prefix):
            continue
        row = f"  {label:<45}"
        for bid in block_ids:
            times = block_data[bid].get(label, [])
            if times:
                avg = sum(times) / len(times)
                row += f" | {avg:>10.1f}"
            else:
                row += f" | {'N/A':>10}"
        print(row)

    # E2E row
    row = f"  {'E2E_total (s)':<45}"
    for bid in block_ids:
        e2e = e2e_times.get(bid)
        if e2e is not None:
            row += f" | {e2e:>10.3f}"
        else:
            row += f" | {'N/A':>10}"
    print(f"  {'-'*45}" + ("-+-" + "-" * 10) * len(block_ids))
    print(row)


def _collect_chip_times(data):
    """Extract per-chip gpu_generate_extra_record_and_main times from a single block's data dict."""
    prefix = "BaseProver.gpu_generate_extra_record_and_main."
    chip_times = defaultdict(list)
    for label, times in data.items():
        if label.startswith(prefix):
            chip_name = label[len(prefix):]
            chip_times[chip_name].extend(times)
    return chip_times


def _collect_prove_impl_times(data):
    """Extract prove_impl.* times from a single block's data dict."""
    prefix = "prove_impl."
    prove_impl_times = OrderedDict()
    for label, times in data.items():
        if label.startswith(prefix):
            prove_impl_times[label] = times
    return prove_impl_times


def _print_prove_impl_table(prove_impl_times, title):
    """Print a prove_impl timing breakdown table."""
    if not prove_impl_times:
        return

    rows = []
    for label, times in prove_impl_times.items():
        calls = len(times)
        total_ms = sum(times)
        avg_ms = total_ms / calls
        total_s = total_ms / 1000.0
        rows.append((label, calls, avg_ms, total_ms, total_s))

    rows.sort(key=lambda r: r[3], reverse=True)

    grand_calls = sum(r[1] for r in rows)
    grand_total_ms = sum(r[3] for r in rows)
    grand_total_s = grand_total_ms / 1000.0

    print(f"\nprove_impl Breakdown: {title}")
    print("-" * 90)
    print(f"{'Stage':<50} | {'Calls':>6} | {'Avg (ms)':>10} | {'Total (ms)':>12} | {'Total (s)':>10}")
    print("-" * 90)
    for label, calls, avg_ms, total_ms, total_s in rows:
        print(f"{label:<50} | {calls:>6} | {avg_ms:>10.3f} | {total_ms:>12.3f} | {total_s:>10.3f}")
    print("-" * 90)
    print(f"{'TOTAL':<50} | {grand_calls:>6} |            | {grand_total_ms:>12.3f} | {grand_total_s:>10.3f}")
    print("-" * 90)


def _print_chip_table(chip_times, title):
    """Print a per-chip timing table given a chip_times dict and a title string."""
    if not chip_times:
        return

    rows = []
    for chip_name, times in chip_times.items():
        calls = len(times)
        total_ms = sum(times)
        avg_ms = total_ms / calls
        total_s = total_ms / 1000.0
        rows.append((chip_name, calls, avg_ms, total_ms, total_s))

    rows.sort(key=lambda r: r[3], reverse=True)

    grand_calls = sum(r[1] for r in rows)
    grand_total_ms = sum(r[3] for r in rows)
    grand_total_s = grand_total_ms / 1000.0

    print(f"\nPer-Chip gpu_generate_extra_record_and_main Timing: {title}")
    print("-" * 90)
    print(f"{'Chip':<35} | {'Calls':>6} | {'Avg (ms)':>10} | {'Total (ms)':>12} | {'Total (s)':>10}")
    print("-" * 90)
    for chip_name, calls, avg_ms, total_ms, total_s in rows:
        print(f"{chip_name:<35} | {calls:>6} | {avg_ms:>10.3f} | {total_ms:>12.3f} | {total_s:>10.3f}")
    print("-" * 90)
    print(f"{'TOTAL':<35} | {grand_calls:>6} |            | {grand_total_ms:>12.3f} | {grand_total_s:>10.3f}")
    print("-" * 90)


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 analyze_bench_timers.py <log_file> [block_list_file]")
        sys.exit(1)

    log_file = sys.argv[1]
    block_list = None
    if len(sys.argv) >= 3:
        with open(sys.argv[2], "r") as f:
            block_list = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    block_data, e2e_times = parse_logs(log_file, block_list)

    if not any(block_data.values()):
        print("No [bench-timer] logs found in the provided file.")
        return

    # Print per-block summaries + per-chip breakdown + prove_impl breakdown per block
    for block_id, data in block_data.items():
        if data:
            print_block_summary(block_id, data, e2e_times.get(block_id))
            title = f"Block {block_id}" if block_id != "__init__" else "Initialization"
            chip_times = _collect_chip_times(data)
            _print_chip_table(chip_times, title)
            prove_impl_times = _collect_prove_impl_times(data)
            _print_prove_impl_table(prove_impl_times, title)

    # Print cross-block comparison
    print_overall_summary(block_data, e2e_times)

    # Print overall per-chip aggregation across all blocks
    all_chip_times = defaultdict(list)
    for block_id, data in block_data.items():
        for chip_name, times in _collect_chip_times(data).items():
            all_chip_times[chip_name].extend(times)
    _print_chip_table(all_chip_times, "ALL BLOCKS")

    # Print overall prove_impl aggregation across all blocks
    all_prove_impl_times = OrderedDict()
    for block_id, data in block_data.items():
        for label, times in _collect_prove_impl_times(data).items():
            if label not in all_prove_impl_times:
                all_prove_impl_times[label] = []
            all_prove_impl_times[label].extend(times)
    _print_prove_impl_table(all_prove_impl_times, "ALL BLOCKS")


if __name__ == "__main__":
    main()
