#!/usr/bin/env python3
"""
Parse blocks whose e2e times exceed the SLA threshold.

Usage:
    python parse_sla_violations.py <csv_file>
    python parse_sla_violations.py data/run16_t12_u4_lt_gj_4167.csv --threshold 10
    python parse_sla_violations.py data/run16_t12_u4_lt_gj_4167.csv -o violations.csv
"""

import argparse
import os
import sys

import pandas as pd

THRESHOLD_S = 12


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Parse blocks whose e2e times exceed the SLA threshold."
    )
    parser.add_argument(
        "csv_file", help="Path to the CSV file containing an 'e2e_s' column"
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=THRESHOLD_S,
        help=f"SLA threshold in seconds (default: {THRESHOLD_S})",
    )
    parser.add_argument(
        "-o",
        "--output",
        default=None,
        help="Write violation rows to a CSV file",
    )
    parser.add_argument(
        "--sort",
        choices=["e2e", "block", "cycles"],
        default="e2e",
        help="Sort violations by this field (default: e2e, descending)",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    csv_path = args.csv_file
    if not os.path.isfile(csv_path):
        sys.exit(f"Error: file not found: {csv_path}")

    df = pd.read_csv(csv_path)
    if "e2e_s" not in df.columns:
        sys.exit(
            f"Error: column 'e2e_s' not found in {csv_path}. "
            f"Available: {list(df.columns)}"
        )

    threshold: float = args.threshold
    total = len(df)
    violations: pd.DataFrame = df.loc[df["e2e_s"] > threshold].copy()
    n_violations = len(violations)
    pct = n_violations / total * 100 if total > 0 else 0.0

    sort_col: str = {"e2e": "e2e_s", "block": "block", "cycles": "cycles"}[args.sort]
    ascending: bool = args.sort == "block"
    violations = violations.sort_values(by=sort_col, ascending=ascending)

    # --- summary -----------------------------------------------------------
    print(f"{'=' * 60}")
    print(f"  SLA VIOLATIONS  (threshold > {threshold:.0f}s)")
    print(f"{'=' * 60}")
    print(f"  Source:      {csv_path}")
    print(f"  Total:       {total:,} blocks")
    print(f"  Violations:  {n_violations:,} blocks  ({pct:.1f}%)")
    print(f"  Within SLA:  {total - n_violations:,} blocks  ({100 - pct:.1f}%)")

    if n_violations == 0:
        print(f"\n  No blocks exceed {threshold:.0f}s.")
        print(f"{'=' * 60}")
        return

    v_times = violations["e2e_s"]
    print(f"{'- ' * 30}")
    print(f"  Violation stats:")
    print(f"    Mean:    {v_times.mean():.2f}s")
    print(f"    Median:  {v_times.median():.2f}s")
    print(f"    Min:     {v_times.min():.2f}s")
    print(f"    Max:     {v_times.max():.2f}s")
    print(f"    Std:     {v_times.std():.2f}s")

    if "cycles" in violations.columns:
        v_cycles = violations["cycles"].dropna()
        if len(v_cycles) > 0:
            print(f"    Cycles (mean):  {v_cycles.mean():,.0f}")
            print(f"    Cycles (max):   {v_cycles.max():,.0f}")

    print(f"{'= ' * 30}")

    # --- per-block table ---------------------------------------------------
    display_cols = [
        c
        for c in ["block", "e2e_s", "cycles", "kind", "status", "tag"]
        if c in violations.columns
    ]
    print(f"\n  {'Sorted by':>10}: {args.sort} ({'asc' if ascending else 'desc'})")
    print()
    print(violations[display_cols].to_string(index=False))
    print("\n--- BLOCK LIST ONLY ---")
    for b in violations["block"]:
        print(b)

    # --- optional CSV export -----------------------------------------------
    if args.output:
        violations.to_csv(args.output, index=False)
        print(f"\nViolations written to: {args.output}")


if __name__ == "__main__":
    main()
