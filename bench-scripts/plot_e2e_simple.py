#!/usr/bin/env python3
"""
Simple e2e histogram with 1-second buckets.
Values > threshold are clamped into a single ">N" bucket.

Usage:
    python plot_e2e_simple.py <csv_file> [--threshold 12]
"""

import argparse
import os
import sys

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd


def main():
    parser = argparse.ArgumentParser(description="Simple 1s-bucket e2e histogram")
    parser.add_argument("csv_file", help="CSV file with 'e2e_s' column")
    parser.add_argument("--threshold", type=float, default=12, help="Threshold in seconds (default: 12)")
    parser.add_argument("-o", "--output", default=None, help="Output stem (default: <csv>_simple_hist)")
    args = parser.parse_args()

    if not os.path.isfile(args.csv_file):
        sys.exit(f"Error: file not found: {args.csv_file}")

    df = pd.read_csv(args.csv_file)
    if "e2e_s" not in df.columns:
        sys.exit(f"Error: 'e2e_s' column not found. Available: {list(df.columns)}")

    e2e = df["e2e_s"].dropna().values.astype(float)
    threshold = args.threshold
    thr = int(threshold)
    total = len(e2e)
    n_above = int((e2e > threshold).sum())
    n_below = total - n_above

    # Clamp values > threshold to threshold + 0.5, so they all land in [threshold, threshold+1) bin
    e2e_clamped = np.where(e2e > threshold, threshold + 0.5, e2e)

    # 1-second bins from floor(min) to threshold+1
    bin_min = int(np.floor(e2e.min()))
    bins = np.arange(bin_min, thr + 2, 1)  # e.g. [1, 2, ..., 12, 13]

    fig, ax = plt.subplots(figsize=(14, 5))
    fig.patch.set_facecolor("#fafafa")
    ax.set_facecolor("#fafafa")

    counts, edges, patches = ax.hist(e2e_clamped, bins=bins, edgecolor="white", linewidth=0.8)

    # Color bars: blue if < threshold, red for the >threshold bucket
    for patch, left in zip(patches, edges[:-1]):
        if left >= threshold:
            patch.set_facecolor("#E07A5F")
            patch.set_edgecolor("#C96A52")
        else:
            patch.set_facecolor("#6C9BC2")
            patch.set_edgecolor("#5A87AD")
        patch.set_alpha(0.88)

    # Count labels on top of each bar
    for count, patch in zip(counts, patches):
        if count > 0:
            ax.text(
                patch.get_x() + patch.get_width() / 2, count + max(counts) * 0.015,
                f"{int(count)}", ha="center", va="bottom", fontsize=8, fontweight="bold",
            )

    # Ratio annotation box
    ratio_text = (
        f"≤{thr}s: {n_below:,} / {total:,}  ({n_below/total*100:.1f}%)\n"
        f">{thr}s:  {n_above:,} / {total:,}  ({n_above/total*100:.1f}%)"
    )
    ax.text(
        0.02, 0.95, ratio_text, transform=ax.transAxes, fontsize=10, fontfamily="monospace",
        va="top", bbox=dict(boxstyle="round,pad=0.4", facecolor="white", edgecolor="#cccccc", alpha=0.9),
    )

    # Axis labels and ticks — replace last tick label with ">threshold"
    ax.set_xlabel("E2E Time (seconds)", fontsize=12, fontweight="bold")
    ax.set_ylabel("Block Count", fontsize=12, fontweight="bold")
    block_min = int(df["block"].min()) if "block" in df.columns else "?"
    block_max = int(df["block"].max()) if "block" in df.columns else "?"
    ax.set_title(f"E2E Block Time Distribution ({block_min}-{block_max})", fontsize=14, fontweight="bold")

    tick_positions = list(bins[:-1])
    tick_labels = [str(b) for b in bins[:-1]]
    tick_labels[-1] = f">{thr}"
    ax.set_xticks(tick_positions)
    ax.set_xticklabels(tick_labels)

    ax.tick_params(axis="both", labelsize=10)
    ax.grid(axis="y", color="#dddddd", ls=":", lw=0.5, alpha=0.7)
    for spine in ("top", "right"):
        ax.spines[spine].set_visible(False)

    plt.tight_layout()

    output_stem = args.output or (os.path.splitext(args.csv_file)[0] + "_simple_hist")
    fig.savefig(f"{output_stem}.png", dpi=300, bbox_inches="tight", facecolor=fig.get_facecolor())
    fig.savefig(f"{output_stem}.pdf", bbox_inches="tight", facecolor=fig.get_facecolor())
    print(f"Saved: {output_stem}.png")
    print(f"Saved: {output_stem}.pdf")
    print(f"\n≤{thr}s: {n_below:,} ({n_below/total*100:.1f}%)  |  >{thr}s: {n_above:,} ({n_above/total*100:.1f}%)")


if __name__ == "__main__":
    main()
