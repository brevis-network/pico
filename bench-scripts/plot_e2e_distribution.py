#!/usr/bin/env python3
"""
Plot e2e total time distribution from a CSV file.
Highlights the 12s critical threshold with dual-colored bars.

Usage:
    python plot_e2e_distribution.py <csv_file>
    python plot_e2e_distribution.py data/run16_t12_u4_lt_gj_4167.csv
"""

import argparse
import os
import sys
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd


# ---------------------------------------------------------------------------
# Color palette
# ---------------------------------------------------------------------------
CLR_PASS = "#6C9BC2"  # muted steel blue — blocks within SLA
CLR_FAIL = "#E07A5F"  # soft terracotta  — blocks exceeding threshold
CLR_PASS_EDGE = "#5A87AD"
CLR_FAIL_EDGE = "#C96A52"
CLR_THRESHOLD = "#C0392B"
CLR_MEAN = "#8E7CC3"  # muted purple
CLR_MEDIAN = "#F0AD4E"  # warm amber
CLR_BG = "#fafafa"
CLR_GRID = "#dddddd"
THRESHOLD_S = 12


def parse_args():
    parser = argparse.ArgumentParser(
        description="Plot e2e total time distribution with 12s threshold analysis."
    )
    parser.add_argument(
        "csv_file", help="Path to the CSV file containing an 'e2e_s' column"
    )
    parser.add_argument(
        "-o",
        "--output",
        default=None,
        help="Output file path (without extension). Defaults to <csv_stem>_e2e_dist",
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=THRESHOLD_S,
        help=f"SLA threshold in seconds (default: {THRESHOLD_S})",
    )
    return parser.parse_args()


def load_data(csv_path: str) -> pd.Series:
    df = pd.read_csv(csv_path)
    if "e2e_s" not in df.columns:
        sys.exit(
            f"Error: column 'e2e_s' not found in {csv_path}. "
            f"Available: {list(df.columns)}"
        )
    return pd.Series(df["e2e_s"].dropna().values, dtype=float)


def plot(e2e_times: pd.Series, threshold: float, output_stem: str, source_label: str):
    # ---- statistics --------------------------------------------------------
    total = len(e2e_times)
    mean_t = e2e_times.mean()
    median_t = e2e_times.median()
    std_t = e2e_times.std()
    p90_t = e2e_times.quantile(0.90)
    p95_t = e2e_times.quantile(0.95)
    p99_t = e2e_times.quantile(0.99)
    n_above = int((e2e_times > threshold).sum())
    n_below = total - n_above
    pct_above = n_above / total * 100
    pct_below = 100 - pct_above

    # ---- figure setup ------------------------------------------------------
    fig, (ax_main, ax_box) = plt.subplots(
        2,
        1,
        figsize=(13, 8),
        gridspec_kw={"height_ratios": [5, 1], "hspace": 0.08},
        sharex=True,
    )
    fig.patch.set_facecolor(CLR_BG)
    for ax in (ax_main, ax_box):
        ax.set_facecolor(CLR_BG)

    # ---- histogram with dual-color bars ------------------------------------
    thr = int(threshold)
    e2e_clamped = np.where(e2e_times > threshold, threshold + 0.5, e2e_times)
    bins = np.arange(int(np.floor(e2e_times.min())), thr + 2, 1)
    _, bin_edges, patches = ax_main.hist(
        e2e_clamped,
        bins=bins,
        edgecolor="white",
        linewidth=0.6,
    )
    for patch, left_edge in zip(patches, bin_edges[:-1]):
        if left_edge >= threshold:
            patch.set_facecolor(CLR_FAIL)
            patch.set_edgecolor(CLR_FAIL_EDGE)
        else:
            patch.set_facecolor(CLR_PASS)
            patch.set_edgecolor(CLR_PASS_EDGE)
        patch.set_alpha(0.85)

    # ---- threshold line + shaded region ------------------------------------
    ax_main.axvline(
        x=threshold,
        color=CLR_THRESHOLD,
        linestyle="-",
        linewidth=2.5,
        zorder=5,
    )
    y_max = ax_main.get_ylim()[1]
    ax_main.fill_betweenx(
        [0, y_max],
        threshold,
        e2e_times.max() * 1.02,
        color=CLR_FAIL,
        alpha=0.06,
        zorder=0,
    )

    # threshold annotation
    ax_main.annotate(
        f"{threshold:.0f}s SLA",
        xy=(threshold, y_max * 0.65),
        xytext=(threshold + (e2e_times.max() - e2e_times.min()) * 0.04, y_max * 0.60),
        fontsize=12,
        fontweight="bold",
        color=CLR_THRESHOLD,
        arrowprops=dict(arrowstyle="-|>", color=CLR_THRESHOLD, lw=1.8),
        va="top",
    )

    # ---- mean / median lines ----------------------------------------------
    ax_main.axvline(x=mean_t, color=CLR_MEAN, ls="--", lw=1.8, zorder=4)
    ax_main.axvline(x=median_t, color=CLR_MEDIAN, ls="--", lw=1.8, zorder=4)

    # ---- legend (manual for clarity) ---------------------------------------
    from matplotlib.lines import Line2D
    from matplotlib.patches import Patch

    legend_items = [
        Patch(
            facecolor=CLR_PASS,
            edgecolor=CLR_PASS_EDGE,
            alpha=0.85,
            label=f"Within SLA  ({n_below:,} / {total:,}  =  {pct_below:.1f}%)",
        ),
        Patch(
            facecolor=CLR_FAIL,
            edgecolor=CLR_FAIL_EDGE,
            alpha=0.85,
            label=f"Exceeds SLA ({n_above:,} / {total:,}  =  {pct_above:.1f}%)",
        ),
        Line2D(
            [], [], color=CLR_THRESHOLD, lw=2.5, label=f"Threshold: {threshold:.0f}s"
        ),
        Line2D([], [], color=CLR_MEAN, ls="--", lw=1.8, label=f"Mean: {mean_t:.2f}s"),
        Line2D(
            [], [], color=CLR_MEDIAN, ls="--", lw=1.8, label=f"Median: {median_t:.2f}s"
        ),
    ]
    ax_main.legend(
        handles=legend_items,
        loc="upper right",
        fontsize=9.5,
        frameon=True,
        fancybox=True,
        shadow=False,
        edgecolor="#cccccc",
        facecolor="white",
        framealpha=0.92,
    )

    # ---- statistics text box -----------------------------------------------
    stats = "\n".join(
        [
            f"n = {total:,}",
            f"Mean   {mean_t:.2f}s",
            f"Median {median_t:.2f}s",
            f"Std    {std_t:.2f}s",
            f"P90    {p90_t:.2f}s",
            f"P95    {p95_t:.2f}s",
            f"P99    {p99_t:.2f}s",
            f"Min    {e2e_times.min():.2f}s",
            f"Max    {e2e_times.max():.2f}s",
        ]
    )
    ax_main.text(
        0.015,
        0.96,
        stats,
        transform=ax_main.transAxes,
        fontsize=8.5,
        fontfamily="monospace",
        va="top",
        bbox=dict(
            boxstyle="round,pad=0.5", facecolor="white", edgecolor="#cccccc", alpha=0.9
        ),
    )

    # ---- box plot on secondary axis ----------------------------------------
    ax_box.boxplot(
        e2e_times,
        vert=False,
        widths=0.5,
        patch_artist=True,
        boxprops=dict(facecolor=CLR_PASS, edgecolor=CLR_PASS_EDGE, alpha=0.6, lw=1.2),
        medianprops=dict(color=CLR_MEDIAN, lw=2),
        meanprops=dict(
            marker="D", markerfacecolor=CLR_MEAN, markeredgecolor=CLR_MEAN, markersize=6
        ),
        whiskerprops=dict(color="#888888", lw=1.2),
        capprops=dict(color="#888888", lw=1.2),
        flierprops=dict(
            marker="o",
            markerfacecolor=CLR_FAIL,
            markeredgecolor=CLR_FAIL_EDGE,
            markersize=4,
            alpha=0.7,
        ),
        showmeans=True,
    )
    ax_box.axvline(x=threshold, color=CLR_THRESHOLD, ls="-", lw=2.5, zorder=5)
    ax_box.set_yticks([])

    # ---- axis styling ------------------------------------------------------
    ax_main.set_ylabel("Block Count", fontsize=12, fontweight="bold", labelpad=10)
    ax_box.set_xlabel("E2E Time (seconds)", fontsize=12, fontweight="bold", labelpad=10)
    ax_main.set_title(
        f"End-to-End Block Time Distribution — {threshold:.0f}s Threshold Analysis",
        fontsize=14,
        fontweight="bold",
        pad=14,
    )

    for ax in (ax_main, ax_box):
        ax.grid(axis="x", color=CLR_GRID, ls="-", lw=0.5, alpha=0.7)
        ax.grid(axis="y", color=CLR_GRID, ls=":", lw=0.4, alpha=0.5)
        for spine in ("top", "right"):
            ax.spines[spine].set_visible(False)
        for spine in ("bottom", "left"):
            ax.spines[spine].set_color("#bbbbbb")
    # X-tick labels: replace the last one with ">threshold"
    tick_positions = list(bins[:-1])
    tick_labels = [str(b) for b in bins[:-1]]
    tick_labels[-1] = f">{thr}"
    ax_main.set_xticks(tick_positions)
    ax_main.set_xticklabels(tick_labels)
    ax_main.tick_params(axis="both", labelsize=10)
    ax_box.tick_params(axis="x", labelsize=10)

    # ---- save --------------------------------------------------------------
    png_path = f"{output_stem}.png"
    pdf_path = f"{output_stem}.pdf"
    fig.savefig(png_path, dpi=300, bbox_inches="tight", facecolor=fig.get_facecolor())
    fig.savefig(pdf_path, bbox_inches="tight", facecolor=fig.get_facecolor())
    print(f"Saved: {png_path}")
    print(f"Saved: {pdf_path}")

    # ---- console summary ---------------------------------------------------
    print(f"\n{'=' * 54}")
    print(f"  E2E BLOCK TIME DISTRIBUTION — {threshold:.0f}s THRESHOLD")
    print(f"{'=' * 54}")
    print(f"  Source:  {source_label}")
    print(f"  Blocks:  {total:,}")
    print(f"  Mean:    {mean_t:.2f}s    Std: {std_t:.2f}s")
    print(f"  Median:  {median_t:.2f}s")
    print(f"  P90:     {p90_t:.2f}s    P95: {p95_t:.2f}s    P99: {p99_t:.2f}s")
    print(f"  Min:     {e2e_times.min():.2f}s    Max: {e2e_times.max():.2f}s")
    print(f"{'-' * 54}")
    print(f"  Within SLA  (<= {threshold:.0f}s):  {n_below:>5,}  ({pct_below:5.1f}%)")
    print(f"  Exceeds SLA (>  {threshold:.0f}s):  {n_above:>5,}  ({pct_above:5.1f}%)")
    print(f"{'=' * 54}")


def main():
    args = parse_args()

    csv_path = args.csv_file
    if not os.path.isfile(csv_path):
        sys.exit(f"Error: file not found: {csv_path}")

    source_label = Path(csv_path).name
    output_stem = args.output or str(Path(csv_path).with_suffix("")) + "_e2e_dist"

    e2e_times = load_data(csv_path)
    plot(e2e_times, args.threshold, output_stem, source_label)


if __name__ == "__main__":
    main()
