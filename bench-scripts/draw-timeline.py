#!/usr/bin/env python3
"""
Timeline visualization tool for benchmark data.

Usage:
    python draw-timeline.py bench_time.csv chunk.svg lane.svg

Generates two timeline visualizations:
1. Chunk timeline - shows events grouped by chunk_id
2. Lane timeline - shows events by execution lane (emulator/GPU/CPU)
"""
from __future__ import annotations
import argparse
from pathlib import Path
from typing import Any, Dict, List, Tuple
import itertools

import pandas as pd
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D
from matplotlib import patches as mpatches
from matplotlib.axes import Axes
from matplotlib.collections import LineCollection
from matplotlib.ticker import MaxNLocator, FuncFormatter, AutoMinorLocator

# --------------------------------------------------------------------------- #
# VISUALIZATION CONSTANTS                                                     #
# --------------------------------------------------------------------------- #

# Figure size calculation parameters
PIXELS_PER_MS = 0.3  # Width: readable without being excessive (target ~40-60 inches)
MIN_FIGURE_WIDTH = 20  # Inches (minimum for readability)
MAX_FIGURE_WIDTH = 60  # Inches (maximum for navigation)
LANE_HEIGHT_FACTOR = 0.5  # Inches per lane (0.5 = ~0.5" per lane)
LANE_MIN_HEIGHT = 12  # Minimum total height (inches)

# Visual styling
LANE_BAR_WIDTH = 8  # Line width for lane bars (increased from 4)
LANE_MARKER_SIZE = 0.25  # Vertical marker half-height (increased from 0.1)
TEXT_OFFSET_Y = 0.4  # Chunk label offset (increased from 0.3)
CHUNK_BAR_ALPHA = 0.85  # Transparency for bars (reduced for better layering)
CRITICAL_BAR_ALPHA = 0.95  # Higher alpha for critical events
DPI = 120  # Default DPI for figure rendering

# Chunk timeline line widths by context group
CHUNK_GROUP_LINEWIDTHS = {
    "simple_emulator": 15.0,
    "emulator": 10.0,
    "riscv": 2.0,
    "deferred": 6.0,
    "convert": 4.0,
    "combine": 8.0,
}

# Color palettes (legacy - kept for chunk timeline)
SET2_NO_GRAY = plt.colormaps["Set2"].colors[:-1]  # pyright: ignore  # 7 vivid swatches
PREP_GREY = "lightgrey"
TAB10 = plt.colormaps["tab10"]

# --------------------------------------------------------------------------- #
# VIBRANT COLOR PALETTE                                                       #
# --------------------------------------------------------------------------- #
# Optimized for maximum visual distinction between event types

EVENT_COLORS = {
    # Emulation (dark blues from palette)
    "simple_emulator": "#003f5c",  # Dark blue
    "emulator": "#2f4b7c",  # Navy
    # Preparation (purples/magentas from palette)
    "riscv-preparer": "#665191",  # Purple
    "deferred-preparer": "#a05195",  # Magenta
    "convert-preparer": "#d45087",  # Pink
    "combine-preparer": "#bc5090",  # Extended: between #a05195 and #d45087
    # GPU Proving (warm oranges from palette)
    "riscv-gpu-prover": "#ff7c43",  # Orange
    "deferred-gpu-prover": "#ffa600",  # Yellow-orange
    "convert-gpu-prover": "#ff9933",  # Extended: between #ff7c43 and #ffa600
    "combine-gpu-prover": "#f95d6a",  # Coral
    # Other (coral/gray)
    "generate-preprocessed": "#58508d",  # Extended: deeper purple
    "setup_keys_gm": "#8a508f",  # Extended: muted magenta
    "split-burst": "#A9A9A9",  # Gray
}

# Lane group background colors (subtle backgrounds for visual separation)
LANE_GROUP_COLORS = {
    "simple_emulator": "#E6F3FF",  # Light blue
    "emulator": "#E6F3FF",  # Light blue
    "cpu": "#E8F5E9",  # Light green
    "gpu": "#FFF3E0",  # Light orange
}

# Event importance levels for visual emphasis
CRITICAL_EVENTS = {"combine-gpu-prover"}  # Final output stage
HIGH_IMPORTANCE_EVENTS = {
    "riscv-preparer",
    "deferred-gpu-prover",
}  # Key pipeline stages

# Legend grouping for organized display
LEGEND_GROUPS = [
    ("Emulation", ["simple_emulator", "emulator"]),
    (
        "Preparation",
        ["riscv-preparer", "deferred-preparer", "convert-preparer", "combine-preparer"],
    ),
    (
        "GPU Proving",
        [
            "riscv-gpu-prover",
            "deferred-gpu-prover",
            "convert-gpu-prover",
            "combine-gpu-prover",
        ],
    ),
    ("Other", ["generate-preprocessed", "setup_keys_gm", "split-burst"]),
]

# --------------------------------------------------------------------------- #
# DIMENSION CALCULATION                                                       #
# --------------------------------------------------------------------------- #


def calculate_figure_width(df: pd.DataFrame) -> float:
    """
    Calculate optimal figure width based on data time range.

    Args:
        df: DataFrame with 'start_ms' and 'end_ms' columns

    Returns:
        Figure width in inches (clamped to MIN_FIGURE_WIDTH - MAX_FIGURE_WIDTH)
    """
    time_range = df["end_ms"].max() - df["start_ms"].min()
    optimal_width_px = time_range * PIXELS_PER_MS
    optimal_width_inches = optimal_width_px / DPI
    return max(MIN_FIGURE_WIDTH, min(optimal_width_inches, MAX_FIGURE_WIDTH))


def calculate_lane_figure_height(num_lanes: int) -> float:
    """
    Calculate figure height for lane timeline based on number of lanes.

    Args:
        num_lanes: Number of distinct lanes to display

    Returns:
        Figure height in inches
    """
    return max(LANE_MIN_HEIGHT, num_lanes * LANE_HEIGHT_FACTOR + 3)


# --------------------------------------------------------------------------- #
# BASIC HELPERS                                                               #
# --------------------------------------------------------------------------- #


def is_cpu_process(ctx: str) -> bool:
    """Check if context represents a CPU process."""
    return ctx in [
        "simple_emulator",
        "emulator",
        "riscv-preparer",
        "deferred-preparer",
        "convert-preparer",
        "combine-preparer",
    ]


def setup_time_axis(ax: Axes, with_minor_ticks: bool = True) -> None:
    """
    Configure x-axis for time display with improved tick labels.

    Args:
        ax: Matplotlib axis to configure
        with_minor_ticks: Whether to add minor tick marks
    """
    # Major ticks with denser spacing - request more bins for better granularity
    ax.xaxis.set_major_locator(MaxNLocator(nbins=100, steps=[1, 2, 5, 10]))

    # Add minor ticks for finer granularity
    if with_minor_ticks:
        ax.xaxis.set_minor_locator(AutoMinorLocator(5))

    # Format numbers with comma separators
    ax.xaxis.set_major_formatter(FuncFormatter(lambda x, p: f"{int(x):,}"))

    # Enhanced grid
    ax.grid(which="major", axis="x", linestyle="-", alpha=0.4, linewidth=0.8)
    if with_minor_ticks:
        ax.grid(which="minor", axis="x", linestyle=":", alpha=0.15, linewidth=0.5)


# --------------------------------------------------------------------------- #
# CPU-LANE ASSIGNER – keep families separate                                  #
# --------------------------------------------------------------------------- #


def assign_cpu_lanes(df: pd.DataFrame) -> pd.Series:
    """
    Assign CPU lanes using greedy scheduling per preparer family.

    Runs once per preparer family (riscv/convert/combine/etc.) to ensure
    lanes within each family are kept separate and don't overlap visually.

    Args:
        df: DataFrame with timing events including 'context', 'start_ms', 'end_ms'

    Returns:
        Series mapping DataFrame index to CPU lane ID (NaN for non-CPU processes)
    """
    families = [
        "simple_emulator",
        "emulator",
        "riscv-preparer",
        "deferred-preparer",
        "convert-preparer",
        "combine-preparer",
    ]
    idx_to_lane: dict[int, int] = {}
    offset = 0  # Running lane-id offset across families

    for fam in families[1:]:
        fam_rows = (
            df[df["context"] == fam].copy().sort_values("start_ms")
        )  # pyright: ignore
        lane_end: list[float] = []  # Free-at timestamps per lane

        for idx, row in fam_rows.iterrows():  # pyright: ignore
            start, end = row["start_ms"], row["end_ms"]
            # Find first free lane
            for lane, free_at in enumerate(lane_end):
                if start >= free_at:
                    lane_end[lane] = end  # pyright: ignore
                    idx_to_lane[idx] = offset + lane  # pyright: ignore
                    break
            else:
                # Need a new lane in this family
                lane_end.append(end)  # pyright: ignore
                idx_to_lane[idx] = offset + len(lane_end) - 1  # pyright: ignore

        offset += len(lane_end)  # Reserve ID range for next family

    return pd.Series(idx_to_lane, dtype="float")


# --------------------------------------------------------------------------- #
# UTILIZATION STATISTICS                                                      #
# --------------------------------------------------------------------------- #


def compute_utilization_stats(
    df: pd.DataFrame, total_time: float
) -> Dict[str, Dict[str, float]]:
    """
    Compute utilization percentage per lane type.

    Args:
        df: DataFrame with timing events including 'lane', 'duration_ms' (or start_ms/end_ms)
        total_time: Total time span in milliseconds

    Returns:
        Dictionary mapping lane type to {util: percentage, lanes: count}
    """
    stats = {}

    # Ensure duration_ms exists
    if "duration_ms" not in df.columns:
        df = df.copy()
        df["duration_ms"] = df["end_ms"] - df["start_ms"]

    for lane_type in ["simple_emulator", "emulator", "cpu", "gpu"]:
        type_df = df[df["lane"].apply(lambda s: split_lane(s)[1] == lane_type)]
        if type_df.empty:
            continue

        active_time = type_df["duration_ms"].sum()
        num_lanes = type_df[
            "lane"
        ].nunique()  # pyright: ignore[reportAttributeAccessIssue]

        if num_lanes > 0 and total_time > 0:
            utilization = (active_time / (total_time * num_lanes)) * 100
            stats[lane_type] = {"util": min(utilization, 100.0), "lanes": num_lanes}

    return stats


def get_lane_group(lane: str) -> str:
    """Extract lane group from lane name (e.g., 'gpu-0' -> 'gpu')."""
    return lane.split("-")[0]


def split_lane(lane: str) -> Tuple[str, str]:
    """
    Split lane into (role, type) where role is primary/secondary/unknown.
    """
    parts = lane.split("-")
    if parts[0] in {"primary", "secondary"} and len(parts) >= 2:
        return parts[0], parts[1]
    return "unknown", parts[0]


# --------------------------------------------------------------------------- #
# PALETTES                                                                    #
# --------------------------------------------------------------------------- #


def build_gpu_palette(gpu_ids) -> Dict[int, tuple]:
    """
    Build color palette for GPU prover IDs.

    Args:
        gpu_ids: Iterable of GPU/prover IDs

    Returns:
        Dictionary mapping GPU ID to RGB color tuple
    """
    cyc = itertools.cycle(SET2_NO_GRAY)  # Loop if >7 GPUs
    return {
        gid: (next(cyc) if gid >= 0 else PREP_GREY) for gid in sorted(gpu_ids)
    }  # pyright: ignore


def build_event_palette(events, use_semantic: bool = True) -> Dict[str, Any]:
    """
    Build color palette for event contexts.

    Assigns distinct colors to different event types using the semantic
    colorblind-friendly palette when available.

    Args:
        events: Iterable of event context names
        use_semantic: If True, use semantic EVENT_COLORS palette

    Returns:
        Dictionary mapping event name to color (hex string or RGB tuple)
    """
    if use_semantic:
        # Use semantic colorblind-friendly palette
        res = {}
        cmap = TAB10
        fallback_idx = 0

        for evt in sorted(events):
            if evt in EVENT_COLORS:
                res[evt] = EVENT_COLORS[evt]
            else:
                # Fallback for unknown events
                res[evt] = cmap(fallback_idx)
                fallback_idx = (fallback_idx + 1) % 10
        return res

    # Legacy palette (kept for backwards compatibility)
    cmap = TAB10
    events = sorted(events)

    # Pre-assign special colors for key events
    res = {
        "setup_keys_gm": cmap(7),
        "generate-preprocessed": cmap(5),
        "simple_emulator": cmap(9),
        "deferred-preparer": cmap(2),
        "deferred-gpu-prover": cmap(3),
    }

    # Assign remaining events to available colors
    i = 0
    for evt in events:
        if evt in res:
            continue
        while i in [5, 7, 9, 2, 3]:  # Skip reserved colors
            i += 1
        res[evt] = cmap(i)
        i += 1
    return res


# --------------------------------------------------------------------------- #
# ARG PARSING                                                                 #
# --------------------------------------------------------------------------- #


def parse_args() -> argparse.Namespace:
    """
    Parse command-line arguments.

    Returns:
        Parsed arguments with csv, chunk_svg, and lane_svg paths
    """
    p = argparse.ArgumentParser(
        description="Generate timeline visualizations from benchmark CSV data"
    )
    p.add_argument("csv", help="Input CSV file with timing data")
    p.add_argument("chunk_svg", help="Output SVG file for chunk timeline")
    p.add_argument("lane_svg", help="Output SVG file for lane timeline")
    return p.parse_args()


# --------------------------------------------------------------------------- #
# LOAD + PRE-PROCESS                                                          #
# --------------------------------------------------------------------------- #


def load_data(csv_path: str) -> pd.DataFrame:
    """
    Load and preprocess timing data from CSV.

    Args:
        csv_path: Path to CSV file

    Returns:
        DataFrame with timing events, with start_ms and end_ms as floats
    """
    df = pd.read_csv(csv_path)
    if "role" not in df.columns:
        df["role"] = "unknown"
    df[["start_ms", "end_ms"]] = df[["start_ms", "end_ms"]].astype(float)
    return df


# --------------------------------------------------------------------------- #
# FIGURE 1 – per-chunk timeline                                               #
# --------------------------------------------------------------------------- #


def draw_chunk_timeline(df_origin: pd.DataFrame, out_file: Path) -> None:
    """
    Generate chunk-based timeline visualization.

    Args:
        df_origin: DataFrame with timing events
        out_file: Path to output SVG file
    """

    def ctx_group(ctx_base: str) -> str:
        """Extract context group prefix (e.g., 'riscv' from 'riscv-preparer')."""
        return ctx_base.lstrip("[").split("-")[0].lower()

    # Prepare data
    df = df_origin.copy()
    df = df[df["chunk_id"] >= 0]
    chunk_ids = sorted(df["chunk_id"].unique())  # pyright: ignore
    chunk_y = {cid: i for i, cid in enumerate(chunk_ids)}
    gpu_colour = build_gpu_palette(df["prover_id"].unique())  # pyright: ignore

    # Calculate dynamic width
    width = calculate_figure_width(df)  # pyright: ignore
    fig, ax = plt.subplots(figsize=(width, 8), dpi=DPI)
    ax.set_title("Timeline by chunk_id (colour = GPU, linewidth = context)")

    # Draw bars
    for _, r in df.iterrows():
        y = chunk_y[r.chunk_id]
        col = gpu_colour[r.prover_id]
        lw = CHUNK_GROUP_LINEWIDTHS.get(ctx_group(r.context), 2.0)
        ax.hlines(y, r.start_ms, r.end_ms, color=col, lw=lw, alpha=CHUNK_BAR_ALPHA)
        if r.context != "emulator":
            ax.plot(
                [r.start_ms, r.end_ms],
                [y, y],
                linestyle="none",
                marker="o",
                markersize=4,
                markerfacecolor=col,
                markeredgecolor="black",
                markeredgewidth=0.6,
            )

    # Configure axes
    ax.set_xlabel("time (ms)")
    ax.set_yticks(range(len(chunk_ids)))
    ax.set_yticklabels(chunk_ids)
    ax.set_ylabel("chunk_id")
    setup_time_axis(ax, with_minor_ticks=True)

    # Legends
    gpu_handles = []
    for g, col in gpu_colour.items():
        if g == -1:
            gpu_handles.append(mpatches.Patch(color=col, label="CPU"))
        else:
            gpu_handles.append(mpatches.Patch(color=col, label=f"GPU {g}"))
    lg_gpu = ax.legend(
        handles=gpu_handles,
        title="prover_id",
        bbox_to_anchor=(1.02, 1),
        loc="upper left",
    )
    ax.add_artist(lg_gpu)

    lw_handles = [
        Line2D([0], [0], color="black", lw=w, label=f"{k}-*")
        for k, w in CHUNK_GROUP_LINEWIDTHS.items()
    ]
    ax.legend(
        handles=lw_handles,
        title="context",
        bbox_to_anchor=(1.02, 0.35),
        loc="upper left",
    )

    # Set x-axis limits dynamically
    ax.set_xlim(left=0, right=df["end_ms"].max() * 1.02)

    # Annotate last combine-gpu-prover
    last_x = df.loc[df.context == "combine-gpu-prover", "end_ms"].max()
    if pd.notna(last_x):
        ax.axvline(last_x, color="red", lw=1.5, ls=":", alpha=0.9)
        ax.text(
            last_x,
            len(chunk_ids) - 0.3,
            f"final combine ⟶ {last_x:.0f} ms",
            rotation=90,
            ha="left",
            va="bottom",
            fontsize="small",
            fontweight="bold",
            color="red",
        )

    fig.tight_layout()
    fig.savefig(out_file, bbox_inches="tight")
    plt.close(fig)


# --------------------------------------------------------------------------- #
# FIGURE 2 – lane timeline                                                    #
# --------------------------------------------------------------------------- #


def _draw_lane_group_backgrounds(
    ax: Axes, lanes: List[str]
) -> Dict[str, Tuple[int, int]]:
    """
    Draw background shading for lane groups and separators.

    Args:
        ax: Matplotlib axes
        lanes: Sorted list of lane names

    Returns:
        Dictionary mapping group name to (start_y, end_y) positions
    """
    if not lanes:
        return {}

    # Find lane group boundaries
    group_boundaries: Dict[str, Tuple[int, int]] = {}
    current_group = None
    group_start = 0

    for i, lane in enumerate(lanes):
        group = get_lane_group(lane)
        if group != current_group:
            if current_group is not None:
                group_boundaries[current_group] = (group_start, i - 1)
            current_group = group
            group_start = i

    # Don't forget the last group
    if current_group is not None:
        group_boundaries[current_group] = (group_start, len(lanes) - 1)

    # Draw background spans for each group
    for group, (start_y, end_y) in group_boundaries.items():
        bg_color = LANE_GROUP_COLORS.get(group, "#F5F5F5")
        ax.axhspan(
            start_y - 0.5,
            end_y + 0.5,
            facecolor=bg_color,
            alpha=0.3,
            zorder=0,
        )

    # Draw separator lines between groups
    prev_group = None
    for i, lane in enumerate(lanes):
        group = get_lane_group(lane)
        if prev_group is not None and group != prev_group:
            ax.axhline(
                y=i - 0.5,
                color="#666666",
                linewidth=1.5,
                linestyle="-",
                alpha=0.6,
                zorder=1,
            )
        prev_group = group

    return group_boundaries


def _draw_utilization_stats(ax: Axes, stats: Dict[str, Dict[str, float]]) -> None:
    """
    Draw utilization statistics panel in upper-right corner.

    Args:
        ax: Matplotlib axes
        stats: Utilization statistics from compute_utilization_stats()
    """
    if not stats:
        return

    # Build stats text
    lines = []
    display_names = {
        "gpu": "GPU",
        "cpu": "CPU",
        "emulator": "Emulator",
        "simple_emulator": "Simple Emu",
    }

    for lane_type in ["gpu", "cpu", "emulator", "simple_emulator"]:
        if lane_type in stats:
            s = stats[lane_type]
            name = display_names.get(lane_type, lane_type)
            lines.append(f"{name}: {s['util']:.1f}% ({int(s['lanes'])} lanes)")

    if not lines:
        return

    text = "Lane Utilization\n" + "\n".join(lines)

    # Draw text box in upper-right area (use axes transform)
    ax.text(
        0.99,
        0.99,
        text,
        transform=ax.transAxes,
        fontsize="small",
        fontfamily="monospace",
        verticalalignment="top",
        horizontalalignment="right",
        bbox=dict(
            boxstyle="round,pad=0.4",
            facecolor="white",
            edgecolor="#666666",
            alpha=0.9,
        ),
        zorder=10,
    )


def _build_grouped_legend(
    ax: Axes, evt_colour: Dict[str, str], events_in_data: set
) -> None:
    """
    Build legend organized by category groups.

    Args:
        ax: Matplotlib axes
        evt_colour: Color mapping for events
        events_in_data: Set of event names actually present in data
    """
    handles = []
    labels = []

    for group_name, group_events in LEGEND_GROUPS:
        # Filter to events that exist in data
        present_events = [e for e in group_events if e in events_in_data]
        if not present_events:
            continue

        # Add group header (invisible patch)
        handles.append(mpatches.Patch(color="none", label=""))
        labels.append(f"── {group_name} ──")

        # Add events in this group
        for evt in present_events:
            color = evt_colour.get(evt, "#888888")
            handles.append(mpatches.Patch(color=color, label=evt))
            labels.append(evt)

    # Handle any events not in predefined groups
    known_events = set()
    for _, group_events in LEGEND_GROUPS:
        known_events.update(group_events)
    unknown_events = events_in_data - known_events

    if unknown_events:
        handles.append(mpatches.Patch(color="none", label=""))
        labels.append("── Unknown ──")
        for evt in sorted(unknown_events):
            color = evt_colour.get(evt, "#888888")
            handles.append(mpatches.Patch(color=color, label=evt))
            labels.append(evt)

    ax.legend(
        handles=handles,
        labels=labels,
        title="Events",
        bbox_to_anchor=(1.02, 1),
        loc="upper left",
        fontsize="small",
        framealpha=0.95,
    )


def draw_lane_timeline(df: pd.DataFrame, out_file: Path) -> None:
    """
    Generate lane-based timeline visualization with dynamic sizing.
    Roles (primary/secondary) are drawn as separate panels.
    """
    def _prepare_role_df(df_role: pd.DataFrame) -> Tuple[pd.DataFrame, List[str], Dict[str, int]]:
        df_role = df_role.copy()
        df_role["cpu_id"] = assign_cpu_lanes(df_role)
        df_role["lane"] = df_role.apply(
            lambda r: (
                f"simple_emulator-{int(r.emulator_id)}"
                if r.context == "simple_emulator"
                else (
                    f"emulator-{int(r.emulator_id)}"
                    if r.emulator_id >= 0
                    else (
                        f"gpu-{int(r.prover_id)}"
                        if r.prover_id >= 0
                        else (
                            f"cpu-{int(r.cpu_id)}" if is_cpu_process(r.context) else ""
                        )
                    )
                )
            ),
            axis=1,
        )
        df_role = df_role[df_role["lane"] != ""].copy()  # pyright: ignore
        df_role["duration_ms"] = df_role["end_ms"] - df_role["start_ms"]
        key_order = {"simple_emulator": 0, "emulator": 1, "cpu": 2, "gpu": 3}
        lanes = sorted(
            df_role.lane.unique(),
            key=lambda s: (key_order.get(s.split("-")[0], 9), int(s.split("-")[1])),
        )
        lane_y = {lane: i for i, lane in enumerate(lanes)}
        return df_role, lanes, lane_y

    known_roles = [r for r in ["primary", "secondary"] if r in set(df["role"])]

    # Events without a role tag (e.g. emulator, simple_emulator, preparers)
    # belong to whichever machine produced the log.  When exactly one known
    # role exists, re-label "unknown" events to that role so they aren't
    # dropped.  When both roles are present (merged logs) or neither is,
    # keep "unknown" as its own panel.
    if len(known_roles) == 1:
        df.loc[df["role"] == "unknown", "role"] = known_roles[0]
        roles_in_data = known_roles
    elif known_roles:
        roles_in_data = known_roles + (
            ["unknown"] if "unknown" in set(df["role"]) else []
        )
    else:
        roles_in_data = ["unknown"]

    role_dfs: List[Tuple[str, pd.DataFrame, List[str], Dict[str, int]]] = []
    for role in roles_in_data:
        df_role, lanes, lane_y = _prepare_role_df(df.loc[df["role"] == role])
        if lanes:
            role_dfs.append((role, df_role, lanes, lane_y))

    width = calculate_figure_width(df)
    total_lanes = sum(len(lanes) for _, _, lanes, _ in role_dfs)
    height = calculate_lane_figure_height(max(total_lanes, 1))

    fig, axes = plt.subplots(
        nrows=len(role_dfs),
        ncols=1,
        figsize=(width, height),
        dpi=DPI,
        sharex=True,
    )
    if len(role_dfs) == 1:
        axes = [axes]

    evt_colour = build_event_palette(df.context.unique(), use_semantic=True)
    x_max = df["end_ms"].max() * 1.02

    for ax, (role, df_role, lanes, lane_y) in zip(axes, role_dfs):
        if df_role.empty:
            ax.set_axis_off()
            continue

        total_time = df_role["end_ms"].max() - df_role["start_ms"].min()
        ax.set_title(
            f"{role.capitalize()} lanes (colour = event, label = chunk_id) - {len(lanes)} lanes"
        )

        _draw_lane_group_backgrounds(ax, lanes)
        split_burst_df = df_role[df_role["context"] == "split-burst"]
        regular_df = df_role[df_role["context"] != "split-burst"]

        if not regular_df.empty:
            non_critical_segments = []
            non_critical_colors = []
            critical_segments = []
            critical_colors = []

            for _, r in regular_df.iterrows():
                y = lane_y[r.lane]
                segment = [(r.start_ms, y), (r.end_ms, y)]
                color = evt_colour[r.context]

                if r.context in CRITICAL_EVENTS:
                    critical_segments.append(segment)
                    critical_colors.append(color)
                else:
                    non_critical_segments.append(segment)
                    non_critical_colors.append(color)

            if non_critical_segments:
                lc = LineCollection(
                    non_critical_segments,
                    colors=non_critical_colors,
                    linewidths=LANE_BAR_WIDTH,
                    alpha=CHUNK_BAR_ALPHA,
                    zorder=3,
                )
                ax.add_collection(lc)

            if critical_segments:
                lc_critical = LineCollection(
                    critical_segments,
                    colors=critical_colors,
                    linewidths=LANE_BAR_WIDTH + 2,
                    alpha=CRITICAL_BAR_ALPHA,
                    zorder=4,
                )
                ax.add_collection(lc_critical)

                for segment, _color in zip(critical_segments, critical_colors):
                    start_x, y = segment[0]
                    end_x, _ = segment[1]
                    ax.plot(
                        [start_x, end_x],
                        [y, y],
                        color="black",
                        linewidth=LANE_BAR_WIDTH + 4,
                        alpha=0.3,
                        zorder=3,
                        solid_capstyle="round",
                    )

            for _, r in regular_df.iterrows():
                y = lane_y[r.lane]
                col = evt_colour[r.context]

                if r.context in CRITICAL_EVENTS:
                    marker_lw = 1.2
                    marker_color = "black"
                elif r.context in HIGH_IMPORTANCE_EVENTS:
                    marker_lw = 0.8
                    marker_color = "#333333"
                else:
                    marker_lw = 0.5
                    marker_color = "black"

                ax.vlines(
                    [r.start_ms, r.end_ms],
                    y - LANE_MARKER_SIZE,
                    y + LANE_MARKER_SIZE,
                    color=marker_color,
                    lw=marker_lw,
                    alpha=0.9,
                    zorder=5,
                )

                if r.chunk_id >= 0:
                    ax.text(
                        (r.start_ms + r.end_ms) / 2,
                        y - TEXT_OFFSET_Y,
                        str(r.chunk_id),
                        rotation=90,
                        ha="center",
                        va="center",
                        fontsize="x-small",
                        fontweight="bold",
                        color=col,
                        zorder=6,
                    )
                elif (
                    "deferred_index" in df_role.columns
                    and pd.notna(r.deferred_index)
                    and int(r.deferred_index) >= 0
                ):
                    ax.text(
                        (r.start_ms + r.end_ms) / 2,
                        y - TEXT_OFFSET_Y,
                        f"D{int(r.deferred_index)}",
                        rotation=90,
                        ha="center",
                        va="center",
                        fontsize="x-small",
                        fontweight="bold",
                        color=col,
                        zorder=6,
                    )

                if r.context == "riscv-preparer" or r.context == "deferred-preparer":
                    ax.vlines(
                        [r.end_ms],
                        y,
                        len(lanes) - 0.5,
                        color=col,
                        ls="--",
                        lw=0.5,
                        alpha=0.9,
                        zorder=2,
                    )

        for _, r in split_burst_df.iterrows():
            y = lane_y[r.lane]
            col = evt_colour[r.context]
            ax.vlines(
                [r.start_ms], y - 0.35, y + 0.35, color=col, lw=1.5, alpha=0.9, zorder=5
            )
            if (
                "burst_count" in df_role.columns
                and pd.notna(r.burst_count)
                and int(r.burst_count) > 0
            ):
                ax.text(
                    r.start_ms + 2,
                    y,
                    f"×{int(r.burst_count)}",
                    rotation=0,
                    ha="left",
                    va="center",
                    fontsize="x-small",
                    fontweight="bold",
                    color=col,
                    zorder=6,
                )

        ax.set_yticks(range(len(lanes)))
        ax.set_yticklabels(lanes)
        ax.set_ylabel("lane")
        setup_time_axis(ax, with_minor_ticks=True)
        ax.set_xlim(left=0, right=x_max)

        util_stats = compute_utilization_stats(df_role, total_time)
        _draw_utilization_stats(ax, util_stats)

        last_combine = df_role.loc[df_role.context == "combine-gpu-prover", "end_ms"]
        if not last_combine.empty:
            last_x = last_combine.max()
            if pd.notna(last_x):
                ax.axvline(last_x, color="#AA3377", lw=2.0, ls=":", alpha=0.9, zorder=7)
                ax.text(
                    last_x + (x_max * 0.005),
                    len(lanes) - 0.5,
                    f"final combine → {last_x:,.0f} ms",
                    rotation=90,
                    ha="left",
                    va="top",
                    fontsize="small",
                    fontweight="bold",
                    color="#AA3377",
                    zorder=8,
                )

    axes[-1].set_xlabel("time (ms)")
    events_in_data = set(df.context.unique())
    _build_grouped_legend(axes[-1], evt_colour, events_in_data)

    fig.tight_layout()
    fig.savefig(out_file, bbox_inches="tight")
    plt.close(fig)


# --------------------------------------------------------------------------- #
# MAIN                                                                        #
# --------------------------------------------------------------------------- #


def main() -> None:
    """
    Main entry point for timeline visualization generation.

    Loads timing data from CSV and generates two SVG visualizations:
    1. Chunk timeline - events grouped by chunk_id
    2. Lane timeline - events by execution lane (emulator/GPU/CPU)
    """
    args = parse_args()
    df = load_data(args.csv)
    draw_chunk_timeline(df.copy(), Path(args.chunk_svg))
    draw_lane_timeline(df.copy(), Path(args.lane_svg))
    print(f"✓ Wrote {args.chunk_svg} and {args.lane_svg}")


if __name__ == "__main__":
    main()
