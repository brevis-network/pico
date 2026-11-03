//! The device side of one chunk's GPU trace generation, the facts of its `prove.build_ctx_gpu`
//! stage: how long the device sat idle between the chunk's first bracketed event and its last, how
//! long the chunk's thread blocks in stream synchronisations, how long the host-to-device copies
//! take and how much of that time no other device work overlaps, and how long each chip's kernels
//! and zero-fills run on the device.
//!
//! A copy, a kernel, a fill or a transpose is timed by a CUDA event pair on the stream it runs on:
//! the copies are asynchronous, so a host clock around one times the enqueue. The elapsed times are
//! read in [`Session::finish`], after the chunk's last synchronisation, when every recorded event
//! has completed. Reading one earlier would take a wait of its own and change what the wait count
//! measures, so an event still pending there is counted as unread and never waited on. Each
//! interval carries its stream's role: `orchestrator`, `prover` (the thread's own stream), or `s1`,
//! `s2`, ... in the order a chip first uses its streams.
//!
//! `device.idle_us` is the span from the first event to the last end, less the union of every
//! bracketed interval; device work outside a bracket (the host-generated chips' byte-table round
//! trip, the CPU chip's one-cell write) reads as idle. A wait inside a kernel launcher is not seen:
//! the Global chip's launcher synchronises its own stream, uncounted here. Fills inside a launcher
//! (Global's, Poseidon2's, local memory's) stay in that chip's kernel bracket, so
//! `kernel.global_poseidon2_local_memory.us` is an upper bound; the launchers' own steps, below,
//! split them out. The bridge's final wait is `host_wait_final_us`, outside `host_waits` and
//! `host_wait_us`.
//!
//! The same intervals, by name, are the trace generator's brackets ([`Readout::brackets`]), every
//! figure a union: each chip's kernels, fills and launcher steps on whichever streams it used
//! (`chip.<chip>_ms`); each step (`step.<chip>.<step>_ms`) and, for a launcher with steps, its time
//! outside them (`step.<chip>.between_ms`); each kind of copy, by the name its site gives
//! (`copy.<what>_ms`); the bridge's transposes and uploads (`bridge.*_ms`); device work no chip
//! owns (`other_ms`); the sum of all but the steps (`sum_ms`), which counts overlap across figures
//! twice, their union (`union_ms`) and the device span (`span_ms`). A copy's figure runs from its
//! stream reaching it to its landing, so it holds any wait behind another stream's copy. The
//! steps are the Byte chip's table setup and finalize, and the Global, Poseidon2 and local memory
//! launchers' own: a launcher takes events through its step-events argument ([`steps`]) and records
//! them on its stream around each step, two events per step and launch, created only when the
//! launch's own bracket times it; given null, it records nothing. They are read with the rest,
//! once, in [`Session::finish`], and written as a second info line per chunk
//! (`[gpu-tracegen-brackets]`) and, when the stage ledger records the chunk's prove slot, as its
//! `gpu.tracegen` stage, timed by the host around the orchestrator.
//!
//! Recording needs the `stage-ledger` feature and the [`TARGET`] log target enabled at debug level
//! when the chunk starts (`RUST_LOG=…,gpu_tracegen=debug`). The summary is one info line per chunk
//! on that target; each wait and each interval is a debug line. Otherwise [`wait`] is the stream's
//! own synchronisation, a [`Bracket`] or [`Steps`] holds nothing, a launcher is handed null and a
//! thread-local read is the whole cost; without the feature every function here is an empty twin.

use serde_json::Value;

#[cfg(feature = "stage-ledger")]
mod live;
#[cfg(feature = "stage-ledger")]
pub use live::*;

#[cfg(not(feature = "stage-ledger"))]
mod off;
#[cfg(not(feature = "stage-ledger"))]
pub use off::*;

/// The log target whose debug level switches the readings on.
pub const TARGET: &str = "gpu_tracegen";

/// What a chunk's readings come to.
pub struct Readout {
    /// The context build's facts, `prove.build_ctx_gpu`'s in the stage ledger.
    pub device: Value,
    /// The trace generator's brackets, the `gpu.tracegen` stage's facts.
    pub brackets: Value,
}

/// The chips whose kernels a stream pool could overlap with the CPU chip's: their summed kernel time
/// bounds what such overlap can hide on a CPU chunk.
pub const OVERLAPPABLE_CHIPS: [&str; 3] = ["Global", "RiscvKoalaBearPoseidon2", "MemoryLocal"];

/// Copies above this size are counted apart: from pageable memory, `cudaMemcpyAsync` can hold the
/// calling thread until the driver has staged the whole source.
pub const LARGE_COPY: usize = 64 * 1024;

/// The total length of `copies` that no interval of `kernels` covers, every interval a
/// `(start, end)` pair on one time axis.
#[cfg(any(feature = "stage-ledger", test))]
fn uncovered(copies: &[(f64, f64)], kernels: &[(f64, f64)]) -> f64 {
    let copies = union(copies);
    let kernels = union(kernels);
    let (mut i, mut j, mut covered) = (0, 0, 0.0);
    while i < copies.len() && j < kernels.len() {
        let ((c0, c1), (k0, k1)) = (copies[i], kernels[j]);
        covered += (c1.min(k1) - c0.max(k0)).max(0.0);
        if c1 < k1 {
            i += 1;
        } else {
            j += 1;
        }
    }
    measure(&copies) - covered
}

/// The total length of `intervals`, overlaps counted once.
#[cfg(any(feature = "stage-ledger", test))]
fn covered(intervals: &[(f64, f64)]) -> f64 {
    measure(&union(intervals))
}

#[cfg(any(feature = "stage-ledger", test))]
fn measure(disjoint: &[(f64, f64)]) -> f64 {
    disjoint.iter().map(|(start, end)| end - start).sum()
}

/// `intervals` merged into disjoint ones in start order, the empty ones dropped.
#[cfg(any(feature = "stage-ledger", test))]
fn union(intervals: &[(f64, f64)]) -> Vec<(f64, f64)> {
    let mut sorted: Vec<(f64, f64)> = intervals.iter().copied().filter(|(a, b)| b > a).collect();
    sorted.sort_by(|x, y| x.0.total_cmp(&y.0));
    let mut merged: Vec<(f64, f64)> = Vec::with_capacity(sorted.len());
    for (start, end) in sorted {
        match merged.last_mut() {
            Some(last) if start <= last.1 => last.1 = last.1.max(end),
            _ => merged.push((start, end)),
        }
    }
    merged
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_copy_under_a_kernel_is_not_exposed() {
        assert_eq!(uncovered(&[(2.0, 4.0)], &[(1.0, 5.0)]), 0.0);
    }

    #[test]
    fn a_copy_alone_is_exposed_whole() {
        assert_eq!(uncovered(&[(0.0, 3.0)], &[]), 3.0);
        assert_eq!(uncovered(&[(0.0, 3.0)], &[(5.0, 9.0)]), 3.0);
    }

    #[test]
    fn overlapping_copies_count_once_and_only_their_uncovered_part() {
        // Copies cover [0, 6) once merged; the kernels cover [1, 2) and [4, 10) of it.
        let copies = [(0.0, 4.0), (3.0, 6.0)];
        let kernels = [(1.0, 2.0), (4.0, 10.0), (4.5, 5.0)];
        assert_eq!(uncovered(&copies, &kernels), 3.0);
    }

    #[test]
    fn alternating_slices_expose_only_the_first_copy_and_the_gaps() {
        // Two streams: copy i on one overlaps kernel i - 1 on the other.
        let copies = [(0.0, 2.0), (2.0, 4.0), (4.0, 6.0)];
        let kernels = [(2.0, 5.0), (5.0, 8.0), (8.0, 9.0)];
        assert_eq!(uncovered(&copies, &kernels), 2.0);
    }

    #[test]
    fn covered_counts_overlaps_once_and_drops_empty_intervals() {
        assert_eq!(
            covered(&[(0.0, 2.0), (1.0, 3.0), (5.0, 5.0), (6.0, 7.0)]),
            4.0
        );
    }
}
