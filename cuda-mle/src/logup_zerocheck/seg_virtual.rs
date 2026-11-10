// Copyright (c) 2025-2026 Brevis.
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Segmented GKR input: store each trace's real rows only.
//!
//! The GKR input is the stacked interaction layout: traces tallest first, and inside a trace one
//! slab of `height` leaves per interaction, so every (trace, interaction) slab is a power of two
//! long and aligned to its length. A trace's rows past its real rows are padding rows, and a
//! padding row evaluates each interaction to the same leaf. The virtual input stores only a
//! prefix of the whole input; this stores only each slab's real rows.
//!
//! The input is cut into aligned power-of-two **blocks** of at least a granule (`2^g` leaves), each
//! either all real (stored) or all one padding leaf (a *pad* block, not stored): a slab's real rows
//! are rounded up to a granule and split into aligned blocks, as is the rest of the slab; slabs
//! shorter than a granule sit at the tail of the input and are stored whole; the zero padding up
//! to `L` is pad blocks of the zero leaf. Real blocks are stored back to back in leaf order, each
//! in its own bit-reversed local tree, exactly the dense prover's in-place tree over the block's
//! leaves.
//!
//! In the bit-reversed position space of any layer or folded vector below level `g`, a block is a
//! sub-cube: its entries are the positions whose low `log L - b` bits are the block's `id` (`b` the
//! block's log length), the high bits its local position. So the eq weight of an entry factors
//! into a local part and the block's part, and every kernel of a round runs the dense kernel's
//! body on each real block, with a pad block's whole contribution `eq(id) * term(pad leaf)`
//! computed once per outer round ([`SegPlan`] has the id of every block). The layers at level
//! `g - 1` and above, `L >> (g - 1)` nodes, and every vector folded that far, are small and
//! proved dense.

/// One trace's slab of the stacked input: `interactions` blocks of `2^log_height` leaves from
/// `offset`, the first `real_rows` of each real.
#[derive(Clone, Copy, Debug)]
pub struct TraceSlab {
    pub trace_idx: usize,
    pub offset: usize,
    pub log_height: u32,
    pub interactions: usize,
    pub real_rows: usize,
}

/// What a block holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockKind {
    /// Stored from `base` in the storage buffer.
    Real { base: usize },
    /// Every leaf is constant `konst` (index into the constants table, 0 the zero leaf).
    Pad { konst: u32 },
}

/// An aligned block of `2^log_size` leaves from `offset`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GkrBlock {
    pub offset: usize,
    pub log_size: u32,
    pub kind: BlockKind,
}

/// How the input evaluation writes one trace into the storage buffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SlabWrite {
    pub trace_idx: usize,
    /// Storage index of interaction 0's row 0.
    pub base: usize,
    /// Rows written per interaction, which is also the stride between interactions.
    pub rows: usize,
    /// The constants of interaction `i` live at `konst + i`, taken from row `rows`; `None` when
    /// every row is stored.
    pub konst: Option<u32>,
}

/// The segmented layout of one GKR input.
#[derive(Clone, Debug)]
pub struct SegPlan {
    pub log_len: u32,
    pub granule_log: u32,
    /// Tiles `[0, L)` in order.
    pub blocks: Vec<GkrBlock>,
    pub storage_len: usize,
    /// Constants table length, the zero leaf included (index 0).
    pub n_consts: usize,
    pub writes: Vec<SlabWrite>,
    /// Storage range the input evaluation does not write (the rounding of the input's end up to a
    /// granule), to be zeroed.
    pub zero_fill: (usize, usize),
}

#[inline]
pub fn rev(value: usize, bits: u32) -> usize {
    if bits == 0 {
        0
    } else {
        value.reverse_bits() >> (usize::BITS - bits)
    }
}

/// Splits `[a, b)` (both multiples of the smallest block) into maximal aligned power-of-two blocks.
fn aligned_blocks(mut a: usize, b: usize, mut f: impl FnMut(usize, u32)) {
    while a < b {
        let align = if a == 0 {
            usize::MAX
        } else {
            1usize << a.trailing_zeros()
        };
        let room = 1usize << (usize::BITS - 1 - (b - a).leading_zeros());
        let size = align.min(room);
        f(a, size.trailing_zeros());
        a += size;
    }
}

impl SegPlan {
    /// The plan for an input of `logical_len` leaves, `used` of them written by `slabs`, which must
    /// be the stacked layout's: contiguous from 0, tallest first. `None` if they are not, or if the
    /// input is too small to segment.
    pub fn new(
        slabs: &[TraceSlab],
        used: usize,
        logical_len: usize,
        granule_log: u32,
    ) -> Option<Self> {
        assert!(logical_len.is_power_of_two() && used <= logical_len);
        let granule = 1usize << granule_log;
        let log_len = logical_len.trailing_zeros();
        // The layers from level g - 1 up are dense: at least four nodes there, and a granule of at
        // least 2^11 leaves (the bit-reversal kernel's tile).
        if granule_log < 11 || log_len < granule_log + 2 {
            return None;
        }
        // Intervals in leaf order: (start, end, None) real or (start, end, Some(konst)) padding.
        let mut intervals: Vec<(usize, usize, Option<u32>)> = Vec::new();
        let mut writes = Vec::new();
        let mut cursor = 0usize;
        let mut tail_start: Option<usize> = None;
        let mut n_consts = 1usize; // 0 is the zero leaf
        for slab in slabs {
            let height = 1usize << slab.log_height;
            if slab.offset != cursor || slab.offset % height != 0 {
                return None;
            }
            cursor += slab.interactions * height;
            if slab.log_height < granule_log {
                tail_start.get_or_insert(slab.offset);
                writes.push(SlabWrite {
                    trace_idx: slab.trace_idx,
                    base: usize::MAX, // set below
                    rows: height,
                    konst: None,
                });
                continue;
            }
            if tail_start.is_some() {
                // a granule-or-taller slab after a shorter one: not the stacked order
                return None;
            }
            let rows = slab
                .real_rows
                .min(height)
                .next_multiple_of(granule)
                .min(height);
            let konst = (rows < height).then(|| {
                let k = n_consts as u32;
                n_consts += slab.interactions;
                k
            });
            for i in 0..slab.interactions {
                let at = slab.offset + i * height;
                if rows > 0 {
                    intervals.push((at, at + rows, None));
                }
                if let Some(k) = konst {
                    intervals.push((at + rows, at + height, Some(k + i as u32)));
                }
            }
            writes.push(SlabWrite {
                trace_idx: slab.trace_idx,
                base: usize::MAX,
                rows,
                konst,
            });
        }
        if cursor != used {
            return None;
        }
        let end = used.next_multiple_of(granule);
        if let Some(t) = tail_start {
            debug_assert_eq!(t % granule, 0, "tall slabs end on a granule");
            intervals.push((t, end, None));
        }
        if end < logical_len {
            intervals.push((end, logical_len, Some(0)));
        }

        // Merge adjacent real intervals, then cut everything into aligned blocks.
        let mut blocks = Vec::new();
        let mut storage_len = 0usize;
        let mut i = 0;
        while i < intervals.len() {
            let (a, mut b, kind) = intervals[i];
            i += 1;
            match kind {
                None => {
                    while i < intervals.len() && intervals[i].2.is_none() && intervals[i].0 == b {
                        b = intervals[i].1;
                        i += 1;
                    }
                    aligned_blocks(a, b, |offset, log_size| {
                        blocks.push(GkrBlock {
                            offset,
                            log_size,
                            kind: BlockKind::Real { base: storage_len },
                        });
                        storage_len += 1 << log_size;
                    });
                }
                Some(konst) => aligned_blocks(a, b, |offset, log_size| {
                    blocks.push(GkrBlock {
                        offset,
                        log_size,
                        kind: BlockKind::Pad { konst },
                    });
                }),
            }
        }

        if storage_len == 0 {
            return None; // nothing real to prove segmented
        }
        let mut plan = SegPlan {
            log_len,
            granule_log,
            blocks,
            storage_len,
            n_consts,
            writes,
            zero_fill: (0, 0),
        };
        // Storage bases of the writes: a slab's real rows start a real block.
        let mut w = 0;
        for slab in slabs {
            if slab.log_height < granule_log {
                // tail slabs: stored whole, contiguous from the tail's first granule
                let t = tail_start.unwrap();
                plan.writes[w].base = plan.storage_of(t)? + (slab.offset - t);
            } else if plan.writes[w].rows > 0 {
                plan.writes[w].base = plan.storage_of(slab.offset)?;
            } else {
                plan.writes[w].base = 0; // nothing stored
            }
            w += 1;
        }
        if end > used {
            plan.zero_fill = (
                plan.storage_of(end - granule)? + (used % granule),
                end - used,
            );
        }
        Some(plan)
    }

    pub fn logical_len(&self) -> usize {
        1 << self.log_len
    }

    /// Storage index of real leaf `leaf`, `None` for a padding leaf.
    pub fn storage_of(&self, leaf: usize) -> Option<usize> {
        let i = self.blocks.partition_point(|b| b.offset <= leaf) - 1;
        let b = self.blocks[i];
        match b.kind {
            BlockKind::Real { base } => Some(base + (leaf - b.offset)),
            BlockKind::Pad { .. } => None,
        }
    }

    /// The block's id: the low `log L - log_size` bits of each of its positions.
    pub fn block_id(&self, b: &GkrBlock) -> usize {
        rev(b.offset >> b.log_size, self.log_len - b.log_size)
    }

    pub fn smallest_block_log(&self) -> u32 {
        self.blocks.iter().map(|b| b.log_size).min().unwrap()
    }

    /// The device tables: real blocks (storage order), the storage granule table, pad blocks, and
    /// the leaf granule table (`0x8000_0000 | konst` for a pad block, else the real block index).
    pub fn device_tables(&self) -> SegTables {
        let g = self.granule_log;
        let mut real = Vec::new();
        let mut pads = Vec::new();
        let mut leaf_gran = vec![0u32; self.logical_len() >> g];
        let mut storage_gran = vec![0u32; self.storage_len >> g];
        for b in &self.blocks {
            let id = self.block_id(b) as u32;
            let granules = (b.offset >> g)..((b.offset + (1usize << b.log_size)) >> g);
            match b.kind {
                BlockKind::Real { base } => {
                    let idx = real.len() as u32;
                    real.push(SegBlk {
                        base: base as u32,
                        log: b.log_size,
                        id,
                        konst: 0,
                    });
                    leaf_gran[granules].fill(idx);
                    let s = base >> g;
                    storage_gran[s..s + (1usize << (b.log_size - g))].fill(idx);
                }
                BlockKind::Pad { konst } => {
                    pads.push(SegBlk {
                        base: 0,
                        log: b.log_size,
                        id,
                        konst,
                    });
                    leaf_gran[granules].fill(0x8000_0000 | konst);
                }
            }
        }
        SegTables {
            real,
            pads,
            leaf_gran,
            storage_gran,
        }
    }
}

/// A block as the kernels read it (gkr.cu `SegBlk`).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SegBlk {
    pub base: u32,
    pub log: u32,
    pub id: u32,
    pub konst: u32,
}

pub struct SegTables {
    pub real: Vec<SegBlk>,
    pub pads: Vec<SegBlk>,
    pub leaf_gran: Vec<u32>,
    pub storage_gran: Vec<u32>,
}

/// The granule, `2^MLE_GKR_SEG_GRANULE_LOG` leaves (default 12): the smallest block.
pub fn granule_log() -> u32 {
    static V: std::sync::OnceLock<u32> = std::sync::OnceLock::new();
    *V.get_or_init(|| {
        std::env::var("MLE_GKR_SEG_GRANULE_LOG")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(12)
    })
}

/// `MLE_GKR_SEG`: `0` turns the segmented input off; on by default.
pub fn seg_requested() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| !matches!(std::env::var("MLE_GKR_SEG").as_deref(), Ok("0")))
}

/// Largest storage, as a share of `used` (what the virtual input stores), worth segmenting for
/// (`MLE_GKR_SEG_MAX_RATIO`, default 0.9).
pub fn max_ratio() -> f64 {
    static V: std::sync::OnceLock<f64> = std::sync::OnceLock::new();
    *V.get_or_init(|| {
        std::env::var("MLE_GKR_SEG_MAX_RATIO")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(0.9)
    })
}

/// The slabs of a prove's GKR input, in stacked order: one per trace with interactions, its real
/// rows the context's `real_rows` hint (all rows when there is none, and for a short trace, whose
/// leaves the input lifts by repetition).
///
/// `real_rows_ok(air)`: whether to take the AIR's hint; see [`deny_air`].
pub fn slabs_of<PB: mle_core::prover::ProverBackend>(
    trace_interactions: &[Option<super::gkr_input::TraceInteractionMeta>],
    ctx: &mle_core::prover::ProvingContext<PB>,
    interactions_of: impl Fn(usize) -> usize,
    real_rows_ok: impl Fn(usize) -> bool,
    l_skip: usize,
) -> Vec<TraceSlab> {
    let mut slabs: Vec<TraceSlab> = trace_interactions
        .iter()
        .flatten()
        .filter_map(|meta| {
            let air_ctx = &ctx.per_trace[meta.trace_idx].1;
            let interactions = interactions_of(meta.air_idx);
            if interactions == 0 {
                return None;
            }
            let height = air_ctx.height();
            let lifted = height.max(1 << l_skip);
            let real_rows = if height == lifted && real_rows_ok(meta.air_idx) {
                air_ctx.real_rows.unwrap_or(height).min(height)
            } else {
                lifted
            };
            Some(TraceSlab {
                trace_idx: meta.trace_idx,
                offset: meta.layout_slices.first()?.row_idx,
                log_height: lifted.trailing_zeros(),
                interactions,
                real_rows,
            })
        })
        .collect();
    slabs.sort_by_key(|s| s.offset);
    slabs
}

/// AIRs whose padding rows turned out not to be constant (the input evaluation checks): their
/// `real_rows` hint is ignored for the rest of the process.
static DENIED_AIRS: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());

pub fn deny_air(name: &str) {
    let mut denied = DENIED_AIRS.lock().unwrap();
    if !denied.iter().any(|n| n == name) {
        tracing::warn!(target: "bench", "[gkr-seg] not segmenting {name} from now on");
        denied.push(name.to_string());
    }
}

pub fn air_denied(name: &str) -> bool {
    DENIED_AIRS.lock().unwrap().iter().any(|n| n == name)
}

/// `MLE_GKR_SEG_REPORT=1`: one line per prove with what the segmented input stores.
pub fn report(plan: Option<&SegPlan>, used: usize, logical_len: usize) {
    if std::env::var("MLE_GKR_SEG_REPORT").is_err() || used < (1 << 16) {
        return;
    }
    let Some(plan) = plan else {
        tracing::info!(target: "bench", "[gkr-seg] used={used} logical={logical_len}: not segmentable");
        return;
    };
    let real = plan
        .blocks
        .iter()
        .filter(|b| matches!(b.kind, BlockKind::Real { .. }))
        .count();
    tracing::info!(
        target: "bench",
        "[gkr-seg] used={used} logical={logical_len} blocks={} real_blocks={real} consts={} \
         storage={} (storage/used {:.3})",
        plan.blocks.len(),
        plan.n_consts,
        plan.storage_len,
        plan.storage_len as f64 / used as f64
    );
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) struct Lcg(pub u64);
    impl Lcg {
        pub fn next(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            self.0 >> 33
        }
        pub fn below(&mut self, n: u64) -> u64 {
            self.next() % n
        }
    }

    /// Random stacked slabs, tallest first, with granule `2^g`: heights from `2^(g-3)` up.
    pub(crate) fn random_slabs(rng: &mut Lcg, g: u32, max_extra: u32) -> (Vec<TraceSlab>, usize) {
        let n_slabs = 1 + rng.below(7) as usize;
        let mut logs: Vec<u32> = (0..n_slabs)
            .map(|_| g - 3 + rng.below(max_extra as u64 + 4) as u32)
            .collect();
        logs.sort_unstable_by(|a, b| b.cmp(a));
        let mut slabs = Vec::new();
        let mut offset = 0usize;
        for (trace_idx, log_height) in logs.into_iter().enumerate() {
            let height = 1usize << log_height;
            let real_rows = match rng.below(8) {
                0 => 0,
                1 => 1,
                2 => height,
                3 => height - 1,
                4 => height / 2,
                5 => height / 2 + 1,
                _ => rng.below(height as u64 + 1) as usize,
            };
            let interactions = 1 + rng.below(4) as usize;
            slabs.push(TraceSlab {
                trace_idx,
                offset,
                log_height,
                interactions,
                real_rows,
            });
            offset += interactions * height;
        }
        (slabs, offset)
    }

    /// The tiling, storage and write rules, and that every block is a sub-cube of each vector's
    /// position space, on random inputs.
    #[test]
    fn plan_invariants() {
        let g = 11u32;
        for seed in 0..300u64 {
            let mut rng = Lcg(seed);
            let (slabs, used) = random_slabs(&mut rng, g, 6);
            let logical_len = (1usize << (usize::BITS - used.leading_zeros())).max(1 << (g + 2));
            let Some(plan) = SegPlan::new(&slabs, used, logical_len, g) else {
                // only an input without a real leaf is turned down
                assert!(
                    slabs.iter().all(|s| s.real_rows == 0 && s.log_height >= g),
                    "seed {seed}"
                );
                continue;
            };
            let case = format!("seed={seed} slabs={slabs:?}");
            // tiling, alignment, size
            let mut at = 0;
            let mut stored = 0;
            for b in &plan.blocks {
                assert_eq!(b.offset, at, "{case}");
                assert!(b.log_size >= g, "{case}: {b:?}");
                assert_eq!(b.offset % (1 << b.log_size), 0, "{case}: {b:?}");
                if let BlockKind::Real { base } = b.kind {
                    assert_eq!(base, stored, "{case}");
                    stored += 1 << b.log_size;
                }
                at += 1 << b.log_size;
            }
            assert_eq!(at, logical_len, "{case}");
            assert_eq!(stored, plan.storage_len, "{case}");
            // each slab's written rows are real and contiguous in storage; the rest is its pad
            for (slab, w) in slabs.iter().zip(&plan.writes) {
                let height = 1usize << slab.log_height;
                assert!(w.rows >= slab.real_rows.min(height), "{case}");
                for i in 0..slab.interactions {
                    for row in 0..height {
                        let leaf = slab.offset + i * height + row;
                        let s = plan.storage_of(leaf);
                        if row < w.rows {
                            assert_eq!(s, Some(w.base + i * w.rows + row), "{case}: leaf {leaf}");
                        } else {
                            assert_eq!(s, None, "{case}: leaf {leaf}");
                            let b =
                                plan.blocks[plan.blocks.partition_point(|b| b.offset <= leaf) - 1];
                            assert_eq!(
                                b.kind,
                                BlockKind::Pad {
                                    konst: w.konst.unwrap() + i as u32
                                },
                                "{case}"
                            );
                        }
                    }
                }
            }
            // sub-cube: for each vector level c below g - 1, (block, local p) <-> position is a
            // bijection, and position (p << (log L - b)) | id covers the block's leaves
            for c in 0..=(g - 2) {
                let n = plan.log_len - c;
                let mut seen = vec![false; 1 << n];
                for b in &plan.blocks {
                    let id = plan.block_id(b);
                    let idbits = plan.log_len - b.log_size;
                    for p in 0..(1usize << (b.log_size - c)) {
                        let pos = (p << idbits) | id;
                        assert!(!seen[pos], "{case}: c={c} pos {pos} twice");
                        seen[pos] = true;
                        let node = rev(pos, n);
                        let leaf = node << c;
                        assert!(
                            leaf >= b.offset && leaf < b.offset + (1 << b.log_size),
                            "{case}: c={c} {b:?} p={p}"
                        );
                        assert_eq!(rev(node - (b.offset >> c), b.log_size - c), p, "{case}");
                    }
                }
                assert!(seen.iter().all(|&s| s), "{case}: c={c}");
            }
            // device tables agree with the blocks
            let t = plan.device_tables();
            for (gi, &e) in t.storage_gran.iter().enumerate() {
                let blk = t.real[e as usize];
                let at = gi << g;
                assert!(
                    at >= blk.base as usize && at < blk.base as usize + (1 << blk.log),
                    "{case}"
                );
            }
            for (gi, &e) in t.leaf_gran.iter().enumerate() {
                let leaf = gi << g;
                match plan.storage_of(leaf) {
                    Some(s) => {
                        let blk = t.real[e as usize];
                        assert!(e & 0x8000_0000 == 0, "{case}");
                        assert!(s >= blk.base as usize && s < blk.base as usize + (1 << blk.log));
                    }
                    None => assert!(e & 0x8000_0000 != 0, "{case}"),
                }
            }
        }
    }

    #[test]
    fn plan_example() {
        let g = 11;
        let h = 1usize << 13;
        let slabs = [
            TraceSlab {
                trace_idx: 0,
                offset: 0,
                log_height: 13,
                interactions: 2,
                real_rows: 3000, // -> 4096
            },
            TraceSlab {
                trace_idx: 1,
                offset: 2 * h,
                log_height: 9,
                interactions: 3,
                real_rows: 512,
            },
        ];
        let used = 2 * h + 3 * 512;
        let plan = SegPlan::new(&slabs, used, 1 << 15, g).unwrap();
        let kinds: Vec<_> = plan
            .blocks
            .iter()
            .map(|b| (b.offset, b.log_size, b.kind))
            .collect();
        use BlockKind::*;
        assert_eq!(
            kinds,
            vec![
                (0, 12, Real { base: 0 }),
                (4096, 12, Pad { konst: 1 }),
                (8192, 12, Real { base: 4096 }),
                (12288, 12, Pad { konst: 2 }),
                (16384, 11, Real { base: 8192 }),
                (18432, 11, Pad { konst: 0 }),
                (20480, 12, Pad { konst: 0 }),
                (24576, 13, Pad { konst: 0 }),
            ]
        );
        assert_eq!(plan.storage_len, 8192 + 2048);
        assert_eq!(
            plan.writes,
            vec![
                SlabWrite {
                    trace_idx: 0,
                    base: 0,
                    rows: 4096,
                    konst: Some(1)
                },
                SlabWrite {
                    trace_idx: 1,
                    base: 8192,
                    rows: 512,
                    konst: None
                },
            ]
        );
        assert_eq!(plan.zero_fill, (8192 + 1536, 512));
    }
}
