//! Deriving a run's figures from recorded spans: per-role occupancy, device-facing lane
//! concurrency, role overlap, and the occupancy strip.
//!
//! Pure functions of a span list, so they are testable without a prover and cannot perturb a run.
//! Two conventions the field docs below depend on: **`idle` includes `wait`** (one number for "not
//! working", one for the contended part of it), and **a pool's figures are summed over its lanes**,
//! so `busy` may exceed `wall` and occupancy divides by the lanes' summed lifetimes rather than by
//! `wall` — see [`RoleFigures::lane_time_us`], which is also where the reconciliation lives.
use std::collections::BTreeMap;

use super::record::{LaneId, Role, Span, State, WorkKind};

// ------------------------------------------------------------------------------- per-role rollup

/// What one role — and every lane playing it — did.
#[derive(Clone, Debug, PartialEq)]
pub struct RoleFigures {
    pub role: Role,
    /// Lanes seen for this role. Zero means the role did not run — a stage can be skipped
    /// (`--step`), and a role that never existed must report as absent rather than as idle.
    pub lanes: usize,
    pub busy_us: u64,
    /// All not-working time, `wait_us` included.
    pub idle_us: u64,
    /// The contended part of `idle_us`: blocked on a gate, a barrier or a full queue.
    pub wait_us: u64,
    /// First lane start to last lane end, across the role's lanes. An envelope, so it may exceed any
    /// single lane's life — use [`Self::lane_time_us`] whenever the question is "out of how much".
    pub wall_us: u64,
    /// Sum of the role's lanes' own lifetimes, and the denominator for occupancy. Not `lanes ×
    /// wall_us`, which charges a lane that died early for time it did not exist for.
    ///
    /// Reconciles as `busy_us + idle_us + gaps`, gaps being lane time no span covered — measured by
    /// [`super::record::validate`], small but not zero.
    pub lane_time_us: u64,
    /// Busy split by what the work was. Only interesting where one lane does several kinds — the
    /// recursion lane takes convert and combine work in turn, and under `MLE_RECURSION_LANE=0` the
    /// one prover lane takes all three — but recorded for every role so the split never has to be
    /// special-cased.
    pub busy_by_work: BTreeMap<&'static str, u64>,
}

impl RoleFigures {
    /// Busy as a fraction of the lane-time the role had available. `None` when the role did not
    /// run, so a caller prints "absent" rather than 0 %.
    ///
    /// Against the role's own lane-time, not the window — so occupancies are **not comparable between
    /// roles**: a preparer that dies a third of the way in is measured against its own third.
    pub fn occ(&self) -> Option<f64> {
        (self.lane_time_us > 0).then(|| self.busy_us as f64 / self.lane_time_us as f64)
    }
}

/// Accumulator for one role while rolling spans up. Named rather than a tuple: the fields are all
/// `u64` and positional access would make a transposition impossible to see.
#[derive(Default)]
struct Acc {
    /// Each lane's own first-start and last-end. Both the lane count and the occupancy denominator
    /// are read off this, so a lane cannot be counted without its lifetime being tracked with it.
    per_lane: BTreeMap<LaneId, (u64, u64)>,
    busy_us: u64,
    idle_us: u64,
    wait_us: u64,
    busy_by_work: BTreeMap<&'static str, u64>,
}

/// Roll every span up by role. Roles with no spans are absent from the result, not zeroed.
pub fn by_role(spans: &[Span]) -> Vec<RoleFigures> {
    let mut acc_by_role: BTreeMap<Role, Acc> = BTreeMap::new();
    for s in spans {
        let a = acc_by_role.entry(s.lane.role).or_default();
        let life = a.per_lane.entry(s.lane).or_insert((s.start_us, s.end_us));
        life.0 = life.0.min(s.start_us);
        life.1 = life.1.max(s.end_us);
        let d = s.duration_us();
        match s.state {
            State::Busy => {
                a.busy_us += d;
                *a.busy_by_work.entry(s.work.as_str()).or_default() += d;
            }
            // Both count toward idle; wait is additionally tallied as the contended subset of it.
            State::Idle => a.idle_us += d,
            State::Wait => {
                a.idle_us += d;
                a.wait_us += d;
            }
        }
    }
    acc_by_role
        .into_iter()
        .map(|(role, a)| {
            let first = a.per_lane.values().map(|(f, _)| *f).min().unwrap_or(0);
            let last = a.per_lane.values().map(|(_, l)| *l).max().unwrap_or(0);
            RoleFigures {
                role,
                lanes: a.per_lane.len(),
                busy_us: a.busy_us,
                idle_us: a.idle_us,
                wait_us: a.wait_us,
                wall_us: last.saturating_sub(first),
                lane_time_us: a.per_lane.values().map(|(f, l)| l.saturating_sub(*f)).sum(),
                busy_by_work: a.busy_by_work,
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------- interval machinery

/// Each lane's own lifetime: its first span's start to its last span's end. Distinct from a role's
/// wall, which spans every lane of the role — a per-lane figure needs the per-lane denominator.
pub fn lane_lifetimes(spans: &[Span]) -> Vec<(LaneId, u64)> {
    let mut by_lane: BTreeMap<LaneId, (u64, u64)> = BTreeMap::new();
    for s in spans {
        let e = by_lane.entry(s.lane).or_insert((u64::MAX, 0));
        e.0 = e.0.min(s.start_us);
        e.1 = e.1.max(s.end_us);
    }
    by_lane
        .into_iter()
        .map(|(lane, (first, last))| (lane, last.saturating_sub(first)))
        .collect()
}

/// Merge intervals into a disjoint, sorted set. Every cross-lane figure below is defined on sets of
/// instants, so the first step is always to stop thinking about spans and start thinking about the
/// union they cover.
fn merge(mut iv: Vec<(u64, u64)>) -> Vec<(u64, u64)> {
    iv.retain(|(a, b)| b > a);
    iv.sort_unstable();
    let mut out: Vec<(u64, u64)> = Vec::with_capacity(iv.len());
    for (a, b) in iv {
        match out.last_mut() {
            Some(last) if a <= last.1 => last.1 = last.1.max(b),
            _ => out.push((a, b)),
        }
    }
    out
}

/// Measure of the intersection of two interval sets, both assumed merged.
fn intersect(a: &[(u64, u64)], b: &[(u64, u64)]) -> u64 {
    let (mut i, mut j, mut acc) = (0, 0, 0u64);
    while i < a.len() && j < b.len() {
        let lo = a[i].0.max(b[j].0);
        let hi = a[i].1.min(b[j].1);
        if hi > lo {
            acc += hi - lo;
        }
        if a[i].1 < b[j].1 {
            i += 1;
        } else {
            j += 1;
        }
    }
    acc
}

fn busy_intervals_of(spans: &[Span], role: Role) -> Vec<(u64, u64)> {
    merge(
        spans
            .iter()
            .filter(|s| s.lane.role == role && s.state == State::Busy)
            .map(|s| (s.start_us, s.end_us))
            .collect(),
    )
}

/// How long two roles were both working. The measure of whether they ran in parallel, as opposed
/// to merely both having happened — which their separate totals cannot distinguish.
pub fn overlap_us(spans: &[Span], a: Role, b: Role) -> u64 {
    intersect(&busy_intervals_of(spans, a), &busy_intervals_of(spans, b))
}

/// Total keygen time recorded on one role's lanes.
///
/// Exists to be checked against the figure the machine that did the keygens reports for itself: two
/// independent measurements of one quantity, and the only place the span layer can be checked against
/// something it did not produce. A mismatch means a missed close or an uninstrumented keygen call site,
/// neither of which has any other symptom.
pub fn keygen_us_on(spans: &[Span], role: Role) -> u64 {
    spans
        .iter()
        .filter(|s| s.lane.role == role && s.state == State::Busy && s.work == WorkKind::Keygen)
        .map(|s| s.duration_us())
        .sum()
}

// ------------------------------------------------------------------------------- device-facing lanes

/// How many device-facing lanes were working at once, over the window.
///
/// Named for what it measures: **lanes**, not hardware. A lane counts as working while its thread is
/// inside GPU-related work, which is not the same as the device having kernels in flight — two lanes
/// submitting to one stream serialise on the device while both count here. The hardware question
/// needs a device-level timeline; this answers whether the pipeline's roles were arranged to
/// overlap at all.
#[derive(Clone, Debug, PartialEq)]
pub struct GpuLaneFigures {
    /// Window length the buckets are shares of.
    pub window_us: u64,
    /// `buckets[k]` = time with exactly k device-facing lanes working. `buckets[0]` is the dead
    /// time: nothing device-facing was working at all.
    pub buckets: Vec<u64>,
}

impl GpuLaneFigures {
    pub fn dead_us(&self) -> u64 {
        self.buckets.first().copied().unwrap_or(0)
    }
    pub fn share(&self, k: usize) -> f64 {
        if self.window_us == 0 {
            return 0.0;
        }
        self.buckets.get(k).copied().unwrap_or(0) as f64 / self.window_us as f64
    }
}

/// Sweep the device-facing busy spans. Overlapping spans on *different* lanes are the point; spans
/// on one lane cannot overlap (see [`super::spans::validate`]), so a level of k really does mean k
/// distinct lanes.
pub fn gpu_lane_figures(spans: &[Span], window_us: u64) -> GpuLaneFigures {
    let mut events: Vec<(u64, i32)> = Vec::new();
    for s in spans.iter().filter(|s| s.is_gpu_busy()) {
        events.push((s.start_us, 1));
        events.push((s.end_us, -1));
    }
    events.sort_unstable();

    // Max level is bounded by the lanes that can be device-facing at once, but the sweep does not
    // assume a bound: an unexpectedly high level is a finding, not something to clamp away.
    let mut buckets = vec![0u64; 1];
    let mut level = 0usize;
    let mut prev = 0u64;
    let mut covered = 0u64;
    for (t, delta) in events {
        if t > prev && level > 0 {
            if buckets.len() <= level {
                buckets.resize(level + 1, 0);
            }
            buckets[level] += t - prev;
            covered += t - prev;
        }
        prev = t;
        level = if delta > 0 {
            level + 1
        } else {
            level.saturating_sub(1)
        };
    }
    // Everything the sweep did not cover is dead: the window minus the union of working time.
    buckets[0] = window_us.saturating_sub(covered);
    GpuLaneFigures { window_us, buckets }
}

// ----------------------------------------------------------------------------------------- strip

/// One line of the occupancy strip.
#[derive(Clone, Debug, PartialEq)]
pub struct StripRow {
    pub label: String,
    /// `None` for the prove lane's per-work sub-rows, which are shares of the row above rather than
    /// occupancies of their own.
    pub occ: Option<f64>,
    pub cells: String,
}

/// Shade thresholds. Kept beside the legend text that describes them so the two cannot drift.
pub const LEGEND: &str = "░ <12%  ▒ 12-37%  ▓ 37-75%  █ >75%  ▨ blocked";

fn glyph(frac: f64) -> char {
    match frac {
        f if f < 0.125 => '░',
        f if f < 0.375 => '▒',
        f if f < 0.75 => '▓',
        _ => '█',
    }
}

/// Overlap of `[lo, hi)` with a span, in microseconds.
fn clipped(s: &Span, lo: u64, hi: u64) -> u64 {
    let a = s.start_us.max(lo);
    let b = s.end_us.min(hi);
    b.saturating_sub(a)
}

/// How much of `[lo, hi)` the spans satisfying `pred` covered. Shared by the role rows and the prove
/// sub-rows, which ask the same question of different subsets.
fn covered_in(spans: &[Span], lo: u64, hi: u64, pred: impl Fn(&Span) -> bool) -> u64 {
    spans
        .iter()
        .filter(|s| pred(s))
        .map(|s| clipped(s, lo, hi))
        .sum()
}

/// The roles drawn, in order. Preparer pools get one row each rather than one per lane: with both
/// arms shown, six preparer lanes would be most of the figure, and a pool's aggregate shade already
/// makes imbalance visible — one of two lanes permanently working reads as a steady half-shade.
const DRAWN: &[Role] = &[
    Role::Snapshot,
    Role::Emulate,
    Role::RiscvPreparer,
    Role::ConvertPreparer,
    Role::CombinePreparer,
    Role::Prove,
    Role::ProveRecursion,
];

/// Render the strip: one row per drawn role, plus one sub-row per work kind a role that takes
/// more than one took.
///
/// **`cell_us` is a fixed duration, not the window divided by `cells`.** That is what lets two runs be
/// compared without either knowing the other's window: identical cells mean the same column means the
/// same elapsed time in both, and the slower run simply runs to more of them. Dividing the window
/// instead would give the two arms cells of subtly different length — a drift that reaches a whole cell
/// by the right-hand edge, silently breaking the one property the comparison rests on.
pub fn strip(spans: &[Span], cell_us: u64, cells: usize, window_us: u64) -> Vec<StripRow> {
    let mut rows = Vec::new();
    if cell_us == 0 || cells == 0 {
        return rows;
    }
    // The last cell may extend past the end of the window, since the count is rounded up so the tail is
    // drawn at all. Its occupancy has to be taken against the part that exists: dividing a few
    // milliseconds of work by a whole cell renders a lane that was busy to the very last instant as
    // nearly idle, which is the opposite of what the tail is there to show.
    let denom_of = |lo: u64| -> u64 {
        if window_us > lo {
            cell_us.min(window_us - lo)
        } else {
            cell_us
        }
    };
    let role_index: BTreeMap<Role, RoleFigures> =
        by_role(spans).into_iter().map(|f| (f.role, f)).collect();

    for &role in DRAWN {
        let Some(fig) = role_index.get(&role) else {
            continue; // the role did not run; drawing an empty row would imply it was idle
        };
        let lanes = fig.lanes.max(1) as u64;
        let mut cs = String::with_capacity(cells);
        for c in 0..cells {
            let lo = c as u64 * cell_us;
            let hi = lo + cell_us;
            let busy = covered_in(spans, lo, hi, |s| {
                s.lane.role == role && s.state == State::Busy
            });
            let wait = covered_in(spans, lo, hi, |s| {
                s.lane.role == role && s.state == State::Wait
            });
            // Contention wins the cell when it dominated it: a lane blocked downstream for most of
            // a cell is a different fact from one that was lightly loaded, and shading alone
            // conflates the two.
            cs.push(if wait > busy {
                '▨'
            } else {
                glyph(busy as f64 / (denom_of(lo) * lanes) as f64)
            });
        }
        rows.push(StripRow {
            label: if fig.lanes > 1 {
                format!("{}×{}", role.as_str(), fig.lanes)
            } else {
                role.as_str().to_string()
            },
            // Against the lane's own lifetime, while the cells beside it divide by the cell — so a
            // lane that ends early trails pale cells this number does not average in.
            occ: fig.occ(),
            cells: cs,
        });

        // A lane that took more than one kind of prove work gets its row as a total, with the kinds
        // visible only as sub-rows — which is what makes "combine crowding out convert" readable.
        // Which kinds those are comes from `busy_by_work`, which already holds exactly this (the
        // kinds this role recorded as busy), rather than from a per-role constant: the roles do not
        // have fixed kinds. Under `MLE_RECURSION_LANE=0` the one `prove` lane takes all three, and
        // the split has to appear there exactly as it appears on `prove-rec` when the lane is on.
        //
        // A lane with a single kind gets none — that row would be its parent by another name, and
        // at N lanes it would read N times darker, since a sub-row is shaded against one cell while
        // the row above divides by `cell x lanes`. (That denominator mismatch predates the lane
        // split and is left alone here; correcting it would move every published strip.) Dropping
        // that row is the one place the strip deliberately differs, and each shape sees it in one
        // step mode only: with the lane on, `--step convert`, where the recursion lane used to draw
        // a lone `convert`; with it off, `--step riscv`, where the single lane used to draw a lone
        // `riscv` — the two-lane shape never drew that one, since `prove` had no sub-rows at all.
        // `--step combine` — every benchmark — has two kinds or more on both shapes and is
        // untouched.
        let ran: Vec<WorkKind> = [
            WorkKind::ProveRiscv,
            WorkKind::ProveConvert,
            WorkKind::ProveCombine,
        ]
        .into_iter()
        .filter(|work| fig.busy_by_work.contains_key(work.as_str()))
        .collect();
        if ran.len() > 1 {
            for work in ran {
                let mut cs = String::with_capacity(cells);
                for c in 0..cells {
                    let lo = c as u64 * cell_us;
                    let d = covered_in(spans, lo, lo + cell_us, |s| {
                        s.lane.role == role && s.state == State::Busy && s.work == work
                    });
                    cs.push(glyph(d as f64 / denom_of(lo) as f64));
                }
                rows.push(StripRow {
                    label: format!("  {}", work.as_str().trim_start_matches("prove-")),
                    occ: None,
                    cells: cs,
                });
            }
        }
    }
    rows
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sp(role: Role, idx: usize, state: State, work: WorkKind, a: u64, b: u64) -> Span {
        Span {
            lane: LaneId::new(role, idx),
            state,
            work,
            item: None,
            start_us: a,
            end_us: b,
        }
    }

    #[test]
    fn pool_occupancy_divides_by_lane_count() {
        // Two lanes, each busy 400 of a 1000 wall: busy sums to 800, occupancy is 40 %.
        let spans = vec![
            sp(
                Role::RiscvPreparer,
                0,
                State::Busy,
                WorkKind::PrepareRiscv,
                0,
                400,
            ),
            sp(
                Role::RiscvPreparer,
                0,
                State::Idle,
                WorkKind::PrepareRiscv,
                400,
                1000,
            ),
            sp(
                Role::RiscvPreparer,
                1,
                State::Busy,
                WorkKind::PrepareRiscv,
                0,
                400,
            ),
            sp(
                Role::RiscvPreparer,
                1,
                State::Idle,
                WorkKind::PrepareRiscv,
                400,
                1000,
            ),
        ];
        let f = &by_role(&spans)[0];
        assert_eq!(f.lanes, 2);
        assert_eq!(f.busy_us, 800);
        assert_eq!(f.wall_us, 1000);
        assert_eq!(f.lane_time_us, 2000);
        assert!((f.occ().unwrap() - 0.4).abs() < 1e-9);
        // Equal only because these spans tile each lane with no gap; a real lane leaves small ones.
        assert_eq!(f.busy_us + f.idle_us, f.lane_time_us);
    }

    /// The case the equal-lifetime test above cannot reach: a role whose lanes do not live equally
    /// long. `wall` is the envelope of both, so multiplying it by the lane count charges the shorter
    /// lane for time it did not exist for. Today's pipeline spawns and drains a role's lanes together,
    /// so the two agree in practice — this pins the behaviour for when they stop agreeing.
    #[test]
    fn occupancy_denominator_is_lane_time_not_lanes_times_wall() {
        let spans = vec![
            // Lane 0 lives the whole envelope, half of it busy.
            sp(
                Role::ConvertPreparer,
                0,
                State::Busy,
                WorkKind::PrepareConvert,
                0,
                500,
            ),
            sp(
                Role::ConvertPreparer,
                0,
                State::Idle,
                WorkKind::PrepareConvert,
                500,
                1000,
            ),
            // Lane 1 starts late and dies early: 400 µs of life, all of it busy.
            sp(
                Role::ConvertPreparer,
                1,
                State::Busy,
                WorkKind::PrepareConvert,
                200,
                600,
            ),
        ];
        let f = &by_role(&spans)[0];
        assert_eq!(f.wall_us, 1000, "the envelope spans both lanes");
        assert_eq!(f.lane_time_us, 1400, "1000 + 400, not 2 x 1000");
        assert_eq!(f.busy_us + f.idle_us, f.lane_time_us);
        // 900/1400 = 64.3 %. The old denominator gave 900/2000 = 45 %, understating it by 19 pp by
        // charging lane 1 with 600 µs of non-existence.
        assert!((f.occ().unwrap() - 900.0 / 1400.0).abs() < 1e-9);
    }

    #[test]
    fn wait_is_counted_inside_idle_and_also_on_its_own() {
        let spans = vec![
            sp(
                Role::ConvertPreparer,
                0,
                State::Busy,
                WorkKind::Keygen,
                0,
                100,
            ),
            sp(
                Role::ConvertPreparer,
                0,
                State::Wait,
                WorkKind::Keygen,
                100,
                300,
            ),
            sp(
                Role::ConvertPreparer,
                0,
                State::Idle,
                WorkKind::Keygen,
                300,
                400,
            ),
        ];
        let f = &by_role(&spans)[0];
        assert_eq!(f.busy_us, 100);
        assert_eq!(f.wait_us, 200);
        assert_eq!(f.idle_us, 300, "idle must include the wait");
        assert_eq!(f.busy_us + f.idle_us, f.wall_us);
    }

    #[test]
    fn absent_role_reports_no_occupancy_rather_than_zero() {
        let spans = vec![sp(Role::Prove, 0, State::Busy, WorkKind::ProveRiscv, 0, 10)];
        let all = by_role(&spans);
        assert_eq!(all.len(), 1, "a role with no spans is absent, not zeroed");
        assert!(all[0].occ().is_some());
    }

    #[test]
    fn concurrency_buckets_partition_the_window() {
        // convert-preparer [0,400) and prove [200,600) over a 1000 window:
        //   k=2 on [200,400) = 200; k=1 on [0,200)+[400,600) = 400; k=0 = 400.
        let spans = vec![
            sp(
                Role::ConvertPreparer,
                0,
                State::Busy,
                WorkKind::Keygen,
                0,
                400,
            ),
            sp(Role::Prove, 0, State::Busy, WorkKind::ProveRiscv, 200, 600),
        ];
        let g = gpu_lane_figures(&spans, 1000);
        assert_eq!(g.buckets[2], 200);
        assert_eq!(g.buckets[1], 400);
        assert_eq!(g.dead_us(), 400);
        assert_eq!(
            g.buckets.iter().sum::<u64>(),
            1000,
            "buckets partition the window"
        );
    }

    #[test]
    fn blocked_lanes_do_not_occupy_the_device() {
        // A gate wait on a device-facing lane must not count as working.
        let spans = vec![
            sp(
                Role::ConvertPreparer,
                0,
                State::Wait,
                WorkKind::Keygen,
                0,
                500,
            ),
            sp(Role::Prove, 0, State::Busy, WorkKind::ProveRiscv, 0, 500),
        ];
        let g = gpu_lane_figures(&spans, 500);
        assert_eq!(g.buckets[1], 500);
        assert_eq!(g.buckets.get(2).copied().unwrap_or(0), 0);
    }

    #[test]
    fn cpu_work_is_excluded_from_the_device_sweep() {
        let spans = vec![
            sp(
                Role::RiscvPreparer,
                0,
                State::Busy,
                WorkKind::PrepareRiscv,
                0,
                500,
            ),
            sp(
                Role::ConvertPreparer,
                0,
                State::Busy,
                WorkKind::PrepareConvert,
                0,
                500,
            ),
        ];
        let g = gpu_lane_figures(&spans, 500);
        assert_eq!(
            g.dead_us(),
            500,
            "three busy CPU preparers still leave the device idle"
        );
    }

    #[test]
    fn overlap_measures_simultaneous_work_only() {
        let spans = vec![
            sp(
                Role::ConvertPreparer,
                0,
                State::Busy,
                WorkKind::Keygen,
                0,
                300,
            ),
            sp(
                Role::ConvertPreparer,
                0,
                State::Busy,
                WorkKind::Keygen,
                500,
                700,
            ),
            sp(Role::Prove, 0, State::Busy, WorkKind::ProveRiscv, 200, 600),
        ];
        // [200,300) and [500,600)
        assert_eq!(overlap_us(&spans, Role::ConvertPreparer, Role::Prove), 200);
        // Symmetric, and self-overlap is the role's own busy union.
        assert_eq!(overlap_us(&spans, Role::Prove, Role::ConvertPreparer), 200);
    }

    #[test]
    fn every_drawn_role_appears_once() {
        // `strip` emits one row per entry, so a repeated role silently draws the same lane twice —
        // which is what a blanket rename of a retired role did, and what the row count then caught
        // several tests later rather than here.
        let mut seen = std::collections::BTreeSet::new();
        for &r in DRAWN {
            assert!(seen.insert(r), "{r:?} appears twice in DRAWN");
        }
    }

    #[test]
    fn strip_shades_by_occupancy_and_marks_dominant_waits() {
        // Four cells over 400us. Cell 0 fully busy, cell 1 fully blocked, cell 2 half busy,
        // cell 3 untouched.
        let spans = vec![
            sp(
                Role::ConvertPreparer,
                0,
                State::Busy,
                WorkKind::Keygen,
                0,
                100,
            ),
            sp(
                Role::ConvertPreparer,
                0,
                State::Wait,
                WorkKind::Keygen,
                100,
                200,
            ),
            sp(
                Role::ConvertPreparer,
                0,
                State::Busy,
                WorkKind::Keygen,
                200,
                250,
            ),
            sp(
                Role::ConvertPreparer,
                0,
                State::Idle,
                WorkKind::Keygen,
                250,
                400,
            ),
        ];
        let rows = strip(&spans, 100, 4, 400);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].cells, "█▨▓░");
    }

    #[test]
    fn cells_are_a_fixed_duration_and_do_not_drift() {
        // Busy exactly over the third cell. With a fixed cell the mark lands on cell 2 and nowhere
        // else; a cell derived by dividing the window would smear it as the row got longer.
        let l = LaneId::new(Role::Prove, 0);
        let spans = vec![sp(
            Role::Prove,
            0,
            State::Busy,
            WorkKind::ProveRiscv,
            200,
            300,
        )];
        let _ = l;
        assert_eq!(strip(&spans, 100, 5, 500)[0].cells, "░░█░░");
        // Same spans, more cells: the mark stays put rather than moving with the row's length.
        assert_eq!(strip(&spans, 100, 9, 900)[0].cells, "░░█░░░░░░");
    }

    #[test]
    fn the_tail_cell_is_measured_against_the_part_inside_the_window() {
        // Window 250us, cells of 100us: the third cell is only 50us long. A lane busy for all 50 of
        // them is fully occupied, and must not render as 50/100 just because the cell was rounded up.
        let spans = vec![sp(
            Role::Prove,
            0,
            State::Busy,
            WorkKind::ProveRiscv,
            200,
            250,
        )];
        assert_eq!(strip(&spans, 100, 3, 250)[0].cells, "░░█");
    }

    #[test]
    fn keygen_total_is_summed_per_role_for_the_cross_check() {
        let spans = vec![
            sp(
                Role::CombinePreparer,
                0,
                State::Busy,
                WorkKind::Keygen,
                0,
                200,
            ),
            sp(
                Role::CombinePreparer,
                1,
                State::Busy,
                WorkKind::Keygen,
                300,
                450,
            ),
            // Another role's keygen, and a wait on the right role, must both stay out of it.
            sp(
                Role::ConvertPreparer,
                0,
                State::Busy,
                WorkKind::Keygen,
                0,
                999,
            ),
            sp(
                Role::CombinePreparer,
                0,
                State::Wait,
                WorkKind::Keygen,
                500,
                900,
            ),
        ];
        assert_eq!(keygen_us_on(&spans, Role::CombinePreparer), 350);
        assert_eq!(keygen_us_on(&spans, Role::ConvertPreparer), 999);
    }

    #[test]
    fn one_prove_lane_splits_into_all_three_kinds() {
        // `MLE_RECURSION_LANE=0`: the single `prove` lane takes riscv, convert and combine in turn,
        // and the strip has to show that split under it — the `busy split:` log line gives the
        // totals, but the sub-rows are the only place a reader can see *when* recursion crowded out
        // riscv. Sub-row order is the pipeline's, not the order the kinds happened to run in.
        let spans = vec![
            sp(Role::Prove, 0, State::Busy, WorkKind::ProveCombine, 0, 100),
            sp(Role::Prove, 0, State::Busy, WorkKind::ProveRiscv, 100, 200),
            sp(
                Role::Prove,
                0,
                State::Busy,
                WorkKind::ProveConvert,
                200,
                300,
            ),
        ];
        let rows = strip(&spans, 100, 3, 300);
        let labels: Vec<&str> = rows.iter().map(|r| r.label.trim()).collect();
        assert_eq!(labels, vec!["prove", "riscv", "convert", "combine"]);
        // The sub-rows are shares of the row above, so they carry no occupancy of their own.
        assert!(rows[0].occ.is_some());
        assert!(rows[1..].iter().all(|r| r.occ.is_none()));
    }

    #[test]
    fn sub_rows_appear_only_for_kinds_that_ran() {
        // Riscv and convert on one lane, no combine: the layer that did not run gets no row, so a
        // `--step convert` strip cannot be misread as a collapsed combine tree.
        let spans = vec![
            sp(Role::Prove, 0, State::Busy, WorkKind::ProveRiscv, 0, 100),
            sp(
                Role::Prove,
                0,
                State::Busy,
                WorkKind::ProveConvert,
                100,
                200,
            ),
        ];
        let rows = strip(&spans, 100, 2, 200);
        let labels: Vec<&str> = rows.iter().map(|r| r.label.trim()).collect();
        assert_eq!(labels, vec!["prove", "riscv", "convert"]);
    }

    #[test]
    fn a_single_kind_lane_gets_no_sub_rows() {
        // The two-lane default: `prove` takes riscv alone. Its one sub-row would be the row above
        // by another name — and worse, shaded against one cell where the parent divides by
        // `cell x lanes`, so on a four-card run it would read four times darker on identical work.
        let spans = vec![
            sp(Role::Prove, 0, State::Busy, WorkKind::ProveRiscv, 0, 100),
            sp(
                Role::ProveRecursion,
                0,
                State::Busy,
                WorkKind::ProveConvert,
                100,
                200,
            ),
        ];
        let rows = strip(&spans, 100, 2, 200);
        let labels: Vec<&str> = rows.iter().map(|r| r.label.trim()).collect();
        assert_eq!(labels, vec!["prove", "prove-rec"]);
    }

    #[test]
    fn recursion_sub_rows_do_not_count_the_riscv_lane() {
        // Before the lanes split, the sub-row filter was on work kind alone. It has to be on the
        // role too, or the recursion row's sub-rows would sum in whatever the riscv lane did.
        let spans = vec![
            sp(Role::Prove, 0, State::Busy, WorkKind::ProveConvert, 0, 100),
            sp(
                Role::ProveRecursion,
                0,
                State::Busy,
                WorkKind::ProveConvert,
                100,
                150,
            ),
            // Only to give `prove-rec` a second kind, so it gets sub-rows at all.
            sp(
                Role::ProveRecursion,
                0,
                State::Busy,
                WorkKind::ProveCombine,
                150,
                200,
            ),
        ];
        let rows = strip(&spans, 100, 2, 200);
        // Anchored after the `prove-rec` row rather than found by label alone: `prove` draws a
        // `convert` sub-row of its own the moment it takes a second kind, and this assertion is
        // about the recursion lane's.
        let rec = rows
            .iter()
            .position(|r| r.label.trim() == "prove-rec")
            .expect("prove-rec row");
        let sub = rows[rec..]
            .iter()
            .find(|r| r.label.trim() == "convert")
            .expect("prove-rec's convert sub-row");
        // Cell 0 is the riscv lane's span, which this row must not see; cell 1 is half the
        // recursion lane's.
        assert_eq!(sub.cells.chars().next(), Some(glyph(0.0)));
    }
}
