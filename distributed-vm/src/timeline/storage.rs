use crate::timeline::{Stage, Stage::*, Timeline, COORD_TL_ID};
use dashmap::DashMap;
use std::{collections::HashMap, fmt::Write as _, sync::RwLock, time::SystemTime};
use tracing::{info, warn};

pub trait TimelineStore {
    fn insert_active(&self, key: usize, tl: Timeline);
    fn remove_active(&self, key: &usize) -> Option<Timeline>;
    fn push_finished(&self, tl: Timeline);
    fn all_finished(&self) -> Vec<Timeline>;
}

pub struct InMemStore {
    active: DashMap<usize, Timeline>,
    finished: RwLock<Vec<Timeline>>,
}

impl InMemStore {
    pub fn new() -> Self {
        Self {
            active: DashMap::new(),
            finished: RwLock::new(vec![]),
        }
    }
}

impl TimelineStore for InMemStore {
    // Notes: currently, insert_active & remove_active is only used for coordinator timeline.
    fn insert_active(&self, key: usize, tl: Timeline) {
        self.active.insert(key, tl);
    }
    fn remove_active(&self, key: &usize) -> Option<Timeline> {
        self.active.remove(key).map(|(_, tl)| tl)
    }
    fn push_finished(&self, tl: Timeline) {
        self.finished.write().unwrap().push(tl);
    }
    fn all_finished(&self) -> Vec<Timeline> {
        self.finished.read().unwrap().clone()
    }
}

impl InMemStore {
    pub fn summarize_finished(&self) {
        let mut all = self.all_finished();
        let (mut single, mut multi): (Vec<_>, Vec<_>) = all
            .into_iter()
            .partition(|tl| tl.start_index == tl.end_index);
        single.sort_by_key(|tl| tl.start_index);
        single.extend(multi);
        let all = single;

        // helper fn in this script
        let ts = |tl: &Timeline, s: Stage| tl.get(s);
        let ms = |a: Option<SystemTime>, b: Option<SystemTime>| match (a, b) {
            (Some(a), Some(b)) => a.duration_since(b).ok().map(|d| d.as_millis()),
            _ => None,
        };
        fn fmt_ms(opt: Option<u128>) -> String {
            opt.map(|v| format!("{v} ms"))
                .unwrap_or_else(|| "N/A".into())
        }

        // Coordinator Timeline
        let coord_tl = all
            .iter()
            .find(|tl| tl.start_index == COORD_TL_ID && tl.end_index == COORD_TL_ID)
            .expect("coordinator timeline missing");
        let e2e_ms = ms(
            ts(coord_tl, CoordinatorFinished),
            ts(coord_tl, CoordinatorStarted),
        )
        .expect("No E2E coordinator timeline!");

        // Riscv & Convert
        struct RiscvRow {
            chunk: usize,
            created: Option<u128>,
            waiting: Option<u128>,
            net_c2w: Option<u128>,
            gen: Option<u128>,
            net_w2c: Option<u128>,
        }

        let mut riscv_rows = Vec::<RiscvRow>::new();

        // Collect rows
        let mut prev_created = None;
        for tl in &all {
            match (tl.start_index, tl.end_index) {
                (idx, _) if idx == tl.end_index && idx != COORD_TL_ID => {
                    let created = ts(tl, RecordCreated);
                    let sending = ts(tl, RecordSending);
                    let recv = ts(tl, WorkerRecv);
                    let convert_end = ts(tl, RiscvConvertDone);
                    let cordi_recv = ts(tl, CoordinatorRecv);

                    let mut waiting_ms = ms(sending, created);
                    // used for single-node mode
                    if sending.is_none() {
                        waiting_ms = ms(recv, created);
                    }

                    let mut created_gap = ms(created, prev_created);

                    // chunk_index starts from 0
                    if idx == 0 {
                        created_gap = ms(created, ts(coord_tl, CoordinatorStarted));
                    }

                    prev_created = created;

                    riscv_rows.push(RiscvRow {
                        chunk: idx,
                        created: created_gap,
                        waiting: waiting_ms,
                        net_c2w: ms(recv, sending),
                        gen: ms(convert_end, recv),
                        net_w2c: ms(cordi_recv, convert_end),
                    });
                }

                _ => {}
            }
        }
        // Combine
        struct CombRow {
            inputs: String,
            wait: Option<u128>,
            net_c2w: Option<u128>,
            comb: Option<u128>,
            net_w2c: Option<u128>,
        }
        let mut comb_rows = Vec::<CombRow>::new();

        let mut range_map: HashMap<(usize, usize), &Timeline> = HashMap::new();
        for tl in &all {
            range_map.insert((tl.start_index, tl.end_index), tl);
        }
        for tl in &all {
            if tl.get(CombineStart).is_none() {
                continue;
            }

            let start = tl.start_index;
            let end = tl.end_index;
            let start_time = ts(tl, CombineStart);
            let sending_time = ts(tl, CombineSending);
            let w_recv_time = ts(tl, WorkerRecv);
            let combine_done_time = ts(tl, CombineDone);
            let cordi_recv_time = ts(tl, CoordinatorRecv);

            let mut wait = ms(sending_time, start_time);
            // used for single-node mode
            if sending_time.is_none() {
                wait = ms(w_recv_time, start_time);
            }
            let net_c2w = ms(w_recv_time, sending_time);
            let comb_ms = ms(combine_done_time, w_recv_time);
            let net_w2c = ms(cordi_recv_time, combine_done_time);

            let mut inputs = format!("[{start}, {end}]");
            for cand_left_end in start..end {
                let left = range_map.get(&(start, cand_left_end));
                let right = range_map.get(&(cand_left_end + 1, end));
                if let (Some(_), Some(_)) = (left, right) {
                    inputs = format!(
                        "[[{start}, {cand_left_end}], [{}, {end}]]",
                        cand_left_end + 1
                    );
                    break;
                }
            }

            comb_rows.push(CombRow {
                inputs,
                wait,
                net_c2w,
                comb: comb_ms,
                net_w2c,
            });
        }

        // Pretty print
        let mut buf = String::new();
        writeln!(&mut buf, "\nE2E_total = {:.3} s", e2e_ms as f64 / 1000.0).unwrap();

        if !riscv_rows.is_empty() {
            writeln!(
                &mut buf,
                "\n{:<6} │ {:>20} │ {:>10} │ {:>8} │ {:>15}│ {:>8}",
                "chunk", "record_created_gap", "waiting", "net_c2w", "riscv_convert_ms", "net_w2c"
            )
            .unwrap();
            writeln!(&mut buf, "{}", "─".repeat(90)).unwrap();
            for r in riscv_rows {
                writeln!(
                    &mut buf,
                    "{:<6} │ {:>20} │ {:>10} │ {:>8} │ {:>15}│ {:>8}",
                    r.chunk,
                    fmt_ms(r.created),
                    fmt_ms(r.waiting),
                    fmt_ms(r.net_c2w),
                    fmt_ms(r.gen),
                    fmt_ms(r.net_w2c),
                )
                .unwrap();
            }
        }

        if !comb_rows.is_empty() {
            writeln!(
                &mut buf,
                "\n{:<23} │ {:>12} │ {:>12} │ {:>12} │ {:>12}",
                "sub-proofs", "wait", "net_c2w", "combine", "net_w2c"
            )
            .unwrap();
            writeln!(&mut buf, "{}", "─".repeat(100)).unwrap();

            for c in comb_rows {
                let wait_str = fmt_ms(c.wait);
                let net_c2w_str = fmt_ms(c.net_c2w);
                let comb_str = fmt_ms(c.comb);
                let net_w2c_str = fmt_ms(c.net_w2c);
                writeln!(
                    &mut buf,
                    "{:<23} │ {:>12} │ {:>12} │ {:>12} │ {:>12}",
                    c.inputs, wait_str, net_c2w_str, comb_str, net_w2c_str
                )
                .unwrap();
            }
        }

        // Final Output
        if !buf.is_empty() {
            info!("\n{}", buf);
        }
    }
}
