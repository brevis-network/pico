//! What the pipeline's replay workers report of each chunk they replayed, for the pass that runs
//! them as AOT cores against the interpreter's.
//!
//! The records come out the same whichever engine replayed a chunk, so a worker that interpreted
//! its chunk instead of running compiled code passes every record comparison. The worker says
//! which engine it was and what it ran on its `worker.replay` ledger line: `worker_kind`, the
//! compiled blocks it entered (`dispatches`) and the instructions its fallback interpreter ran
//! (`fallback_insns`). Short chunks may contain no block leader, so compiled execution is required
//! across the run while worker identity and replay coverage are checked per chunk. Chunks are
//! numbered as the ledger numbers them, from zero, where [`crate::emitting`]'s lines count from one.
//!
//! An AOT worker runs only recording blocks, so its recording bodies' instructions
//! (`recorder_insns`) and its fallback's must sum to the chunk's cycles; a dispatch count cannot
//! show that, as it also counts a block that fell back. The checking build checks only the rows
//! written directly (`recorder_direct_insns`), so a checking run must show some: a short chunk may
//! have none, but a run with none checked nothing.
//!
//! The ledger's sink is chosen once per process, from `MLE_LEDGER` as the process's first pipeline
//! run opens its window, so [`Ledger::start`] sets it before any run and every run of the process
//! writes to it. [`Ledger::arm`] notes the bytes one arm's run appended, which is all the audit
//! reads: an arm that recorded nothing reads as that, not as the last arm that did.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::{ErrorKind, Read, Seek, SeekFrom},
    ops::Range,
    path::PathBuf,
    sync::{Mutex, PoisonError},
};

use serde_json::Value;

/// The `worker_kind` the ledger writes for an AOT replay worker.
const AOT_KIND: &str = "aot";

/// Which code the AOT workers run, and so what each of their chunks has to show.
#[derive(Clone, Copy)]
pub enum Expect {
    /// Generated code: short chunks may contain no block leader, and a block that does not fit
    /// what is left of a chunk runs in the fallback by design. Require compiled execution across
    /// the run so these chunks do not make an otherwise exercised AOT engine fail the audit.
    Compiled,
    /// The bootstrap stub's code, which interprets every instruction.
    AllFallback,
}

/// One `worker.replay` line: what a worker says it did for a chunk, or for a segment of it.
#[derive(Debug, Clone, PartialEq)]
struct Replayed {
    chunk: u64,
    kind: Option<String>,
    cycles: u64,
    dispatches: Option<u64>,
    fallback_insns: Option<u64>,
    recorder_insns: Option<u64>,
    recorder_direct_insns: Option<u64>,
}

/// The `worker.replay` lines of `text`, a ledger's lines or a slice of them.
fn replays(text: &str) -> Result<Vec<Replayed>, String> {
    let mut rows = Vec::new();
    for (index, line) in text
        .lines()
        .enumerate()
        .filter(|(_, line)| !line.trim().is_empty())
    {
        let at = index + 1;
        let line: Value =
            serde_json::from_str(line).map_err(|err| format!("ledger line {at}: {err}"))?;
        if line["stage"] != "worker.replay" || line["skipped"] == true {
            continue;
        }
        let facts = &line["facts"];
        rows.push(Replayed {
            chunk: line["chunk"]
                .as_u64()
                .ok_or_else(|| format!("ledger line {at}: a worker.replay line with no chunk"))?,
            kind: facts["worker_kind"].as_str().map(str::to_owned),
            cycles: facts["cycles"]
                .as_u64()
                .ok_or_else(|| format!("ledger line {at}: a worker.replay line with no cycles"))?,
            dispatches: facts["dispatches"].as_u64(),
            fallback_insns: facts["fallback_insns"].as_u64(),
            recorder_insns: facts["recorder_insns"].as_u64(),
            recorder_direct_insns: facts["recorder_direct_insns"].as_u64(),
        });
    }
    Ok(rows)
}

/// What the workers say of one chunk, summed over the segments a split chunk was replayed in.
struct Chunk {
    cycles: u64,
    dispatches: Option<u64>,
    fallback_insns: Option<u64>,
    recorder_insns: Option<u64>,
    recorder_direct_insns: Option<u64>,
    kinds: BTreeSet<String>,
}

fn chunks(rows: &[Replayed]) -> BTreeMap<u64, Chunk> {
    let mut chunks: BTreeMap<u64, Chunk> = BTreeMap::new();
    for row in rows {
        let chunk = chunks.entry(row.chunk).or_insert_with(|| Chunk {
            cycles: 0,
            dispatches: Some(0),
            fallback_insns: Some(0),
            recorder_insns: Some(0),
            recorder_direct_insns: Some(0),
            kinds: BTreeSet::new(),
        });
        chunk.cycles += row.cycles;
        // A count a segment did not report leaves the chunk's unreported.
        chunk.dispatches = chunk.dispatches.zip(row.dispatches).map(|(a, b)| a + b);
        chunk.fallback_insns = chunk
            .fallback_insns
            .zip(row.fallback_insns)
            .map(|(a, b)| a + b);
        chunk.recorder_insns = chunk
            .recorder_insns
            .zip(row.recorder_insns)
            .map(|(a, b)| a + b);
        chunk.recorder_direct_insns = chunk
            .recorder_direct_insns
            .zip(row.recorder_direct_insns)
            .map(|(a, b)| a + b);
        chunk
            .kinds
            .insert(row.kind.clone().unwrap_or_else(|| "none".to_string()));
    }
    chunks
}

fn only(kind: &str, kinds: &BTreeSet<String>) -> bool {
    kinds.len() == 1 && kinds.contains(kind)
}

/// Adds to `problems` what the two arms' workers show, prints what ran each chunk of the
/// candidate, and returns a suffix for the run's line. The reference's workers are interpreters;
/// the candidate's are the AOT core on the recording blocks, `checked` when those are the checking
/// build's.
fn audit_arms(
    expect: Expect,
    checked: bool,
    reference: &[Replayed],
    candidate: &[Replayed],
    totals: [(u32, u64); 2],
    problems: &mut Vec<String>,
) -> String {
    let reference = chunks(reference);
    let candidate = chunks(candidate);
    if candidate.is_empty() {
        problems.push(
            "the AOT workers' arm wrote no worker.replay line, so nothing shows what its workers \
             ran"
            .to_string(),
        );
    }

    for (chunk, work) in &reference {
        if !only("interpreter", &work.kinds) {
            problems.push(format!(
                "chunk {chunk}: the reference arm's workers report {:?}, not the interpreter",
                work.kinds
            ));
        }
    }
    let unpaired: Vec<u64> = reference
        .keys()
        .copied()
        .collect::<BTreeSet<_>>()
        .symmetric_difference(&candidate.keys().copied().collect())
        .copied()
        .collect();
    if !unpaired.is_empty() {
        problems.push(format!(
            "chunk(s) {unpaired:?} were replayed in one arm only"
        ));
    }
    // Compare each ledger with its own emulation output: matching omissions in both arms
    // must not escape the audit. Split chunks can have several rows, already summed above.
    for ((name, chunks), (count, cycles)) in
        [("reference", &reference), ("AOT workers", &candidate)]
            .into_iter()
            .zip(totals)
    {
        if !chunks.keys().copied().eq(0..u64::from(count)) {
            problems.push(format!(
                "the {name} arm's ledger must cover chunks 0..{count} exactly, got {:?}",
                chunks.keys().collect::<Vec<_>>()
            ));
        }
        let replayed: u64 = chunks.values().map(|chunk| chunk.cycles).sum();
        if replayed != cycles {
            problems.push(format!(
                "the {name} arm's ledger replayed {replayed} cycle(s), but its run emitted {cycles}"
            ));
        }
    }

    let mut total_dispatches = 0;
    let mut interpreted = 0;
    let mut compiled_insns = 0;
    let mut recorder_insns = 0;
    let mut direct_insns = 0;
    for (chunk, work) in &candidate {
        if let Some(theirs) = reference.get(chunk) {
            if theirs.cycles != work.cycles {
                problems.push(format!(
                    "chunk {chunk}: {} cycle(s) replayed by the interpreter, {} by the AOT workers",
                    theirs.cycles, work.cycles
                ));
            }
        }
        if !only(AOT_KIND, &work.kinds) {
            problems.push(format!(
                "chunk {chunk}: the workers report {:?}, not {AOT_KIND:?}, so the AOT engine was \
                 not the one that replayed it",
                work.kinds
            ));
        }
        let (Some(dispatches), Some(fallback)) = (work.dispatches, work.fallback_insns) else {
            println!(
                "    worker chunk {chunk}: {} cycle(s), no dispatch or fallback count reported",
                work.cycles
            );
            problems.push(format!(
                "chunk {chunk}: the worker reports no dispatch or fallback count"
            ));
            continue;
        };
        total_dispatches += dispatches;
        let share = 100.0 * fallback as f64 / work.cycles.max(1) as f64;
        println!(
            "    worker chunk {chunk}: {} cycle(s), {dispatches} compiled-block dispatch(es), \
             {fallback} fallback instruction(s) ({share:.1} %)",
            work.cycles
        );
        if fallback > work.cycles {
            problems.push(format!(
                "chunk {chunk}: {fallback} instruction(s) in the fallback of {} cycle(s)",
                work.cycles
            ));
            continue;
        }
        interpreted += fallback;
        compiled_insns += work.cycles - fallback;
        match work.recorder_insns {
            None => problems.push(format!(
                "chunk {chunk}: the AOT workers report no recorder-body count"
            )),
            Some(recorded) => {
                let share = 100.0 * recorded as f64 / work.cycles.max(1) as f64;
                let direct = work.recorder_direct_insns.map_or(String::new(), |direct| {
                    format!(", {direct} writing their rows directly")
                });
                println!(
                    "    worker chunk {chunk}: {recorded} instruction(s) in recording bodies \
                     ({share:.1} %){direct}"
                );
                recorder_insns += recorded;
                if recorded + fallback != work.cycles {
                    problems.push(format!(
                        "chunk {chunk}: {recorded} instruction(s) in recording bodies and \
                         {fallback} in the fallback, of {} cycle(s): something else ran the rest",
                        work.cycles
                    ));
                }
                if matches!(expect, Expect::AllFallback) && recorded != 0 {
                    problems.push(format!(
                        "chunk {chunk}: {recorded} instruction(s) in recording bodies, where the \
                         stub's code has none"
                    ));
                }
            }
        }
        if checked {
            match work.recorder_direct_insns {
                None => problems.push(format!(
                    "chunk {chunk}: the checking build's workers report no direct-row count"
                )),
                Some(direct) => direct_insns += direct,
            }
        }
        match expect {
            Expect::AllFallback if dispatches != 0 || fallback != work.cycles => {
                problems.push(format!(
                    "chunk {chunk}: {dispatches} dispatch(es) and {fallback} of {} cycle(s) \
                     interpreted, where the stub's code interprets them all",
                    work.cycles
                ))
            }
            _ => {}
        }
    }
    if matches!(expect, Expect::Compiled) && !candidate.is_empty() && total_dispatches == 0 {
        problems.push("no compiled block entered during the run".to_string());
    }
    // A dispatch alone does not show it: a block that does not fit what is left of its chunk
    // hands its first instruction straight to the fallback.
    if matches!(expect, Expect::Compiled) && !candidate.is_empty() && compiled_insns == 0 {
        problems.push("compiled code ran no instruction of the run".to_string());
    }
    if matches!(expect, Expect::Compiled) && !candidate.is_empty() && recorder_insns == 0 {
        problems.push("no recording body ran an instruction of the run".to_string());
    }
    if checked && matches!(expect, Expect::Compiled) && !candidate.is_empty() && direct_insns == 0 {
        problems.push(
            "no recording block wrote a row directly in the run, so the checking build checked \
             none"
                .to_string(),
        );
    }
    let checked = if checked {
        format!(", {direct_insns} of them writing their rows directly, each checked")
    } else {
        String::new()
    };
    format!(
        "; {} chunk(s) replayed by {AOT_KIND} workers, {interpreted} instruction(s) interpreted by \
         their fallback, {recorder_insns} in recording bodies{checked}",
        candidate.len()
    )
}

/// The ledger file of this process's runs, and where in it each arm's run begins and ends.
pub struct Ledger {
    path: PathBuf,
    arms: Mutex<Vec<Range<u64>>>,
}

impl Ledger {
    /// Points the stage ledger at a file of this process's own. Before the process's first
    /// pipeline run, which is when the ledger reads its path.
    pub fn start() -> Self {
        let path =
            std::env::temp_dir().join(format!("aot-record-parity-{}.jsonl", std::process::id()));
        match fs::remove_file(&path) {
            Err(err) if err.kind() != ErrorKind::NotFound => {
                panic!("clear the ledger file {}: {err}", path.display())
            }
            _ => {}
        }
        std::env::set_var("MLE_LEDGER", &path);
        assert!(
            pico_vm::mle::ledger::enabled(),
            "the stage ledger is off: pico-vm has to be built with `stage-ledger`, and nothing may \
             have run a pipeline before MLE_LEDGER was set to {}",
            path.display()
        );
        Self::at(path)
    }

    fn at(path: PathBuf) -> Self {
        Self {
            path,
            arms: Mutex::new(Vec::new()),
        }
    }

    fn len(&self) -> u64 {
        fs::metadata(&self.path).map_or(0, |meta| meta.len())
    }

    /// Runs one arm's emulation, which ends with the ledger flushed, and notes the lines it wrote.
    pub fn arm<T>(&self, emulate: impl FnOnce() -> T) -> T {
        let from = self.len();
        let output = emulate();
        self.arms
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(from..self.len());
        output
    }

    fn rows(&self, bytes: &Range<u64>) -> Result<Vec<Replayed>, String> {
        let mut text = vec![0; (bytes.end - bytes.start) as usize];
        let mut file = File::open(&self.path)
            .map_err(|err| format!("read the ledger {}: {err}", self.path.display()))?;
        file.seek(SeekFrom::Start(bytes.start))
            .and_then(|_| file.read_exact(&mut text))
            .map_err(|err| format!("read the ledger {}: {err}", self.path.display()))?;
        replays(&String::from_utf8_lossy(&text))
    }

    /// Adds to `problems` what the last two arms run, the interpreter's workers and then the AOT
    /// workers, show of their workers, and returns a suffix for the run's line.
    /// `checked` says the recording blocks are the checking build's
    /// (`pico_aot_runtime::RECORDER_CHECK`). `totals` holds each arm's emitted chunk count and
    /// cycles, in that same order.
    pub fn audit(
        &self,
        expect: Expect,
        checked: bool,
        totals: [(u32, u64); 2],
        problems: &mut Vec<String>,
    ) -> String {
        let arms = self.arms.lock().unwrap_or_else(PoisonError::into_inner);
        let [.., reference, candidate] = arms.as_slice() else {
            problems.push("the audit ran before the two arms did".to_string());
            return String::new();
        };
        match (self.rows(reference), self.rows(candidate)) {
            (Ok(reference), Ok(candidate)) => {
                audit_arms(expect, checked, &reference, &candidate, totals, problems)
            }
            (reference, candidate) => {
                problems.extend([reference.err(), candidate.err()].into_iter().flatten());
                String::new()
            }
        }
    }

    /// Deletes the file. A run that fails leaves it for whoever reads the failure.
    pub fn remove(self) {
        if let Err(err) = fs::remove_file(&self.path) {
            eprintln!("could not remove {}: {err}", self.path.display());
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn replay_line(chunk: u64, seg: Option<[u64; 2]>, facts: Value) -> String {
        json!({
            "v": 2, "run": "7f1c", "arm": null, "chunk": chunk, "batch": chunk, "seg": seg,
            "record": null, "stage": "worker.replay", "lane": {"role": "emulate", "idx": 3},
            "t0_us": 10, "t1_us": 20, "dur_us": 10, "facts": facts,
        })
        .to_string()
    }

    fn interpreter(chunk: u64, cycles: u64) -> Replayed {
        Replayed {
            chunk,
            kind: Some("interpreter".to_string()),
            cycles,
            dispatches: None,
            fallback_insns: None,
            recorder_insns: None,
            recorder_direct_insns: None,
        }
    }

    /// An AOT worker's chunk: every instruction the fallback did not run, in recording bodies, half
    /// of them writing their rows directly.
    fn aot(chunk: u64, cycles: u64, dispatches: u64, fallback_insns: u64) -> Replayed {
        let recorded = cycles.saturating_sub(fallback_insns);
        Replayed {
            chunk,
            kind: Some("aot".to_string()),
            cycles,
            dispatches: Some(dispatches),
            fallback_insns: Some(fallback_insns),
            recorder_insns: Some(recorded),
            recorder_direct_insns: Some(recorded / 2),
        }
    }

    fn audited(expect: Expect, reference: &[Replayed], candidate: &[Replayed]) -> Vec<String> {
        audited_built(expect, false, reference, candidate)
    }

    fn audited_built(
        expect: Expect,
        checked: bool,
        reference: &[Replayed],
        candidate: &[Replayed],
    ) -> Vec<String> {
        let mut problems = Vec::new();
        let totals = (
            chunks(reference).len() as u32,
            reference.iter().map(|r| r.cycles).sum(),
        );
        audit_arms(
            expect,
            checked,
            reference,
            candidate,
            [totals; 2],
            &mut problems,
        );
        problems
    }

    fn three_chunks() -> Vec<Replayed> {
        vec![interpreter(0, 512), interpreter(1, 512), interpreter(2, 90)]
    }

    #[test]
    fn replays_reads_the_worker_replay_lines_and_nothing_else() {
        let text = [
            json!({"v": 2, "kind": "envelope", "run": "7f1c", "worker_kind": "aot"}).to_string(),
            json!({"v": 2, "run": "7f1c", "chunk": 1, "stage": "worker.recover",
                   "facts": {"recover_kind": "fresh"}})
            .to_string(),
            replay_line(
                1,
                None,
                json!({"cycles": 512, "worker_kind": "aot", "dispatches": 40,
                       "fallback_insns": 7, "recorder_insns": 505,
                       "recorder_direct_insns": 252}),
            ),
            json!({"v": 2, "run": "7f1c", "chunk": 2, "stage": "worker.replay",
                   "skipped": true})
            .to_string(),
            String::new(),
            replay_line(
                2,
                None,
                json!({"cycles": 90, "worker_kind": "interpreter", "dispatches": null,
                       "fallback_insns": null, "cycles_per_dispatch": null}),
            ),
        ]
        .join("\n");
        assert_eq!(
            replays(&text).unwrap(),
            vec![aot(1, 512, 40, 7), interpreter(2, 90)]
        );
    }

    #[test]
    fn an_aot_workers_chunks_are_its_recording_bodies_and_its_fallback() {
        let candidate = [aot(0, 512, 30, 4), aot(1, 512, 31, 0), aot(2, 90, 3, 12)];
        assert_eq!(
            audited(Expect::Compiled, &three_chunks(), &candidate),
            Vec::<String>::new()
        );

        let mut short = aot(1, 512, 31, 0);
        short.recorder_insns = Some(500);
        let mut silent = aot(2, 90, 3, 12);
        silent.recorder_insns = None;
        let problems = audited(
            Expect::Compiled,
            &three_chunks(),
            &[aot(0, 512, 30, 4), short, silent],
        );
        assert_eq!(problems.len(), 2, "{problems:?}");
        assert!(problems[0].starts_with("chunk 1:") && problems[0].contains("something else"));
        assert!(problems[1].starts_with("chunk 2:") && problems[1].contains("no recorder-body"));

        let renamed = candidate.map(|chunk| Replayed {
            kind: Some("aot-recorder".to_string()),
            ..chunk
        });
        let problems = audited(Expect::Compiled, &three_chunks(), &renamed);
        assert_eq!(
            problems
                .iter()
                .filter(|problem| problem.contains("not \"aot\""))
                .count(),
            3,
            "{problems:?}"
        );
    }

    #[test]
    fn the_aot_workers_have_to_run_their_recording_bodies_on_generated_code_only() {
        let stub = [aot(0, 512, 0, 512), aot(1, 512, 0, 512), aot(2, 90, 0, 90)];
        assert_eq!(
            audited(Expect::AllFallback, &three_chunks(), &stub),
            Vec::<String>::new()
        );
        let problems = audited(
            Expect::Compiled,
            &three_chunks(),
            &[aot(0, 512, 1, 512), aot(1, 512, 1, 512), aot(2, 90, 1, 90)],
        );
        assert!(
            problems
                .iter()
                .any(|p| p == "no recording body ran an instruction of the run"),
            "{problems:?}"
        );
        let mut recorded = aot(1, 512, 0, 500);
        recorded.dispatches = Some(0);
        let problems = audited(
            Expect::AllFallback,
            &three_chunks(),
            &[aot(0, 512, 0, 512), recorded, aot(2, 90, 0, 90)],
        );
        assert!(
            problems
                .iter()
                .any(|p| p.contains("where the stub's code has none")),
            "{problems:?}"
        );
    }

    /// One chunk with direct rows is enough: a short chunk may have none.
    #[test]
    fn the_checking_build_has_to_see_direct_rows_somewhere_in_the_run() {
        let undirected = |chunk, cycles, dispatches, fallback_insns| Replayed {
            recorder_direct_insns: Some(0),
            ..aot(chunk, cycles, dispatches, fallback_insns)
        };
        let none_direct = [
            undirected(0, 512, 30, 4),
            undirected(1, 512, 31, 0),
            undirected(2, 90, 3, 12),
        ];
        let checked = |candidate: &[Replayed]| {
            audited_built(Expect::Compiled, true, &three_chunks(), candidate)
        };
        assert_eq!(
            audited(Expect::Compiled, &three_chunks(), &none_direct),
            Vec::<String>::new()
        );
        assert_eq!(
            checked(&none_direct),
            ["no recording block wrote a row directly in the run, so the checking build checked \
              none"
                .to_string()]
        );

        let one_direct = [
            undirected(0, 512, 30, 4),
            aot(1, 512, 31, 0),
            undirected(2, 90, 3, 12),
        ];
        assert_eq!(checked(&one_direct), Vec::<String>::new());

        let mut silent = aot(1, 512, 31, 0);
        silent.recorder_direct_insns = None;
        let problems = checked(&[aot(0, 512, 30, 4), silent, aot(2, 90, 3, 12)]);
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(
            problems[0].starts_with("chunk 1:") && problems[0].contains("no direct-row count"),
            "{problems:?}"
        );
    }

    #[test]
    fn replays_names_the_line_it_cannot_read() {
        let text = format!("{}\nnot json", replay_line(1, None, json!({"cycles": 1})));
        assert!(replays(&text).unwrap_err().starts_with("ledger line 2:"));
        let no_cycles = replay_line(1, None, json!({"worker_kind": "aot"}));
        assert!(replays(&no_cycles).unwrap_err().contains("no cycles"));
    }

    #[test]
    fn a_run_where_every_chunk_entered_compiled_code_passes() {
        let candidate = [aot(0, 512, 30, 4), aot(1, 512, 31, 0), aot(2, 90, 3, 12)];
        assert_eq!(
            audited(Expect::Compiled, &three_chunks(), &candidate),
            Vec::<String>::new()
        );
    }

    #[test]
    fn one_chunk_without_a_dispatch_passes_when_the_run_has_many() {
        let candidate = [aot(0, 512, 30, 4), aot(1, 512, 0, 512), aot(2, 90, 3, 12)];
        let problems = audited(Expect::Compiled, &three_chunks(), &candidate);
        assert_eq!(problems, Vec::<String>::new());
    }

    #[test]
    fn a_run_without_any_dispatch_fails_on_generated_code() {
        let candidate = [aot(0, 512, 0, 512), aot(1, 512, 0, 512), aot(2, 90, 0, 90)];
        let problems = audited(Expect::Compiled, &three_chunks(), &candidate);
        assert!(
            problems
                .iter()
                .any(|p| p == "no compiled block entered during the run"),
            "zero-dispatch run must fail the dispatch audit: {problems:?}"
        );
        assert!(problems
            .iter()
            .any(|p| p == "compiled code ran no instruction of the run"));
    }

    #[test]
    fn dispatches_that_ran_no_instruction_fail_the_run() {
        let candidate = [aot(0, 512, 1, 512), aot(1, 512, 1, 512), aot(2, 90, 1, 90)];
        let problems = audited(Expect::Compiled, &three_chunks(), &candidate);
        assert_eq!(
            problems,
            [
                "compiled code ran no instruction of the run".to_string(),
                "no recording body ran an instruction of the run".to_string()
            ]
        );
    }

    #[test]
    fn workers_that_are_not_the_aot_engine_fail_every_chunk() {
        let problems = audited(Expect::Compiled, &three_chunks(), &three_chunks());
        assert!(
            problems
                .iter()
                .filter(|problem| problem.contains("not \"aot\""))
                .count()
                == 3,
            "{problems:?}"
        );
    }

    #[test]
    fn a_reference_that_is_not_the_interpreter_fails() {
        let candidate = [aot(0, 512, 30, 4), aot(1, 512, 31, 0), aot(2, 90, 3, 12)];
        let problems = audited(
            Expect::Compiled,
            &[aot(0, 512, 30, 4), interpreter(1, 512), interpreter(2, 90)],
            &candidate,
        );
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(problems[0].starts_with("chunk 0:"), "{problems:?}");
    }

    #[test]
    fn a_missing_count_fails_its_chunk() {
        let mut silent = aot(1, 512, 31, 0);
        silent.fallback_insns = None;
        let candidate = [aot(0, 512, 30, 4), silent, aot(2, 90, 3, 12)];
        let problems = audited(Expect::Compiled, &three_chunks(), &candidate);
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(problems[0].contains("no dispatch or fallback count"));
    }

    #[test]
    fn a_fallback_longer_than_its_chunk_fails() {
        let candidate = [aot(0, 512, 30, 4), aot(1, 512, 31, 513), aot(2, 90, 3, 12)];
        let problems = audited(Expect::Compiled, &three_chunks(), &candidate);
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(problems[0].starts_with("chunk 1:"), "{problems:?}");
    }

    #[test]
    fn the_arms_have_to_replay_the_same_chunks_over_the_same_cycles() {
        let missing = [aot(0, 512, 30, 4), aot(2, 90, 3, 12)];
        let problems = audited(Expect::Compiled, &three_chunks(), &missing);
        assert!(
            problems.iter().any(|p| p.contains("one arm only")),
            "{problems:?}"
        );
        assert!(
            problems.iter().any(|p| p.contains("must cover chunks")),
            "{problems:?}"
        );
        let shifted = [aot(0, 512, 30, 4), aot(1, 500, 31, 0), aot(2, 90, 3, 12)];
        let problems = audited(Expect::Compiled, &three_chunks(), &shifted);
        assert_eq!(problems.len(), 2, "{problems:?}");
        assert!(
            problems.iter().any(|p| p.starts_with("chunk 1:")),
            "{problems:?}"
        );
    }

    #[test]
    fn both_arms_omitting_the_same_chunk_fail_coverage() {
        // A shared missing tail still leaves matching, consecutive ledger chunks.
        let reference = [interpreter(0, 512), interpreter(1, 512)];
        let candidate = [aot(0, 512, 30, 4), aot(1, 512, 31, 0)];
        let mut problems = Vec::new();
        audit_arms(
            Expect::Compiled,
            false,
            &reference,
            &candidate,
            [(3, 1114); 2],
            &mut problems,
        );
        for arm in ["reference", "AOT workers"] {
            assert!(
                problems
                    .iter()
                    .any(|p| p.starts_with(&format!("the {arm} arm's ledger must cover chunks"))),
                "missing shared chunk must fail coverage for {arm}: {problems:?}"
            );
            let cycle_error =
                format!("the {arm} arm's ledger replayed 1024 cycle(s), but its run emitted 1114");
            assert!(problems.contains(&cycle_error), "{problems:?}");
        }
    }

    #[test]
    fn an_arm_with_no_line_fails() {
        let problems = audited(Expect::Compiled, &three_chunks(), &[]);
        assert!(problems[0].contains("wrote no worker.replay line"));
    }

    #[test]
    fn the_segments_of_a_split_chunk_are_one_chunk() {
        let reference = [interpreter(0, 300), interpreter(0, 212), interpreter(1, 90)];
        let candidate = [aot(0, 300, 12, 2), aot(0, 212, 0, 212), aot(1, 90, 5, 0)];
        assert_eq!(
            audited(Expect::Compiled, &reference, &candidate),
            Vec::<String>::new()
        );
        let silent = [aot(0, 300, 0, 300), aot(0, 212, 0, 212), aot(1, 90, 5, 0)];
        assert_eq!(
            audited(Expect::Compiled, &reference, &silent),
            Vec::<String>::new()
        );
    }

    #[test]
    fn the_stub_control_wants_every_instruction_in_the_fallback() {
        let stub = [aot(0, 512, 0, 512), aot(1, 512, 0, 512), aot(2, 90, 0, 90)];
        assert_eq!(
            audited(Expect::AllFallback, &three_chunks(), &stub),
            Vec::<String>::new()
        );
        let compiled = [aot(0, 512, 0, 512), aot(1, 512, 4, 500), aot(2, 90, 0, 90)];
        let problems = audited(Expect::AllFallback, &three_chunks(), &compiled);
        assert_eq!(problems.len(), 2, "{problems:?}");
        assert!(
            problems
                .iter()
                .all(|problem| problem.starts_with("chunk 1:")),
            "{problems:?}"
        );
        let entered = [aot(0, 512, 0, 512), aot(1, 512, 1, 512), aot(2, 90, 0, 90)];
        assert_eq!(
            audited(Expect::AllFallback, &three_chunks(), &entered).len(),
            1
        );
    }

    #[test]
    fn an_arm_is_read_from_the_bytes_it_wrote() {
        let path = std::env::temp_dir().join(format!(
            "aot-record-parity-unit-{}.jsonl",
            std::process::id()
        ));
        let _ = fs::remove_file(&path);
        let ledger = Ledger::at(path.clone());
        let append = |lines: &[String]| {
            let mut text = fs::read_to_string(&path).unwrap_or_default();
            for line in lines {
                text.push_str(line);
                text.push('\n');
            }
            fs::write(&path, text).unwrap();
        };
        let interpreted = |chunk| {
            replay_line(
                chunk,
                None,
                json!({"cycles": 512, "worker_kind": "interpreter", "dispatches": null,
                       "fallback_insns": null}),
            )
        };
        let compiled = |chunk, dispatches| {
            replay_line(
                chunk,
                None,
                json!({"cycles": 512, "worker_kind": "aot", "dispatches": dispatches,
                       "fallback_insns": 3, "recorder_insns": 509,
                       "recorder_direct_insns": 200}),
            )
        };
        // An earlier run in the file, which the audit must not read.
        append(&[compiled(0, 0)]);
        ledger.arm(|| append(&[interpreted(0), interpreted(1)]));
        ledger.arm(|| append(&[compiled(0, 9), compiled(1, 8)]));
        let mut problems = Vec::new();
        ledger.audit(Expect::Compiled, false, [(2, 1024); 2], &mut problems);
        assert_eq!(problems, Vec::<String>::new());

        // The next pair writes nothing for its second arm.
        ledger.arm(|| append(&[interpreted(0)]));
        ledger.arm(|| ());
        let mut problems = Vec::new();
        ledger.audit(Expect::Compiled, false, [(1, 512); 2], &mut problems);
        assert!(
            problems[0].contains("wrote no worker.replay line"),
            "{problems:?}"
        );
        ledger.remove();
    }
}
