//! A replayed segment emits the interpreter's records.
//!
//! The AOT snapshot thread runs a guest at a small chunk size and cuts every chunk into segments,
//! as the pipeline's does. Each segment is replayed by the interpreter's worker and by the AOT core,
//! and every record a replay cuts, the deferred records the run leaves (precompile events, and the
//! memory initialize and finalize events of the final state), and each replay's report have to
//! agree field by field. The AOT core replays twice: through the registered replay factory and the
//! VM's worker, running the bootstrap stub's code on its recording entry point, which interprets
//! every block; and on its own, running stand-in compiled blocks, so that a segment's target falls
//! inside a block.

use std::{
    cell::{Cell, RefCell},
    io::Read,
    num::NonZeroUsize,
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex, MutexGuard, Once, PoisonError,
    },
    thread,
    time::{Duration, Instant},
};

use pico_aot_runtime::{register, AotEmulatorCore, AotProgram, BlockFn, NextStep};
use pico_vm::{
    compiler::riscv::{
        compiler::{Compiler, SourceType},
        opcode::Opcode,
        program::Program,
    },
    configs::stark_config::KoalaBearPoseidon2,
    emulator::{
        aot::create_aot_emulator,
        emulator::{AotReplayMetaEmulator, MetaEmulator},
        opts::{EmulatorOpts, ReplayWorkers, SnapshotMainMode},
        record::RecordBehavior,
        riscv::{
            emulator::{EmulationDeferredState, SharedDeferredState},
            memory::{ContiguousRiscvMemory, GLOBAL_MEMORY_RECYCLER},
            public_values::RecordFinalPvsState,
            record::EmulationRecord,
            record_digest::first_difference,
            record_slots::{hold_records_unbounded, init_record_slots},
        },
        stdin::EmulatorStdin,
    },
    machine::{report::EmulationReport, witness::ProvingWitness},
    mle::machine::riscv::emulate_with_pipeline,
    proverchain::riscv::{
        emulate_snapshot_pipeline_with, max_pipeline_workers, DeferredSplit, RiscvChips,
    },
};

const FIB_ELF: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../perf/bench_data/rv64/fib-elf"
));
const POSEIDON2_ELF: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../perf/bench_data/rv64/poseidon2-elf"
));

type Chips = RiscvChips<KoalaBearPoseidon2>;
type Witness = ProvingWitness<KoalaBearPoseidon2, Chips, Vec<u8>>;

/// The bootstrap stub's code under a digest `register` takes: every block interpreted. The snapshot
/// thread runs its ordinary entry point, so its cuts land on any instruction, and the factory's
/// replay worker its recording one.
static STUB_CODE: AotProgram =
    AotProgram::stamped([0x5a; 32], AotProgram::CODEGEN_STAMP, interpret_every_block)
        .with_recorder(record_every_block);

/// Runs of the stub's ordinary entry point: the snapshot thread's.
static PLAIN_RUNS: AtomicU64 = AtomicU64::new(0);

/// Of those, runs with a sink set: none expected, since the replay workers run the recording
/// entry point.
static EMITTING_RUNS: AtomicU64 = AtomicU64::new(0);

/// Runs of the stub's recording entry point, which only an AOT replay worker makes.
static RECORDING_RUNS: AtomicU64 = AtomicU64::new(0);

/// Counts replays down to one that fails: 1 fails the next, 0 none.
static FAIL_IN: AtomicU64 = AtomicU64::new(0);

fn interpret_every_block(emu: &mut AotEmulatorCore) -> Result<(), String> {
    PLAIN_RUNS.fetch_add(1, Ordering::Relaxed);
    if emu.is_emitting() {
        EMITTING_RUNS.fetch_add(1, Ordering::Relaxed);
    }
    emu.run_blocks(|_| None)
}

/// No recording block, so every instruction runs in the fallback interpreter, on the core's sink.
fn record_every_block(emu: &mut AotEmulatorCore) -> Result<(), String> {
    RECORDING_RUNS.fetch_add(1, Ordering::Relaxed);
    if FAIL_IN.try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_sub(1)) == Ok(1) {
        return Err("injected replay failure".into());
    }
    emu.run_record_blocks(|_| None)
}

/// Split replay on for every chunk and the stub's code registered. Both are read once per process,
/// so this runs before anything reads them. The guard runs this file's tests one at a time, so
/// the run counters count one test's runs.
fn setup() -> MutexGuard<'static, ()> {
    static ONCE: Once = Once::new();
    static SERIAL: Mutex<()> = Mutex::new(());
    let serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    ONCE.call_once(|| {
        // Unless a child process was given its own.
        if std::env::var_os("MLE_SPLIT_REPLAY").is_none() {
            std::env::set_var("MLE_SPLIT_REPLAY", "3");
        }
        std::env::set_var("MLE_SPLIT_CHUNKS", "64");
        hold_records_unbounded();
        register(&STUB_CODE).expect("a stamped program registers");
    });
    serial
}

/// The longest stand-in block: what a generated block's size is capped at is not what matters
/// here, only that a block runs several instructions with no stop between them.
const MAX_BLOCK: usize = 32;

thread_local! {
    /// The program the stand-in blocks are cut from.
    static BLOCK_PROGRAM: RefCell<Option<Arc<Program>>> = const { RefCell::new(None) };
    /// Stand-in blocks that would have run past their replay's target, and fell back.
    static CROSSINGS: Cell<usize> = const { Cell::new(0) };
}

/// The instructions of the stand-in block at `pc`: up to and including the first that ends a block.
fn block_len(program: &Program, pc: u64) -> u32 {
    use Opcode::*;
    let rest = &program.instructions[((pc - program.pc_base) / 4) as usize..];
    let len = rest
        .iter()
        .take(MAX_BLOCK)
        .position(|inst| {
            matches!(
                inst.opcode,
                JAL | JALR | BEQ | BNE | BLT | BGE | BLTU | BGEU | ECALL | EBREAK | UNIMP
            )
        })
        .map_or(rest.len().min(MAX_BLOCK), |last| last + 1);
    len as u32
}

/// Stands in for a generated block as `compiler.rs` writes one: the fit test at entry, the fallback
/// when it fails or inside an unconstrained block, then the block's instructions with no stop
/// between them.
fn stand_in_block(emu: &mut AotEmulatorCore) -> Result<NextStep, String> {
    let len = BLOCK_PROGRAM.with_borrow(|program| {
        block_len(
            program.as_ref().expect("a stand-in pass sets its program"),
            emu.pc,
        )
    });
    if !emu.can_fit_block(len, 0, 0, 0) {
        CROSSINGS.set(CROSSINGS.get() + 1);
        return emu.interpret_from_current_pc();
    }
    if emu.is_unconstrained_mode() {
        return emu.interpret_from_current_pc();
    }
    for _ in 0..len {
        emu.debug_interpret_single_step()?;
    }
    emu.check_chunk_boundary_fast();
    Ok(NextStep::Dynamic(emu.pc))
}

fn run_stand_in_blocks(emu: &mut AotEmulatorCore) -> Result<(), String> {
    emu.run_blocks(|_| Some(stand_in_block as BlockFn))
}

#[derive(Clone, Copy, Debug)]
enum Replayer {
    /// The interpreter's worker: `MetaEmulator::recover_riscv` and `try_next_record_batch`.
    Interpreter,
    /// The AOT core behind the registered replay factory and the VM's worker, on the stub's
    /// recording entry point, recovered in place.
    AotWorker,
    /// The AOT core on its own, running stand-in compiled blocks, recovered in place.
    AotStandIn,
}

#[derive(Default)]
struct Pass {
    /// The segments the snapshot thread cut each chunk into.
    segments: Vec<usize>,
    /// Each replay's record, in clock order.
    records: Vec<EmulationRecord>,
    /// Each replay's report: (global clock reached, chunk started in, done).
    reports: Vec<(u64, u32, bool)>,
    /// Where each replay left the core: (pc, chunk, chunk clock, global clock). None for the
    /// factory's worker, whose core is behind its trait.
    ends: Vec<(u64, u32, u64, u64)>,
    /// The deferred pool once the run is done, split into its records.
    deferred: Vec<EmulationRecord>,
    dispatches: u64,
}

impl Pass {
    fn replayed(&mut self, report: &EmulationReport) {
        self.reports
            .push((report.current_cycle, report.start_chunk, report.done));
    }
}

/// Back to the pool the snapshot thread took it from, as the pipeline's workers give it back.
fn release(memory: ContiguousRiscvMemory) {
    let _ = GLOBAL_MEMORY_RECYCLER.send((memory, true));
}

fn witness(elf: &[u8], input: u32, chunk_size: u32) -> Witness {
    let program: Arc<Program> = Compiler::new(SourceType::RISCV, elf)
        .expect("the ELF parses")
        .compile();
    let mut stdin = EmulatorStdin::<Program, Vec<u8>>::new_builder::<KoalaBearPoseidon2>();
    stdin.write(&input);
    // Every field stated, since `EmulatorOpts::default` reads the environment.
    let opts = EmulatorOpts {
        chunk_size,
        chunk_batch_size: 1,
        max_cycles: Some(1 << 32),
        cycle_tracker: false,
        cost_estimator: false,
        snapshot_main: SnapshotMainMode::Aot,
        replay_workers: ReplayWorkers::Interpreter,
    };
    Witness::setup_for_mle_riscv(program, stdin.finalize(), opts)
}

/// Runs the AOT snapshot thread over the witness and replays every segment it hands out with
/// `replayer`, in clock order, into one deferred pool.
fn pass(witness: &Witness, replayer: Replayer) -> Pass {
    let program = witness.program.clone().expect("the witness has a program");
    let opts = witness.opts.expect("the witness has options");
    let inputs = witness.stdin.as_ref().expect("stdin").inputs.to_vec();
    let mut snapshots = create_aot_emulator(
        program.clone(),
        inputs,
        opts,
        Arc::new(RecordFinalPvsState::default()),
    )
    .expect("the stub's code is registered");
    let shared_ds: SharedDeferredState =
        EmulationDeferredState::shared(program.clone(), Arc::new(RecordFinalPvsState::default()));
    BLOCK_PROGRAM.set(Some(program.clone()));

    let mut out = Pass::default();
    let mut worker: Option<AotReplayMetaEmulator<KoalaBearPoseidon2, Chips>> = None;
    let mut core: Option<AotEmulatorCore> = None;
    let mut core_deferred = EmulationRecord::new(program.clone());
    loop {
        let (segments, batch) = snapshots
            .next_state_batch_segments()
            .expect("the snapshot thread runs the guest");
        out.segments.push(segments.len());
        let count = segments.len();
        for (index, (state, target)) in segments.into_iter().enumerate() {
            let final_segment = index + 1 == count;
            match replayer {
                Replayer::Interpreter => {
                    let mut emu = MetaEmulator::recover_riscv(
                        witness,
                        state,
                        shared_ds.clone(),
                        target,
                        final_segment,
                    );
                    let report = emu
                        .try_next_record_batch(&mut |record| out.records.push(record))
                        .expect("the interpreter replays the segment");
                    out.replayed(&report);
                    let state = emu.emulator.take().expect("an emulator").state;
                    out.ends
                        .push((state.pc, state.current_chunk, state.clk, state.global_clk));
                    release(state.memory);
                }
                Replayer::AotWorker => {
                    let worker = match worker.as_mut() {
                        Some(worker) => {
                            release(worker.recover_riscv_in_place(
                                state,
                                shared_ds.clone(),
                                target,
                                final_segment,
                            ));
                            worker
                        }
                        None => worker.insert(AotReplayMetaEmulator::recover_riscv(
                            witness,
                            state,
                            shared_ds.clone(),
                            target,
                            final_segment,
                        )),
                    };
                    let report = worker
                        .try_next_record_batch(&mut |record| out.records.push(record))
                        .expect("the AOT worker replays the segment");
                    out.replayed(&report);
                }
                Replayer::AotStandIn => {
                    let core = match core.as_mut() {
                        Some(core) => {
                            release(core.recover_in_place(state, target, final_segment));
                            core
                        }
                        None => core.insert(AotEmulatorCore::recover(
                            program.clone(),
                            state,
                            target,
                            final_segment,
                        )),
                    };
                    let (chunk, report) = core
                        .replay(run_stand_in_blocks)
                        .expect("the AOT core replays the segment");
                    // What the interpreter's worker does with its record: defers its precompile
                    // events, and after the run's last replay its memory events.
                    let mut record = chunk.record;
                    core_deferred.append(&mut record.defer());
                    out.records.push(record);
                    if report.done {
                        let mut memory_events = EmulationRecord::new(program.clone());
                        core.postprocess(&mut memory_events);
                        core_deferred.append(&mut memory_events.defer());
                    }
                    out.replayed(&report);
                    out.ends.push((
                        core.pc,
                        core.current_chunk,
                        u64::from(core.clk),
                        core.insn_count,
                    ));
                }
            }
        }
        if batch.done {
            break;
        }
    }

    out.deferred = match replayer {
        Replayer::AotStandIn => {
            let mut records = core_deferred.split(true, u32::MAX);
            if let Some(last) = records.last_mut() {
                last.is_last = true;
            }
            records
        }
        _ => shared_ds.lock().take_split_records(true, u32::MAX),
    };
    if let Some(worker) = worker {
        out.dispatches = worker.compiled_block_dispatches();
        release(worker.into_memory());
    }
    if let Some(mut core) = core {
        out.dispatches = core.compiled_block_dispatches();
        release(std::mem::take(&mut core.memory));
    }
    out
}

/// `aot`'s records, deferred records and reports against the interpreter's, field by field.
fn assert_replays_alike(interpreter: &Pass, aot: &Pass, replayer: Replayer) {
    assert_eq!(aot.segments, interpreter.segments, "{replayer:?}: the cut");
    assert_eq!(
        aot.records.len(),
        interpreter.records.len(),
        "{replayer:?}: records cut"
    );
    for (index, (left, right)) in interpreter.records.iter().zip(&aot.records).enumerate() {
        assert_eq!(
            first_difference(left, right),
            None,
            "{replayer:?}: segment {index}'s record, the interpreter's first"
        );
    }
    assert_eq!(aot.reports, interpreter.reports, "{replayer:?}: reports");
    assert_eq!(
        aot.deferred.len(),
        interpreter.deferred.len(),
        "{replayer:?}: deferred records"
    );
    for (index, (left, right)) in interpreter.deferred.iter().zip(&aot.deferred).enumerate() {
        assert_eq!(
            first_difference(left, right),
            None,
            "{replayer:?}: deferred record {index}, the interpreter's first"
        );
    }
}

/// The three replays of one run, compared, with what makes the comparison more than two empty runs
/// agreeing: the run's memory events, and stand-in blocks that ran.
fn replay_all(elf: &[u8], input: u32, chunk_size: u32) -> Pass {
    let _serial = setup();
    let witness = witness(elf, input, chunk_size);
    let interpreter = pass(&witness, Replayer::Interpreter);
    assert!(
        interpreter
            .deferred
            .iter()
            .any(|record| !record.memory_finalize_events.is_empty()),
        "the run left no memory finalize event"
    );

    let worker = pass(&witness, Replayer::AotWorker);
    assert_replays_alike(&interpreter, &worker, Replayer::AotWorker);
    assert_eq!(
        worker.dispatches, 0,
        "the stub's code interprets every block"
    );

    CROSSINGS.set(0);
    let stand_in = pass(&witness, Replayer::AotStandIn);
    assert_replays_alike(&interpreter, &stand_in, Replayer::AotStandIn);
    assert_eq!(
        stand_in.ends, interpreter.ends,
        "(pc, chunk, chunk clock, global clock) after each replay: a final segment rolls the \
         chunk over"
    );
    assert!(stand_in.dispatches > 0, "no stand-in block ran");
    interpreter
}

/// [`replay_all`] on a run of several chunks, each cut into segments, some of whose targets fall
/// inside a stand-in block.
fn check_chunked(elf: &[u8], input: u32, chunk_size: u32) -> Pass {
    let interpreter = replay_all(elf, input, chunk_size);
    assert!(
        interpreter.segments.len() >= 3,
        "{} chunks",
        interpreter.segments.len()
    );
    assert!(
        interpreter.segments.iter().any(|&segments| segments > 1),
        "no chunk was cut into segments: {:?}",
        interpreter.segments
    );
    assert!(
        CROSSINGS.get() > 0,
        "no segment's target fell inside a stand-in block"
    );
    interpreter
}

#[test]
fn a_replayed_fib_run_emits_the_interpreters_records() {
    check_chunked(FIB_ELF, 10, 2048);
}

#[test]
fn a_replayed_poseidon2_run_emits_the_interpreters_records() {
    let interpreter = check_chunked(POSEIDON2_ELF, 1, 1 << 12);
    assert!(
        interpreter
            .deferred
            .iter()
            .any(|record| !record.precompile_events.is_empty()),
        "the run deferred no precompile event"
    );
}

/// A run that ends in its first batch: its one replay starts from the run's final uninitialized
/// memory, which already holds the words its hint reads write.
#[test]
fn a_run_replayed_in_one_batch_emits_the_interpreters_records() {
    let interpreter = replay_all(FIB_ELF, 10, 1 << 22);
    assert_eq!(interpreter.segments, [1], "the whole run is one segment");
}

/// The pipeline with AOT replay workers, each recovered in place across its batches, hands on the
/// interpreter workers' records: the same records in the same order, deferred ones included. The
/// AOT workers are shown to have run the recording entry point, since interpreters under the AOT
/// option would give equal records, and the snapshot thread the ordinary one, with no sink.
#[test]
fn the_pipeline_with_aot_workers_emits_the_interpreter_workers_records() {
    let _serial = setup();
    for (elf, input, chunk_size) in [(FIB_ELF, 10, 2048), (POSEIDON2_ELF, 1, 1 << 12)] {
        let witness = witness(elf, input, chunk_size);
        let program = witness.program.clone().expect("the witness has a program");
        let stdin = witness.stdin.clone().expect("the witness has stdin");
        let opts = witness.opts.expect("the witness has options");
        let workers = NonZeroUsize::new(2).expect("two workers");
        let run = |replay_workers| {
            let runs = || {
                [&PLAIN_RUNS, &EMITTING_RUNS, &RECORDING_RUNS]
                    .map(|runs| runs.load(Ordering::Relaxed))
            };
            let before = runs();
            let output = emulate_with_pipeline(
                program.clone(),
                &stdin,
                opts.with_replay_workers(replay_workers),
                workers,
            )
            .expect("the pipeline runs the guest");
            let after = runs();
            (output, [0, 1, 2].map(|at| after[at] - before[at]))
        };
        let (interpreter, [plain, emitting, recording]) = run(ReplayWorkers::Interpreter);
        assert!(interpreter.chunks >= 3, "{} chunks", interpreter.chunks);
        assert!(
            plain > 0,
            "the AOT snapshot thread ran no ordinary entry point"
        );
        assert_eq!(
            [emitting, recording],
            [0, 0],
            "an interpreter worker ran the AOT code"
        );
        let chunks = u64::from(interpreter.chunks);
        let (aot, [plain, emitting, recording]) = run(ReplayWorkers::Aot);
        assert!(
            plain > 0 && emitting == 0,
            "the ordinary entry point ran {plain} times, {emitting} with a sink: only the \
             snapshot thread may run it"
        );
        assert!(
            recording >= chunks,
            "{recording} replays of the recording entry point for {chunks} chunks"
        );
        assert_eq!(
            (aot.chunks, aot.cycles, &aot.committed_bytes),
            (
                interpreter.chunks,
                interpreter.cycles,
                &interpreter.committed_bytes
            )
        );
        assert_eq!(aot.records.len(), interpreter.records.len(), "records");
        for (index, (left, right)) in interpreter.records.iter().zip(&aot.records).enumerate() {
            assert_eq!(
                first_difference(left, right),
                None,
                "record {index}, the interpreter workers' first"
            );
        }
    }
}

/// Re-runs `test` alone in a child process under `env`, and fails if it does, if it does not finish
/// within `deadline`, or if it never printed `marker`: a pipeline that lost a pool memory waits
/// on the pool for good, and the pool's size is read once per process.
fn in_child(test: &str, env: &[(&str, &str)], deadline: Duration, marker: &str) {
    let mut child = Command::new(std::env::current_exe().expect("the test binary"))
        .args(["--exact", test, "--nocapture"])
        .env(CHILD, "1")
        .envs(env.iter().copied())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("re-run this test binary");
    // Read as it comes: a child blocked on a full pipe would pass for a hung pipeline.
    let pipe = |mut from: Box<dyn Read + Send>| {
        thread::spawn(move || {
            let mut text = String::new();
            let _ = from.read_to_string(&mut text);
            text
        })
    };
    let stdout = pipe(Box::new(child.stdout.take().expect("stdout")));
    let stderr = pipe(Box::new(child.stderr.take().expect("stderr")));
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().expect("wait on the child") {
            break Some(status);
        }
        if started.elapsed() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
        thread::sleep(Duration::from_millis(100));
    };
    let (stdout, stderr) = (
        stdout.join().expect("stdout"),
        stderr.join().expect("stderr"),
    );
    let tail = |text: &str| text.lines().rev().take(20).collect::<Vec<_>>().join("\n");
    let status = status.unwrap_or_else(|| {
        panic!(
            "the child hung, killed after {deadline:?}\n{}\n{}",
            tail(&stdout),
            tail(&stderr)
        )
    });
    assert!(
        status.success(),
        "the child failed:\n{}\n{}",
        tail(&stdout),
        tail(&stderr)
    );
    // `--exact` against a stale name matches nothing and still exits 0.
    assert!(
        stdout.contains(marker),
        "the child ran no assertion\n{}",
        tail(&stdout)
    );
}

/// Set in a child process [`in_child`] started.
const CHILD: &str = "PICO_AOT_REPLAY_CHILD";

/// One AOT worker on a pool of one memory, which the run goes on with only once the worker gives
/// each batch's memory back. A replay that fails, on a fresh core or on one recovered in place,
/// is the run's error and leaves the pool whole: the run after it, which a lost memory would stop
/// for good, finishes.
#[test]
fn an_aot_worker_on_a_one_memory_pool_survives_a_failed_replay() {
    const MARKER: &str = "[aot-pool] an AOT worker finished on a one-memory pool";
    if std::env::var_os(CHILD).is_none() {
        in_child(
            "an_aot_worker_on_a_one_memory_pool_survives_a_failed_replay",
            &[("MEMORY_POOL_SIZE", "1"), ("MLE_SPLIT_REPLAY", "1")],
            Duration::from_secs(120),
            MARKER,
        );
        return;
    }
    let _serial = setup();
    let witness = witness(FIB_ELF, 10, 2048);
    let program = witness.program.clone().expect("the witness has a program");
    let stdin = witness.stdin.clone().expect("the witness has stdin");
    let opts = witness
        .opts
        .expect("the witness has options")
        .with_replay_workers(ReplayWorkers::Aot);
    let run = || emulate_with_pipeline(program.clone(), &stdin, opts, NonZeroUsize::MIN);
    let whole = run().expect("the pipeline runs the guest");
    assert!(whole.chunks >= 2, "{} chunks", whole.chunks);

    // The worker's first replay builds its core; its second recovers that core in place.
    for fail_in in [1, 2] {
        FAIL_IN.store(fail_in, Ordering::Relaxed);
        let failed = run().map(|_| ());
        assert!(
            failed
                .as_ref()
                .is_err_and(|e| e.to_string().contains("injected replay failure")),
            "replay {fail_in}: {failed:?}"
        );
        assert_eq!(FAIL_IN.load(Ordering::Relaxed), 0, "replay {fail_in} ran");
        let again = run().expect("the run after a failed one");
        assert_eq!(again.records.len(), whole.records.len());
    }
    println!("{MARKER}");
}

/// [`setup`] for a child process whose records are bounded at `slots` history slots, with
/// `program` registered and every chunk split as `MLE_SPLIT_REPLAY`, which the child is given,
/// asks.
fn bounded(slots: usize, program: &'static AotProgram) {
    std::env::set_var("MLE_SPLIT_CHUNKS", "64");
    register(program).expect("a stamped program registers");
    assert_eq!(init_record_slots(slots), slots);
}

/// Two history slots and every chunk cut into three segments. Each segment's history holds its
/// slot until its chunk is whole, so the first chunk's third segment would wait for a slot for
/// good; the run is refused before it starts instead.
#[test]
fn a_split_wider_than_the_history_slots_is_refused() {
    const MARKER: &str = "[aot-slots] a split wider than the history slots was refused";
    if std::env::var_os(CHILD).is_none() {
        in_child(
            "a_split_wider_than_the_history_slots_is_refused",
            &[("MLE_SPLIT_REPLAY", "3")],
            Duration::from_secs(120),
            MARKER,
        );
        return;
    }
    bounded(2, &STUB_CODE);
    let refused = emulate_snapshot_pipeline_with(
        &witness(FIB_ELF, 10, 2048),
        NonZeroUsize::new(2).expect("two workers"),
        DeferredSplit::AfterEveryChunk,
        |_, _| {},
    )
    .map(|_| ());
    assert!(
        refused
            .as_ref()
            .is_err_and(|e| e.to_string().contains("history slot")),
        "{refused:?}"
    );
    println!("{MARKER}");
}

/// Armed by a test: the first replay to start inside the first chunk past its first instruction,
/// a later segment of it, fails before its first write once three other replays have started.
static FAIL_A_SEGMENT: AtomicBool = AtomicBool::new(false);

/// Replays of [`SEGMENT_FAILING_CODE`] started and not failed.
static STARTED: AtomicU64 = AtomicU64::new(0);

/// The replays in flight when the armed failure came.
static IN_FLIGHT_AT_FAILURE: AtomicU64 = AtomicU64::new(0);

/// Every block interpreted, as [`STUB_CODE`]; only the recording entry point, which only the AOT
/// replay workers run, meets the failure.
static SEGMENT_FAILING_CODE: AotProgram =
    AotProgram::stamped([0x5b; 32], AotProgram::CODEGEN_STAMP, interpret_a_segment)
        .with_recorder(fail_a_segment);

fn interpret_a_segment(emu: &mut AotEmulatorCore) -> Result<(), String> {
    emu.run_blocks(|_| None)
}

fn fail_a_segment(emu: &mut AotEmulatorCore) -> Result<(), String> {
    let later_segment_of_first_chunk = emu.current_chunk == 1 && emu.insn_count > 0;
    if later_segment_of_first_chunk && FAIL_A_SEGMENT.swap(false, Ordering::Relaxed) {
        let deadline = Instant::now() + Duration::from_secs(30);
        while STARTED.load(Ordering::Relaxed) < 3 && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(1));
        }
        IN_FLIGHT_AT_FAILURE.store(STARTED.load(Ordering::Relaxed), Ordering::Relaxed);
        return Err("injected replay failure".into());
    }
    STARTED.fetch_add(1, Ordering::Relaxed);
    emu.run_record_blocks(|_| None)
}

/// Two history slots, every chunk cut into two segments, four AOT workers (a CI runner's cores), and
/// the first chunk's second segment failing before its first write while the first four segments
/// are in flight. The first chunk then never completes, and its first segment keeps its slot in the
/// fold that waits for it; the second chunk's first segment takes the last slot, and its second finds none,
/// with nothing left to free one. The failure is the run's result all the same, and the run after
/// it finishes.
#[test]
fn a_segment_failing_before_its_first_write_ends_a_bounded_split_run() {
    const MARKER: &str = "[aot-slots] a bounded split run ended on a failed segment";
    if std::env::var_os(CHILD).is_none() {
        in_child(
            "a_segment_failing_before_its_first_write_ends_a_bounded_split_run",
            &[("MLE_SPLIT_REPLAY", "2")],
            Duration::from_secs(120),
            MARKER,
        );
        return;
    }
    assert!(max_pipeline_workers() >= 4, "four workers need four cores");
    bounded(2, &SEGMENT_FAILING_CODE);
    let mut witness = witness(FIB_ELF, 10, 2048);
    witness.opts = witness
        .opts
        .map(|opts| opts.with_replay_workers(ReplayWorkers::Aot));
    let run = || {
        emulate_snapshot_pipeline_with(
            &witness,
            NonZeroUsize::new(4).expect("four workers"),
            DeferredSplit::AfterEveryChunk,
            |_, _| {},
        )
    };

    FAIL_A_SEGMENT.store(true, Ordering::Relaxed);
    let failed = run().map(|_| ());
    assert!(
        failed
            .as_ref()
            .is_err_and(|e| e.to_string().contains("injected replay failure")),
        "{failed:?}"
    );
    assert!(
        !FAIL_A_SEGMENT.load(Ordering::Relaxed),
        "no segment of the first chunk failed"
    );
    assert!(
        IN_FLIGHT_AT_FAILURE.load(Ordering::Relaxed) >= 3,
        "{} other replays in flight at the failure",
        IN_FLIGHT_AT_FAILURE.load(Ordering::Relaxed)
    );
    let (reports, cycles, _) = run().expect("the run after the failed one");
    assert!(
        reports.len() >= 2 && cycles > 0,
        "{} reports",
        reports.len()
    );
    println!("{MARKER}");
}
