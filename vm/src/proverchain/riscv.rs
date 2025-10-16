use super::{InitialProverSetup, MachineProver};
use crate::{
    chips::{
        chips::riscv_poseidon2::FieldSpecificPoseidon2Chip,
        precompiles::poseidon2::FieldSpecificPrecompilePoseidon2Chip,
    },
    compiler::riscv::{
        compiler::{Compiler, SourceType},
        program::Program,
    },
    configs::config::{Com, Dom, PcsProverData, StarkGenericConfig, Val},
    emulator::{
        emulator::MetaEmulator,
        opts::EmulatorOpts,
        riscv::{
            emulator::{EmulationDeferredState, EmulationError, SharedDeferredState},
            record::EmulationRecord,
            riscv_emulator::ParOptions,
            state::RiscvEmulationState,
        },
        stdin::EmulatorStdin,
    },
    instances::{
        chiptype::riscv_chiptype::RiscvChipType,
        compiler::{shapes::riscv_shape::RiscvShapeConfig, vk_merkle::vk_verification_enabled},
        machine::riscv::RiscvMachine,
    },
    machine::{
        chip::ChipBehavior,
        field::FieldSpecificPoseidon2Config,
        folder::{ProverConstraintFolder, VerifierConstraintFolder},
        keys::{BaseProvingKey, BaseVerifyingKey, HashableKey},
        machine::{BaseMachine, MachineBehavior},
        proof::{BaseProof, MetaProof},
        report::EmulationReport,
        witness::ProvingWitness,
    },
    primitives::{consts::RISCV_NUM_PVS, Poseidon2Init},
};
use alloc::sync::Arc;
use core_affinity;
use crossbeam::{
    channel as cb,
    channel::{bounded, unbounded},
};
use p3_air::Air;
use p3_field::PrimeField32;
use p3_maybe_rayon::prelude::*;
use p3_symmetric::Permutation;
use std::{collections::BTreeMap, env, sync::Mutex, thread, time::Instant};
use tracing::info;

pub type RiscvChips<SC> = RiscvChipType<Val<SC>>;

pub struct RiscvProver<SC, P>
where
    SC: StarkGenericConfig,
    Val<SC>: PrimeField32 + FieldSpecificPoseidon2Config,
{
    program: Arc<P>,
    machine: RiscvMachine<SC, RiscvChips<SC>>,
    opts: EmulatorOpts,
    shape_config: Option<RiscvShapeConfig<Val<SC>>>,
    pk: BaseProvingKey<SC>,
    vk: BaseVerifyingKey<SC>,
}

#[derive(Debug)]
pub(crate) enum TracegenMessage {
    #[allow(dead_code)]
    Record(Arc<EmulationRecord>),
    CycleCount(u64),
}

impl<SC> RiscvProver<SC, Program>
where
    SC: Send + StarkGenericConfig + 'static,
    Com<SC>: Send + Sync,
    Dom<SC>: Send + Sync,
    PcsProverData<SC>: Clone + Send + Sync,
    BaseProof<SC>: Send + Sync,
    BaseVerifyingKey<SC>: HashableKey<Val<SC>>,
    Val<SC>: PrimeField32 + FieldSpecificPoseidon2Config + Poseidon2Init,
    <Val<SC> as Poseidon2Init>::Poseidon2: Permutation<[Val<SC>; 16]>,
    FieldSpecificPoseidon2Chip<Val<SC>>: Air<ProverConstraintFolder<SC>>,
    FieldSpecificPrecompilePoseidon2Chip<Val<SC>>: Air<ProverConstraintFolder<SC>>,
{
    pub fn prove_report(
        &self,
        stdin: EmulatorStdin<Program, Vec<u8>>,
    ) -> (MetaProof<SC>, Vec<EmulationReport>) {
        let witness = ProvingWitness::setup_for_riscv(
            self.program.clone(),
            stdin,
            self.opts,
            self.pk.clone(),
            self.vk.clone(),
        );
        self.machine
            .prove_with_shape_report(&witness, self.shape_config.as_ref())
    }

    pub fn prove_cycles(&self, stdin: EmulatorStdin<Program, Vec<u8>>) -> (MetaProof<SC>, u64) {
        let (proof, reports) = self.prove_report(stdin);
        (proof, reports.last().unwrap().current_cycle)
    }

    pub fn run_tracegen(&self, stdin: EmulatorStdin<Program, Vec<u8>>) -> (u64, f64) {
        let witness = ProvingWitness::<SC, RiscvChips<SC>, _>::setup_for_riscv(
            self.program.clone(),
            stdin,
            self.opts,
            self.pk.clone(),
            self.vk.clone(),
        );
        let (tx, rx) = cb::bounded::<TracegenMessage>(256);
        let consumer = thread::spawn(move || {
            let mut total_cycles = 0_u64;

            for msg in rx {
                match msg {
                    TracegenMessage::Record(_r) => {
                        // let stats = r.stats();
                        // for (key, value) in &stats {
                        //     println!("|- {:<25}: {}", key, value);
                        // }
                    }
                    TracegenMessage::CycleCount(c) => total_cycles = c,
                }
            }
            let ret = 1;
            (total_cycles, ret)
        });

        let num_threads = env::var("NUM_THREADS")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(1);
        println!("Emulator trace threads: {}", num_threads);
        let start_time = Instant::now();

        {
            use std::sync::Arc;
            let cores = core_affinity::get_core_ids().unwrap();
            assert!(num_threads <= cores.len());
            let tx_arc = Arc::new(tx);

            (0..num_threads).into_par_iter().for_each(|tid| {
                // Note: Assigning specific CPU cores to emulators can lead to reduced performance.
                // let core_id = cores[tid];
                // core_affinity::set_for_current(core_id);

                let tx = tx_arc.clone();

                let par_opts = ParOptions {
                    num_threads: num_threads as u32,
                    thread_id: tid as u32,
                };

                let mut emu = MetaEmulator::setup_riscv(&witness, Some(par_opts));

                let thread_start = Instant::now();
                loop {
                    let report = emu.next_record_batch(&mut |_rec| {});

                    if report.done {
                        let thread_elapsed = thread_start.elapsed().as_secs_f64();
                        let thread_cycles = emu.cycles();

                        println!(
                            "[Thread {}] Done. Cycles: {} | Time: {:.3}s | Speed: {:.3} MHz",
                            tid,
                            thread_cycles,
                            thread_elapsed,
                            thread_cycles as f64 / thread_elapsed / 1e6
                        );
                        if tid == 0 {
                            tx.send(TracegenMessage::CycleCount(emu.cycles())).unwrap();
                        }
                        break;
                    }
                }
            });
            drop(tx_arc);
        }

        let (total_cycles, _all) = consumer.join().unwrap();
        let elapsed_secs = start_time.elapsed().as_secs_f64();
        let hz = total_cycles as f64 / elapsed_secs;
        println!("Final Total cycles: {}", total_cycles);
        println!("Final Elapsed time: {:.3} seconds", elapsed_secs);
        println!(
            "Final Effective speed: {:.3} Hz | {:.3} kHz | {:.3} MHz",
            hz,
            hz / 1e3,
            hz / 1e6
        );

        (total_cycles, hz)
    }

    pub fn run_tracegen_snapshot(&self, stdin: EmulatorStdin<Program, Vec<u8>>) -> (u64, f64) {
        let t_witness_setup = Instant::now();
        let witness = ProvingWitness::<SC, RiscvChips<SC>, _>::setup_for_riscv(
            self.program.clone(),
            stdin,
            self.opts,
            self.pk.clone(),
            self.vk.clone(),
        );
        println!(
            "witness setup duration: {}ms",
            t_witness_setup.elapsed().as_secs_f64() * 1000.0
        );
        let start_time = Instant::now();

        // Note: unbounded to prevent deadlock in shared_ds
        let (tx, rx) = unbounded::<TracegenMessage>();

        // final consumer
        let consumer = thread::spawn(move || {
            let mut total_cycles = 0_u64;
            for msg in rx {
                if let TracegenMessage::CycleCount(c) = msg {
                    total_cycles = c;
                }
            }
            (total_cycles, 1 /* placeholder */)
        });

        let record_tx = tx.clone();
        let (_, total_cycles, _pv_stream) =
            emulate_snapshot_pipeline(&witness, move |rec, _done| {
                record_tx
                    .send(TracegenMessage::Record(Arc::new(rec)))
                    .unwrap();
            })
            .unwrap();

        tx.send(TracegenMessage::CycleCount(total_cycles)).unwrap();

        drop(tx);

        let (total_cycles, _dummy) = consumer.join().unwrap();
        let elapsed_secs = start_time.elapsed().as_secs_f64();
        let hz = total_cycles as f64 / elapsed_secs;

        println!("Final Total cycles: {}", total_cycles);
        println!("Final Elapsed time: {:.3} seconds", elapsed_secs);
        println!(
            "Final Effective speed: {:.3} Hz | {:.3} kHz | {:.3} MHz",
            hz,
            hz / 1e3,
            hz / 1e6
        );

        (total_cycles, hz)
    }

    // /// Pure Simple Mode
    // set par_opts 9999
    // pub fn run_tracegen_simple(&self, stdin: EmulatorStdin<Program, Vec<u8>>) -> (u64, f64) {
    //     let witness = ProvingWitness::<SC, RiscvChips<SC>, _>::setup_for_riscv(
    //         self.program.clone(),
    //         stdin,
    //         self.opts,
    //         self.pk.clone(),
    //         self.vk.clone(),
    //     );
    //
    //     let par_opts = ParOptions {
    //         num_threads: 9999 as u32,
    //         thread_id: 9999 as u32,
    //     };
    //     let mut emu = MetaEmulator::setup_riscv(&witness, Some(par_opts));
    //     let mut batch_index = 0;
    //
    //     let thread_start = Instant::now();
    //     loop {
    //         let t_batch_start = Instant::now();
    //         let done = emu.next_record_batch(&mut |_rec| {});
    //         let batch_dur = t_batch_start.elapsed();
    //         batch_index += 1;
    //
    //
    //         info!(
    //                     %batch_index,
    //                     cycles = emu.cycles(),
    //                     emulate_ms = batch_dur.as_secs_f64() * 1e3,
    //                     "Simple mode batch finished"
    //                 );
    //
    //         if done {
    //             let thread_elapsed = thread_start.elapsed().as_secs_f64();
    //             let thread_cycles = emu.cycles();
    //
    //             println!(
    //                 "[Thread Simple] Done. Cycles: {} | Time: {:.3}s | Speed: {:.3} MHz",
    //                 thread_cycles,
    //                 thread_elapsed,
    //                 thread_cycles as f64 / thread_elapsed / 1e6
    //             );
    //
    //             break;
    //         }
    //     }
    //
    //     (0, 0 as f64)
    // }

    /// Snapshot Main Mode
    pub fn run_tracegen_simple(&self, stdin: EmulatorStdin<Program, Vec<u8>>) -> (u64, f64) {
        let witness = ProvingWitness::<SC, RiscvChips<SC>, _>::setup_for_riscv(
            self.program.clone(),
            stdin,
            self.opts,
            self.pk.clone(),
            self.vk.clone(),
        );

        let mut emu = MetaEmulator::setup_riscv(&witness, None);
        let mut batch_index = 0;
        let thread_start = Instant::now();
        loop {
            let t_batch_start = Instant::now();
            let (_snapshot, report) = emu.next_state_batch(true, &mut |_rec| {}).unwrap();
            let batch_dur = t_batch_start.elapsed();
            batch_index += 1;

            info!(
                %batch_index,
                cycles = emu.cycles(),
                emulate_ms = batch_dur.as_secs_f64() * 1e3,
                "Snapshot mode batch finished"
            );

            if report.done {
                let thread_elapsed = thread_start.elapsed().as_secs_f64();
                let thread_cycles = emu.cycles();

                println!(
                    "[Thread Snapshot Simple] Done. Cycles: {} | Time: {:.3}s | Speed: {:.3} MHz",
                    thread_cycles,
                    thread_elapsed,
                    thread_cycles as f64 / thread_elapsed / 1e6
                );

                break;
            }
        }

        (0, 0 as f64)
    }

    pub fn emulate(
        &self,
        stdin: EmulatorStdin<Program, Vec<u8>>,
    ) -> (Vec<EmulationReport>, Vec<u8>) {
        let witness = ProvingWitness::<SC, RiscvChips<SC>, _>::setup_for_riscv(
            self.program.clone(),
            stdin,
            self.opts,
            self.pk.clone(),
            self.vk.clone(),
        );
        let mut emulator = MetaEmulator::setup_riscv(&witness, None);
        let mut reports = Vec::new();
        loop {
            let report = emulator.next_record_batch(&mut |_| {});
            let done = report.done;
            reports.push(report);
            if done {
                break;
            }
        }
        let pv_stream = emulator.get_pv_stream();
        (reports, pv_stream)
    }

    /// Emulate and collect RISCOF signatures from memory between the given addresses
    pub fn test_emulator(&self, begin: u32, end: u32) -> Vec<u32> {
        use crate::emulator::riscv::riscv_emulator::RiscvEmulator;

        let mut emulator =
            RiscvEmulator::new_single::<Val<SC>>(self.program.clone(), self.opts, None);

        loop {
            let mut batch_records = vec![];
            let result = emulator.emulate_batch(&mut |record| batch_records.push(record));

            match result {
                Ok(true) => break,     // Normal completion
                Ok(false) => continue, // Continue execution
                Err(_) => break,       // Error - still try to collect signatures
            }
        }

        emulator.collect_signatures(begin, end)
    }

    pub fn get_program(&self) -> Arc<Program> {
        self.program.clone()
    }

    pub fn vk(&self) -> &BaseVerifyingKey<SC> {
        &self.vk
    }

    pub fn pk(&self) -> &BaseProvingKey<SC> {
        &self.pk
    }
}

impl<SC> InitialProverSetup for RiscvProver<SC, Program>
where
    SC: Send + StarkGenericConfig,
    Com<SC>: Send + Sync,
    Dom<SC>: Send + Sync,
    PcsProverData<SC>: Send + Sync,
    BaseProof<SC>: Send + Sync,
    Val<SC>: PrimeField32 + FieldSpecificPoseidon2Config + Poseidon2Init,
    <Val<SC> as Poseidon2Init>::Poseidon2: Permutation<[Val<SC>; 16]>,
{
    type Input<'a> = (SC, &'a [u8]);
    type Opts = EmulatorOpts;

    type ShapeConfig = RiscvShapeConfig<Val<SC>>;

    fn new_initial_prover(
        input: Self::Input<'_>,
        opts: Self::Opts,
        shape_config: Option<Self::ShapeConfig>,
    ) -> Self {
        let (config, elf) = input;
        let mut program = Compiler::new(SourceType::RISCV, elf).compile();

        if vk_verification_enabled() {
            if let Some(shape_config) = shape_config.clone() {
                let p = Arc::get_mut(&mut program).expect("cannot get program");
                shape_config
                    .padding_preprocessed_shape(p)
                    .expect("cannot padding preprocessed shape");
            }
        }

        let machine = RiscvMachine::new(config, RiscvChipType::all_chips(), RISCV_NUM_PVS);
        let (pk, vk) = machine.setup_keys(&program);
        Self {
            program,
            machine,
            opts,
            shape_config,
            pk,
            vk,
        }
    }
}

impl<SC> MachineProver<SC> for RiscvProver<SC, Program>
where
    SC: Send + StarkGenericConfig + 'static,
    Com<SC>: Send + Sync,
    Dom<SC>: Send + Sync,
    PcsProverData<SC>: Clone + Send + Sync,
    BaseProof<SC>: Send + Sync,
    BaseVerifyingKey<SC>: HashableKey<Val<SC>>,
    Val<SC>: PrimeField32 + FieldSpecificPoseidon2Config + Poseidon2Init,
    <Val<SC> as Poseidon2Init>::Poseidon2: Permutation<[Val<SC>; 16]>,
    FieldSpecificPoseidon2Chip<Val<SC>>:
        Air<ProverConstraintFolder<SC>> + for<'b> Air<VerifierConstraintFolder<'b, SC>>,
    FieldSpecificPrecompilePoseidon2Chip<Val<SC>>:
        Air<ProverConstraintFolder<SC>> + for<'b> Air<VerifierConstraintFolder<'b, SC>>,
{
    type Witness = EmulatorStdin<Program, Vec<u8>>;
    type Chips = RiscvChips<SC>;

    fn machine(&self) -> &BaseMachine<SC, Self::Chips> {
        self.machine.base_machine()
    }

    fn prove(&self, stdin: Self::Witness) -> MetaProof<SC> {
        self.prove_cycles(stdin).0
    }

    fn verify(&self, proof: &MetaProof<SC>, riscv_vk: &dyn HashableKey<Val<SC>>) -> bool {
        self.machine.verify(proof, riscv_vk).is_ok()
    }
}

pub enum Msg {
    Record {
        chunk: u32,
        rec: Arc<EmulationRecord>,
        done: bool,
    },
    SnapShotDone {
        chunk: u32,
    },
}

pub struct Bucket {
    pub(crate) recs: Vec<(Arc<EmulationRecord>, bool)>,
    pub(crate) finished: bool,
}

pub fn emulate_snapshot_pipeline<SC, C, F>(
    witness: &ProvingWitness<SC, C, Vec<u8>>,
    handle_record: F,
) -> Result<(Vec<EmulationReport>, u64, Vec<u8>), EmulationError>
where
    SC: 'static + StarkGenericConfig + Send + Sync,
    SC::Val: PrimeField32 + Poseidon2Init,
    C: 'static + ChipBehavior<Val<SC>, Program = Program, Record = EmulationRecord>,
    F: Fn(EmulationRecord, bool) + Send + Sync + 'static,
    <SC::Val as Poseidon2Init>::Poseidon2: Permutation<[SC::Val; 16]>,
    <SC as StarkGenericConfig>::Domain: Send,
{
    let split_opts = witness
        .opts
        .as_ref()
        .expect("witness.opts not set")
        .split_opts;

    let num_threads = std::env::var("NUM_THREADS")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(1);
    println!("Emulator snapshot worker threads: {}", num_threads);

    let (snap_tx, snap_rx) = bounded::<(usize, RiscvEmulationState, bool, u64)>(256);
    let (snapshot_msg_tx, snapshot_msg_rx) = unbounded::<Msg>();

    let program = witness.program.as_ref().unwrap();
    let shared_ds: SharedDeferredState =
        Arc::new(Mutex::new(EmulationDeferredState::new(program.clone())));

    let mut emu_result = Ok(());
    let mut total_cycles = 0u64;
    let mut pv_stream: Vec<u8> = Vec::new();
    let reports = Mutex::new(Vec::new());

    thread::scope(|s| {
        // sequencer
        s.spawn({
            let shared_ds = Arc::clone(&shared_ds);
            move || {
                let mut stash: BTreeMap<u32, Bucket> = BTreeMap::new();
                let mut next = 0u32;
                while let Ok(msg) = snapshot_msg_rx.recv() {
                    match msg {
                        Msg::Record { chunk, rec, done } => {
                            stash
                                .entry(chunk)
                                .or_insert_with(|| Bucket {
                                    recs: Vec::new(),
                                    finished: false,
                                })
                                .recs
                                .push((rec, done));
                        }

                        Msg::SnapShotDone { chunk } => {
                            stash
                                .entry(chunk)
                                .or_insert_with(|| Bucket {
                                    recs: Vec::new(),
                                    finished: false,
                                })
                                .finished = true;
                        }
                    }

                    // TODO: handle disorder records (get pvs by snapshot main)
                    while let Some(bkt) = stash.get(&next) {
                        if !bkt.finished {
                            break;
                        }
                        let Bucket { mut recs, .. } = stash.remove(&next).unwrap();

                        for (mut rec, done_flag) in recs.drain(..) {
                            let rec_mut = Arc::make_mut(&mut rec);
                            let mut ds = shared_ds.lock().unwrap();
                            ds.update_public_values(done_flag, rec_mut);

                            handle_record(Arc::try_unwrap(rec).unwrap(), done_flag);

                            for mut split_rec in ds.take_split_records(done_flag, split_opts) {
                                ds.update_public_values(done_flag, &mut split_rec);
                                handle_record(split_rec, done_flag);
                            }
                        }
                        next += 1;
                    }
                }
            }
        });

        // snapshot main thread
        s.spawn({
            || {
                let mut emu = MetaEmulator::setup_riscv(witness, None);
                // disable cost estimation if it is enabled on the snapshotter, only need it for the trace generator
                if let Some(e) = &mut emu.emulator {
                    e.opts.cost_estimator = false;
                }
                let t_snapshot_main = Instant::now();
                let mut batch_idx = 0;
                loop {
                    let t_batch_start = Instant::now();
                    let (snapshot, report) = match emu.next_state_batch(true, &mut |_| {}) {
                        Ok(res) => res,
                        Err(err) => {
                            emu_result = Err(err);
                            break;
                        }
                    };
                    let done = report.done;
                    let batch_dur = t_batch_start.elapsed();

                    let t_send_start = Instant::now();
                    snap_tx
                        .send((batch_idx, snapshot, done, emu.cycles()))
                        .unwrap();
                    let send_dur = t_send_start.elapsed();

                    info!(
                        %batch_idx,
                        cycles = emu.cycles(),
                        emulate_ms = batch_dur.as_secs_f64() * 1e3,
                        send_ms    = send_dur.as_secs_f64() * 1e3,
                        "batch finished"
                    );

                    if done {
                        total_cycles = emu.cycles();
                        pv_stream = emu.get_pv_stream();
                        // cycles_for_snapshot.store(emu.cycles(), Ordering::Relaxed);
                        break;
                    }
                    batch_idx += 1;
                }
                drop(snap_tx);
                println!(
                    "[Thread Snapshot] Done in {:.3}s",
                    t_snapshot_main.elapsed().as_secs_f64()
                );
            }
        });

        // workers
        let cores = core_affinity::get_core_ids().unwrap();
        assert!(num_threads <= cores.len());
        (0..num_threads).into_par_iter().for_each(|tid| {
            let snap_rx = snap_rx.clone();
            let snapshot_msg_tx = snapshot_msg_tx.clone();
            let shared_ds = shared_ds.clone();

            while let Ok((batch_idx, snapshot, done, _global_clk)) = snap_rx.recv() {
                let t_recover_and_emu = Instant::now();
                let mut emu =
                    MetaEmulator::recover_riscv(witness, snapshot, None, shared_ds.clone());
                let report = emu.next_record_batch(&mut |rec| {
                    snapshot_msg_tx
                        .send(Msg::Record {
                            chunk: batch_idx as u32,
                            rec: Arc::new(rec),
                            done,
                        })
                        .unwrap();
                });
                {
                    // thread safe append reports
                    let mut lock = reports.lock().expect("ok");
                    lock.push(report);
                }
                snapshot_msg_tx
                    .send(Msg::SnapShotDone {
                        chunk: batch_idx as u32,
                    })
                    .unwrap();
                println!(
                    "[Thread {}] Done, Batch: {}, Recover & Emulate One Batch: {}ms.",
                    tid,
                    batch_idx,
                    t_recover_and_emu.elapsed().as_secs_f64() * 1000.0
                );
            }
        });
        drop(snapshot_msg_tx);
    });

    emu_result.map(|_| (reports.into_inner().expect("ok"), total_cycles, pv_stream))
}
