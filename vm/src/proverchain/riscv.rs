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
        riscv::{record::EmulationRecord, riscv_emulator::ParOptions},
        stdin::EmulatorStdin,
    },
    instances::{
        chiptype::riscv_chiptype::RiscvChipType,
        compiler::{shapes::riscv_shape::RiscvShapeConfig, vk_merkle::vk_verification_enabled},
        machine::riscv::RiscvMachine,
    },
    machine::{
        field::FieldSpecificPoseidon2Config,
        folder::{ProverConstraintFolder, VerifierConstraintFolder},
        keys::{BaseProvingKey, BaseVerifyingKey, HashableKey},
        machine::{BaseMachine, MachineBehavior},
        proof::{BaseProof, MetaProof},
        witness::ProvingWitness,
    },
    primitives::{consts::RISCV_NUM_PVS, Poseidon2Init},
};
use alloc::sync::Arc;
use core_affinity;
use crossbeam::channel as cb;
use p3_air::Air;
use p3_field::PrimeField32;
use p3_maybe_rayon::prelude::*;
use p3_symmetric::Permutation;
use std::{env, thread, time::Instant};

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
    pub fn prove_cycles(&self, stdin: EmulatorStdin<Program, Vec<u8>>) -> (MetaProof<SC>, u64) {
        let witness = ProvingWitness::setup_for_riscv(
            self.program.clone(),
            stdin,
            self.opts,
            self.pk.clone(),
            self.vk.clone(),
        );
        self.machine
            .prove_with_shape_cycles(&witness, self.shape_config.as_ref())
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
                let core_id = cores[tid];
                core_affinity::set_for_current(core_id);

                let tx = tx_arc.clone();

                let par_opts = ParOptions {
                    num_threads: num_threads as u32,
                    thread_id: tid as u32,
                };

                let mut emu = MetaEmulator::setup_riscv(&witness, Some(par_opts));

                let thread_start = Instant::now();
                loop {
                    let done = emu.next_record_batch(&mut |_rec| {});

                    if done {
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

    pub fn get_program(&self) -> Arc<Program> {
        self.program.clone()
    }

    pub fn vk(&self) -> &BaseVerifyingKey<SC> {
        &self.vk
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
