use crate::{
    messages::{
        emulator::EmulatorMsg,
        gateway::GatewayMsg,
        riscv::{RiscvMsg, RiscvRequest},
    },
    timeline::{Stage::RecordCreated, Timeline},
};
use anyhow::Result;
use crossbeam::channel::{bounded, Receiver, Sender};
use log::{debug, info};
use p3_baby_bear::BabyBear;
use p3_commit::Pcs;
use p3_koala_bear::KoalaBear;
use pico_perf::common::{
    bench_program::{load, BenchProgram},
    print_utils::log_section,
};
use pico_vm::{
    compiler::riscv::{
        compiler::{Compiler, SourceType},
        program::Program,
    },
    configs::{
        config::StarkGenericConfig,
        stark_config::{bb_poseidon2::BabyBearPoseidon2, kb_poseidon2::KoalaBearPoseidon2},
    },
    emulator::{emulator::MetaEmulator, opts::EmulatorOpts},
    instances::{
        chiptype::riscv_chiptype::RiscvChipType,
        compiler::{shapes::riscv_shape::RiscvShapeConfig, vk_merkle::HasStaticVkManager},
        configs::{
            riscv_config::StarkConfig as RiscvBBSC, riscv_kb_config::StarkConfig as RiscvKBSC,
        },
        machine::riscv::RiscvMachine,
    },
    machine::{machine::MachineBehavior, proof::MetaProof, witness::ProvingWitness},
    primitives::consts::RISCV_NUM_PVS,
};
use std::{sync::Arc, thread, time::Instant};
use tokio::task::JoinHandle;

pub fn merge_meta_proofs<SC>(list: Vec<MetaProof<SC>>) -> MetaProof<SC>
where
    SC: StarkGenericConfig,
{
    let mut proofs_vec = Vec::with_capacity(list.len());
    let mut vks_vec = Vec::with_capacity(list.len());
    let pv_stream = None;

    for mp in list {
        debug_assert_eq!(mp.proofs.len(), 1);
        debug_assert_eq!(mp.vks.len(), 1);
        debug_assert!(mp.pv_stream.is_none());

        proofs_vec.extend_from_slice(mp.proofs.as_ref());
        vks_vec.extend_from_slice(mp.vks.as_ref());
    }

    MetaProof {
        proofs: Arc::from(proofs_vec.into_boxed_slice()),
        vks: Arc::from(vks_vec.into_boxed_slice()),
        pv_stream,
    }
}
/// specialization for running emulator on either babybear or koalabear
trait EmulatorRunner: StarkGenericConfig {
    fn run(
        bench_program: &BenchProgram,
        gateway_endpoint: Arc<Sender<GatewayMsg<Self>>>,
    ) -> Result<()>;
}

impl<SC: StarkGenericConfig> EmulatorRunner for SC {
    /// default implementation
    default fn run(
        _bench_program: &BenchProgram,
        _gateway_endpoint: Arc<Sender<GatewayMsg<Self>>>,
    ) -> Result<()> {
        panic!("unsupported");
    }
}

impl EmulatorRunner for BabyBearPoseidon2 {
    fn run(
        bench_program: &BenchProgram,
        gateway_endpoint: Arc<Sender<GatewayMsg<Self>>>,
    ) -> Result<()> {
        // Setups
        let vk_manager = <BabyBearPoseidon2 as HasStaticVkManager>::static_vk_manager();
        let (elf, stdin) = load::<Program, BabyBearPoseidon2>(bench_program)?;
        println!("bench program: {}", bench_program.name);

        let riscv_machine =
            RiscvMachine::new(RiscvBBSC::new(), RiscvChipType::all_chips(), RISCV_NUM_PVS);
        let mut program = Compiler::new(SourceType::RISCV, &elf).compile();
        if vk_manager.vk_verification_enabled() {
            let shape_config = RiscvShapeConfig::<BabyBear>::default();
            let p = Arc::get_mut(&mut program).expect("cannot get program");
            shape_config
                .padding_preprocessed_shape(p)
                .expect("cannot padding preprocessed shape");
        }
        let (pk, vk) = riscv_machine.setup_keys(&program);

        let riscv_opts = EmulatorOpts::bench_riscv_ops();
        let witness =
            ProvingWitness::<BabyBearPoseidon2, RiscvChipType<BabyBear>, Vec<u8>>::setup_for_riscv(
                program.clone(),
                stdin,
                riscv_opts,
                pk.clone(),
                vk.clone(),
            );
        // Initialize the emulator.
        let mut emulator = MetaEmulator::setup_riscv(&witness, None);

        let channel_capacity = (4 * witness
            .opts
            .as_ref()
            .map(|opts| opts.chunk_batch_size)
            .unwrap_or(64)) as usize;
        // Initialize the channel for sending emulation records from the emulator thread to prover.
        let (record_sender, record_receiver): (Sender<_>, Receiver<_>) = bounded(channel_capacity);

        // Start the emulator thread.
        log_section("RISCV EMULATE PHASE");
        let emulator_handle = thread::spawn(move || {
            let mut batch_num = 1;
            loop {
                let start_local = Instant::now();

                let done = emulator.next_record_batch(&mut |record| {
                    record_sender.send(record).expect(
                        "Failed to send an emulation record from emulator thread to prover thread",
                    )
                });

                tracing::debug!(
                    "--- Generate riscv records for batch-{} in {:?}",
                    batch_num,
                    start_local.elapsed(),
                );

                if done {
                    break;
                }

                batch_num += 1;
            }

            // Move and return the emulator for further usage.
            emulator

            // `record_sender` will be dropped when the emulator thread completes.
        });

        // RISCV Phase
        log_section("RISCV & CONVERT PHASE");
        let mut chunk_index = 0;

        while let Ok(record) = record_receiver.recv() {
            let mut tl = Timeline::new(chunk_index, chunk_index);
            tl.mark(RecordCreated);

            let req = RiscvRequest {
                chunk_index,
                record,
            };

            tracing::info!("send emulation record-{chunk_index}");
            gateway_endpoint.send(GatewayMsg::Riscv(
                RiscvMsg::Request(req),
                // TODO: fix to id and ip address
                chunk_index.to_string(),
                "".to_string(),
                Some(tl),
            ))?;

            chunk_index += 1;
        }

        // send the emulator complete message
        gateway_endpoint.send(GatewayMsg::EmulatorComplete)?;

        let emulator = emulator_handle.join().unwrap();
        info!("Total Cycles: {}", emulator.cycles());

        Ok(())
    }
}

impl EmulatorRunner for KoalaBearPoseidon2 {
    fn run(
        bench_program: &BenchProgram,
        gateway_endpoint: Arc<Sender<GatewayMsg<Self>>>,
    ) -> Result<()> {
        // Setups
        let vk_manager = <KoalaBearPoseidon2 as HasStaticVkManager>::static_vk_manager();
        let (elf, stdin) = load::<Program, KoalaBearPoseidon2>(bench_program)?;
        println!("bench program: {}", bench_program.name);

        let riscv_machine =
            RiscvMachine::new(RiscvKBSC::new(), RiscvChipType::all_chips(), RISCV_NUM_PVS);
        let mut program = Compiler::new(SourceType::RISCV, &elf).compile();
        if vk_manager.vk_verification_enabled() {
            let shape_config = RiscvShapeConfig::<KoalaBear>::default();
            let p = Arc::get_mut(&mut program).expect("cannot get program");
            shape_config
                .padding_preprocessed_shape(p)
                .expect("cannot padding preprocessed shape");
        }
        let (pk, vk) = riscv_machine.setup_keys(&program);

        let riscv_opts = EmulatorOpts::bench_riscv_ops();
        let witness =
            ProvingWitness::<KoalaBearPoseidon2, RiscvChipType<KoalaBear>, Vec<u8>>::setup_for_riscv(
                program.clone(),
                stdin,
                riscv_opts,
                pk.clone(),
                vk.clone(),
            );
        // Initialize the emulator.
        let mut emulator = MetaEmulator::setup_riscv(&witness, None);

        let channel_capacity = (4 * witness
            .opts
            .as_ref()
            .map(|opts| opts.chunk_batch_size)
            .unwrap_or(64)) as usize;
        // Initialize the channel for sending emulation records from the emulator thread to prover.
        let (record_sender, record_receiver): (Sender<_>, Receiver<_>) = bounded(channel_capacity);

        // Start the emulator thread.
        log_section("RISCV EMULATE PHASE");
        let emulator_handle = thread::spawn(move || {
            let mut batch_num = 1;
            loop {
                let start_local = Instant::now();

                let done = emulator.next_record_batch(&mut |record| {
                    record_sender.send(record).expect(
                        "Failed to send an emulation record from emulator thread to prover thread",
                    )
                });

                tracing::debug!(
                    "--- Generate riscv records for batch-{} in {:?}",
                    batch_num,
                    start_local.elapsed(),
                );

                if done {
                    break;
                }

                batch_num += 1;
            }

            // Move and return the emulator for further usage.
            emulator

            // `record_sender` will be dropped when the emulator thread completes.
        });

        // RISCV Phase
        log_section("RISCV & CONVERT PHASE");
        let mut chunk_index = 0;

        while let Ok(record) = record_receiver.recv() {
            let mut tl = Timeline::new(chunk_index, chunk_index);
            tl.mark(RecordCreated);
            let req = RiscvRequest {
                chunk_index,
                record,
            };

            tracing::debug!("send emulation record-{chunk_index}");
            gateway_endpoint.send(GatewayMsg::Riscv(
                RiscvMsg::Request(req),
                // TODO: fix to id and ip address
                chunk_index.to_string(),
                "".to_string(),
                Some(tl),
            ))?;

            chunk_index += 1;
        }

        // send the emulator complete message
        gateway_endpoint.send(GatewayMsg::EmulatorComplete)?;

        let emulator = emulator_handle.join().unwrap();
        info!("Total Cycles: {}", emulator.cycles());

        Ok(())
    }
}

pub fn run<SC: StarkGenericConfig + 'static>(
    program: BenchProgram,
    emulator_receiver: Arc<Receiver<EmulatorMsg>>,
    gateway_endpoint: Arc<Sender<GatewayMsg<SC>>>,
) -> JoinHandle<()>
where
    <SC::Pcs as Pcs<
        <SC as StarkGenericConfig>::Challenge,
        <SC as StarkGenericConfig>::Challenger,
    >>::ProverData: Send,
    <SC as StarkGenericConfig>::Domain: Send,
{
    debug!("[coordinator] emulator init");

    let handle = tokio::task::spawn_blocking(move || {
        while let Ok(msg) = emulator_receiver.recv() {
            match msg {
                EmulatorMsg::Start => SC::run(&program, gateway_endpoint.clone()).unwrap(),
                EmulatorMsg::Stop => break,
            }
        }
    });

    debug!("[coordinator] emulator init end");

    handle
}
