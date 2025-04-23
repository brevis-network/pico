use super::config::CoordinatorConfig;
use anyhow::Result;
use crossbeam::channel::{bounded, Receiver, Sender};
use log::{debug, info};
use p3_baby_bear::BabyBear;
use p3_commit::Pcs;
use p3_koala_bear::KoalaBear;
use pico_perf::common::{
    bench_program::{load, BenchProgram},
    gnark_utils::send_gnark_prove_task,
    print_utils::{format_results, log_performance_summary, log_section, PerformanceReport},
};
use pico_vm::{
    compiler::riscv::{
        compiler::{Compiler, SourceType},
        program::Program,
    },
    configs::{
        config::StarkGenericConfig,
        field_config::{BabyBearBn254, KoalaBearBn254},
        stark_config::{
            bb_bn254_poseidon2::BabyBearBn254Poseidon2, bb_poseidon2::BabyBearPoseidon2,
            kb_bn254_poseidon2::KoalaBearBn254Poseidon2, kb_poseidon2::KoalaBearPoseidon2,
        },
    },
    emulator::{emulator::MetaEmulator, opts::EmulatorOpts},
    instances::{
        chiptype::{recursion_chiptype::RecursionChipType, riscv_chiptype::RiscvChipType},
        compiler::{
            onchain_circuit::{
                gnark::builder::OnchainVerifierCircuit, stdin::OnchainStdin,
                utils::build_gnark_config_with_str,
            },
            shapes::{recursion_shape::RecursionShapeConfig, riscv_shape::RiscvShapeConfig},
            vk_merkle::{vk_verification_enabled, HasStaticVkManager},
        },
        configs::{
            riscv_config::StarkConfig as RiscvBBSC, riscv_kb_config::StarkConfig as RiscvKBSC,
        },
        machine::riscv::RiscvMachine,
    },
    machine::{machine::MachineBehavior, proof::MetaProof, witness::ProvingWitness},
    messages::{emulator::EmulatorMsg, gateway::GatewayMsg},
    primitives::consts::RISCV_NUM_PVS,
    proverchain::{
        CombineProver, CompressProver, ConvertProver, EmbedProver, InitialProverSetup,
        MachineProver, ProverChain, RiscvProver,
    },
    thread::channel::DuplexUnboundedEndpoint,
};
use std::{
    path::PathBuf,
    sync::Arc,
    thread,
    time::{Duration, Instant},
};
use tokio::task::JoinHandle;

pub fn merge_meta_proofs<SC>(list: Vec<MetaProof<SC>>) -> MetaProof<SC>
where
    SC: StarkGenericConfig,
{
    let mut proofs_vec = Vec::with_capacity(list.len());
    let mut vks_vec = Vec::with_capacity(list.len());
    let mut pv_stream = None;

    for mut mp in list {
        debug_assert_eq!(mp.proofs.len(), 1);
        debug_assert_eq!(mp.vks.len(), 1);
        debug_assert_eq!(mp.pv_stream.is_none(), true);

        proofs_vec.extend_from_slice(mp.proofs.as_ref());
        vks_vec.extend_from_slice(mp.vks.as_ref());
    }

    MetaProof {
        proofs: Arc::from(proofs_vec.into_boxed_slice()),
        vks: Arc::from(vks_vec.into_boxed_slice()),
        pv_stream,
    }
}
/// specialization for running emulator on either babybear or  koalabear
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
        let vk_manager = <BabyBearPoseidon2 as HasStaticVkManager>::static_vk_manager();
        let vk_enabled = vk_manager.vk_verification_enabled();

        let (elf, stdin) = load::<Program>(bench_program)?;
        println!("bench program: {}", bench_program.name);
        let riscv_opts = EmulatorOpts::bench_riscv_ops();
        let recursion_opts = EmulatorOpts::bench_recursion_opts();

        info!(
            "RISCV Chunk Size: {}, RISCV Chunk Batch Size: {}",
            riscv_opts.chunk_size, riscv_opts.chunk_batch_size
        );
        info!(
            "Recursion Chunk Size: {}, Recursion Chunk Batch Size: {}",
            recursion_opts.chunk_size, recursion_opts.chunk_batch_size
        );

        // Conditionally create shape configs if VK is enabled.
        let riscv_shape_config = vk_enabled.then(RiscvShapeConfig::<BabyBear>::default);

        let riscv = RiscvMachine::new(RiscvBBSC::new(), RiscvChipType::all_chips(), RISCV_NUM_PVS);
        let mut program = Compiler::new(SourceType::RISCV, &elf).compile();
        if vk_verification_enabled() {
            if let Some(shape_config) = riscv_shape_config.clone() {
                let p = Arc::get_mut(&mut program).expect("cannot get program");
                shape_config
                    .padding_preprocessed_shape(p)
                    .expect("cannot padding preprocessed shape");
            }
        }
        let (pk, vk) = riscv.setup_keys(&program);

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
        let mut emulator = MetaEmulator::setup_riscv(&witness);

        let channel_capacity = (4 * witness
            .opts
            .as_ref()
            .map(|opts| opts.chunk_batch_size)
            .unwrap_or(64)) as usize;
        // Initialize the channel for sending emulation records from the emulator thread to prover.
        let (record_sender, record_receiver): (Sender<_>, Receiver<_>) = bounded(channel_capacity);

        // Start the emulator thread.
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

            // Move and return the emulator for futher usage.
            emulator

            // `record_sender` will be dropped when the emulator thread completes.
        });


        // RISCV Phase
        log_section("RISCV & CONVERT PHASE");
        info!("Generating RISCV & CONVERT proof");
        riscv.prove_remote(record_receiver, &gateway_endpoint);

        Ok(())
    }
}

impl EmulatorRunner for KoalaBearPoseidon2 {
    fn run(
        bench_program: &BenchProgram,
        gateway_endpoint: Arc<Sender<GatewayMsg<Self>>>,
    ) -> Result<()> {
        let vk_manager = <KoalaBearPoseidon2 as HasStaticVkManager>::static_vk_manager();
        let vk_enabled = vk_manager.vk_verification_enabled();

        let (elf, stdin) = load(bench_program)?;
        let riscv_opts = EmulatorOpts::bench_riscv_ops();
        let recursion_opts = EmulatorOpts::bench_recursion_opts();

        info!(
            "RISCV Chunk Size: {}, RISCV Chunk Batch Size: {}",
            riscv_opts.chunk_size, riscv_opts.chunk_batch_size
        );
        info!(
            "Recursion Chunk Size: {}, Recursion Chunk Batch Size: {}",
            recursion_opts.chunk_size, recursion_opts.chunk_batch_size
        );

        // Conditionally create shape configs if VK is enabled.
        let riscv_shape_config = vk_enabled.then(RiscvShapeConfig::<KoalaBear>::default);

        let riscv = RiscvProver::new_initial_prover(
            (RiscvKBSC::new(), &elf),
            riscv_opts,
            riscv_shape_config,
            Some(gateway_endpoint),
        );

        // RISCV Phase
        log_section("RISCV PHASE");

        // emulate the current program and send proving tasks to workers
        info!("Emulating RISCV program");
        riscv.prove_cycles(stdin);

        Ok(())
    }
}

pub fn run<SC: StarkGenericConfig + 'static>(
    config: Arc<CoordinatorConfig>,
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

    let handle = tokio::spawn(async move {
        while let Ok(msg) = emulator_receiver.recv() {
            match msg {
                EmulatorMsg::Start => SC::run(&config.program, gateway_endpoint.clone()).unwrap(),
                EmulatorMsg::Stop => break,
            }
        }
    });

    debug!("[coordinator] emulator init end");

    handle
}
