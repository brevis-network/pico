use super::config::CoordinatorConfig;
use anyhow::Result;
use crossbeam::channel::{Receiver, Sender};
use log::{debug, info};
use p3_baby_bear::BabyBear;
use p3_commit::Pcs;
use p3_koala_bear::KoalaBear;
use pico_perf::common::{
    bench_program::{load, BenchProgram},
    print_utils::log_section,
};
use pico_vm::{
    configs::{
        config::StarkGenericConfig,
        stark_config::{bb_poseidon2::BabyBearPoseidon2, kb_poseidon2::KoalaBearPoseidon2},
    },
    emulator::opts::EmulatorOpts,
    instances::{
        compiler::{shapes::riscv_shape::RiscvShapeConfig, vk_merkle::HasStaticVkManager},
        configs::{
            riscv_config::StarkConfig as RiscvBBSC, riscv_kb_config::StarkConfig as RiscvKBSC,
        },
    },
    messages::{emulator::EmulatorMsg, gateway::GatewayMsg},
    proverchain::{InitialProverSetup, RiscvProver},
};
use std::sync::Arc;
use tokio::task::JoinHandle;

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
        let riscv_shape_config = vk_enabled.then(RiscvShapeConfig::<BabyBear>::default);

        let riscv = RiscvProver::new_initial_prover(
            (RiscvBBSC::new(), &elf),
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
