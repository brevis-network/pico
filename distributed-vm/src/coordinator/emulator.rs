use super::config::CoordinatorConfig;
use anyhow::Result;
use crossbeam::channel::Receiver;
use log::info;
use p3_baby_bear::BabyBear;
use p3_commit::Pcs;
use p3_koala_bear::KoalaBear;
use pico_perf::common::{
    bench_program::{load, BenchProgram},
    gnark_utils::send_gnark_prove_task,
    print_utils::{format_results, log_performance_summary, log_section, PerformanceReport},
};
use pico_vm::{
    configs::{
        config::StarkGenericConfig,
        field_config::{BabyBearBn254, KoalaBearBn254},
        stark_config::{
            bb_bn254_poseidon2::BabyBearBn254Poseidon2, bb_poseidon2::BabyBearPoseidon2,
            kb_bn254_poseidon2::KoalaBearBn254Poseidon2, kb_poseidon2::KoalaBearPoseidon2,
        },
    },
    emulator::opts::EmulatorOpts,
    instances::{
        chiptype::recursion_chiptype::RecursionChipType,
        compiler::{
            onchain_circuit::{
                gnark::builder::OnchainVerifierCircuit, stdin::OnchainStdin,
                utils::build_gnark_config_with_str,
            },
            shapes::{recursion_shape::RecursionShapeConfig, riscv_shape::RiscvShapeConfig},
            vk_merkle::HasStaticVkManager,
        },
        configs::{
            riscv_config::StarkConfig as RiscvBBSC, riscv_kb_config::StarkConfig as RiscvKBSC,
        },
    },
    messages::{emulator::EmulatorMsg, riscv::RiscvMsg},
    proverchain::{
        CombineProver, CompressProver, ConvertProver, EmbedProver, InitialProverSetup,
        MachineProver, ProverChain, RiscvProver,
    },
    thread::channel::DuplexUnboundedEndpoint,
};
use std::{
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::task::JoinHandle;

/// specialization for running emulator on either babybear or  koalabear
trait EmulatorRunner: StarkGenericConfig {
    fn run(
        bench_program: &BenchProgram,
        riscv_endpoint: Arc<DuplexUnboundedEndpoint<RiscvMsg<Self>, RiscvMsg<Self>>>,
    ) -> Result<PerformanceReport>;
}

impl<SC: StarkGenericConfig> EmulatorRunner for SC {
    /// default implementation
    default fn run(
        _bench_program: &BenchProgram,
        _riscv_endpoint: Arc<DuplexUnboundedEndpoint<RiscvMsg<Self>, RiscvMsg<Self>>>,
    ) -> Result<PerformanceReport> {
        panic!("unsupported");
    }
}

impl EmulatorRunner for BabyBearPoseidon2 {
    fn run(
        bench_program: &BenchProgram,
        riscv_endpoint: Arc<DuplexUnboundedEndpoint<RiscvMsg<Self>, RiscvMsg<Self>>>,
    ) -> Result<PerformanceReport> {
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
        let recursion_shape_config =
            vk_enabled.then(RecursionShapeConfig::<BabyBear, RecursionChipType<BabyBear>>::default);

        let riscv = RiscvProver::new_initial_prover(
            (RiscvBBSC::new(), &elf),
            riscv_opts,
            riscv_shape_config,
            Some(riscv_endpoint),
        );
        let convert = ConvertProver::new_with_prev(&riscv, recursion_opts, recursion_shape_config);

        let recursion_shape_config =
            vk_enabled.then(RecursionShapeConfig::<BabyBear, RecursionChipType<BabyBear>>::default);
        let combine =
            CombineProver::new_with_prev(&convert, recursion_opts, recursion_shape_config);
        let compress = CompressProver::new_with_prev(&combine, (), None);
        let embed = EmbedProver::<_, _, Vec<u8>>::new_with_prev(&compress, (), None);

        let riscv_vk = riscv.vk();

        // RISCV Phase
        log_section("RISCV PHASE");
        info!("Generating RISCV proof");
        let ((proof, cycles), riscv_duration) = time_operation(|| riscv.prove_cycles(stdin));
        info!("Verifying RISCV proof..");
        assert!(riscv.verify(&proof, riscv_vk));

        // Convert Phase
        log_section("CONVERT PHASE");
        info!("Generating CONVERT proof");
        let (proof, convert_duration) = time_operation(|| convert.prove(proof));
        info!("Verifying CONVERT proof..");
        assert!(convert.verify(&proof, riscv_vk));

        // Combine Phase
        log_section("COMBINE PHASE");
        info!("Generating COMBINE proof");
        let (proof, combine_duration) = time_operation(|| combine.prove(proof));
        info!("Verifying COMBINE proof..");
        assert!(combine.verify(&proof, riscv_vk));

        // Compress Phase
        log_section("COMPRESS PHASE");
        info!("Generating COMPRESS proof");
        let (proof, compress_duration) = time_operation(|| compress.prove(proof));
        info!("Verifying COMPRESS proof..");
        assert!(compress.verify(&proof, riscv_vk));

        // Embed Phase
        log_section("EMBED PHASE");
        info!("Generating EMBED proof");
        let (proof, embed_duration) = time_operation(|| embed.prove(proof));
        info!("Verifying EMBED proof..");
        assert!(embed.verify(&proof, riscv_vk));

        // Onchain Phase (only if VK enabled)
        let evm_duration_opt = vk_enabled.then(|| {
            log_section("ONCHAIN PHASE");
            let (_, evm_duration) = time_operation(|| {
                let onchain_stdin = OnchainStdin {
                    machine: embed.machine().clone(),
                    vk: proof.vks().first().unwrap().clone(),
                    proof: proof.proofs().first().unwrap().clone(),
                    flag_complete: true,
                };

                // Generate gnark data
                let (constraints, witness) = OnchainVerifierCircuit::<
                    BabyBearBn254,
                    BabyBearBn254Poseidon2,
                >::build(&onchain_stdin);
                let gnark_witness =
                    build_gnark_config_with_str(constraints, witness, PathBuf::from("./"));
                let gnark_proof_data = send_gnark_prove_task(gnark_witness);
                info!(
                    "gnark prove success with proof data {}",
                    gnark_proof_data.unwrap_or_else(|e| format!("Error: {}", e))
                );

                1_u32
            });

            evm_duration
        });

        let (recursion_duration, total_duration) = log_performance_summary(
            riscv_duration,
            convert_duration,
            combine_duration,
            compress_duration,
            embed_duration,
            evm_duration_opt,
        );

        Ok(PerformanceReport {
            program: bench_program.name.to_string(),
            cycles,
            riscv_duration,
            convert_duration,
            combine_duration,
            compress_duration,
            embed_duration,
            recursion_duration,
            evm_duration: evm_duration_opt.unwrap_or_default(),
            total_duration,
            success: true,
        })
    }
}

impl EmulatorRunner for KoalaBearPoseidon2 {
    fn run(
        bench_program: &BenchProgram,
        riscv_endpoint: Arc<DuplexUnboundedEndpoint<RiscvMsg<Self>, RiscvMsg<Self>>>,
    ) -> Result<PerformanceReport> {
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
        let recursion_shape_config = vk_enabled
            .then(RecursionShapeConfig::<KoalaBear, RecursionChipType<KoalaBear>>::default);

        let riscv = RiscvProver::new_initial_prover(
            (RiscvKBSC::new(), &elf),
            riscv_opts,
            riscv_shape_config,
            Some(riscv_endpoint),
        );
        let convert = ConvertProver::new_with_prev(&riscv, recursion_opts, recursion_shape_config);

        let recursion_shape_config = vk_enabled
            .then(RecursionShapeConfig::<KoalaBear, RecursionChipType<KoalaBear>>::default);
        let combine =
            CombineProver::new_with_prev(&convert, recursion_opts, recursion_shape_config);
        let compress = CompressProver::new_with_prev(&combine, (), None);
        let embed = EmbedProver::<_, _, Vec<u8>>::new_with_prev(&compress, (), None);

        let riscv_vk = riscv.vk();

        // RISCV Phase
        log_section("RISCV PHASE");
        info!("Generating RISCV proof");
        let ((proof, cycles), riscv_duration) = time_operation(|| riscv.prove_cycles(stdin));
        info!("Verifying RISCV proof..");
        assert!(riscv.verify(&proof, riscv_vk));

        // Convert Phase
        log_section("CONVERT PHASE");
        info!("Generating CONVERT proof");
        let (proof, convert_duration) = time_operation(|| convert.prove(proof));
        info!("Verifying CONVERT proof..");
        assert!(convert.verify(&proof, riscv_vk));

        // Combine Phase
        log_section("COMBINE PHASE");
        info!("Generating COMBINE proof");
        let (proof, combine_duration) = time_operation(|| combine.prove(proof));
        info!("Verifying COMBINE proof..");
        assert!(combine.verify(&proof, riscv_vk));

        // Compress Phase
        log_section("COMPRESS PHASE");
        info!("Generating COMPRESS proof");
        let (proof, compress_duration) = time_operation(|| compress.prove(proof));
        info!("Verifying COMPRESS proof..");
        assert!(compress.verify(&proof, riscv_vk));

        // Embed Phase
        log_section("EMBED PHASE");
        info!("Generating EMBED proof");
        let (proof, embed_duration) = time_operation(|| embed.prove(proof));
        info!("Verifying EMBED proof..");
        assert!(embed.verify(&proof, riscv_vk));

        // Onchain Phase (only if VK enabled)
        let evm_duration_opt = vk_enabled.then(|| {
            log_section("ONCHAIN PHASE");
            let (_, evm_duration) = time_operation(|| {
                let onchain_stdin = OnchainStdin {
                    machine: embed.machine().clone(),
                    vk: proof.vks().first().unwrap().clone(),
                    proof: proof.proofs().first().unwrap().clone(),
                    flag_complete: true,
                };

                // Generate gnark data
                let (constraints, witness) = OnchainVerifierCircuit::<
                    KoalaBearBn254,
                    KoalaBearBn254Poseidon2,
                >::build(&onchain_stdin);
                let gnark_witness =
                    build_gnark_config_with_str(constraints, witness, PathBuf::from("./"));
                let gnark_proof_data = send_gnark_prove_task(gnark_witness);
                info!(
                    "gnark prove success with proof data {}",
                    gnark_proof_data.unwrap_or_else(|e| format!("Error: {}", e))
                );

                1_u32
            });

            evm_duration
        });

        let (recursion_duration, total_duration) = log_performance_summary(
            riscv_duration,
            convert_duration,
            combine_duration,
            compress_duration,
            embed_duration,
            evm_duration_opt,
        );

        Ok(PerformanceReport {
            program: bench_program.name.to_string(),
            cycles,
            riscv_duration,
            convert_duration,
            combine_duration,
            compress_duration,
            embed_duration,
            recursion_duration,
            evm_duration: evm_duration_opt.unwrap_or_default(),
            total_duration,
            success: true,
        })
    }
}

pub fn run<SC: StarkGenericConfig + 'static>(
    config: Arc<CoordinatorConfig>,
    emulator_receiver: Arc<Receiver<EmulatorMsg>>,
    riscv_endpoint: Arc<DuplexUnboundedEndpoint<RiscvMsg<SC>, RiscvMsg<SC>>>,
) -> JoinHandle<()>
where
    <SC::Pcs as Pcs<
        <SC as StarkGenericConfig>::Challenge,
        <SC as StarkGenericConfig>::Challenger,
    >>::ProverData: Send,
{
    tokio::spawn(async move {
        while let Ok(msg) = emulator_receiver.recv() {
            match msg {
                EmulatorMsg::Start => {
                    let result = SC::run(&config.program, riscv_endpoint.clone()).unwrap();

                    // Print results.
                    let output = format_results(&[result]);
                    println!("{}", output.join("\n"));
                }
                EmulatorMsg::Stop => break,
            }
        }
    })
}

fn time_operation<T, F: FnOnce() -> T>(operation: F) -> (T, Duration) {
    let start = Instant::now();
    let result = operation();
    let duration = start.elapsed();
    (result, duration)
}
