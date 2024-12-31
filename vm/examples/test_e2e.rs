use cpu_time::ProcessTime;
use p3_baby_bear::BabyBear;
use p3_field::FieldAlgebra;
use pico_vm::{
    compiler::{
        recursion_v2::circuit::witness::Witnessable,
        riscv::compiler::{Compiler, SourceType},
    },
    configs::config::{Challenge, Val},
    emulator::{opts::EmulatorOpts, riscv::stdin::EmulatorStdin},
    instances::{
        chiptype::{recursion_chiptype_v2::RecursionChipType, riscv_chiptype::RiscvChipType},
        compiler_v2::{
            onchain_circuit::{
                gnark::builder::OnchainVerifierCircuit, stdin::OnchainStdin,
                utils::build_gnark_config,
            },
            recursion_circuit::{
                compress::builder::CompressVerifierCircuit, embed::builder::EmbedVerifierCircuit,
                stdin::RecursionStdin,
            },
        },
        configs::{
            embed_config::StarkConfig as EmbedSC,
            recur_config::{FieldConfig as RecursionFC, StarkConfig as RecursionSC},
            riscv_config::StarkConfig as RiscvBBSC,
        },
        machine::{
            combine::CombineMachine, compress::CompressMachine, convert::ConvertMachine,
            embed::EmbedMachine, riscv::RiscvMachine,
        },
    },
    machine::{logger::setup_logger, machine::MachineBehavior, witness::ProvingWitness},
    primitives::consts::{
        BABYBEAR_S_BOX_DEGREE, COMBINE_DEGREE, COMBINE_SIZE, COMPRESS_DEGREE, CONVERT_DEGREE,
        DIGEST_SIZE, EMBED_DEGREE, PERMUTATION_WIDTH, RECURSION_NUM_PVS_V2, RISCV_NUM_PVS,
    },
    recursion_v2::runtime::Runtime,
};
use std::{
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};
use tracing::info;

#[path = "common/parse_args.rs"]
mod parse_args;

fn main() {
    setup_logger();

    // -------- Riscv Machine --------

    info!("\n Begin RISCV..");

    let (elf, riscv_stdin, args) = parse_args::parse_args();

    info!("PERF-machine=riscv");
    let start = Instant::now();
    let riscv_start = Instant::now();

    info!("Setting up RISCV..");
    let riscv_compiler = Compiler::new(SourceType::RiscV, elf);
    let riscv_program = riscv_compiler.compile();

    let riscv_machine = RiscvMachine::new(
        RiscvBBSC::new(),
        RiscvChipType::<BabyBear>::all_chips(),
        RISCV_NUM_PVS,
    );

    // Setup machine prover, verifier, pk and vk.
    let (riscv_pk, riscv_vk) = riscv_machine.setup_keys(&riscv_program.clone());

    let core_opts = if args.bench {
        info!("use benchmark options");
        EmulatorOpts::bench_riscv_ops()
    } else {
        EmulatorOpts::default()
    };
    info!("core_opts: {:?}", core_opts);

    // Generate the proof.
    info!("Generating RISCV proof (at {:?})..", start.elapsed());
    let (riscv_proof, riscv_time) = timed_run(|| {
        let riscv_witness = ProvingWitness::setup_for_riscv(
            riscv_program.clone(),
            riscv_stdin,
            core_opts,
            riscv_pk,
            riscv_vk.clone(),
        );

        riscv_machine.prove(&riscv_witness)
    });
    info!(
        "PERF-step=prove-user_time={}",
        riscv_start.elapsed().as_millis()
    );

    let riscv_proof_size = bincode::serialize(&riscv_proof.proofs()).unwrap().len();
    info!("PERF-step=proof_size-{}", riscv_proof_size);

    // Verify the proof.
    info!("Verifying RISCV proof (at {:?})..", start.elapsed());
    let riscv_result = riscv_machine.verify(&riscv_proof);
    info!(
        "The proof is verified: {} (at {:?})..",
        riscv_result.is_ok(),
        start.elapsed()
    );
    assert!(riscv_result.is_ok());
    if args.step == "riscv" {
        print_stats(
            riscv_time,
            TIME_ZERO,
            TIME_ZERO,
            TIME_ZERO,
            TIME_ZERO,
            riscv_proof_size,
            0,
            0,
            0,
            0,
        );
        return;
    }

    // -------- Riscv Convert Recursion Machine --------

    info!("\n Begin CONVERT..");

    let recursion_opts = if args.bench {
        EmulatorOpts::bench_recursion_opts()
    } else {
        EmulatorOpts::default()
    };
    info!("recursion_opts: {:?}", recursion_opts);

    info!("PERF-machine=convert");
    let convert_start = Instant::now();

    // TODO: Initialize the VK root.
    let vk_root = [BabyBear::ZERO; DIGEST_SIZE];

    info!("Setting up CONVERT..");
    let convert_machine = ConvertMachine::new(
        RecursionSC::new(),
        RecursionChipType::<BabyBear, CONVERT_DEGREE>::all_chips(),
        RECURSION_NUM_PVS_V2,
    );

    info!("Generating CONVERT proof (at {:?})..", start.elapsed());
    let (convert_proof, convert_time) = timed_run(|| {
        let convert_stdin = EmulatorStdin::setup_for_convert(
            &riscv_vk,
            vk_root,
            riscv_machine.base_machine(),
            &riscv_proof.proofs(),
        );

        let convert_witness = ProvingWitness::setup_for_convert(
            convert_stdin,
            convert_machine.config(),
            recursion_opts,
        );

        convert_machine.prove(&convert_witness)
    });
    info!(
        "PERF-step=prove-user_time={}",
        convert_start.elapsed().as_millis()
    );

    let convert_proof_size = bincode::serialize(&convert_proof.proofs()).unwrap().len();
    info!("PERF-step=proof_size-{}", convert_proof_size);

    // Verify the proof.
    info!("Verifying CONVERT proof (at {:?})..", start.elapsed());
    let convert_result = convert_machine.verify(&convert_proof);
    info!(
        "The CONVERT proof is verified: {} (at {:?})",
        convert_result.is_ok(),
        start.elapsed()
    );
    assert!(convert_result.is_ok());

    if args.step == "convert" {
        print_stats(
            riscv_time,
            convert_time,
            TIME_ZERO,
            TIME_ZERO,
            TIME_ZERO,
            riscv_proof_size,
            convert_proof_size,
            0,
            0,
            0,
        );
        return;
    }

    // -------- Combine Recursion Machine --------

    info!("\n Begin COMBINE..");

    info!("PERF-machine=combine");
    let combine_start = Instant::now();

    // TODO: Initialize the VK root.
    let vk_root = [BabyBear::ZERO; DIGEST_SIZE];

    info!("Setting up COMBINE");
    let combine_machine = CombineMachine::new(
        RecursionSC::new(),
        RecursionChipType::<BabyBear, COMBINE_DEGREE>::all_chips(),
        RECURSION_NUM_PVS_V2,
    );

    info!("Generating COMBINE proof (at {:?})..", start.elapsed());
    let (combine_proof, combine_time) = timed_run(|| {
        let combine_stdin = EmulatorStdin::setup_for_combine(
            vk_root,
            convert_proof.vks(),
            &convert_proof.proofs(),
            convert_machine.base_machine(),
            COMBINE_SIZE,
            false,
        );

        let combine_witness = ProvingWitness::setup_for_recursion(
            vk_root,
            combine_stdin,
            combine_machine.config(),
            recursion_opts,
        );

        combine_machine.prove(&combine_witness)
    });
    info!(
        "PERF-step=prove-user_time={}",
        combine_start.elapsed().as_millis(),
    );

    let combine_proof_size = bincode::serialize(&combine_proof.proofs()).unwrap().len();
    info!("PERF-step=proof_size-{}", combine_proof_size);

    // Verify the proof.
    info!("Verifying COMBINE proof (at {:?})..", start.elapsed());
    let combine_result = combine_machine.verify(&combine_proof);
    info!(
        "The COMBINE proof is verified: {} (at {:?})",
        combine_result.is_ok(),
        start.elapsed()
    );
    assert!(combine_result.is_ok());

    if args.step == "combine" {
        print_stats(
            riscv_time,
            convert_time,
            combine_time,
            TIME_ZERO,
            TIME_ZERO,
            riscv_proof_size,
            convert_proof_size,
            combine_proof_size,
            0,
            0,
        );
        return;
    }

    // -------- Compress Recursion Machine --------

    info!("\n Begin COMPRESS..");

    info!("PERF-machine=compress");
    let compress_start = Instant::now();

    // TODO: Initialize the VK root.
    let vk_root = [BabyBear::ZERO; DIGEST_SIZE];

    info!("Setting up COMPRESS");
    let compress_machine = CompressMachine::new(
        RecursionSC::compress(),
        RecursionChipType::<BabyBear, COMPRESS_DEGREE>::compress_chips(),
        RECURSION_NUM_PVS_V2,
    );

    info!("Generating COMPRESS proof (at {:?})..", start.elapsed());
    let (compress_proof, compress_time) = timed_run(|| {
        let compress_stdin = RecursionStdin::new(
            compress_machine.base_machine(),
            combine_proof.vks.clone(),
            combine_proof.proofs.clone(),
            true,
            vk_root,
        );

        let compress_program = CompressVerifierCircuit::<RecursionFC, RecursionSC>::build(
            combine_machine.base_machine(),
            &compress_stdin,
        );

        compress_program.print_stats();

        let (compress_pk, compress_vk) = compress_machine.setup_keys(&compress_program);

        let record = {
            let mut witness_stream = Vec::new();
            Witnessable::<RecursionFC>::write(&compress_stdin, &mut witness_stream);
            let mut runtime = Runtime::<
                Val<RecursionSC>,
                Challenge<RecursionSC>,
                _,
                _,
                PERMUTATION_WIDTH,
                BABYBEAR_S_BOX_DEGREE,
            >::new(
                Arc::new(compress_program),
                combine_machine.config().perm.clone(),
            );
            runtime.witness_stream = witness_stream.into();
            runtime.run().unwrap();
            runtime.record
        };
        let compress_witness =
            ProvingWitness::setup_with_keys_and_records(compress_pk, compress_vk, vec![record]);

        compress_machine.prove(&compress_witness)
    });
    info!(
        "PERF-step=prove-user_time={}",
        compress_start.elapsed().as_millis()
    );

    let compress_proof_size = bincode::serialize(&compress_proof.proofs()).unwrap().len();
    info!("PERF-step=proof_size-{}", compress_proof_size);

    info!("Verifying COMPRESS proof (at {:?})..", start.elapsed());
    let compress_result = compress_machine.verify(&compress_proof);

    info!(
        "The COMPRESS proof is verified: {} (at {:?})",
        compress_result.is_ok(),
        start.elapsed()
    );
    assert!(compress_result.is_ok());

    if args.step == "compress" {
        print_stats(
            riscv_time,
            convert_time,
            combine_time,
            compress_time,
            TIME_ZERO,
            riscv_proof_size,
            convert_proof_size,
            combine_proof_size,
            compress_proof_size,
            0,
        );
        return;
    }

    // -------- Embed Machine --------

    info!("\n Begin EMBED..");
    info!("PERF-machine=embed");
    let embed_start = Instant::now();

    // TODO: Initialize the VK root.
    let vk_root = [BabyBear::ZERO; DIGEST_SIZE];

    info!("Setting up EMBED");
    let embed_machine = EmbedMachine::<_, _, Vec<u8>>::new(
        EmbedSC::new(),
        RecursionChipType::<BabyBear, EMBED_DEGREE>::embed_chips(),
        RECURSION_NUM_PVS_V2,
    );

    info!("Generating EMBED proof (at {:?})..", start.elapsed());
    let (embed_proof, embed_time) = timed_run(|| {
        let embed_stdin = RecursionStdin::new(
            compress_machine.base_machine(),
            compress_proof.vks,
            compress_proof.proofs,
            true,
            vk_root,
        );

        let embed_program = EmbedVerifierCircuit::<RecursionFC, RecursionSC>::build(
            compress_machine.base_machine(),
            &embed_stdin,
        );

        embed_program.print_stats();

        let (embed_pk, embed_vk) = embed_machine.setup_keys(&embed_program);

        let record = {
            let mut witness_stream = Vec::new();
            Witnessable::<RecursionFC>::write(&embed_stdin, &mut witness_stream);
            let mut runtime = Runtime::<
                Val<RecursionSC>,
                Challenge<RecursionSC>,
                _,
                _,
                PERMUTATION_WIDTH,
                BABYBEAR_S_BOX_DEGREE,
            >::new(
                Arc::new(embed_program),
                compress_machine.config().perm.clone(),
            );
            runtime.witness_stream = witness_stream.into();
            runtime.run().unwrap();
            runtime.record
        };

        let embed_witness =
            ProvingWitness::setup_with_keys_and_records(embed_pk, embed_vk, vec![record]);

        embed_machine.prove(&embed_witness)
    });
    info!(
        "PERF-step=prove-user_time={}",
        embed_start.elapsed().as_millis()
    );

    let embed_proof_size = bincode::serialize(&embed_proof.proofs()).unwrap().len();
    info!("PERF-step=proof_size-{}", embed_proof_size);

    info!("Verifying EMBED proof (at {:?})..", start.elapsed());
    let embed_result = embed_machine.verify(&embed_proof);

    info!(
        "The EMBED proof is verified: {} (at {:?})",
        compress_result.is_ok(),
        start.elapsed()
    );
    assert!(embed_result.is_ok());

    print_stats(
        riscv_time,
        convert_time,
        combine_time,
        compress_time,
        embed_time,
        riscv_proof_size,
        convert_proof_size,
        combine_proof_size,
        compress_proof_size,
        embed_proof_size,
    );

    info!("\n Begin Onchain..");
    let onchain_stdin = OnchainStdin {
        machine: embed_machine.base_machine(),
        vk: embed_proof.vks().first().unwrap().clone(),
        proof: embed_proof.proofs().first().unwrap().clone(),
        flag_complete: true,
    };

    let (constraints, witness) = OnchainVerifierCircuit::build(&onchain_stdin);

    build_gnark_config(constraints, witness, PathBuf::from("./"));
    info!("Finished exporting gnark data");
}

struct TimeStats {
    pub wall_time: Duration,
    pub cpu_time: Duration,
    pub parallelism: f64,
}

const TIME_ZERO: TimeStats = TimeStats {
    wall_time: Duration::from_secs(0),
    cpu_time: Duration::from_secs(0),
    parallelism: 0.0,
};

fn timed_run<T, F: FnOnce() -> T>(operation: F) -> (T, TimeStats) {
    let start = Instant::now();
    let start_cpu = ProcessTime::now();
    let result = operation();
    let wall_time = start.elapsed();
    let cpu_time = start_cpu.elapsed();
    let parallelism = cpu_time.as_secs_f64() / wall_time.as_secs_f64();
    (
        result,
        TimeStats {
            wall_time,
            cpu_time,
            parallelism,
        },
    )
}

#[allow(clippy::too_many_arguments)]
fn print_stats(
    riscv_time: TimeStats,
    convert_time: TimeStats,
    combine_time: TimeStats,
    compress_time: TimeStats,
    embed_time: TimeStats,
    riscv_proof_size: usize,
    convert_proof_size: usize,
    combine_proof_size: usize,
    compress_proof_size: usize,
    embed_proof_size: usize,
) {
    let recursion_time = convert_time.wall_time
        + combine_time.wall_time
        + compress_time.wall_time
        + embed_time.wall_time;
    let recursion_cpu_time = convert_time.cpu_time
        + combine_time.cpu_time
        + compress_time.cpu_time
        + embed_time.cpu_time;
    let recursion_parallelism = recursion_cpu_time.as_secs_f64() / recursion_time.as_secs_f64();
    let total_time = riscv_time.wall_time + recursion_time;
    let total_cpu_time = riscv_time.cpu_time + recursion_cpu_time;
    let total_parallelism = total_cpu_time.as_secs_f64() / total_time.as_secs_f64();

    info!("Proof time: (wall_time, total_cpu_time, parallelism)");
    info!(
        "|- riscv      {:<12}  {:<10}  {:.2}",
        format_duration(riscv_time.wall_time.as_secs_f64()),
        format_duration(riscv_time.cpu_time.as_secs_f64()),
        riscv_time.parallelism
    );
    info!(
        "|- recursion  {:<12}  {:<10}  {:.2}",
        format_duration(recursion_time.as_secs_f64()),
        format_duration(recursion_cpu_time.as_secs_f64()),
        recursion_parallelism
    );
    info!(
        "   |- convert   {:10}  {:<10}  {:.2}",
        format_duration(convert_time.wall_time.as_secs_f64()),
        format_duration(convert_time.cpu_time.as_secs_f64()),
        convert_time.parallelism
    );
    info!(
        "   |- combine   {:<10}  {:<10}  {:.2}",
        format_duration(combine_time.wall_time.as_secs_f64()),
        format_duration(combine_time.cpu_time.as_secs_f64()),
        combine_time.parallelism
    );
    info!(
        "   |- compress  {:<10}  {:<10}  {:.2}",
        format_duration(compress_time.wall_time.as_secs_f64()),
        format_duration(compress_time.cpu_time.as_secs_f64()),
        compress_time.parallelism
    );
    info!(
        "   |- embed     {:<10}  {:<10}  {:.2}",
        format_duration(embed_time.wall_time.as_secs_f64()),
        format_duration(embed_time.cpu_time.as_secs_f64()),
        embed_time.parallelism
    );
    info!(
        "|- total      {:<12}  {:<12}  {:.2}",
        format_duration(total_time.as_secs_f64()),
        format_duration(total_cpu_time.as_secs_f64()),
        total_parallelism
    );

    info!("");
    info!("Proof size:");
    info!("|- riscv    {:?}K", (riscv_proof_size as f64) / 1000.0);
    info!("|- convert  {:?}K", (convert_proof_size as f64) / 1000.0);
    info!("|- combine  {:?}K", (combine_proof_size as f64) / 1000.0);
    info!("|- compress {:?}K", (compress_proof_size as f64) / 1000.0);
    info!("|- embed    {:?}K", (embed_proof_size as f64) / 1000.0);
}

fn format_duration(duration: f64) -> String {
    let secs = duration.round() as u64;
    let minutes = secs / 60;
    let seconds = secs % 60;

    if minutes > 0 {
        format!("{}m:{}s", minutes, seconds)
    } else if seconds > 0 {
        format!(
            "{}s:{}ms",
            seconds,
            ((duration - seconds as f64) * 1000.0).round() as u64
        )
    } else {
        format!("{}ms", (duration * 1000.0).round() as u64)
    }
}
