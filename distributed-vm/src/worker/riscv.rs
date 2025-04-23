use crate::worker::message::WorkerMsg;
use log::debug;
use p3_baby_bear::BabyBear;
use p3_commit::Pcs;
use p3_field::{FieldAlgebra, PrimeField32};
use p3_koala_bear::KoalaBear;
use p3_poseidon2::GenericPoseidon2LinearLayers;
use p3_symmetric::Permutation;
use pico_perf::common::{
    bench_program::{load, BenchProgram},
    print_utils::log_section,
};
use pico_vm::{
    compiler::{
        recursion::circuit::{config::CircuitConfig, hash::FieldHasher, witness::Witnessable},
        riscv::{
            compiler::{Compiler, SourceType},
            program::Program,
        },
    },
    configs::{
        config::{FieldGenericConfig, StarkGenericConfig, Val},
        field_config::{BabyBearSimple, KoalaBearSimple},
        stark_config::{BabyBearPoseidon2, KoalaBearPoseidon2},
    },
    emulator::{opts::EmulatorOpts, stdin::EmulatorStdin},
    instances::{
        chiptype::{recursion_chiptype::RecursionChipType, riscv_chiptype::RiscvChipType},
        compiler::{
            shapes::{recursion_shape::RecursionShapeConfig, riscv_shape::RiscvShapeConfig},
            vk_merkle::{vk_verification_enabled, HasStaticVkManager, VkMerkleManager},
        },
        machine::{convert::ConvertMachine, riscv::RiscvMachine},
    },
    machine::{
        field::FieldSpecificPoseidon2Config, machine::MachineBehavior, witness::ProvingWitness,
    },
    messages::{
        gateway::GatewayMsg,
        riscv::{RiscvMsg, RiscvResponse},
    },
    primitives::{
        consts::{DIGEST_SIZE, RECURSION_NUM_PVS, RISCV_NUM_PVS},
        Poseidon2Init,
    },
    thread::channel::DuplexUnboundedEndpoint,
};
use std::{fmt::Debug, sync::Arc, time::Instant};
use tokio::task::JoinHandle;
use tracing::info;

// TODO: remove redundant code
pub fn get_vk_root<SC>(vk_manager: &VkMerkleManager<SC>) -> [Val<SC>; DIGEST_SIZE]
where
    SC: StarkGenericConfig + FieldHasher<Val<SC>, Digest = [Val<SC>; DIGEST_SIZE]>,
    Val<SC>: Ord,
{
    if vk_manager.vk_verification_enabled() {
        vk_manager.merkle_root
    } else {
        [Val::<SC>::ZERO; DIGEST_SIZE]
    }
}

pub fn run_bb(
    program: BenchProgram,
    endpoint: Arc<
        DuplexUnboundedEndpoint<WorkerMsg<BabyBearPoseidon2>, WorkerMsg<BabyBearPoseidon2>>,
    >,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        // opts and setups
        let vk_manager = <BabyBearPoseidon2 as HasStaticVkManager>::static_vk_manager();
        let vk_enabled = vk_manager.vk_verification_enabled();
        let vk_root = get_vk_root(&vk_manager);
        println!("vk_root: {:?}", vk_root);
        let riscv_shape_config = if vk_enabled {
            Some(RiscvShapeConfig::<BabyBear>::default())
        } else {
            None
        };
        let recursion_shape_config = vk_enabled
            .then(|| RecursionShapeConfig::<BabyBear, RecursionChipType<BabyBear>>::default());
        let (elf, _) = load::<Program>(&program).unwrap();

        // RISCV PHASE
        log_section("RISCV PHASE");
        let machine = RiscvMachine::new(
            BabyBearPoseidon2::default(),
            RiscvChipType::all_chips(),
            RISCV_NUM_PVS,
        );

        let riscv_compiler = Compiler::new(SourceType::RISCV, &elf);
        let mut riscv_program = riscv_compiler.compile();
        if let Some(ref shape_config) = riscv_shape_config {
            let program = Arc::get_mut(&mut riscv_program).expect("cannot get_mut arc");
            shape_config
                .padding_preprocessed_shape(program)
                .expect("cannot padding preprocessed shape");
        }
        let (pk, riscv_vk) = machine.setup_keys(&riscv_program);

        let challenger = machine.config().challenger();

        while let Ok(msg) = endpoint.recv() {
            match msg {
                WorkerMsg::ProcessTask(GatewayMsg::Riscv(
                    RiscvMsg::Request(req),
                    task_id,
                    ip_addr,
                )) => {
                    let mut challenger = challenger.clone();
                    pk.observed_by(&mut challenger);

                    let chunk_index = req.chunk_index;
                    let is_last_chunk = req.record.is_last;

                    debug!("[worker] start to prove chunk-{chunk_index}");
                    let start = Instant::now();

                    let proof = machine.prove_record(
                        chunk_index,
                        &pk,
                        &challenger,
                        riscv_shape_config.as_ref(),
                        req.record,
                    );

                    println!("RISCV Phase complete! chunk_index: {}", chunk_index);

                    // CONVERT PHASE
                    log_section("CONVERT PHASE");

                    let recursion_opts = EmulatorOpts::default();
                    debug!("recursion_opts: {:?}", recursion_opts);

                    let convert_machine = ConvertMachine::new(
                        BabyBearPoseidon2::new(),
                        RecursionChipType::<BabyBear>::all_chips(),
                        RECURSION_NUM_PVS,
                    );

                    // println!("Generating CONVERT proof (at {:?})..", start.elapsed());
                    let convert_stdin = EmulatorStdin::setup_for_convert_with_index::<
                        <BabyBearSimple as FieldGenericConfig>::F,
                        BabyBearSimple,
                    >(
                        &riscv_vk,
                        vk_root,
                        machine.base_machine(),
                        &proof,
                        &recursion_shape_config,
                        chunk_index,
                        is_last_chunk,
                    );
                    // TODO: replace SC::new() with convert_machine.config()
                    let convert_witness = ProvingWitness::setup_for_convert(
                        convert_stdin,
                        BabyBearPoseidon2::new().into(),
                        recursion_opts,
                    );

                    let proof =
                        convert_machine.prove_with_index(chunk_index as u32, &convert_witness);

                    info!(
                        "[worker] finish proving chunk-{chunk_index}, time used: {}ms",
                        start.elapsed().as_millis()
                    );

                    // return the riscv result
                    let msg = WorkerMsg::RespondResult(GatewayMsg::Riscv(
                        RiscvMsg::Response(RiscvResponse { chunk_index, proof }),
                        task_id,
                        ip_addr,
                    ));
                    endpoint.send(msg).unwrap();

                    // request for the next task
                    let msg = WorkerMsg::RequestTask;
                    endpoint.send(msg).unwrap();
                }
                WorkerMsg::Exit => break,
                _ => panic!("unsupported"),
            }
        }
    })
}

pub fn run_kb(
    program: BenchProgram,
    endpoint: Arc<
        DuplexUnboundedEndpoint<WorkerMsg<KoalaBearPoseidon2>, WorkerMsg<KoalaBearPoseidon2>>,
    >,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        // opts and setups
        let vk_manager = <KoalaBearPoseidon2 as HasStaticVkManager>::static_vk_manager();
        let vk_enabled = vk_manager.vk_verification_enabled();
        let vk_root = get_vk_root(&vk_manager);
        println!("vk_root: {:?}", vk_root);
        let riscv_shape_config = if vk_enabled {
            Some(RiscvShapeConfig::<KoalaBear>::default())
        } else {
            None
        };
        let recursion_shape_config = vk_enabled
            .then(|| RecursionShapeConfig::<KoalaBear, RecursionChipType<KoalaBear>>::default());
        let (elf, _) = load::<Program>(&program).unwrap();

        // RISCV PHASE
        log_section("RISCV PHASE");
        let machine = RiscvMachine::new(
            KoalaBearPoseidon2::default(),
            RiscvChipType::all_chips(),
            RISCV_NUM_PVS,
        );

        let riscv_compiler = Compiler::new(SourceType::RISCV, &elf);
        let mut riscv_program = riscv_compiler.compile();
        if let Some(ref shape_config) = riscv_shape_config {
            let program = Arc::get_mut(&mut riscv_program).expect("cannot get_mut arc");
            shape_config
                .padding_preprocessed_shape(program)
                .expect("cannot padding preprocessed shape");
        }
        let (pk, riscv_vk) = machine.setup_keys(&riscv_program);

        let challenger = machine.config().challenger();

        while let Ok(msg) = endpoint.recv() {
            match msg {
                WorkerMsg::ProcessTask(GatewayMsg::Riscv(
                    RiscvMsg::Request(req),
                    task_id,
                    ip_addr,
                )) => {
                    let mut challenger = challenger.clone();
                    pk.observed_by(&mut challenger);

                    let chunk_index = req.chunk_index;
                    let is_last_chunk = req.record.is_last;

                    debug!("[worker] start to prove chunk-{chunk_index}");
                    let start = Instant::now();

                    let proof = machine.prove_record(
                        chunk_index,
                        &pk,
                        &challenger,
                        riscv_shape_config.as_ref(),
                        req.record,
                    );

                    println!("RISCV Phase complete! chunk_index: {}", chunk_index);

                    // CONVERT PHASE
                    log_section("CONVERT PHASE");

                    let recursion_opts = EmulatorOpts::default();
                    debug!("recursion_opts: {:?}", recursion_opts);

                    let convert_machine = ConvertMachine::new(
                        KoalaBearPoseidon2::new(),
                        RecursionChipType::<KoalaBear>::all_chips(),
                        RECURSION_NUM_PVS,
                    );

                    // println!("Generating CONVERT proof (at {:?})..", start.elapsed());
                    let convert_stdin = EmulatorStdin::setup_for_convert_with_index::<
                        <KoalaBearSimple as FieldGenericConfig>::F,
                        KoalaBearSimple,
                    >(
                        &riscv_vk,
                        vk_root,
                        machine.base_machine(),
                        &proof,
                        &recursion_shape_config,
                        chunk_index,
                        is_last_chunk,
                    );
                    // TODO: replace SC::new() with convert_machine.config()
                    let convert_witness = ProvingWitness::setup_for_convert(
                        convert_stdin,
                        KoalaBearPoseidon2::new().into(),
                        recursion_opts,
                    );

                    let proof =
                        convert_machine.prove_with_index(chunk_index as u32, &convert_witness);

                    info!(
                        "[worker] finish proving chunk-{chunk_index}, time used: {}ms",
                        start.elapsed().as_millis()
                    );

                    // return the riscv result
                    let msg = WorkerMsg::RespondResult(GatewayMsg::Riscv(
                        RiscvMsg::Response(RiscvResponse { chunk_index, proof }),
                        task_id,
                        ip_addr,
                    ));
                    endpoint.send(msg).unwrap();

                    // request for the next task
                    let msg = WorkerMsg::RequestTask;
                    endpoint.send(msg).unwrap();
                }
                WorkerMsg::Exit => break,
                _ => panic!("unsupported"),
            }
        }
    })
}
