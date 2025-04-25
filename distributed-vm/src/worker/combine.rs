use crate::worker::{message::WorkerMsg, riscv::get_vk_root};
use p3_baby_bear::BabyBear;
use p3_koala_bear::KoalaBear;
use pico_perf::common::{bench_program::load, print_utils::log_section};
use pico_vm::{
    compiler::riscv::program::Program,
    configs::{
        config::{StarkGenericConfig, Val},
        stark_config::{BabyBearPoseidon2, KoalaBearPoseidon2},
    },
    instances::{
        chiptype::recursion_chiptype::RecursionChipType,
        compiler::{
            shapes::{recursion_shape::RecursionShapeConfig, riscv_shape::RiscvShapeConfig},
            vk_merkle::HasStaticVkManager,
        },
        machine::combine::CombineMachine,
    },
    messages::{
        combine::{CombineMsg, CombineRequest, CombineResponse},
        gateway::GatewayMsg,
        riscv::{RiscvMsg, RiscvResponse},
    },
    primitives::consts::RECURSION_NUM_PVS,
    thread::channel::DuplexUnboundedEndpoint,
};
use std::sync::Arc;
use tokio::task::JoinHandle;
use tracing::info;

pub fn run_bb(
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
        let recursion_shape_config = vk_enabled
            .then(|| RecursionShapeConfig::<BabyBear, RecursionChipType<BabyBear>>::default());

        // COMBINE PHASE
        log_section("COMBINE PHASE");
        let combine_machine = CombineMachine::<_, _>::new(
            BabyBearPoseidon2::new(),
            RecursionChipType::<Val<BabyBearPoseidon2>>::all_chips(),
            RECURSION_NUM_PVS,
        );

        while let Ok(msg) = endpoint.recv() {
            match msg {
                WorkerMsg::ProcessTask(GatewayMsg::Combine(
                    CombineMsg::Request(CombineRequest {
                        chunk_index,
                        flag_complete,
                        proofs,
                    }),
                    task_id,
                    ip_addr,
                )) => {
                    // TODO: add combine logic
                    info!("receive combine request: chunk_index = {}", chunk_index);

                    let meta_a = Arc::try_unwrap(proofs[0].clone()).unwrap_or_else(|_| {
                        panic!("meta_a still has multiple references, cannot unwrap Arc");
                    });
                    let meta_b = Arc::try_unwrap(proofs[1].clone()).unwrap_or_else(|_| {
                        panic!("meta_b still has multiple references, cannot unwrap Arc");
                    });

                    let result = combine_machine.prove_two(meta_a, meta_b, flag_complete);

                    let msg = WorkerMsg::RespondResult(GatewayMsg::Combine(
                        CombineMsg::Response(CombineResponse {
                            chunk_index,
                            proof: result,
                        }),
                        task_id,
                        ip_addr,
                    ));
                    endpoint.send(msg).unwrap();
                    info!("Finish combine request: chunk_index = {}", chunk_index);

                    // request for the next task
                    let msg = WorkerMsg::RequestTask;
                    endpoint.send(msg).unwrap();
                }
                // ignore other task types
                WorkerMsg::ProcessTask(..) => (),
                WorkerMsg::Exit => break,
                _ => panic!("unsupported"),
            }
        }
    })
}

pub fn run_kb(
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
        let recursion_shape_config = vk_enabled
            .then(|| RecursionShapeConfig::<KoalaBear, RecursionChipType<KoalaBear>>::default());

        // COMBINE PHASE
        log_section("COMBINE PHASE");
        let combine_machine = CombineMachine::<_, _>::new(
            KoalaBearPoseidon2::new(),
            RecursionChipType::<Val<KoalaBearPoseidon2>>::all_chips(),
            RECURSION_NUM_PVS,
        );

        while let Ok(msg) = endpoint.recv() {
            match msg {
                WorkerMsg::ProcessTask(GatewayMsg::Combine(
                    CombineMsg::Request(CombineRequest {
                        chunk_index,
                        flag_complete,
                        proofs,
                    }),
                    task_id,
                    ip_addr,
                )) => {
                    // TODO: add combine logic
                    info!("receive combine request: chunk_index = {}", chunk_index);

                    let meta_a = Arc::try_unwrap(proofs[0].clone()).unwrap_or_else(|_| {
                        panic!("meta_a still has multiple references, cannot unwrap Arc");
                    });
                    let meta_b = Arc::try_unwrap(proofs[1].clone()).unwrap_or_else(|_| {
                        panic!("meta_b still has multiple references, cannot unwrap Arc");
                    });

                    let result = combine_machine.prove_two(meta_a, meta_b, flag_complete);

                    let msg = WorkerMsg::RespondResult(GatewayMsg::Combine(
                        CombineMsg::Response(CombineResponse {
                            chunk_index,
                            proof: result,
                        }),
                        task_id,
                        ip_addr,
                    ));
                    endpoint.send(msg).unwrap();
                    info!("Finish combine request: chunk_index = {}", chunk_index);

                    // request for the next task
                    let msg = WorkerMsg::RequestTask;
                    endpoint.send(msg).unwrap();
                }
                // ignore other task types
                WorkerMsg::ProcessTask(..) => (),
                WorkerMsg::Exit => break,
                _ => panic!("unsupported"),
            }
        }
    })
}
