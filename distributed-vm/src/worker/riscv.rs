use crate::worker::message::WorkerMsg;
use p3_commit::Pcs;
use p3_field::PrimeField32;
use p3_poseidon2::GenericPoseidon2LinearLayers;
use p3_symmetric::Permutation;
use pico_vm::{
    configs::config::StarkGenericConfig,
    instances::{
        chiptype::riscv_chiptype::RiscvChipType, compiler::shapes::riscv_shape::RiscvShapeConfig,
        machine::riscv::RiscvMachine,
    },
    machine::{field::FieldSpecificPoseidon2Config, machine::MachineBehavior},
    messages::{
        gateway::GatewayMsg,
        riscv::{RiscvMsg, RiscvResponse},
    },
    primitives::{consts::RISCV_NUM_PVS, Poseidon2Init},
    thread::channel::DuplexUnboundedEndpoint,
};
use std::sync::Arc;
use tokio::task::JoinHandle;

pub fn run<SC: Send + StarkGenericConfig + 'static>(
    sc: SC,
    endpoint: Arc<DuplexUnboundedEndpoint<WorkerMsg<SC>, WorkerMsg<SC>>>,
) -> JoinHandle<()>
where
    SC::Val: FieldSpecificPoseidon2Config + Poseidon2Init + PrimeField32 + Send,
    <SC::Val as Poseidon2Init>::Poseidon2: Permutation<[SC::Val; 16]>,
    <SC::Val as FieldSpecificPoseidon2Config>::LinearLayers:
        GenericPoseidon2LinearLayers<<SC::Val as p3_field::Field>::Packing, 16>,
    <SC::Pcs as Pcs<
        <SC as StarkGenericConfig>::Challenge,
        <SC as StarkGenericConfig>::Challenger,
    >>::ProverData: Send,
{
    tokio::spawn(async move {
        let shape_config = RiscvShapeConfig::<SC::Val>::default();
        let machine = RiscvMachine::new(sc, RiscvChipType::all_chips(), RISCV_NUM_PVS);

        let challenger = machine.config().challenger();

        while let Ok(msg) = endpoint.recv() {
            match msg {
                WorkerMsg::ProcessTask(GatewayMsg::Riscv(
                    RiscvMsg::Request(req),
                    task_id,
                    ip_addr,
                )) => {
                    let pk = req.pk;
                    let mut challenger = challenger.clone();
                    pk.observed_by(&mut challenger);

                    let chunk_index = req.chunk_index;
                    let proof = machine.prove_record(
                        chunk_index,
                        &pk,
                        &challenger,
                        Some(&shape_config),
                        req.record,
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
