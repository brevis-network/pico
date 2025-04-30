pub mod combine;
pub mod riscv;

use super::WorkerEndpoint;
use crate::{
    messages::{combine::CombineMsg, gateway::GatewayMsg, riscv::RiscvMsg},
    timeline::Stage::*,
};
use combine::{CombineHandler, CombineProver};
use p3_commit::Pcs;
use p3_field::{extension::BinomiallyExtendable, FieldAlgebra, PrimeField32};
use p3_symmetric::Permutation;
use pico_perf::common::bench_program::BenchProgram;
use pico_vm::{
    compiler::recursion::circuit::hash::FieldHasher,
    configs::{
        config::{StarkGenericConfig, Val},
        stark_config::{BabyBearPoseidon2, KoalaBearPoseidon2},
    },
    instances::compiler::vk_merkle::{HasStaticVkManager, VkMerkleManager},
    machine::field::FieldSpecificPoseidon2Config,
    primitives::{
        consts::{DIGEST_SIZE, EXTENSION_DEGREE},
        Poseidon2Init,
    },
};
use riscv::{RiscvConvertHandler, RiscvConvertProver};
use std::sync::Arc;
use tokio::task::JoinHandle;
use tracing::info;

type VkRoot<SC> = [<SC as StarkGenericConfig>::Val; DIGEST_SIZE];

pub struct Prover<SC>
where
    SC: StarkGenericConfig,
    SC::Val: PrimeField32 + FieldSpecificPoseidon2Config + BinomiallyExtendable<EXTENSION_DEGREE>,
{
    prover_id: String,
    endpoint: Arc<WorkerEndpoint<SC>>,
    riscv_convert: RiscvConvertProver<SC>,
    combine: CombineProver<SC>,
    vk_root: VkRoot<SC>,
}

impl<SC> Prover<SC>
where
    SC: StarkGenericConfig
        + HasStaticVkManager
        + FieldHasher<Val<SC>, Digest = [Val<SC>; DIGEST_SIZE]>
        + Default
        + Send
        + 'static,
    SC::Val: Ord
        + PrimeField32
        + Poseidon2Init
        + FieldSpecificPoseidon2Config
        + BinomiallyExtendable<EXTENSION_DEGREE>,
    <SC::Val as Poseidon2Init>::Poseidon2: Permutation<[SC::Val; 16]>,
    <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::ProverData: Send,
{
    pub fn new(
        prover_id: String,
        program: BenchProgram,
        endpoint: Arc<WorkerEndpoint<SC>>,
    ) -> Self {
        let riscv_convert = RiscvConvertProver::new(prover_id.clone(), program);
        let combine = CombineProver::new(prover_id.clone());

        let vk_manager = <SC as HasStaticVkManager>::static_vk_manager();
        let vk_root = get_vk_root(vk_manager);

        Self {
            prover_id,
            endpoint,
            riscv_convert,
            combine,
            vk_root,
        }
    }
}

/// specialization for running emulator on either babybear or koalabear
pub trait ProverRunner {
    fn run(self) -> JoinHandle<()>;
}

impl<SC> ProverRunner for Prover<SC>
where
    SC: StarkGenericConfig,
    SC::Val: PrimeField32 + FieldSpecificPoseidon2Config + BinomiallyExtendable<EXTENSION_DEGREE>,
{
    /// default implementation
    default fn run(self) -> JoinHandle<()> {
        panic!("unsupported");
    }
}

impl ProverRunner for Prover<BabyBearPoseidon2> {
    fn run(self) -> JoinHandle<()> {
        info!("[{}] : start", self.prover_id);

        tokio::task::spawn_blocking(move || {
            // request for task first
            let msg = GatewayMsg::RequestTask;
            self.endpoint.send(msg).unwrap();

            while let Ok(msg) = self.endpoint.recv() {
                match msg {
                    GatewayMsg::Riscv(RiscvMsg::Request(req), task_id, ip_addr, tl) => {
                        info!(
                            "[{}] receive riscv request of chunk-{}",
                            self.prover_id, &req.chunk_index,
                        );
                        let mut timeline = tl.unwrap();
                        timeline.mark(WorkerRecv);
                        let res = self.riscv_convert.process(req, &self.vk_root);
                        info!(
                            "[{}] send riscv response of chunk-{}",
                            self.prover_id, &res.chunk_index,
                        );
                        timeline.mark(RiscvConvertDone);
                        let msg = GatewayMsg::Riscv(
                            RiscvMsg::Response(res),
                            task_id,
                            ip_addr,
                            Some(timeline),
                        );
                        self.endpoint.send(msg).unwrap();
                    }
                    GatewayMsg::Combine(CombineMsg::Request(req), task_id, ip_addr, tl) => {
                        info!(
                            "[{}] receive combine request of chunk-{}",
                            self.prover_id, &req.chunk_index,
                        );
                        let mut timeline = tl.unwrap();
                        timeline.mark(WorkerRecv);
                        let res = self.combine.process(req);
                        info!(
                            "[{}] send combine response of chunk-{}",
                            self.prover_id, &res.chunk_index,
                        );
                        timeline.mark(CombineDone);
                        let msg = GatewayMsg::Combine(
                            CombineMsg::Response(res),
                            task_id,
                            ip_addr,
                            Some(timeline),
                        );
                        self.endpoint.send(msg).unwrap();
                    }
                    GatewayMsg::Exit => break,
                    _ => panic!("unsupported"),
                }

                // request for the next task
                let msg = GatewayMsg::RequestTask;
                self.endpoint.send(msg).unwrap();
            }
        })
    }
}

impl ProverRunner for Prover<KoalaBearPoseidon2> {
    fn run(self) -> JoinHandle<()> {
        info!("[{}] : start", self.prover_id);

        tokio::task::spawn_blocking(move || {
            // request for task first
            let msg = GatewayMsg::RequestTask;
            self.endpoint.send(msg).unwrap();

            while let Ok(msg) = self.endpoint.recv() {
                match msg {
                    GatewayMsg::Riscv(RiscvMsg::Request(req), task_id, ip_addr, tl) => {
                        info!(
                            "[{}] receive riscv request of chunk-{}",
                            self.prover_id, &req.chunk_index,
                        );
                        let mut timeline = tl.unwrap();
                        timeline.mark(WorkerRecv);
                        let res = self.riscv_convert.process(req, &self.vk_root);
                        info!(
                            "[{}] send riscv response of chunk-{}",
                            self.prover_id, &res.chunk_index,
                        );
                        timeline.mark(RiscvConvertDone);
                        let msg = GatewayMsg::Riscv(
                            RiscvMsg::Response(res),
                            task_id,
                            ip_addr,
                            Some(timeline),
                        );
                        self.endpoint.send(msg).unwrap();
                    }
                    GatewayMsg::Combine(CombineMsg::Request(req), task_id, ip_addr, tl) => {
                        info!(
                            "[{}] receive combine request of chunk-{}",
                            self.prover_id, &req.chunk_index,
                        );
                        let mut timeline = tl.unwrap();
                        timeline.mark(WorkerRecv);
                        let res = self.combine.process(req);
                        info!(
                            "[{}] send combine response of chunk-{}",
                            self.prover_id, &res.chunk_index,
                        );
                        timeline.mark(CombineDone);
                        let msg = GatewayMsg::Combine(
                            CombineMsg::Response(res),
                            task_id,
                            ip_addr,
                            Some(timeline),
                        );
                        self.endpoint.send(msg).unwrap();
                    }
                    GatewayMsg::Exit => break,
                    _ => panic!("unsupported"),
                }

                // request for the next task
                let msg = GatewayMsg::RequestTask;
                self.endpoint.send(msg).unwrap();
            }
        })
    }
}

fn get_vk_root<SC>(vk_manager: &VkMerkleManager<SC>) -> [Val<SC>; DIGEST_SIZE]
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
