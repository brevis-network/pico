use crate::{
    coordinator_server::{Coordinator, CoordinatorServer},
    RiscvResult, RiscvTask, WorkerInfo,
};
use anyhow::Result;
use derive_more::Constructor;
use log::debug;
use p3_commit::Pcs;
use pico_vm::{
    configs::config::StarkGenericConfig, messages::gateway::GatewayMsg,
    thread::channel::DuplexUnboundedEndpoint,
};
use serde::Serialize;
use std::sync::Arc;
use tokio::task::JoinHandle;
use tonic::{async_trait, transport::Server, Request, Response, Status};

type GatewayEndpoint<SC> = Arc<DuplexUnboundedEndpoint<GatewayMsg<SC>, GatewayMsg<SC>>>;

pub async fn run<SC: Send + StarkGenericConfig + 'static>(
    gateway_endpoint: GatewayEndpoint<SC>,
) -> JoinHandle<()>
where
    <SC::Pcs as Pcs<
        <SC as StarkGenericConfig>::Challenge,
        <SC as StarkGenericConfig>::Challenger,
    >>::ProverData: Send,
    SC::Challenger: Serialize,
{
    // TODO: read from a toml file
    let addr = "[::1]:50051".parse().unwrap();
    let srv = GrpcService::new(gateway_endpoint);

    tokio::spawn(async move {
        Server::builder()
            .add_service(CoordinatorServer::new(srv))
            .serve(addr)
            .await
            .expect("failed");
    })
}

#[derive(Constructor)]
struct GrpcService<SC: StarkGenericConfig> {
    gateway_endpoint: GatewayEndpoint<SC>,
}

#[async_trait]
impl<SC: Send + StarkGenericConfig + 'static> Coordinator for GrpcService<SC>
where
    <SC::Pcs as Pcs<
        <SC as StarkGenericConfig>::Challenge,
        <SC as StarkGenericConfig>::Challenger,
    >>::ProverData: Send,
    SC::Challenger: Serialize,
{
    async fn check_health(&self, request: Request<WorkerInfo>) -> Result<Response<()>, Status> {
        debug!("health from worker: {:?}", request.into_inner());

        // TODO: handle as registration, save the workers

        Ok(Response::new(()))
    }

    async fn request_riscv(&self, _request: Request<()>) -> Result<Response<RiscvTask>, Status> {
        while let Ok(msg) = self.gateway_endpoint.recv() {
            // TODO: check worker ip address
            if msg.ip_addr() == "blocked" {
                continue;
            }

            return Ok(Response::new(msg.into()));
        }

        Err(Status::not_found("no task"))
    }

    async fn respond_riscv(&self, req: Request<RiscvResult>) -> Result<Response<()>, Status> {
        let msg = req.into_inner().into();

        self.gateway_endpoint.send(msg).unwrap();

        Ok(Response::new(()))
    }
}
