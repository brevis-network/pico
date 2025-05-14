use crate::{
    common::auth::AuthConfig,
    coordinator::config::CoordinatorConfig,
    coordinator_server::{Coordinator, CoordinatorServer},
    gateway::GatewayEndpoint,
    messages::gateway::GatewayMsg,
    timeline::Stage,
    ProofResult, ProofTask, WorkerInfo,
};
use anyhow::Result;
use derive_more::Constructor;
use log::debug;
use p3_commit::Pcs;
use pico_vm::configs::config::StarkGenericConfig;
use std::sync::Arc;
use tokio::{signal::ctrl_c, task::JoinHandle};
use tonic::{
    async_trait, codec::CompressionEncoding, service::interceptor::InterceptedService,
    transport::Server, Request, Response, Status,
};
use tracing::info;

pub fn run<SC: Send + StarkGenericConfig + 'static>(
    gateway_endpoint: Arc<GatewayEndpoint<SC>>,
    cfg: &CoordinatorConfig,
) -> JoinHandle<()>
where
    <SC::Pcs as Pcs<
        <SC as StarkGenericConfig>::Challenge,
        <SC as StarkGenericConfig>::Challenger,
    >>::ProverData: Send,
    <SC as StarkGenericConfig>::Domain: Send,
{
    debug!("[coordinator] grpc server init");

    let srv = GrpcService::new(gateway_endpoint);
    let addr = cfg.grpc_addr;
    let auth_interceptor = cfg.server_auth_interceptor();

    let handle = tokio::spawn(async move {
        let svc = InterceptedService::new(
            CoordinatorServer::new(srv)
                .accept_compressed(CompressionEncoding::Zstd)
                .send_compressed(CompressionEncoding::Zstd),
            auth_interceptor,
        );

        Server::builder()
            // TODO: check below configurations if extended for lots of machines
            // .concurrency_limit_per_connection(512)
            // .initial_stream_window_size(Some(1024 * 1024 * 1024))
            // .initial_connection_window_size(Some(1024 * 1024 * 1024))
            .add_service(svc)
            .serve_with_shutdown(addr, async {
                ctrl_c().await.expect("failed to wait for shutdown");
            })
            .await
            .expect("failed");
    });

    debug!("[coordinator] grpc server init end");

    handle
}

#[derive(Constructor)]
struct GrpcService<SC: StarkGenericConfig> {
    gateway_endpoint: Arc<GatewayEndpoint<SC>>,
}

#[async_trait]
impl<SC: Send + StarkGenericConfig + 'static> Coordinator for GrpcService<SC>
where
    <SC::Pcs as Pcs<
        <SC as StarkGenericConfig>::Challenge,
        <SC as StarkGenericConfig>::Challenger,
    >>::ProverData: Send,
    <SC as StarkGenericConfig>::Domain: Send,
{
    async fn check_health(&self, request: Request<WorkerInfo>) -> Result<Response<()>, Status> {
        debug!("health from worker: {:?}", request.into_inner());

        // TODO: handle as registration, save the workers

        Ok(Response::new(()))
    }

    async fn request_task(&self, _request: Request<()>) -> Result<Response<ProofTask>, Status> {
        let receiver = self.gateway_endpoint.clone_receiver();
        if let Ok(mut msg) = receiver.try_recv() {
            match &mut msg {
                GatewayMsg::EmulatorComplete => {}
                GatewayMsg::RequestTask => {}
                GatewayMsg::Riscv(_, _, _, tl_opt) => {
                    if let Some(tl) = tl_opt.as_mut() {
                        tl.mark(Stage::RecordSending);
                    }
                }
                GatewayMsg::Combine(_, _, _, tl_opt) => {
                    if let Some(tl) = tl_opt.as_mut() {
                        tl.mark(Stage::CombineSending);
                    }
                }
                GatewayMsg::Close(_) => {}
                GatewayMsg::Exit => {}
            }
            info!("[coord-grpc] return new task");
            Ok::<_, Status>(Response::new(msg.into()))
        } else {
            Err(Status::not_found("no task"))
        }
    }

    async fn respond_result(&self, req: Request<ProofResult>) -> Result<Response<()>, Status> {
        info!("[coord-grpc] got response result");

        let msg = req.into_inner().into();

        self.gateway_endpoint.send(msg).unwrap();

        Ok(Response::new(()))
    }
}
