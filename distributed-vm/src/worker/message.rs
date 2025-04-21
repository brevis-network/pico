use pico_vm::{configs::config::StarkGenericConfig, messages::gateway::GatewayMsg};

pub enum WorkerMsg<SC: StarkGenericConfig> {
    RequestTask,
    ProcessTask(GatewayMsg<SC>),
    RespondResult(GatewayMsg<SC>),
    Exit,
}
