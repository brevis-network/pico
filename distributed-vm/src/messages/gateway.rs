use crate::{
    messages::{combine::CombineMsg, riscv::RiscvMsg},
    timeline::Timeline,
};
use pico_vm::configs::config::StarkGenericConfig;

type IpAddr = String;
type TaskId = String;

#[derive(Clone)]
pub enum GatewayMsg<SC: StarkGenericConfig> {
    // identify the emulator complete
    // TODO: add block number for multiple block proving
    EmulatorComplete,
    // request task by worker
    RequestTask,
    // riscv
    Riscv(RiscvMsg<SC>, TaskId, IpAddr, Option<Timeline>),
    // combine
    Combine(CombineMsg<SC>, TaskId, IpAddr, Option<Timeline>),
    // close a client by ip
    Close(IpAddr),
    // exit
    Exit,
}

impl<SC: StarkGenericConfig> GatewayMsg<SC> {
    pub fn ip_addr(&self) -> IpAddr {
        match self {
            Self::EmulatorComplete | Self::RequestTask | Self::Exit => "",
            Self::Riscv(_, _, ip_addr, _) => ip_addr,
            Self::Combine(_, _, ip_addr, _) => ip_addr,
            Self::Close(ip_addr) => ip_addr,
        }
        .to_string()
    }
}
