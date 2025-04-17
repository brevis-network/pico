use crate::{configs::config::StarkGenericConfig, messages::riscv::RiscvMsg};

type IpAddr = String;
type TaskId = String;

pub enum GatewayMsg<SC: StarkGenericConfig> {
    Riscv(RiscvMsg<SC>, TaskId, IpAddr),
    // close a client by ip
    Close(IpAddr),
}

impl<SC: StarkGenericConfig> GatewayMsg<SC> {
    pub fn ip_addr(&self) -> IpAddr {
        match self {
            Self::Riscv(_, _, ip_addr) => ip_addr,
            Self::Close(ip_addr) => ip_addr,
        }
        .to_string()
    }
}
