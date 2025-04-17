use crate::{RiscvResult, RiscvTask};
use pico_vm::{
    configs::config::StarkGenericConfig,
    messages::{
        gateway::GatewayMsg,
        riscv::{RiscvMsg, RiscvResponse},
    },
};
use serde::Serialize;

impl<SC: StarkGenericConfig> From<RiscvResult> for GatewayMsg<SC> {
    fn from(res: RiscvResult) -> Self {
        let id = res.id;
        let chunk_index = res.chunk_index as usize;
        let proof = bincode::deserialize(&res.proof).unwrap();

        let res = RiscvResponse::new(chunk_index, proof);

        GatewayMsg::Riscv(RiscvMsg::Response(res), id, "".to_string())
    }
}

impl<SC: StarkGenericConfig> From<GatewayMsg<SC>> for RiscvTask
where
    SC::Challenger: Serialize,
{
    fn from(msg: GatewayMsg<SC>) -> Self {
        let (req, id) = if let GatewayMsg::Riscv(msg, id, _) = msg {
            if let RiscvMsg::Request(req) = msg {
                (req, id)
            } else {
                panic!("unsupported");
            }
        } else {
            panic!("unsupported");
        };

        let chunk_index = req.chunk_index as u64;
        let pk = bincode::serialize(&req.pk).unwrap();
        let challenger = bincode::serialize(&req.challenger).unwrap();
        let record = bincode::serialize(&req.record).unwrap();

        RiscvTask {
            id,
            chunk_index,
            pk,
            challenger,
            record,
        }
    }
}
