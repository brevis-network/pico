use crate::{RiscvResult, RiscvTask};
use pico_vm::{
    configs::config::StarkGenericConfig,
    messages::{
        gateway::GatewayMsg,
        riscv::{RiscvMsg, RiscvRequest, RiscvResponse},
    },
};

impl<SC: StarkGenericConfig> From<GatewayMsg<SC>> for RiscvTask {
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
        let record = bincode::serialize(&req.record).unwrap();

        RiscvTask {
            id,
            chunk_index,
            pk,
            record,
        }
    }
}

impl<SC: StarkGenericConfig> From<GatewayMsg<SC>> for RiscvResult {
    fn from(msg: GatewayMsg<SC>) -> Self {
        let (res, id) = if let GatewayMsg::Riscv(msg, id, _) = msg {
            if let RiscvMsg::Response(res) = msg {
                (res, id)
            } else {
                panic!("unsupported");
            }
        } else {
            panic!("unsupported");
        };

        let chunk_index = res.chunk_index as u64;
        let proof = bincode::serialize(&res.proof).unwrap();

        RiscvResult {
            id,
            chunk_index,
            proof,
        }
    }
}

impl<SC: StarkGenericConfig> From<RiscvTask> for GatewayMsg<SC> {
    fn from(task: RiscvTask) -> Self {
        let id = task.id;
        let chunk_index = task.chunk_index as usize;
        let pk = bincode::deserialize(&task.pk).unwrap();
        let record = bincode::deserialize(&task.record).unwrap();

        GatewayMsg::Riscv(
            RiscvMsg::Request(RiscvRequest {
                chunk_index,
                pk,
                record,
            }),
            id,
            "".to_string(),
        )
    }
}

impl<SC: StarkGenericConfig> From<RiscvResult> for GatewayMsg<SC> {
    fn from(res: RiscvResult) -> Self {
        let id = res.id;
        let chunk_index = res.chunk_index as usize;
        let proof = bincode::deserialize(&res.proof).unwrap();

        let res = RiscvResponse::new(chunk_index, proof);

        GatewayMsg::Riscv(RiscvMsg::Response(res), id, "".to_string())
    }
}
