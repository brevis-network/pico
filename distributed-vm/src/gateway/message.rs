use crate::{ProofResult, ProofTask, TaskType};
use pico_vm::{
    configs::config::StarkGenericConfig,
    messages::{
        combine::{CombineMsg, CombineRequest, CombineResponse},
        gateway::GatewayMsg,
        riscv::{RiscvMsg, RiscvRequest, RiscvResponse},
    },
};
use std::sync::Arc;

impl<SC: StarkGenericConfig> From<GatewayMsg<SC>> for ProofTask {
    fn from(msg: GatewayMsg<SC>) -> Self {
        match msg {
            GatewayMsg::Riscv(RiscvMsg::Request(req), id, _) => {
                let chunk_index = req.chunk_index as u64;
                let record = Some(bincode::serialize(&req.record).unwrap());

                ProofTask {
                    id,
                    task_type: TaskType::Riscv as i32,
                    chunk_index,
                    record,
                    flag_complete: None,
                    proofs: vec![],
                }
            }
            GatewayMsg::Combine(CombineMsg::Request(req), id, _) => {
                let chunk_index = req.chunk_index as u64;
                let flag_complete = Some(req.flag_complete);
                let proofs = req
                    .proofs
                    .iter()
                    .map(|p| bincode::serialize(&p).unwrap())
                    .collect();

                ProofTask {
                    id,
                    task_type: TaskType::Combine as i32,
                    chunk_index,
                    record: None,
                    flag_complete,
                    proofs,
                }
            }
            _ => panic!("unsupported"),
        }
    }
}

impl<SC: StarkGenericConfig> From<GatewayMsg<SC>> for ProofResult {
    fn from(msg: GatewayMsg<SC>) -> Self {
        match msg {
            GatewayMsg::Riscv(RiscvMsg::Response(res), id, _) => {
                let chunk_index = res.chunk_index as u64;
                let proof = bincode::serialize(&res.proof).unwrap();

                ProofResult {
                    id,
                    task_type: TaskType::Riscv as i32,
                    chunk_index,
                    proof,
                }
            }
            GatewayMsg::Combine(CombineMsg::Response(res), id, _) => {
                let chunk_index = res.chunk_index as u64;
                let proof = bincode::serialize(&res.proof).unwrap();

                ProofResult {
                    id,
                    task_type: TaskType::Combine as i32,
                    chunk_index,
                    proof,
                }
            }

            _ => panic!("unsupported"),
        }
    }
}

impl<SC: StarkGenericConfig> From<ProofTask> for GatewayMsg<SC> {
    fn from(task: ProofTask) -> Self {
        match TaskType::try_from(task.task_type).unwrap() {
            TaskType::Riscv => {
                let id = task.id;
                let chunk_index = task.chunk_index as usize;
                let record = bincode::deserialize(&task.record.unwrap()).unwrap();

                GatewayMsg::Riscv(
                    RiscvMsg::Request(RiscvRequest {
                        chunk_index,
                        record,
                    }),
                    id,
                    "".to_string(),
                )
            }
            TaskType::Combine => {
                let id = task.id;
                let chunk_index = task.chunk_index as usize;
                let flag_complete = task.flag_complete.unwrap();
                let proofs = task
                    .proofs
                    .iter()
                    .map(|p| Arc::new(bincode::deserialize(p).unwrap()))
                    .collect();

                GatewayMsg::Combine(
                    CombineMsg::Request(CombineRequest {
                        chunk_index,
                        flag_complete,
                        proofs,
                    }),
                    id,
                    "".to_string(),
                )
            }
        }
    }
}

impl<SC: StarkGenericConfig> From<ProofResult> for GatewayMsg<SC> {
    fn from(res: ProofResult) -> Self {
        match TaskType::try_from(res.task_type).unwrap() {
            TaskType::Riscv => {
                let id = res.id;
                let chunk_index = res.chunk_index as usize;
                let proof = bincode::deserialize(&res.proof).unwrap();

                let res = RiscvResponse::new(chunk_index, proof);

                GatewayMsg::Riscv(RiscvMsg::Response(res), id, "".to_string())
            }
            TaskType::Combine => {
                let id = res.id;
                let chunk_index = res.chunk_index as usize;
                let proof = bincode::deserialize(&res.proof).unwrap();

                let res = CombineResponse::new(chunk_index, proof);

                GatewayMsg::Combine(CombineMsg::Response(res), id, "".to_string())
            }
        }
    }
}
