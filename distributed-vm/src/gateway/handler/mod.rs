mod proof_tree;

use anyhow::Result;
use log::info;
use pico_vm::{
    configs::config::StarkGenericConfig,
    machine::proof::MetaProof,
    messages::{
        combine::{CombineMsg, CombineRequest, CombineResponse},
        gateway::GatewayMsg,
        riscv::{RiscvMsg, RiscvRequest, RiscvResponse},
    },
};
use proof_tree::ProofTree;
use std::process;

pub struct GatewayHandler<SC: StarkGenericConfig> {
    // exit the whole app directly if proving complete
    exit_complete: bool,
    // identify if emulation is complete, it could be used to check if the leaves are complete in
    // proof tree
    emulator_complete: bool,
    proof_tree: ProofTree<MetaProof<SC>>,
    // TODO: add other fields
}

impl<SC: StarkGenericConfig> GatewayHandler<SC> {
    pub fn new(exit_complete: bool) -> Self {
        Self {
            exit_complete,
            emulator_complete: false,
            proof_tree: ProofTree::new(),
        }
    }

    pub fn complete(&self) -> bool {
        self.emulator_complete && self.proof_tree.complete()
    }

    pub fn process(&mut self, msg: GatewayMsg<SC>) -> Result<Option<GatewayMsg<SC>>> {
        let mut index_proofs_to_combine = None;
        match msg {
            GatewayMsg::EmulatorComplete => self.emulator_complete = true,
            GatewayMsg::Riscv(msg, _, _) => match msg {
                RiscvMsg::Request(RiscvRequest { chunk_index, .. }) => {
                    // save the placeholder for the processing proof
                    self.proof_tree.init_node(chunk_index);
                }
                RiscvMsg::Response(RiscvResponse { chunk_index, proof }) => {
                    index_proofs_to_combine = self
                        .proof_tree
                        .set_proof(chunk_index, proof)
                        .map(|proofs| (chunk_index, proofs));
                }
            },
            GatewayMsg::Combine(
                CombineMsg::Response(CombineResponse { chunk_index, proof }),
                _,
                _,
            ) => {
                index_proofs_to_combine = self
                    .proof_tree
                    .set_proof(chunk_index, proof)
                    .map(|proofs| (chunk_index, proofs));
            }
            _ => panic!("unsupported"),
        }

        if self.complete() {
            info!("[gateway] proving complete");
            if self.exit_complete {
                // TODO: may exit gracefully
                process::exit(0);
            }
        }

        if let Some((chunk_index, proofs)) = index_proofs_to_combine {
            // return the combine message
            return Ok(Some(GatewayMsg::Combine(
                CombineMsg::Request(CombineRequest {
                    flag_complete: self.proof_tree.len() == 1,
                    chunk_index,
                    proofs,
                }),
                chunk_index.to_string(),
                "".to_string(),
            )));
        }

        Ok(None)
    }
}
