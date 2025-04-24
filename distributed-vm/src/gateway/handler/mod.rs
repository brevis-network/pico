mod proof_tree;

use anyhow::Result;
use log::info;
use pico_vm::{
    configs::config::StarkGenericConfig,
    machine::proof::MetaProof,
    messages::{
        gateway::GatewayMsg,
        riscv::{RiscvMsg, RiscvRequest, RiscvResponse},
    },
};
use proof_tree::ProofTree;

pub struct GatewayHandler<SC: StarkGenericConfig> {
    // identify if emulation is complete, it could be used to check if the leaves are complete in
    // proof tree
    emulator_complete: bool,
    proof_tree: ProofTree<MetaProof<SC>>,
    // TODO: add other fields
}

impl<SC: StarkGenericConfig> Default for GatewayHandler<SC> {
    fn default() -> Self {
        Self {
            emulator_complete: false,
            proof_tree: ProofTree::new(),
        }
    }
}

impl<SC: StarkGenericConfig> GatewayHandler<SC> {
    pub fn complete(&self) -> bool {
        self.emulator_complete && self.proof_tree.complete()
    }

    pub fn process(&mut self, msg: GatewayMsg<SC>) -> Result<()> {
        match msg {
            GatewayMsg::EmulatorComplete => self.emulator_complete = true,
            GatewayMsg::Riscv(msg, _, _) => match msg {
                RiscvMsg::Request(RiscvRequest { chunk_index, .. }) => {
                    // save the placeholder for the processing proof
                    self.proof_tree.init_node(chunk_index);
                }
                RiscvMsg::Response(RiscvResponse { chunk_index, proof }) => {
                    // TODO: handle the returned proofs to combine, send a combine request
                    self.proof_tree.set_proof(chunk_index, proof);

                    if self.complete() {
                        info!("[coordinator] proving complete");
                    }
                }
            },
            _ => panic!("unsupported"),
        }

        Ok(())
    }
}
