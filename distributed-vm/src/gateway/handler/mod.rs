mod proof_tree;

use anyhow::Result;
use log::info;
use pico_vm::{
    configs::config::StarkGenericConfig,
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
    proof_tree: ProofTree<SC>,
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
                    self.proof_tree.set_leaf(chunk_index, None)?;
                }
                RiscvMsg::Response(RiscvResponse { chunk_index, proof }) => {
                    // save the generated proof
                    self.proof_tree.set_leaf(chunk_index, Some(proof))?;

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
