pub mod proof_tree;

use crate::{
    messages::{
        combine::{CombineMsg, CombineRequest, CombineResponse},
        gateway::GatewayMsg,
        riscv::{RiscvMsg, RiscvRequest, RiscvResponse},
    },
    timeline::{InMemStore, Stage::*, Timeline, TimelineStore, COORD_TL_ID},
};
use anyhow::Result;
use pico_vm::{configs::config::StarkGenericConfig, machine::proof::MetaProof};
use proof_tree::ProofTree;
use std::process;
use tracing::info;

pub struct GatewayHandler<SC: StarkGenericConfig> {
    // exit the whole app directly if proving complete
    exit_complete: bool,
    // identify if emulation is complete, it could be used to check if the leaves are complete in
    // proof tree
    emulator_complete: bool,
    proof_tree: ProofTree<MetaProof<SC>>,
}

impl<SC: StarkGenericConfig> GatewayHandler<SC> {
    pub fn new(exit_complete: bool) -> Self {
        Self {
            exit_complete,
            emulator_complete: false,
            proof_tree: ProofTree::default(),
        }
    }

    pub fn complete(&self) -> bool {
        self.emulator_complete && self.proof_tree.complete()
    }

    pub fn process_riscv_req(
        &mut self,
        _timelines: &InMemStore,
        msg: &GatewayMsg<SC>,
    ) -> Result<Option<GatewayMsg<SC>>> {
        match msg {
            GatewayMsg::Riscv(msg, _, _, _) => match msg {
                RiscvMsg::Request(RiscvRequest { chunk_index, .. }) => {
                    // save the placeholder for the processing proof
                    self.proof_tree.init_node(*chunk_index);
                }
                _ => {
                    panic!("unexpected message in process_riscv_req");
                }
            },
            _ => panic!("unsupported"),
        }
        Ok(None)
    }
    pub fn process(
        &mut self,
        timelines: &InMemStore,
        msg: GatewayMsg<SC>,
    ) -> Result<Option<GatewayMsg<SC>>> {
        let mut index_proofs_to_combine = None;
        match msg {
            GatewayMsg::EmulatorComplete => self.emulator_complete = true,
            GatewayMsg::Riscv(msg, _, _, tl) => match msg {
                RiscvMsg::Request(RiscvRequest { chunk_index, .. }) => {
                    // save the placeholder for the processing proof
                    self.proof_tree.init_node(chunk_index);
                }
                RiscvMsg::Response(RiscvResponse { chunk_index, proof }) => {
                    let mut timeline = tl.unwrap();
                    timeline.mark(CoordinatorRecv);
                    timelines.push_finished(timeline);

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
                tl,
            ) => {
                index_proofs_to_combine = self
                    .proof_tree
                    .set_proof(chunk_index, proof)
                    .map(|proofs| (chunk_index, proofs));
                let mut timeline = tl.unwrap();
                timeline.mark(CoordinatorRecv);
                timelines.push_finished(timeline);
            }
            _ => panic!("unsupported"),
        }

        if self.complete() {
            info!("[gateway] proving complete");
            // handle coordinator timeline
            let mut tl = timelines
                .remove_active(&COORD_TL_ID)
                .expect("Coordinator timeline not found");

            tl.mark(CoordinatorFinished);
            timelines.push_finished(tl.clone());

            timelines.summarize_finished();

            if self.exit_complete {
                // TODO: may exit gracefully
                process::exit(0);
            }
        }

        if let Some((chunk_index, proofs)) = index_proofs_to_combine {
            assert_eq!(proofs.len(), 2);
            let start = proofs[0].start_chunk;
            let end = proofs[1].end_chunk;
            let mut timeline = Timeline::new(start, end);
            timeline.mark(CombineStart);
            // return the combine message
            return Ok(Some(GatewayMsg::Combine(
                CombineMsg::Request(CombineRequest {
                    flag_complete: self.proof_tree.len() == 1,
                    chunk_index,
                    proofs,
                }),
                chunk_index.to_string(),
                "".to_string(),
                Some(timeline),
            )));
        }

        Ok(None)
    }
}
