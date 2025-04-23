use anyhow::Result;
use pico_vm::{
    configs::config::StarkGenericConfig,
    machine::proof::{BaseProof, MetaProof},
};

pub struct ProofTree<SC: StarkGenericConfig> {
    leaves: Vec<Option<MetaProof<SC>>>,
    // TODO: add branch layers
}

impl<SC: StarkGenericConfig> ProofTree<SC> {
    pub fn new() -> Self {
        Self { leaves: vec![] }
    }

    pub fn complete(&self) -> bool {
        // TODO: fix to check only the combine root is not none (or embed proof is not none)
        self.leaves.iter().all(|leaf| leaf.is_some())
    }

    pub fn set_leaf(&mut self, index: usize, proof: Option<MetaProof<SC>>) -> Result<()> {
        // extend to save the specified index
        if index >= self.leaves.len() {
            self.leaves.resize(index + 1, None);
        }

        if self.leaves[index].is_some() {
            // TODO: fix to return error after stable
            panic!("proof is existing in tree: index = {index}");
            // bail!("proof is existing in tree: index = {index}");
        }

        self.leaves[index] = proof;

        Ok(())
    }
}
