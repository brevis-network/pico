use hashbrown::HashMap;

use p3_matrix::{dense::RowMajorMatrix, Dimensions};

use crate::config::{StarkGenericConfig, Val, Com, PcsProverData, Dom, };
use crate::chip::{BaseChip, ChipBehavior};


pub struct BaseProvingKey<SC: StarkGenericConfig> {
    /// The commitment to the preprocessed traces.
    pub commit: Com<SC>,
    /// The start pc of the program.
    pub pc_start: Val<SC>,
    /// The preprocessed traces.
    pub traces: Vec<RowMajorMatrix<Val<SC>>>,
    /// The pcs data for the preprocessed traces.
    pub data: PcsProverData<SC>,
    /// The preprocessed chip ordering.
    pub chip_ordering: HashMap<String, usize>,
}

pub struct BaseVerifyingKey<SC: StarkGenericConfig> {
    /// The commitment to the preprocessed traces.
    pub commit: Com<SC>,
    /// The start pc of the program.
    pub pc_start: Val<SC>,
    /// The chip information.
    pub chip_information: Vec<(String, Dom<SC>, Dimensions)>,
    /// The chip ordering.
    pub chip_ordering: HashMap<String, usize>,
}


pub struct Prover<SC: StarkGenericConfig, C> {
    config: SC,

    chips: Vec<BaseChip<Val<SC>, C>>,
}

impl<SC: StarkGenericConfig, C: ChipBehavior<Val<SC>>> Prover<SC, C> {
    pub fn chips(&self) -> &[BaseChip<Val<SC>, C>] {
        &self.chips
    }

    
}