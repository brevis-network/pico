use crate::configs::config::{Com, PcsProverData, StarkGenericConfig};
use hashbrown::HashMap;
use p3_challenger::CanObserve;
use p3_matrix::{dense::RowMajorMatrix, Dimensions};

pub struct BaseProvingKey<SC: StarkGenericConfig> {
    /// The commitment to the named traces.
    pub commit: Com<SC>,
    /// start pc of program
    pub pc_start: SC::Val,
    /// named preprocessed traces.
    pub preprocessed_trace: Vec<RowMajorMatrix<SC::Val>>,
    /// The pcs data for the preprocessed traces.
    pub preprocessed_prover_data: PcsProverData<SC>,
    /// the index of for chips, chip name for key
    pub preprocessed_chip_ordering: HashMap<String, usize>,
}

impl<SC: StarkGenericConfig> BaseProvingKey<SC> {
    /// Observes the values of the proving key into the challenger.
    pub fn observed_by(&self, challenger: &mut SC::Challenger) {
        challenger.observe(self.commit.clone());
        challenger.observe(self.pc_start);
    }
}

pub struct BaseVerifyingKey<SC: StarkGenericConfig> {
    /// The commitment to the preprocessed traces.
    pub commit: Com<SC>,
    /// start pc of program
    pub pc_start: SC::Val,
    /// The preprocessed information.
    pub preprocessed_info: Vec<(String, SC::Domain, Dimensions)>,
    /// the index of for chips, chip name for key
    pub preprocessed_chip_ordering: HashMap<String, usize>,
}

impl<SC: StarkGenericConfig> BaseVerifyingKey<SC> {
    /// Observes the values of the verifying key into the challenger.
    pub fn observed_by(&self, challenger: &mut SC::Challenger) {
        challenger.observe(self.commit.clone());
        challenger.observe(self.pc_start);
    }
}
