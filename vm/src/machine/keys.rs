use crate::configs::config::{Com, Domain, PcsProverData, StarkGenericConfig, Val};
use hashbrown::HashMap;
use p3_matrix::{dense::RowMajorMatrix, Dimensions};

pub struct BaseProvingKey<SC: StarkGenericConfig> {
    /// The commitment to the named traces.
    pub commit: Com<SC>,
    /// named preprocessed traces.
    pub preprocessed_trace: Vec<RowMajorMatrix<Val<SC>>>,
    /// The pcs data for the preprocessed traces.
    pub preprocessed_prover_data: PcsProverData<SC>,
    /// the index of for chips, chip name for key
    pub preprocessed_chip_ordering: HashMap<String, usize>,
}

pub struct BaseVerifyingKey<SC: StarkGenericConfig> {
    /// The commitment to the preprocessed traces.
    pub commit: Com<SC>,
    /// The preprocessed information.
    pub preprocessed_info: Vec<(String, Domain<SC>, Dimensions)>,
    /// the index of for chips, chip name for key
    pub preprocessed_chip_ordering: HashMap<String, usize>,
}
