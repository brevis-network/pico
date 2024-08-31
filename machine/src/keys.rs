use p3_matrix::dense::RowMajorMatrix;
use pico_configs::config::{StarkGenericConfig, Val, Com};

pub struct BaseProvingKey<SC: StarkGenericConfig> {
    /// The commitment to the preprocessed traces.
    pub commit: Com<SC>,
    /// The preprocessed traces.
    pub traces: Vec<RowMajorMatrix<Val<SC>>>,
    // The pcs data for the preprocessed traces.
    // pub data: PcsProverData<SC>,
}

pub struct BaseVerifyingKey<SC: StarkGenericConfig> {
    /// The commitment to the preprocessed traces.
    pub commit: Com<SC>,
    // The chip information.
    // pub chip_information: Vec<(String, Dom<SC>, Dimensions)>,
    // The chip ordering.
    // pub chip_ordering: HashMap<String, usize>,
}