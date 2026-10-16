use crate::{
    configs::config::StarkGenericConfig, machine::field::FieldSpecificPoseidon2Config,
    primitives::PicoPoseidon2KoalaBear,
};
use p3_field::extension::BinomialExtensionField;
use p3_koala_bear::KoalaBear;
use serde::Serialize;

pub type SC_Val = KoalaBear;
pub type SC_Perm = PicoPoseidon2KoalaBear;
pub type SC_Challenge = BinomialExtensionField<SC_Val, 4>;

/// Field-level config tag for KoalaBear + Poseidon2. The FRI PCS / challenger plumbing that used
/// to live here was removed with the FRI proving path (tag `legacy-fri-last`).
#[derive(Clone)]
pub struct KoalaBearPoseidon2 {
    pub perm: SC_Perm,
}

impl Serialize for KoalaBearPoseidon2 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        std::marker::PhantomData::<KoalaBearPoseidon2>.serialize(serializer)
    }
}

impl Default for KoalaBearPoseidon2 {
    fn default() -> Self {
        Self::new()
    }
}

impl StarkGenericConfig for KoalaBearPoseidon2 {
    type Val = SC_Val;
    type Challenge = SC_Challenge;

    fn new() -> Self {
        Self {
            perm: KoalaBear::permutation(),
        }
    }

    fn name(&self) -> String {
        "KoalaBearPoseidon2".to_string()
    }
}
