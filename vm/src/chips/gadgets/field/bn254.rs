use crate::chips::gadgets::utils::field_params::{FieldParameters, FieldType, FpOpField, NumLimbs};
use hybrid_array::typenum::{U32, U62};
use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Clone, Copy, PartialEq, Serialize, Deserialize)]
/// BN254 base field parameter
pub struct Bn254BaseField;

impl FieldParameters for Bn254BaseField {
    const MODULUS: &'static [u8] = &[
        71, 253, 124, 216, 22, 140, 32, 60, 141, 202, 113, 104, 145, 106, 129, 151, 93, 88, 129,
        129, 182, 69, 80, 184, 41, 160, 49, 225, 114, 78, 100, 48,
    ];

    // A rough witness-offset estimate given the size of the limbs and the size of the field.
    const WITNESS_OFFSET: usize = 1usize << 14;
}

impl FpOpField for Bn254BaseField {
    const FIELD_TYPE: FieldType = FieldType::Bn254;
}

impl NumLimbs for Bn254BaseField {
    type Limbs = U32;
    type Witness = U62;
}
