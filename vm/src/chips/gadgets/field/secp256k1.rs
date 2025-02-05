use crate::chips::gadgets::utils::field_params::{FieldParameters, FieldType, FpOpField, NumLimbs};
use hybrid_array::typenum::{U32, U62};
use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Clone, Copy, PartialEq, Serialize, Deserialize)]
/// Secp256k1 base field parameter
pub struct Secp256k1BaseField;

impl FieldParameters for Secp256k1BaseField {
    const MODULUS: &'static [u8] = &[
        47, 252, 255, 255, 254, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    ];

    // A rough witness-offset estimate given the size of the limbs and the size of the field.
    const WITNESS_OFFSET: usize = 1usize << 14;
}

impl FpOpField for Secp256k1BaseField {
    const FIELD_TYPE: FieldType = FieldType::Secp256k1;
}

impl NumLimbs for Secp256k1BaseField {
    type Limbs = U32;
    type Witness = U62;
}
