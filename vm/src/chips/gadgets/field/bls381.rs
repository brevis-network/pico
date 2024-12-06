use crate::chips::gadgets::utils::field_params::{FieldParameters, FieldType, FpOpField, NumLimbs};
use hybrid_array::typenum::{U48, U94};
use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Clone, Copy, PartialEq, Serialize, Deserialize)]
/// Bls12381 base field parameter
pub struct Bls381BaseField;

impl FieldParameters for Bls381BaseField {
    // The modulus has been taken from py_ecc python library by Ethereum Foundation.
    // // https://github.com/ethereum/py_ecc/blob/7b9e1b3/py_ecc/fields/field_properties.py#L30
    // The below value is the little-endian representation of the modulus.
    const NUM_LIMBS: usize = 48;

    const MODULUS: &'static [u8] = &[
        171, 170, 255, 255, 255, 255, 254, 185, 255, 255, 83, 177, 254, 255, 171, 30, 36, 246, 176,
        246, 160, 210, 48, 103, 191, 18, 133, 243, 132, 75, 119, 100, 215, 172, 75, 67, 182, 167,
        27, 75, 154, 230, 127, 57, 234, 17, 1, 26,
    ];

    // A rough witness-offset estimate given the size of the limbs and the size of the field.
    const WITNESS_OFFSET: usize = 1usize << 15;
}

impl FpOpField for Bls381BaseField {
    const FIELD_TYPE: FieldType = FieldType::Bls381;
}

impl NumLimbs for Bls381BaseField {
    type Limbs = U48;
    type Witness = U94;
}
