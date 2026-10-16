pub mod koalabear;

use crate::machine::field::same_field;
use p3_field::PrimeCharacteristicRing;
use p3_koala_bear::KoalaBear;
use std::any::Any;

/// Field trait for adapting Poseidon2 to the base field
pub trait FieldPoseidon2 {
    const FIELD_SBOX_DEGREE: usize;
}

impl<F: Any + PrimeCharacteristicRing> FieldPoseidon2 for F {
    const FIELD_SBOX_DEGREE: usize = field_sbox_degree::<F>();
}

const fn field_sbox_degree<F: Any + PrimeCharacteristicRing>() -> usize {
    if same_field::<F, KoalaBear, 4>() {
        koalabear::FIELD_SBOX_DEGREE
    } else {
        panic!("Unsupported field type");
    }
}
