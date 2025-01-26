pub mod babybear;
pub mod koalabear;
pub mod mersenne31;

use crate::machine::field::same_field;
pub use halo2curves::bn256::Fr as FFBn254Fr;
use p3_baby_bear::BabyBear;
use p3_field::FieldAlgebra;
use p3_koala_bear::KoalaBear;
use std::any::Any;

/// Field trait for adapting Poseidon2 with multiple fields
pub trait FieldPoseidon2 {
    const FIELD_SBOX_DEGREE: usize;
}

impl<F: Any + FieldAlgebra> FieldPoseidon2 for F {
    const FIELD_SBOX_DEGREE: usize = field_sbox_degree::<F>();
}

const fn field_sbox_degree<F: Any + FieldAlgebra>() -> usize {
    if same_field::<F, BabyBear>() {
        babybear::FIELD_SBOX_DEGREE
    } else if same_field::<F, KoalaBear>() {
        koalabear::FIELD_SBOX_DEGREE
    } else {
        // panic!("Unsupported field type");
        babybear::FIELD_SBOX_DEGREE
    }
}
