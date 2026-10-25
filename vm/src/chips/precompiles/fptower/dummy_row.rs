use super::fp::{num_fp_cols, FpOpCols};
use crate::chips::gadgets::{
    field::{
        bls381::Bls381BaseField, bn254::Bn254BaseField, field_op::FieldOperation,
        secp256k1::Secp256k1BaseField,
    },
    utils::field_params::FpOpField,
};
use core::borrow::BorrowMut;
use lazy_static::lazy_static;
use num::BigUint;
use p3_field::PrimeField32;
use p3_koala_bear::KoalaBear;

/// Programmatically generates the correct dummy (padding) row for FpOpCols,
/// matching exactly what the CPU `pad_rows_fixed` lambda produces.
fn generate_dummy_row<F: PrimeField32, P: FpOpField>() -> Vec<F> {
    use super::fp::FpOpChip;
    let mut row = vec![F::ZERO; num_fp_cols::<P>()];
    let cols: &mut FpOpCols<F, P> = row.as_mut_slice().borrow_mut();
    let zero = BigUint::from(0u32);
    cols.is_add = F::from_u8(1);
    FpOpChip::<F, P>::populate_field_ops(
        &mut vec![],
        cols,
        zero.clone(),
        zero,
        FieldOperation::Add,
    );
    row
}

lazy_static! {
    pub static ref DUMMY_ROW_BN254_KB: Vec<KoalaBear> =
        generate_dummy_row::<KoalaBear, Bn254BaseField>();
    pub static ref DUMMY_ROW_BLS381_KB: Vec<KoalaBear> =
        generate_dummy_row::<KoalaBear, Bls381BaseField>();
    pub static ref DUMMY_ROW_SECP256K1_KB: Vec<KoalaBear> =
        generate_dummy_row::<KoalaBear, Secp256k1BaseField>();
}
