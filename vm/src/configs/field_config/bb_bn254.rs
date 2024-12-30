use crate::configs::config::FieldGenericConfig;
use p3_baby_bear::BabyBear;
use p3_bn254_fr::Bn254Fr;
use p3_field::extension::BinomialExtensionField;

#[derive(Clone, Default, Debug)]
pub struct BabyBearBn254;

impl FieldGenericConfig for BabyBearBn254 {
    type N = Bn254Fr;
    type F = BabyBear;
    type EF = BinomialExtensionField<BabyBear, 4>;
}
