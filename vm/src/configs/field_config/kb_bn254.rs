use crate::configs::config::FieldGenericConfig;
use p3_bn254_fr::Bn254Fr;
use p3_field::extension::BinomialExtensionField;
use p3_koala_bear::KoalaBear;

#[derive(Clone, Default, Debug)]
pub struct KoalaBearBn254;

impl FieldGenericConfig for KoalaBearBn254 {
    type N = Bn254Fr;
    type F = KoalaBear;
    type EF = BinomialExtensionField<KoalaBear, 4>;
}
