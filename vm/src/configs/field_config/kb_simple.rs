use crate::configs::config::FieldGenericConfig;
use p3_field::extension::BinomialExtensionField;
use p3_koala_bear::KoalaBear;

#[derive(Debug, Clone, Default)]
pub struct KoalaBearSimple;

impl FieldGenericConfig for KoalaBearSimple {
    type N = KoalaBear;
    type F = KoalaBear;
    type EF = BinomialExtensionField<KoalaBear, 4>;
}
