use crate::configs::config::FieldSimpleConfig;
use p3_field::extension::BinomialExtensionField;
use p3_koala_bear::KoalaBear;

pub type BabyBearSimple = FieldSimpleConfig<KoalaBear, BinomialExtensionField<KoalaBear, 4>>;
