use crate::configs::config::FieldSimpleConfig;
use p3_baby_bear::BabyBear;
use p3_field::extension::BinomialExtensionField;

pub type BabyBearSimple = FieldSimpleConfig<BabyBear, BinomialExtensionField<BabyBear, 4>>;
