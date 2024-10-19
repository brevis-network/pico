use crate::configs::config::RecursionSimpleConfig;
use p3_baby_bear::BabyBear;
use p3_field::extension::BinomialExtensionField;

pub type BabyBearSimple = RecursionSimpleConfig<BabyBear, BinomialExtensionField<BabyBear, 4>>;
