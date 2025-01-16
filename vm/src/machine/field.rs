use crate::{
    configs::config::Poseidon2Config,
    primitives::consts::{BabyBearConfig, KoalaBearConfig, Mersenne31Config},
};
use p3_baby_bear::BabyBear;
use p3_field::Field;
use p3_koala_bear::KoalaBear;
use p3_mersenne_31::Mersenne31;
use std::any::TypeId;

#[derive(Clone, Debug, PartialEq)]
pub enum FieldType {
    TypeGeneralField,
    TypeBabyBear,
    TypeKoalaBear,
    TypeMersenne31,
}

pub trait FieldBehavior {
    fn field_type() -> FieldType {
        FieldType::TypeGeneralField
    }
}

impl<F: Field> FieldBehavior for F {
    fn field_type() -> FieldType {
        match TypeId::of::<F>() {
            type_id if type_id == TypeId::of::<BabyBear>() => FieldType::TypeBabyBear,
            type_id if type_id == TypeId::of::<KoalaBear>() => FieldType::TypeKoalaBear,
            type_id if type_id == TypeId::of::<Mersenne31>() => FieldType::TypeMersenne31,
            _ => FieldType::TypeGeneralField,
        }
    }
}

pub trait FieldSpecificPoseidon2Config {
    type Poseidon2Config: Poseidon2Config;
}

impl FieldSpecificPoseidon2Config for BabyBear {
    type Poseidon2Config = BabyBearConfig;
}

impl FieldSpecificPoseidon2Config for KoalaBear {
    type Poseidon2Config = KoalaBearConfig;
}

impl FieldSpecificPoseidon2Config for Mersenne31 {
    type Poseidon2Config = Mersenne31Config;
}
