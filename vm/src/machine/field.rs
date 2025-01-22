use crate::{
    configs::config::Poseidon2Config,
    primitives::consts::{BabyBearConfig, KoalaBearConfig, Mersenne31Config, PERMUTATION_WIDTH},
};
use p3_baby_bear::{BabyBear, GenericPoseidon2LinearLayersBabyBear};
use p3_field::{Field, FieldAlgebra};
use p3_koala_bear::{GenericPoseidon2LinearLayersKoalaBear, KoalaBear};
use p3_mersenne_31::{GenericPoseidon2LinearLayersMersenne31, Mersenne31};
use p3_poseidon2::GenericPoseidon2LinearLayers;
use std::any::TypeId;

#[derive(Clone, Debug, PartialEq)]
pub enum FieldType {
    TypeGeneralField,
    TypeBabyBear,
    TypeKoalaBear,
    TypeMersenne31,
}

pub trait FieldBehavior {
    fn field_type() -> FieldType;
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

pub trait FieldSpecificPoseidon2Config: FieldAlgebra {
    type Poseidon2Config: Poseidon2Config;
    type LinearLayers: GenericPoseidon2LinearLayers<Self, PERMUTATION_WIDTH>;
}

impl FieldSpecificPoseidon2Config for BabyBear {
    type Poseidon2Config = BabyBearConfig;
    type LinearLayers = GenericPoseidon2LinearLayersBabyBear;
}

impl FieldSpecificPoseidon2Config for KoalaBear {
    type Poseidon2Config = KoalaBearConfig;
    type LinearLayers = GenericPoseidon2LinearLayersKoalaBear;
}

impl FieldSpecificPoseidon2Config for Mersenne31 {
    type Poseidon2Config = Mersenne31Config;
    type LinearLayers = GenericPoseidon2LinearLayersMersenne31;
}
