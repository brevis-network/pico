use crate::{
    compiler::recursion_v2::{ir::SymbolicFelt, prelude::SymbolicExt},
    configs::config::Poseidon2Config,
    primitives::consts::{BabyBearConfig, KoalaBearConfig, Mersenne31Config, PERMUTATION_WIDTH},
};
use core::intrinsics::type_id;
use p3_baby_bear::{BabyBear, GenericPoseidon2LinearLayersBabyBear};
use p3_field::{
    extension::{BinomialExtensionField, BinomiallyExtendable},
    Field, FieldAlgebra,
};
use p3_koala_bear::{GenericPoseidon2LinearLayersKoalaBear, KoalaBear};
use p3_mersenne_31::{GenericPoseidon2LinearLayersMersenne31, Mersenne31};
use p3_poseidon2::GenericPoseidon2LinearLayers;
use p3_uni_stark::SymbolicExpression;
use std::any::{Any, TypeId};

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

// Check if the type T is a specified field F.
// NOTE: This function could not work for trait types with `'static`.
pub const fn same_field<T: Any, F: Field + BinomiallyExtendable<4>>() -> bool {
    unsafe {
        let typ = std::intrinsics::type_id::<T>();

        let field = type_id::<F>();
        let expr = type_id::<SymbolicExpression<F>>();
        let packing = type_id::<<F as Field>::Packing>();
        let binomial = type_id::<BinomialExtensionField<F, 4>>();
        let ext = type_id::<SymbolicExt<F, BinomialExtensionField<F, 4>>>();
        let felt = type_id::<SymbolicFelt<F>>();

        typ == field
            || typ == expr
            || typ == packing
            || typ == binomial
            || typ == ext
            || typ == felt
    }
}
