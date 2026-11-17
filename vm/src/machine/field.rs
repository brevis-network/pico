use crate::{
    chips::gadgets::poseidon2::constants::RoundConstants,
    configs::config::Poseidon2Config,
    primitives::consts::{KoalaBearConfig, PERMUTATION_WIDTH},
};
use core::intrinsics::type_id;
use hybrid_array::Array;
use p3_field::{extension::QuinticTrinomialExtensionField, Field};
use p3_koala_bear::{
    default_koalabear_poseidon2_16, GenericPoseidon2LinearLayersKoalaBear, KoalaBear,
    Poseidon2KoalaBear, KOALABEAR_POSEIDON2_RC_16_EXTERNAL_FINAL,
    KOALABEAR_POSEIDON2_RC_16_EXTERNAL_INITIAL, KOALABEAR_POSEIDON2_RC_16_INTERNAL,
};
use p3_poseidon2::GenericPoseidon2LinearLayers;
use p3_symmetric::Permutation;
use pico_mle_core::air::symbolic::symbolic_expression::SymbolicExpression;
use std::any::{Any, TypeId};

#[derive(Clone, Debug, PartialEq)]
pub enum FieldType {
    TypeGeneralField,
    TypeKoalaBear,
}

pub trait FieldBehavior {
    fn field_type() -> FieldType;
}

impl<F: Field> FieldBehavior for F {
    fn field_type() -> FieldType {
        match TypeId::of::<F>() {
            type_id if type_id == TypeId::of::<KoalaBear>() => FieldType::TypeKoalaBear,
            _ => FieldType::TypeGeneralField,
        }
    }
}

/// The field's width-16 Poseidon2 instance, as seen from every side: the host permutation
/// (`permutation`), the round constants the AIR gadget and the GPU trace-gen consume
/// (`round_constants`), and the linear layers / round structure the gadget is generic over. Every
/// riscv-stage use of Poseidon2 -- the Poseidon2 precompile, the deferred-proof digest -- resolves
/// to this one instance, and it is Plonky3 0.5.4's default for the field
/// (`default_*_poseidon2_16`, the `*_POSEIDON2_RC_16_*` round constants), the same permutation
/// the MLE transcript and Merkle hasher use.
pub trait FieldSpecificPoseidon2Config: Field {
    type Poseidon2Config: Poseidon2Config;
    type LinearLayers: GenericPoseidon2LinearLayers<PERMUTATION_WIDTH>;
    type Perm: Permutation<[Self; PERMUTATION_WIDTH]> + Clone + Send + Sync;
    fn permutation() -> Self::Perm;
    fn round_constants() -> RoundConstants<Self, Self::Poseidon2Config>;
}

impl FieldSpecificPoseidon2Config for KoalaBear {
    type Poseidon2Config = KoalaBearConfig;
    type LinearLayers = GenericPoseidon2LinearLayersKoalaBear;
    type Perm = Poseidon2KoalaBear<PERMUTATION_WIDTH>;
    fn permutation() -> Self::Perm {
        default_koalabear_poseidon2_16()
    }
    fn round_constants() -> RoundConstants<Self, Self::Poseidon2Config> {
        RoundConstants {
            beginning_full_round_constants: Array::from(KOALABEAR_POSEIDON2_RC_16_EXTERNAL_INITIAL),
            partial_round_constants: Array::from(KOALABEAR_POSEIDON2_RC_16_INTERNAL),
            ending_full_round_constants: Array::from(KOALABEAR_POSEIDON2_RC_16_EXTERNAL_FINAL),
        }
    }
}

/// Exact type equality (unlike [`same_field`], which also accepts a field's packed / quintic /
/// symbolic aliases).
pub const fn same_type<T: Any, U: Any>() -> bool {
    // NOTE: removing this unsafe is impossible so we have to allow the warning here
    #[allow(unused_unsafe)]
    const {
        unsafe { std::intrinsics::type_id::<T>() == type_id::<U>() }
    }
}

// Check if the type T is a specified field F.
// NOTE: This function could not work for trait types with `'static`.
pub const fn same_field<T: Any, F: Field + std::cmp::PartialOrd>() -> bool {
    // NOTE: removing this unsafe is impossible so we have to allow the warning here
    #[allow(unused_unsafe)]
    const {
        unsafe {
            let typ = std::intrinsics::type_id::<T>();

            let field = type_id::<F>();
            let packing = type_id::<<F as Field>::Packing>();
            let quintic = type_id::<QuinticTrinomialExtensionField<F>>();
            // The MLE symbolic builder's expression type.
            let mle_expr = type_id::<SymbolicExpression<F>>();

            typ == field || typ == packing || typ == quintic || typ == mle_expr
        }
    }
}
