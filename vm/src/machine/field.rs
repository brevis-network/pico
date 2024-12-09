use p3_baby_bear::BabyBear;
use p3_field::Field;
use p3_mersenne_31::Mersenne31;
use std::any::TypeId;

#[derive(Clone, Debug)]
pub enum FieldType {
    TypeGeneralField,
    TypeBabyBear,
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
            type_id if type_id == TypeId::of::<Mersenne31>() => FieldType::TypeMersenne31,
            _ => FieldType::TypeGeneralField,
        }
    }
}
