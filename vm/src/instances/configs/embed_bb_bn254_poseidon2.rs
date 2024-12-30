pub use crate::configs::{field_config::bb_bn254, stark_config::bb_bn254_poseidon2};

pub type StarkConfig = bb_bn254_poseidon2::BabyBearBn254Poseidon2;
pub type FieldConfig = bb_bn254::BabyBearBn254;

pub type SC_ValMmcs = bb_bn254_poseidon2::SC_ValMmcs;
