use crate::configs::stark_config::bb_poseidon2;

/// A configuration for riscv, with BabyBear field and Poseidon2 hash
pub type StarkConfig = bb_poseidon2::BabyBearPoseidon2;
