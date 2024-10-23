use crate::configs::stark_config::bb_poseidon2;

/// A configuration for riscv, with BabyBear field and Poseidon2 hash

// Each riscv config mod should have public types with the same names as below.

pub type StarkConfig = bb_poseidon2::BabyBearPoseidon2;
