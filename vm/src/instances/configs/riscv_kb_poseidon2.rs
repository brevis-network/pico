use crate::configs::stark_config::kb_poseidon2;

/// A configuration for riscv, with KoalaBear field and Poseidon2 hash
pub type StarkConfig = kb_poseidon2::KoalaBearPoseidon2;
