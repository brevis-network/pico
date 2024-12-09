#![allow(non_camel_case_types)]

pub mod embed_bb_bn254_poseidon2;
pub mod recur_bb_poseidon2;
pub mod riscv_bb_poseidon2;
pub mod riscv_m31_poseidon2;

// replace the following to change global configurations
pub use embed_bb_bn254_poseidon2 as embed_config;
pub use recur_bb_poseidon2 as recur_config;
pub use riscv_bb_poseidon2 as riscv_config;
pub use riscv_m31_poseidon2 as riscv_m31_config;
