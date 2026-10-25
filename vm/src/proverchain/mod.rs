//! Snapshot-based RISC-V emulation pipeline shared by the MLE single-node prover and the AOT
//! tooling. The FRI prover chain that used to live here was removed; see tag `legacy-fri-last`.

pub mod riscv;

pub use riscv::emulate_snapshot_pipeline;
