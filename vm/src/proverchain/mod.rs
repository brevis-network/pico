//! Snapshot-based RISC-V emulation pipeline: the threaded driver for replaying emulator
//! snapshots. The FRI prover chain that used to live here was removed; see tag
//! `legacy-fri-last`.

pub mod riscv;

pub use riscv::emulate_snapshot_pipeline;
