//! The crate's own gates.
//!
//! In-crate rather than under `tests/` on purpose: the comparison against the direct machine path
//! needs the payload a [`crate::Proof`] deliberately does not expose, and the environment contract
//! is a claim about private fields.

#[cfg(feature = "aot")]
mod aot;
mod chain;
mod chunks;
mod committed;
mod coprocessor;
mod emulation_abort;
mod environment;
#[cfg(feature = "multi-field-transcript")]
mod evm;
mod execute;
mod exit_code;
mod fixture;
mod options;
mod poseidon2;
mod precompiles;
mod program_id;
mod scratch;
mod whitelist;
