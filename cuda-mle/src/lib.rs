// Each allow below is named lint debt, scoped to the files listed; do NOT reintroduce blanket
// allow(warnings)/allow(clippy::all).
#![cfg_attr(feature = "strict", deny(warnings))]
#![allow(unused_variables)] // logup_zerocheck/mod.rs
#![allow(unused_unsafe)] // logup_zerocheck/{mle_round,round0}.rs, ntt_field.rs, whir.rs
#![allow(unused_imports)] // logup_zerocheck/*, cuda/*, poly.rs
#![allow(private_interfaces)] // cuda/field_kernels.rs vs stacked_reduction::UnstackedSlice
#![allow(clippy::duplicated_attributes)] // cuda/*_kb.rs cfg dup'd from cuda/mod.rs
#![allow(clippy::assign_op_pattern)] // logup_zerocheck/{fractional,round0,mod}.rs
#![allow(clippy::type_complexity)] // logup_zerocheck/{fractional,gkr_input}.rs
#![allow(clippy::unnecessary_cast)] // logup_zerocheck/gkr_input.rs
#![allow(clippy::too_many_arguments)] // logup_zerocheck/round0.rs
#![allow(clippy::needless_range_loop)] // logup_zerocheck/mod.rs
#![allow(clippy::missing_transmute_annotations)] // cuda/field_kernels.rs
#![allow(clippy::manual_div_ceil)] // ntt_field.rs
#![allow(clippy::map_identity)] // ntt_field.rs
#![allow(clippy::redundant_closure)] // whir.rs

pub mod air_times;
pub mod base;
pub mod breakdown;
pub mod nvtx;
/// The CUDA runtime layer — the crate's host/device boundary (see the module docs).
pub mod runtime;
pub mod scratch;

/// Thread-local proving-phase tag. The STEP_PROF / RS_PROF bench timers fire inside the
/// shared `prove` path for every proof (riscv / convert / combine), so they need a phase label
/// to be attributable in a single-node pipeline run. The vm layer sets this on the prove thread
/// before calling `engine.prove`; the timer lines prepend `prove_phase()`.
pub mod prove_phase {
    use std::cell::Cell;

    thread_local! {
        static PHASE: Cell<&'static str> = const { Cell::new("riscv") };
    }

    /// Set the proving phase for the current thread (e.g. "riscv", "convert", "combine").
    pub fn set_prove_phase(p: &'static str) {
        PHASE.with(|c| c.set(p));
    }

    /// Current proving phase tag for the current thread.
    pub fn prove_phase() -> &'static str {
        PHASE.with(|c| c.get())
    }
}
pub use prove_phase::{prove_phase, set_prove_phase};

/// The streaming column-block RS gate, read once per process. The commit side
/// (`stacked_pcs::stacked_commit`) and the opening side (`whir::prove_whir_opening_gpu`) are two
/// halves of the same gate, so they must agree on it — hence one definition here rather than an
/// `env::var` parse at each site.
pub mod rs_stream {
    use std::sync::OnceLock;

    /// The default block count.
    pub const DEFAULT_BLOCKS: usize = 8;

    /// Column blocks the RS codeword matrix is encoded in, so its peak GPU allocation is about
    /// one block. [`DEFAULT_BLOCKS`] unless `RS_STREAM_BLOCKS` sets a count; `0` or empty selects
    /// the whole-matrix path, which a 2^23 chunk does not fit on a 32 GB card. Streaming keeps no
    /// codeword, so `cache_rs_code_matrix` has no effect while it is on.
    pub fn blocks() -> Option<usize> {
        static BLOCKS: OnceLock<Option<usize>> = OnceLock::new();
        *BLOCKS.get_or_init(|| parse_blocks(std::env::var("RS_STREAM_BLOCKS").ok().as_deref()))
    }

    /// [`blocks`] for a given `RS_STREAM_BLOCKS` value; a value that is not a count keeps the
    /// default, with a warning.
    fn parse_blocks(value: Option<&str>) -> Option<usize> {
        let Some(value) = value.map(str::trim) else {
            return Some(DEFAULT_BLOCKS);
        };
        if value.is_empty() {
            return None;
        }
        match value.parse::<usize>() {
            Ok(0) => None,
            Ok(n) => Some(n),
            Err(_) => {
                tracing::warn!("RS_STREAM_BLOCKS={value:?} is not a count; using {DEFAULT_BLOCKS}");
                Some(DEFAULT_BLOCKS)
            }
        }
    }

    /// `RS_STREAM_VERIFY=1`: re-derive through the monolithic path and assert the results match
    /// bit-exactly. Debug-only; doubles the work.
    pub fn verify() -> bool {
        static VERIFY: OnceLock<bool> = OnceLock::new();
        *VERIFY.get_or_init(|| crate::cuda::jit::env_flag("RS_STREAM_VERIFY", false))
    }

    #[cfg(test)]
    mod tests {
        use super::{parse_blocks, DEFAULT_BLOCKS};

        #[test]
        fn streams_by_default() {
            assert_eq!(parse_blocks(None), Some(DEFAULT_BLOCKS));
            assert_eq!(parse_blocks(Some("4")), Some(4));
            assert_eq!(parse_blocks(Some("0")), None);
            assert_eq!(parse_blocks(Some("")), None);
            assert_eq!(parse_blocks(Some("00")), None);
            assert_eq!(parse_blocks(Some("x")), Some(DEFAULT_BLOCKS));
        }
    }
}

pub mod data_transporter;
pub use data_transporter::transport_row_major_ctx_to_device;
pub mod hash_scheme;
pub mod logup_zerocheck;
pub mod merkle_tree;
pub mod monomial;
pub mod ntt_field;
pub mod poly;
pub mod sponge;
pub mod stacked_pcs;
pub mod stacked_reduction;
pub mod utils;
pub mod whir;

/// Extern declarations of the kernel launchers plus thin Rust wrappers around them.
pub(crate) mod cuda;
mod device;
mod engine;
mod error;
mod gpu_backend;
mod pkey;
mod types;
pub use cuda::{field_kernels::FieldKernels, jit::jit_cache_len, matrix::matrix_transpose_fp_any};
pub use device::*;
pub use engine::*;
pub use error::*;
pub use gpu_backend::*;
pub use hash_scheme::*;
pub use pkey::*;

mod kb_arithmetic_test;
#[cfg(test)]
mod tests;

pub mod prelude {
    pub use crate::types::*;
}
