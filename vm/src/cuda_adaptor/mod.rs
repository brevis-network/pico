//! GPU resource pools shared by the RISC-V trace generators and the MLE backend.
//!
//! The legacy FRI GPU adaptor that used to live here (FRI commit / open, quotient, transpose,
//! codegen) was removed together with the FRI proving path; see tag `legacy-fri-last`.

pub mod resource_pool;

pub use resource_pool::{
    mem_pool::{create_ctx as create_mem_pool, get_global_mem_pool},
    stream_pool::{
        create_stream, get_global_stream_pool, release_stats, streams_created, SyncStreamPool,
    },
};
