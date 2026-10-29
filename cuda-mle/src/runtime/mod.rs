//! The CUDA runtime layer: the host/device boundary, covering device-context lifecycle,
//! streams and events, host↔device memcpy, the crate's CUDA/memory error vocabulary, RAII
//! device buffers, and the per-device memory pool.

pub mod context;
pub mod copy;
pub mod d_buffer;
pub mod error;
pub mod memory_manager;
pub mod stream;
