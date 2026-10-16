use super::permute::STATE_NUM_WORDS;
use crate::{
    chips::chips::riscv_memory::event::{MemoryLocalEvent, MemoryReadRecord, MemoryWriteRecord},
    emulator::riscv::event_types::{RvAddr, RvChunk, RvClk, RvValue},
};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

pub(crate) const STATE_SIZE: usize = 25;

/// Keccak-256 Permutation Event.
///
/// This event is emitted when a keccak-256 permutation operation is performed.
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct KeccakPermuteEvent {
    /// The chunk number.
    pub chunk: RvChunk,
    /// The clock cycle.
    pub clk: RvClk,
    /// The pre-state as a list of u64 words.
    pub pre_state: [RvValue; STATE_SIZE],
    /// The post-state as a list of u64 words.
    pub post_state: [RvValue; STATE_SIZE],
    /// The memory records for the pre-state.
    pub state_read_records: Vec<MemoryReadRecord>,
    /// The memory records for the post-state.
    pub state_write_records: Vec<MemoryWriteRecord>,
    /// The address of the state.
    pub state_addr: RvAddr,
    /// The local memory access records.
    pub local_mem_access: Vec<MemoryLocalEvent>,
}

#[serde_as]
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[repr(C)]
pub struct FFIKeccakPermuteEvent {
    pub chunk: u32,
    pub clk: u32,
    pub pre_state: [u64; STATE_SIZE],
    pub post_state: [u64; STATE_SIZE],
    #[serde_as(as = "[_; STATE_NUM_WORDS]")]
    pub state_read_records: [MemoryReadRecord; STATE_NUM_WORDS],
    #[serde_as(as = "[_; STATE_NUM_WORDS]")]
    pub state_write_records: [MemoryWriteRecord; STATE_NUM_WORDS],
    pub state_addr: u32,
}

impl From<KeccakPermuteEvent> for FFIKeccakPermuteEvent {
    fn from(event: KeccakPermuteEvent) -> Self {
        Self {
            chunk: event.chunk,
            clk: event.clk.try_into().unwrap(),
            pre_state: event.pre_state,
            post_state: event.post_state,
            state_read_records: event
                .state_read_records
                .try_into()
                .expect("state_read_records len not 50"),
            state_write_records: event
                .state_write_records
                .try_into()
                .expect("state_write_records len not 50"),
            state_addr: event.state_addr.try_into().unwrap(),
        }
    }
}

impl From<&KeccakPermuteEvent> for FFIKeccakPermuteEvent {
    fn from(event: &KeccakPermuteEvent) -> Self {
        Self {
            chunk: event.chunk,
            clk: event.clk.try_into().unwrap(),
            pre_state: event.pre_state,
            post_state: event.post_state,
            state_read_records: event
                .state_read_records
                .clone()
                .try_into()
                .expect("state_read_records len not 50"),
            state_write_records: event
                .state_write_records
                .clone()
                .try_into()
                .expect("state_write_records len not 50"),
            state_addr: event.state_addr.try_into().unwrap(),
        }
    }
}
