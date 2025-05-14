mod storage;
mod types;

pub use storage::{InMemStore, TimelineStore};
pub use types::{Stage, Timeline};

pub const COORD_TL_ID: usize = usize::MAX;
