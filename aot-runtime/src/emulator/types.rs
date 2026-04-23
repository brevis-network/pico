/// Minimal register metadata needed for snapshot compatibility.
#[derive(Debug, Copy, Clone, Default)]
pub struct RegisterRecord {
    pub chunk: u32,
    pub timestamp: u32,
}
