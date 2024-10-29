use crate::chips::chips::recursion_memory::MemoryRecord;

#[derive(Debug, Clone)]
pub struct FriFoldEvent<F> {
    pub clk: F,
    pub m: F,
    pub input_ptr: F,
    pub is_last_iteration: F,

    pub z: MemoryRecord<F>,
    pub alpha: MemoryRecord<F>,
    pub x: MemoryRecord<F>,
    pub log_height: MemoryRecord<F>,
    pub mat_opening_ptr: MemoryRecord<F>,
    pub ps_at_z_ptr: MemoryRecord<F>,
    pub alpha_pow_ptr: MemoryRecord<F>,
    pub ro_ptr: MemoryRecord<F>,

    pub p_at_x: MemoryRecord<F>,
    pub p_at_z: MemoryRecord<F>,

    pub alpha_pow_at_log_height: MemoryRecord<F>,
    pub ro_at_log_height: MemoryRecord<F>,
}
