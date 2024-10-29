use crate::{
    chips::chips::recursion_memory::MemoryRecord, compiler::recursion::instruction::Instruction,
};

use crate::recursion::air::Block;
#[derive(Debug, Clone)]
pub struct CpuEvent<F> {
    pub clk: F,
    pub pc: F,
    pub fp: F,
    pub instruction: Instruction<F>,
    pub a: Block<F>,
    pub a_record: Option<MemoryRecord<F>>,
    pub b: Block<F>,
    pub b_record: Option<MemoryRecord<F>>,
    pub c: Block<F>,
    pub c_record: Option<MemoryRecord<F>>,
    pub memory_record: Option<MemoryRecord<F>>,
}
