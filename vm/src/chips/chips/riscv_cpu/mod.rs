use std::marker::PhantomData;

pub mod auipc;
pub mod branch;
pub mod chunk_clk;
pub mod columns;
pub mod constraints;
pub mod ecall;
pub mod event;
pub mod instruction;
pub mod jump;
pub mod opcode_selector;
pub mod opcode_specific;
pub mod public_values;
pub mod register;
pub mod traces;
pub mod utils;

#[derive(Default)]
pub struct CpuChip<F>(PhantomData<F>);
