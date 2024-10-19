#![allow(clippy::type_complexity)]
#![allow(clippy::needless_range_loop)]
pub mod asm;
pub mod instruction;
pub mod ir;
pub mod opcode;
pub mod program;
pub mod program_builder;

pub mod prelude {
    pub use crate::compiler::recursion::ir::*;
    pub use pico_derive::DslVariable;
}
extern crate alloc;
