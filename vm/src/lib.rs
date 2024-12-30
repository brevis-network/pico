// #![deny(warnings)]
#![allow(clippy::needless_range_loop)]
#![allow(clippy::module_inception)]
#![feature(generic_arg_infer)]

extern crate alloc;
extern crate core;

pub mod chips;
pub mod compiler;
pub mod configs;
pub mod emulator;
pub mod instances;
pub mod machine;
pub mod primitives;
pub mod proverchain;
pub mod recursion_v2;
