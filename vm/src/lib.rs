#![deny(warnings)]
#![allow(clippy::module_inception)]
#![allow(clippy::needless_range_loop)]
#![allow(incomplete_features)]
#![allow(internal_features)]
#![allow(unused_unsafe)]
#![feature(const_type_id)]
#![feature(core_intrinsics)]
#![feature(generic_arg_infer)]
#![feature(generic_const_items)]

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
