// lock deny(warnings) behind strict feature
#![cfg_attr(feature = "strict", deny(warnings))]
#![allow(clippy::module_inception)]
#![allow(clippy::needless_range_loop)]
#![allow(incomplete_features)]
#![allow(internal_features)]
// allow unused crate::iter::* imports for now until i figure out how to deal with them
#![cfg_attr(all(not(feature = "rayon"), feature = "strict"), allow(unused_imports))]
#![feature(const_type_id)]
#![feature(core_intrinsics)]
#![feature(generic_const_items)]
#![feature(const_cmp)]
#![feature(const_trait_impl)]

extern crate alloc;
extern crate core;

pub mod chips;
pub mod compiler;
pub mod configs;
pub mod emulator;
pub mod instances;
pub mod iter;
pub mod machine;
pub mod primitives;
pub mod proverchain;

#[cfg(all(feature = "jemalloc", not(target_env = "msvc")))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;
