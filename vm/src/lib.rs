// lock deny(warnings) behind strict feature
#![cfg_attr(feature = "strict", deny(warnings))]
// allow deprecated dependencies when installs from the git URL
#![allow(deprecated)]
#![allow(clippy::module_inception)]
#![allow(clippy::needless_range_loop)]
#![allow(incomplete_features)]
#![allow(internal_features)]
// allow unused crate::iter::* imports for now until i figure out how to deal with them
#![cfg_attr(all(not(feature = "rayon"), feature = "strict"), allow(unused_imports))]
#![feature(core_intrinsics)]
#![feature(generic_const_items)]
#![feature(const_cmp)]
#![feature(const_trait_impl)]

pub static SHOW_BENCH_TIMER: once_cell::sync::Lazy<bool> = once_cell::sync::Lazy::new(|| {
    std::env::var("BENCH_TIMER")
        .map(|v| v == "1")
        .unwrap_or(false)
});

#[macro_export]
macro_rules! bench_timer {
    ($($arg:tt)*) => {
        if *$crate::SHOW_BENCH_TIMER {
            println!($($arg)*);
        }
    };
}

extern crate alloc;
extern crate core;

pub mod chips;
pub mod compiler;
pub mod configs;
#[cfg(feature = "cuda")]
pub mod cuda_adaptor;
pub mod emulator;
pub mod instances;
pub mod iter;
pub mod machine;
pub mod mle;
pub mod primitives;
pub mod proverchain;
pub mod thread;

/// The contract between the code `pico-aot-codegen` generates and the `pico-aot-runtime` that runs
/// it: the generator writes it into every program, and the runtime refuses a program carrying any
/// other. Bump it whenever generated code has to change for the runtime to run it correctly.
///
/// Here because both crates take this one and neither takes the other: the runtime taking the
/// generator would compile `syn` into every generated crate, and the generator taking the runtime
/// would make every `generate_crates` build compile the runtime. `aot-emulator` is on in every
/// `pico-prover` build regardless, since pure `execute` runs on the runtime. Until an AOT program is
/// registered it changes only what the stage ledger records for the snapshot split.
pub const AOT_CODEGEN_STAMP: u32 = 3;

#[cfg(feature = "tcmalloc")]
#[global_allocator]
static GLOBAL: tcmalloc::TCMalloc = tcmalloc::TCMalloc;

// tcmalloc wins when a workspace build unifies both features (the SDK asks for jemalloc).
#[cfg(all(
    feature = "jemalloc",
    not(feature = "tcmalloc"),
    not(target_env = "msvc")
))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;
