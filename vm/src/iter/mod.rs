// Traits that hides the compile time selection of rayon or Rust single-threaded
// iterators

#[cfg(feature = "rayon")]
mod rayon;
#[cfg(feature = "rayon")]
pub use rayon::*;

#[cfg(not(feature = "rayon"))]
mod single;
#[cfg(not(feature = "rayon"))]
pub use single::*;
