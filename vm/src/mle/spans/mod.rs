//! Where the pipeline's wall clock went, lane by lane.
//!
//! [`record`] captures it while a run happens; [`report`] derives figures from what was captured. The
//! split is by direction, not by subject — hence one module with two halves rather than two modules.
//!
//! Vocabulary (lane, busy, idle, wait, occupancy) is defined in the project glossary, not restated here.

pub mod record;
pub mod report;

// Re-exported so callers say `spans::busy(..)` and `spans::Role` rather than naming the half they came
// from: the recording API is the module's surface, and which file it lives in is not the caller's
// business. Glob rather than a list, so adding a type does not need an edit here to be reachable.
pub use record::*;
