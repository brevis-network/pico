//use super::{chip::ChipBehavior, folder::DebugConstraintFolder};
//use crate::configs::config::StarkGenericConfig;
//use p3_air::Air;

pub mod constraints;
pub mod lookups;

#[allow(dead_code)]
pub(crate) enum DebuggerMessageLevel {
    Info,
    Debug,
    Error,
}

//pub(crate) trait IncrementalDebugger {
//    fn print_results(&self) -> bool;
//    fn debug<'r, SC, RI, R, C>(&mut self, records: RI)
//    where
//        SC: StarkGenericConfig,
//        C: ChipBehavior<SC::Val> + for<'a> Air<DebugConstraintFolder<'a, SC::Val, SC::Challenge>>,
//        RI: IntoIterator<Item = &'r C::Record>,
//        C::Record: 'r,
//    ;
//}
