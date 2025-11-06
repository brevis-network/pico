use super::estimator::CycleEstimator;
use hashbrown::HashMap;

// HashMap cannot derive Hash, so this cannot derive Hash
/// This struct contains the emulation report produced after emulation. That is,
/// it will report the total number of guest vm cycles along with any additional
/// information that was requested by the emulator, such as tracking cycle
/// counts when asked.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EmulationReport {
    pub current_cycle: u64,
    pub start_chunk: u32,
    pub done: bool,
    pub cycle_tracker: Option<HashMap<String, Vec<u64>>>,
    pub host_cycle_estimator: Option<Vec<CycleEstimator>>,
}
