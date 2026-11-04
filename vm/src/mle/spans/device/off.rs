//! The device readings with the `stage-ledger` feature off: each hook with its twin's signature in
//! `live` and nothing in its body but the synchronisation a wait stands for.

use std::ffi::c_void;

use cudart::{result::CudaResult, stream::CudaStream};
use pico_gpu_api::step_events::StepEvents;

use super::Readout;

#[must_use = "the chunk's readings stop when the session drops"]
pub struct Session(());

#[inline(always)]
pub fn switched_on() -> bool {
    false
}

#[inline(always)]
pub fn begin(_chunk: u64, _cpu: bool, _device: usize) -> Session {
    Session(())
}

impl Session {
    #[inline(always)]
    pub fn records(&self) -> bool {
        false
    }

    #[inline(always)]
    pub fn finish(self) -> Option<Readout> {
        None
    }
}

#[inline(always)]
#[track_caller]
pub fn wait(stream: &CudaStream) -> CudaResult<()> {
    stream.synchronize()
}

#[inline(always)]
#[track_caller]
pub fn wait_with<T>(sync: impl FnOnce() -> T) -> T {
    sync()
}

#[inline(always)]
#[track_caller]
pub fn final_wait_with<T>(sync: impl FnOnce() -> T) -> T {
    sync()
}

#[must_use = "a bracket times nothing until it is closed"]
pub struct Bracket(());

impl Bracket {
    #[inline(always)]
    pub fn times(&self) -> bool {
        false
    }
}

#[inline(always)]
pub fn start(_stream: &CudaStream) -> Bracket {
    Bracket(())
}

#[inline(always)]
pub fn start_if(_timed: bool, _stream: &CudaStream) -> Bracket {
    Bracket(())
}

#[inline(always)]
pub fn start_on_thread() -> Bracket {
    Bracket(())
}

#[inline(always)]
pub fn copied(
    _bracket: Bracket,
    _stream: &CudaStream,
    _what: &'static str,
    _source: Option<(*const c_void, usize)>,
) {
}

#[inline(always)]
pub fn launched(_bracket: Bracket, _stream: &CudaStream) {}

#[inline(always)]
pub fn launched_step(_bracket: Bracket, _stream: &CudaStream, _step: &'static str) {}

#[inline(always)]
pub fn filled(_bracket: Bracket, _stream: &CudaStream) {}

#[inline(always)]
pub fn transposed_on_thread(_bracket: Bracket) {}

#[inline(always)]
pub fn uploaded_on_thread(_bracket: Bracket) {}

pub struct Steps(());

#[inline(always)]
pub fn steps(_bracket: &Bracket, _names: &'static [&'static str]) -> Steps {
    Steps(())
}

impl Steps {
    /// Null: a launcher handed it records nothing.
    #[inline(always)]
    pub fn ffi(&mut self) -> *mut StepEvents {
        std::ptr::null_mut()
    }
}

#[inline(always)]
pub fn stepped(_steps: Steps, _stream: &CudaStream) {}

#[inline(always)]
pub fn orchestrator_stream(_stream: &CudaStream) {}

#[inline(always)]
pub fn set_chip(_name: impl FnOnce() -> String) {}

#[inline(always)]
pub fn clear_chip() {}
