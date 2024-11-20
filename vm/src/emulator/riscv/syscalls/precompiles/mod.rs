use crate::emulator::riscv::syscalls::{
    precompiles::{
        keccak256::event::KeccakPermuteEvent,
        sha256::event::{ShaCompressEvent, ShaExtendEvent},
    },
    SyscallCode, SyscallEvent,
};
use hashbrown::HashMap;
use serde::{Deserialize, Serialize};
use strum::IntoEnumIterator;
use strum_macros::EnumIter;

pub mod keccak256;
pub mod sha256;

#[derive(Clone, Debug, Serialize, Deserialize, EnumIter)]
/// Precompile event.  There should be one variant for every precompile syscall.
pub enum PrecompileEvent {
    KeccakPermute(KeccakPermuteEvent),
    /// Sha256 extend precompile event.
    ShaExtend(ShaExtendEvent),
    /// Sha256 compress precompile event.
    ShaCompress(ShaCompressEvent),
}

/// A record of all the precompile events.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrecompileEvents {
    events: HashMap<SyscallCode, Vec<(SyscallEvent, PrecompileEvent)>>,
}

impl Default for PrecompileEvents {
    fn default() -> Self {
        let mut events = HashMap::new();
        for syscall_code in SyscallCode::iter() {
            if syscall_code.should_send() == 1 {
                events.insert(syscall_code, Vec::new());
            }
        }

        Self { events }
    }
}

impl PrecompileEvents {
    #[allow(dead_code)]
    pub(crate) fn append(&mut self, other: &mut PrecompileEvents) {
        for (syscall, events) in other.events.iter_mut() {
            if !events.is_empty() {
                self.events.entry(*syscall).or_default().append(events);
            }
        }
    }

    #[inline]
    /// Add a precompile event for a given syscall code.
    pub(crate) fn add_event(
        &mut self,
        syscall_code: SyscallCode,
        syscall_event: SyscallEvent,
        event: PrecompileEvent,
    ) {
        assert!(syscall_code.should_send() == 1);
        self.events
            .entry(syscall_code)
            .or_default()
            .push((syscall_event, event));
    }

    /// Checks if the precompile events are empty.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Get all the precompile events.
    pub fn all_events(&self) -> impl Iterator<Item = &(SyscallEvent, PrecompileEvent)> {
        self.events.values().flatten()
    }

    #[allow(dead_code)]
    #[inline]
    /// Insert a vector of precompile events for a given syscall code.
    pub(crate) fn insert(
        &mut self,
        syscall_code: SyscallCode,
        events: Vec<(SyscallEvent, PrecompileEvent)>,
    ) {
        assert!(syscall_code.should_send() == 1);
        self.events.insert(syscall_code, events);
    }

    /// Get the number of precompile events.
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.events.len()
    }

    #[allow(dead_code)]
    #[inline]
    pub(crate) fn into_iter(
        self,
    ) -> impl Iterator<Item = (SyscallCode, Vec<(SyscallEvent, PrecompileEvent)>)> {
        self.events.into_iter()
    }

    #[allow(dead_code)]
    #[inline]
    pub(crate) fn iter(
        &self,
    ) -> impl Iterator<Item = (&SyscallCode, &Vec<(SyscallEvent, PrecompileEvent)>)> {
        self.events.iter()
    }

    /// Get all the precompile events for a given syscall code.
    #[inline]
    #[must_use]
    pub fn get_events(
        &self,
        syscall_code: SyscallCode,
    ) -> Option<&Vec<(SyscallEvent, PrecompileEvent)>> {
        assert!(syscall_code.should_send() == 1);
        self.events.get(&syscall_code)
    }
}
