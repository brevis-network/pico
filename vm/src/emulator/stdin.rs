//! Guest-program stdin. `EmulatorStdinBuilder` collects the serialized inputs; the finalized
//! `EmulatorStdin` is what the RISC-V emulators consume. The proof-carrying recursion stdins
//! (convert / deferred / combine) of the removed FRI path lived here too; see tag `legacy-fri-last`.

use crate::configs::config::StarkGenericConfig;
use alloc::sync::Arc;
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "I: Serialize", deserialize = "I: Deserialize<'de>"))]
pub struct EmulatorStdinBuilder<I, SC: StarkGenericConfig> {
    pub buffer: Vec<I>,
    #[serde(skip)]
    _config: PhantomData<SC>,
}

impl<I, SC: StarkGenericConfig> Default for EmulatorStdinBuilder<I, SC> {
    fn default() -> Self {
        Self {
            buffer: Vec::new(),
            _config: PhantomData,
        }
    }
}

#[derive(Default, Serialize, Deserialize)]
pub struct EmulatorStdin<P, I> {
    pub programs: Arc<[P]>,
    pub inputs: Arc<[I]>,
    pub flag_empty: bool,
    pub pointer: usize,
}

impl<P, I> Clone for EmulatorStdin<P, I>
where
    P: Clone,
    I: Clone,
{
    fn clone(&self) -> Self {
        Self {
            programs: self.programs.clone(),
            inputs: self.inputs.clone(),
            flag_empty: self.flag_empty,
            pointer: self.pointer,
        }
    }
}

#[allow(clippy::should_implement_trait)]
impl<P, I> EmulatorStdin<P, I> {
    // get both program and input for emulator
    pub fn get_program_and_input(&self, index: usize) -> (&P, &I, bool) {
        let flag_last = index == self.inputs.len() - 1;

        if index < self.programs.len() && index < self.inputs.len() {
            (&self.programs[index], &self.inputs[index], flag_last)
        } else {
            panic!("EmulatorStdin: out of bounds");
        }
    }

    // get input of the program for emulator
    pub fn get_input(&self, index: usize) -> (&I, bool) {
        let flag_last = index == self.inputs.len() - 1;
        if index < self.inputs.len() {
            (&self.inputs[index], flag_last)
        } else {
            panic!("EmulatorStdin: out of bounds");
        }
    }

    pub fn new_builder<SC>() -> EmulatorStdinBuilder<I, SC>
    where
        I: Default,
        SC: StarkGenericConfig,
    {
        EmulatorStdinBuilder::<I, SC>::default()
    }

    pub fn new_riscv(buf: &[I]) -> Self
    where
        I: Clone,
    {
        Self {
            programs: Arc::new([]),
            inputs: Arc::from(buf),
            flag_empty: false,
            pointer: 0,
        }
    }
}

// for riscv machine stdin
impl<SC: StarkGenericConfig> EmulatorStdinBuilder<Vec<u8>, SC> {
    pub fn write<T: Serialize>(&mut self, data: &T) {
        let mut tmp = Vec::new();
        bincode::serialize_into(&mut tmp, data).expect("serialization failed");
        self.buffer.push(tmp);
    }

    /// Write a slice of bytes to the buffer.
    pub fn write_slice(&mut self, slice: &[u8]) {
        self.buffer.push(slice.to_vec());
    }

    pub fn finalize<P>(self) -> EmulatorStdin<P, Vec<u8>> {
        EmulatorStdin {
            programs: Arc::new([]),
            inputs: self.buffer.into(),
            flag_empty: false,
            pointer: 0,
        }
    }
}
