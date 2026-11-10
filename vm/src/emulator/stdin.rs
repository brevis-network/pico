//! Guest-program stdin. `EmulatorStdinBuilder` collects the serialized inputs; the finalized
//! `EmulatorStdin` is what the RISC-V emulators consume. The proof-carrying recursion stdins
//! (convert / deferred / combine) of the removed FRI path lived here too; see tag `legacy-fri-last`.

use crate::configs::config::StarkGenericConfig;
use alloc::sync::Arc;
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;

#[derive(Clone, Serialize, Deserialize)]
pub struct EmulatorStdinBuilder<SC: StarkGenericConfig> {
    pub buffer: Vec<Vec<u8>>,
    #[serde(skip)]
    _config: PhantomData<SC>,
}

impl<SC: StarkGenericConfig> Default for EmulatorStdinBuilder<SC> {
    fn default() -> Self {
        Self {
            buffer: Vec::new(),
            _config: PhantomData,
        }
    }
}

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct EmulatorStdin {
    pub inputs: Arc<[Vec<u8>]>,
}

impl EmulatorStdin {
    pub fn new_builder<SC>() -> EmulatorStdinBuilder<SC>
    where
        SC: StarkGenericConfig,
    {
        EmulatorStdinBuilder::<SC>::default()
    }
}

impl<SC: StarkGenericConfig> EmulatorStdinBuilder<SC> {
    pub fn write<T: Serialize>(&mut self, data: &T) {
        let mut tmp = Vec::new();
        bincode::serialize_into(&mut tmp, data).expect("serialization failed");
        self.buffer.push(tmp);
    }

    pub fn write_slice(&mut self, slice: &[u8]) {
        self.buffer.push(slice.to_vec());
    }

    pub fn finalize(self) -> EmulatorStdin {
        EmulatorStdin {
            inputs: self.buffer.into(),
        }
    }
}
