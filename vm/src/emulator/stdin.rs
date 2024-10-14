use serde::Serialize;

pub struct EmulatorStdin {
    pub buffer: Vec<Vec<u8>>,
    pub cursor: usize,
}

impl EmulatorStdin {
    pub fn default() -> Self {
        Self {
            buffer: Vec::new(),
            cursor: 0,
        }
    }

    pub fn from(data: &[u8]) -> Self {
        Self {
            buffer: vec![data.to_vec()],
            cursor: 0,
        }
    }

    pub fn write<T: Serialize>(&mut self, data: &T) {
        let mut tmp = Vec::new();
        bincode::serialize_into(&mut tmp, data).expect("serialization failed");
        self.buffer.push(tmp);
    }

    pub fn read_slice(&mut self, slice: &mut [u8]) {
        slice.copy_from_slice(&self.buffer[self.cursor]);
        self.cursor += 1;
    }
}
