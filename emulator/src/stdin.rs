use serde::Serialize;

pub struct PicoStdin {
    pub buffer: Vec<Vec<u8>>,
    pub cursor: usize,
}

impl PicoStdin {
    pub fn new() -> Self {
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
}
