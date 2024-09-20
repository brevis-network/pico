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
}
