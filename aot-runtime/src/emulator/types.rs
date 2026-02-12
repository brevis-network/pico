/// Minimal register metadata needed for snapshot compatibility.
#[derive(Debug, Copy, Clone, Default)]
pub struct RegisterRecord {
    pub chunk: u32,
    pub timestamp: u32,
}

/// Bitset for chunk split tracking.
#[derive(Debug, Clone)]
pub struct SimpleBitSet {
    words: Vec<u64>,
    unique_count: usize,
}

impl SimpleBitSet {
    pub fn new() -> Self {
        Self {
            words: vec![0u64; 2 * 512 * 1024], // 32MB bit space
            unique_count: 0,
        }
    }

    #[inline(always)]
    pub fn insert(&mut self, addr: u32) -> bool {
        let bit_index = addr as usize;
        let word_index = bit_index >> 6;
        let bit_offset = bit_index & 63;

        if word_index >= self.words.len() {
            self.expand_to(word_index);
        }

        let mask = 1u64 << bit_offset;
        let word = &mut self.words[word_index];
        if (*word & mask) == 0 {
            *word |= mask;
            self.unique_count += 1;
            true
        } else {
            false
        }
    }

    #[inline(always)]
    pub fn unique_count(&self) -> usize {
        self.unique_count
    }

    pub fn clear(&mut self) {
        if self.unique_count > 0 {
            self.words.fill(0);
            self.unique_count = 0;
        }
    }

    #[cold]
    fn expand_to(&mut self, needed_word_index: usize) {
        let new_size = (needed_word_index + 1).next_power_of_two();
        let max_size = (u32::MAX as usize + 64) / 64;
        let final_size = new_size.min(max_size);
        self.words.resize(final_size, 0);
    }
}

impl Default for SimpleBitSet {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Default)]
pub struct ChunkSplitState {
    pub num_syscall_events: usize,
    pub num_syscall_memory_events: usize,
    pub num_memory_read_write_events: usize,
    memory_access_addrs: SimpleBitSet,
    reg_write_mask: u32,
    unique_reg_writes: usize,
    syscall_depth: u32,
}

impl ChunkSplitState {
    #[inline(always)]
    pub fn num_global_lookup_events(&self) -> usize {
        (self.num_syscall_events
            + self.num_syscall_memory_events
            + self.memory_access_addrs.unique_count()
            + self.unique_reg_writes)
            << 1
    }

    #[inline(always)]
    pub fn insert_memory_address(&mut self, addr: u32) {
        if addr < 32 {
            let bit = 1u32 << addr;
            if (self.reg_write_mask & bit) == 0 {
                self.reg_write_mask |= bit;
                self.unique_reg_writes += 1;
            }
        } else {
            self.memory_access_addrs.insert(addr);
        }
    }

    #[inline(always)]
    pub fn unique_address_count(&self) -> usize {
        self.memory_access_addrs.unique_count() + self.unique_reg_writes
    }

    #[inline(always)]
    pub fn enter_syscall(&mut self) {
        self.syscall_depth = self.syscall_depth.wrapping_add(1);
    }

    #[inline(always)]
    pub fn exit_syscall(&mut self) {
        self.syscall_depth = self.syscall_depth.wrapping_sub(1);
    }

    #[inline(always)]
    pub fn in_syscall(&self) -> bool {
        self.syscall_depth > 0
    }

    pub fn clear(&mut self) {
        self.num_syscall_events = 0;
        self.num_syscall_memory_events = 0;
        self.num_memory_read_write_events = 0;
        self.reg_write_mask = 0;
        self.unique_reg_writes = 0;
        self.memory_access_addrs.clear();
    }
}
