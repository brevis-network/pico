use super::constants::{LOG_PAGE_LEN, PAGE_LEN, PAGE_MASK};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::hash::Hash;

pub trait Addr: Copy + Eq + Hash {
    fn to_usize(self) -> usize;
    fn from_usize(value: usize) -> Self;
}

impl Addr for u32 {
    fn to_usize(self) -> usize {
        self as usize
    }

    fn from_usize(value: usize) -> Self {
        u32::try_from(value).unwrap_or_else(|_| panic!("address index {value} does not fit in u32"))
    }
}

impl Addr for u64 {
    fn to_usize(self) -> usize {
        usize::try_from(self)
            .unwrap_or_else(|_| panic!("address 0x{self:016x} does not fit in usize"))
    }

    fn from_usize(value: usize) -> Self {
        value as u64
    }
}

/// A memory.
///
/// Consists of registers, as well as a page table for main memory.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "A: Serialize, V: Serialize"))]
#[serde(bound(deserialize = "A: DeserializeOwned, V: DeserializeOwned"))]
pub struct Memory<A: Addr, V: Copy + Default> {
    /// The registers.
    pub registers: Registers<V>,
    /// The page table.
    pub page_table: PagedMemory<A, V>,
}

pub type Memory32<V> = Memory<u32, V>;
pub type Memory64<V> = Memory<u64, V>;
pub type PagedMemory32<V> = PagedMemory<u32, V>;
pub type PagedMemory64<V> = PagedMemory<u64, V>;

impl<A: Addr + 'static, V: Copy + Default + 'static> IntoIterator for Memory<A, V> {
    type Item = (A, V);

    type IntoIter = Box<dyn Iterator<Item = Self::Item>>;

    fn into_iter(self) -> Self::IntoIter {
        let reg_iter = self
            .registers
            .into_iter()
            .map(|(addr, value)| (A::from_usize(addr as usize), value));
        Box::new(reg_iter.chain(self.page_table))
    }
}

impl<A: Addr, V: Copy + Default> Default for Memory<A, V> {
    fn default() -> Self {
        Self {
            registers: Registers::default(),
            page_table: PagedMemory::default(),
        }
    }
}

impl<A: Addr, V: Copy + Default> Memory<A, V> {
    /// Initialize a new memory with preallocated page table.
    pub fn new_preallocated() -> Self {
        Self {
            registers: Registers::default(),
            page_table: PagedMemory::new_preallocated(),
        }
    }

    /// Insert a value into the memory.
    ///
    /// When possible, prefer directly accessing the `page_table` or `registers` fields.
    /// This method often incurs unnecessary branching.
    #[inline]
    pub fn insert(&mut self, addr: A, value: V) -> V {
        if addr.to_usize() < 32 {
            self.registers.insert(addr, value)
        } else {
            self.page_table.insert(addr, value)
        }
    }

    /// Get a value from the memory.
    ///
    /// Returns None only if it's a page table address and the page doesn't exist.
    /// When possible, prefer directly accessing the `page_table` or `registers` fields.
    /// This method often incurs unnecessary branching.
    #[inline]
    pub fn get(&self, addr: A) -> Option<&V> {
        if addr.to_usize() < 32 {
            Some(self.registers.get(addr))
        } else {
            self.page_table.get(addr)
        }
    }

    /// Get a mutable reference, creating the page if needed for page table addresses.
    ///
    /// When possible, prefer directly accessing the `page_table` or `registers` fields.
    /// This method often incurs unnecessary branching.
    #[inline]
    pub fn get_mut_or_create(&mut self, addr: A) -> &mut V {
        if addr.to_usize() < 32 {
            self.registers.get_mut(addr)
        } else {
            self.page_table.get_mut_or_create(addr)
        }
    }

    /// Clear the memory.
    #[inline]
    pub fn clear(&mut self) {
        self.registers.clear();
        self.page_table.clear();
    }
}

impl<A: Addr, V: Copy + Default> FromIterator<(A, V)> for Memory<A, V> {
    fn from_iter<T: IntoIterator<Item = (A, V)>>(iter: T) -> Self {
        let mut memory = Self::new_preallocated();
        for (addr, value) in iter {
            memory.insert(addr, value);
        }
        memory
    }
}

/// An array of 32 registers.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "T: Serialize"))]
#[serde(bound(deserialize = "T: DeserializeOwned"))]
pub struct Registers<T: Copy + Default> {
    pub registers: [T; 32],
}

impl<T: Copy + Default> Default for Registers<T> {
    fn default() -> Self {
        Self {
            registers: [T::default(); 32],
        }
    }
}

impl<T: Copy + Default> Registers<T> {
    /// Get a reference to the value at the given address.
    ///
    /// Assumes addr < 32.
    #[inline]
    pub fn get<A: Addr>(&self, addr: A) -> &T {
        &self.registers[addr.to_usize()]
    }

    /// Get a mutable reference to the value at the given address.
    ///
    /// Assumes addr < 32.
    #[inline]
    pub fn get_mut<A: Addr>(&mut self, addr: A) -> &mut T {
        &mut self.registers[addr.to_usize()]
    }

    /// Insert a value into the registers.
    ///
    /// Assumes addr < 32.
    #[inline]
    pub fn insert<A: Addr>(&mut self, addr: A, value: T) -> T {
        std::mem::replace(&mut self.registers[addr.to_usize()], value)
    }

    /// Clear the registers (reset to default).
    #[inline]
    pub fn clear(&mut self) {
        self.registers = [T::default(); 32];
    }
}

impl<V: Copy + Default> FromIterator<(u32, V)> for Registers<V> {
    fn from_iter<T: IntoIterator<Item = (u32, V)>>(iter: T) -> Self {
        let mut mmu = Self::default();
        for (k, v) in iter {
            mmu.insert(k, v);
        }
        mmu
    }
}

impl<V: Copy + Default + 'static> IntoIterator for Registers<V> {
    type Item = (u32, V);

    type IntoIter = Box<dyn Iterator<Item = Self::Item>>;

    fn into_iter(self) -> Self::IntoIter {
        Box::new(
            self.registers
                .into_iter()
                .enumerate()
                .map(|(i, v)| (i as u32, v)),
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "V: Serialize"))]
#[serde(bound(deserialize = "V: DeserializeOwned"))]
pub struct NewPage<V>(Vec<V>);

impl<V: Copy + Default> NewPage<V> {
    pub fn new() -> Self {
        Self(vec![V::default(); PAGE_LEN])
    }
}

impl<V: Copy + Default> Default for NewPage<V> {
    fn default() -> Self {
        Self(Vec::new())
    }
}

/// Paged memory. Balances both memory locality and total memory usage.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "A: Serialize, V: Serialize"))]
#[serde(bound(deserialize = "A: DeserializeOwned, V: DeserializeOwned"))]
pub struct PagedMemory<A: Addr, V: Copy + Default> {
    /// The internal page table.
    pub page_table: Vec<NewPage<V>>,
    pub index: hashbrown::HashMap<usize, u16>,
    #[serde(skip)]
    _marker: core::marker::PhantomData<A>,
}

impl<A: Addr, V: Copy + Default> PagedMemory<A, V> {
    /// The number of lower bits to ignore, since addresses (except registers) are a multiple of 4.
    const NUM_IGNORED_LOWER_BITS: usize = 2;

    /// Create a `PagedMemory`.
    pub fn new_preallocated() -> Self {
        Self {
            page_table: Vec::new(),
            index: hashbrown::HashMap::new(),
            _marker: core::marker::PhantomData,
        }
    }

    /// Get a reference to the memory value at the given address.
    /// Returns None if the page doesn't exist.
    pub fn get(&self, addr: A) -> Option<&V> {
        let (upper, lower) = Self::indices(addr);
        self.index
            .get(&upper)
            .map(|index| &self.page_table[*index as usize].0[lower])
    }

    /// Get a mutable reference to the memory value at the given address.
    /// Returns None if the page doesn't exist.
    pub fn get_mut(&mut self, addr: A) -> Option<&mut V> {
        let (upper, lower) = Self::indices(addr);
        self.index
            .get(&upper)
            .map(|index| &mut self.page_table[*index as usize].0[lower])
    }

    /// Get a mutable reference to the memory value at the given address,
    /// creating the page if it doesn't exist.
    pub fn get_mut_or_create(&mut self, addr: A) -> &mut V {
        let (upper, lower) = Self::indices(addr);
        let mut index = self.index.get(&upper).copied().unwrap_or(u16::MAX);
        if index == u16::MAX {
            index = self.page_table.len() as u16;
            self.index.insert(upper, index);
            self.page_table.push(NewPage::new());
        }
        &mut self.page_table[index as usize].0[lower]
    }

    /// Insert a value at the given address. Returns the previous value.
    pub fn insert(&mut self, addr: A, value: V) -> V {
        let (upper, lower) = Self::indices(addr);
        let mut index = self.index.get(&upper).copied().unwrap_or(u16::MAX);
        if index == u16::MAX {
            index = self.page_table.len() as u16;
            self.index.insert(upper, index);
            self.page_table.push(NewPage::new());
        }
        std::mem::replace(&mut self.page_table[index as usize].0[lower], value)
    }

    /// Returns an iterator over addresses in allocated pages.
    pub fn keys(&self) -> impl Iterator<Item = A> + '_ {
        self.index.iter().flat_map(|(i, index)| {
            let upper = *i << LOG_PAGE_LEN;
            self.page_table[*index as usize]
                .0
                .iter()
                .enumerate()
                .map(move |(lower, _)| Self::decompress_addr(upper + lower))
        })
    }

    /// Get the number of slots in allocated pages.
    pub fn exact_len(&self) -> usize {
        self.index
            .iter()
            .map(|index| self.page_table[*index.1 as usize].0.len())
            .sum()
    }

    /// Estimate the number of addresses in use.
    pub fn estimate_len(&self) -> usize {
        self.index.len() * PAGE_LEN
    }

    /// Clears the page table. Drops all `Page`s, but retains the memory used by the table itself.
    pub fn clear(&mut self) {
        self.page_table.clear();
        self.index.clear();
    }

    /// Break apart an address into an upper and lower index.
    #[inline]
    fn indices(addr: A) -> (usize, usize) {
        let index = Self::compress_addr(addr);
        (index >> LOG_PAGE_LEN, index & PAGE_MASK)
    }

    /// Compress an address from the sparse address space to a contiguous space.
    #[inline]
    fn compress_addr(addr: A) -> usize {
        addr.to_usize() >> Self::NUM_IGNORED_LOWER_BITS
    }

    /// Decompress an address from a contiguous space to the sparse address space.
    #[inline]
    fn decompress_addr(addr: usize) -> A {
        A::from_usize(addr << Self::NUM_IGNORED_LOWER_BITS)
    }
}

impl<A: Addr, V: Copy + Default> Default for PagedMemory<A, V> {
    fn default() -> Self {
        Self {
            page_table: Vec::new(),
            index: hashbrown::HashMap::new(),
            _marker: core::marker::PhantomData,
        }
    }
}

impl<A: Addr, V: Copy + Default> FromIterator<(A, V)> for PagedMemory<A, V> {
    fn from_iter<T: IntoIterator<Item = (A, V)>>(iter: T) -> Self {
        let mut mmu = Self::new_preallocated();
        for (k, v) in iter {
            mmu.insert(k, v);
        }
        mmu
    }
}

impl<A: Addr + 'static, V: Copy + Default + 'static> IntoIterator for PagedMemory<A, V> {
    type Item = (A, V);

    type IntoIter = Box<dyn Iterator<Item = Self::Item>>;

    fn into_iter(mut self) -> Self::IntoIter {
        Box::new(self.index.into_iter().flat_map(move |(i, index)| {
            let upper = i << LOG_PAGE_LEN;
            std::mem::take(&mut self.page_table[index as usize])
                .0
                .into_iter()
                .enumerate()
                .map(move |(lower, v)| (Self::decompress_addr(upper + lower), v))
        }))
    }
}
