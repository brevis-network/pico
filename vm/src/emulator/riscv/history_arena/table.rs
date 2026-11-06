//! One table of a history: rows go into the table's region of a pinned slot until the region is
//! full, then the table moves to a heap allocation that grows, so a chunk past a table's capacity
//! costs a copy and never a row. A table built from rows, cloned, or written by a history that took
//! no slot lives on the heap from the start. No write lands outside a region or a vector's own
//! length.
//!
//! A table in a slot holds the slot: the slot goes back once every table in it has dropped, so a
//! table moved out of its history keeps its rows readable for as long as it lives.

use std::{
    fmt,
    ops::{Deref, DerefMut},
    ptr::NonNull,
    sync::{atomic::Ordering, Arc},
};

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::{capacity::Table, SlotLease};

/// What a table does with a row its region has no room for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpillPolicy {
    /// Move the table to the heap and keep writing.
    Spill,
    /// Refuse the row: the write fails, and the writer must stop.
    Refuse,
}

/// A row refused by [`SpillPolicy::Refuse`]: `table` holds `capacity` rows and was asked for
/// `needed`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TableFull {
    pub table: Table,
    pub capacity: usize,
    pub needed: usize,
}

impl fmt::Display for TableFull {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "history table {} is full at {} rows and was asked for {}, with spilling refused",
            self.table.name(),
            self.capacity,
            self.needed
        )
    }
}

impl std::error::Error for TableFull {}

/// `len` rows at `base`, which has room for `capacity`.
struct Region<T> {
    base: NonNull<T>,
    len: usize,
    capacity: usize,
    table: Table,
    policy: SpillPolicy,
    /// The slot the region lies in; `None` for a region the caller of [`Rows::resident`] owns.
    slot: Option<Arc<SlotLease>>,
}

enum Storage<T> {
    Resident(Region<T>),
    /// Rows that outgrew their region.
    Spilled(Vec<T>),
    /// Rows that never had a region.
    Heap(Vec<T>),
}

/// One table's rows, wherever they are stored. Reads go through the slice it dereferences to;
/// writes go through its own methods, which spill a full region rather than write past it.
pub struct Rows<T: Copy> {
    storage: Storage<T>,
}

// SAFETY: a resident table's region belongs to this table alone (`resident`'s contract), its rows
// are plain `Copy` data, and the slot it holds is `Send + Sync`, so the table moves and shares as a
// `Vec<T>` does.
unsafe impl<T: Copy + Send> Send for Rows<T> {}
unsafe impl<T: Copy + Sync> Sync for Rows<T> {}

impl<T: Copy> Rows<T> {
    /// An empty table on the heap.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            storage: Storage::Heap(Vec::new()),
        }
    }

    /// An empty table writing into the region at `base`, which has room for `capacity` rows, as
    /// `policy` says once it is full. `slot` is held for as long as the table is.
    ///
    /// # Safety
    ///
    /// `base` is aligned for `T` and valid for reads and writes of `capacity` rows for as long as
    /// the table lives (for as long as `slot` is held, when there is one), and nothing else reads
    /// or writes the region meanwhile.
    pub(super) unsafe fn resident(
        table: Table,
        base: NonNull<T>,
        capacity: usize,
        policy: SpillPolicy,
        slot: Option<Arc<SlotLease>>,
    ) -> Self {
        Self {
            storage: Storage::Resident(Region {
                base,
                len: 0,
                capacity,
                table,
                policy,
                slot,
            }),
        }
    }

    #[must_use]
    pub fn as_slice(&self) -> &[T] {
        match &self.storage {
            // SAFETY: the first `len` rows of the region were written by this table.
            Storage::Resident(region) => unsafe {
                std::slice::from_raw_parts(region.base.as_ptr(), region.len)
            },
            Storage::Spilled(rows) | Storage::Heap(rows) => rows,
        }
    }

    #[must_use]
    pub fn as_mut_slice(&mut self) -> &mut [T] {
        match &mut self.storage {
            // SAFETY: as in `as_slice`, and the region is written through this table alone.
            Storage::Resident(region) => unsafe {
                std::slice::from_raw_parts_mut(region.base.as_ptr(), region.len)
            },
            Storage::Spilled(rows) | Storage::Heap(rows) => rows,
        }
    }

    #[must_use]
    #[inline]
    pub fn len(&self) -> usize {
        match &self.storage {
            Storage::Resident(region) => region.len,
            Storage::Spilled(rows) | Storage::Heap(rows) => rows.len(),
        }
    }

    #[must_use]
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Whether the rows are in a slot's region, and so in pinned memory.
    #[must_use]
    pub const fn is_resident(&self) -> bool {
        matches!(self.storage, Storage::Resident(_))
    }

    /// Whether the table outgrew its region.
    #[must_use]
    pub const fn is_spilled(&self) -> bool {
        matches!(self.storage, Storage::Spilled(_))
    }

    /// The slot the table's region lies in.
    pub(super) fn slot(&self) -> Option<&Arc<SlotLease>> {
        match &self.storage {
            Storage::Resident(region) => region.slot.as_ref(),
            Storage::Spilled(_) | Storage::Heap(_) => None,
        }
    }

    /// The rows the table has room for before its next move.
    #[must_use]
    pub fn capacity(&self) -> usize {
        match &self.storage {
            Storage::Resident(region) => region.capacity,
            Storage::Spilled(rows) | Storage::Heap(rows) => rows.capacity(),
        }
    }

    /// Grows a heap table's allocation. A region's room is fixed, so it is left as it is and a row
    /// past it spills or is refused when written. Writes and moves no row either way.
    #[inline]
    pub fn reserve(&mut self, additional: usize) {
        match &mut self.storage {
            Storage::Resident(_) => {}
            Storage::Spilled(rows) | Storage::Heap(rows) => rows.reserve(additional),
        }
    }

    /// Appends `row`.
    ///
    /// # Panics
    ///
    /// When the region is full and its spilling refused, at that row.
    #[inline]
    pub fn push(&mut self, row: T) {
        match &mut self.storage {
            Storage::Resident(region) => {
                if region.len < region.capacity {
                    // SAFETY: row `len` lies inside the region (`resident`'s contract).
                    unsafe { region.base.as_ptr().add(region.len).write(row) };
                    region.len += 1;
                    return;
                }
            }
            Storage::Spilled(rows) | Storage::Heap(rows) => {
                rows.push(row);
                return;
            }
        }
        self.spill_and_push(row);
    }

    #[cold]
    #[inline(never)]
    fn spill_and_push(&mut self, row: T) {
        self.try_extend_from_slice(std::slice::from_ref(&row))
            .unwrap_or_else(|full| panic!("{full}"));
    }

    /// Appends `rows`. `Ok(true)` when this write moved the table out of its region; on `Err`
    /// nothing was written.
    pub fn try_extend_from_slice(&mut self, rows: &[T]) -> Result<bool, TableFull> {
        let region = match &mut self.storage {
            Storage::Resident(region) => region,
            Storage::Spilled(heap) | Storage::Heap(heap) => {
                heap.extend_from_slice(rows);
                return Ok(false);
            }
        };
        let needed = region.len.checked_add(rows.len()).ok_or(TableFull {
            table: region.table,
            capacity: region.capacity,
            needed: usize::MAX,
        })?;
        if needed <= region.capacity {
            // SAFETY: rows `len..needed` lie inside the region (`resident`'s contract), which
            // `rows`, a borrow from outside the table's own storage, does not overlap.
            unsafe {
                std::ptr::copy_nonoverlapping(
                    rows.as_ptr(),
                    region.base.as_ptr().add(region.len),
                    rows.len(),
                );
            }
            region.len = needed;
            return Ok(false);
        }
        if region.policy == SpillPolicy::Refuse {
            return Err(TableFull {
                table: region.table,
                capacity: region.capacity,
                needed,
            });
        }
        // SAFETY: as in `as_slice`.
        let written = unsafe { std::slice::from_raw_parts(region.base.as_ptr(), region.len) };
        let mut heap = Vec::with_capacity(needed.max(region.capacity.saturating_mul(2)));
        heap.extend_from_slice(written);
        heap.extend_from_slice(rows);
        if let Some(slot) = &region.slot {
            slot.counters.spills[region.table.index()].fetch_add(1, Ordering::Relaxed);
        }
        tracing::warn!(
            table = region.table.name(),
            rows = heap.len(),
            "a history table outgrew its arena region and spilled to the heap"
        );
        // The region's slot is let go here; the history's other tables still hold it.
        self.storage = Storage::Spilled(heap);
        Ok(true)
    }

    /// Appends `rows`.
    ///
    /// # Panics
    ///
    /// When they overfill the region and its spilling is refused, before any is written.
    pub fn extend_from_slice(&mut self, rows: &[T]) {
        self.try_extend_from_slice(rows)
            .unwrap_or_else(|full| panic!("{full}"));
    }

    /// Moves every row of `other` to the end of this table, leaving `other` empty.
    pub fn append(&mut self, other: &mut Self) {
        self.extend_from_slice(other);
        other.clear();
    }

    pub fn pop(&mut self) -> Option<T> {
        match &mut self.storage {
            Storage::Resident(region) => {
                let last = region.len.checked_sub(1)?;
                region.len = last;
                // SAFETY: row `last` was written by this table.
                Some(unsafe { region.base.as_ptr().add(last).read() })
            }
            Storage::Spilled(rows) | Storage::Heap(rows) => rows.pop(),
        }
    }

    /// Drops the rows from `len` on; a region keeps its room and its slot.
    pub fn truncate(&mut self, len: usize) {
        match &mut self.storage {
            Storage::Resident(region) => region.len = region.len.min(len),
            Storage::Spilled(rows) | Storage::Heap(rows) => rows.truncate(len),
        }
    }

    pub fn clear(&mut self) {
        self.truncate(0);
    }

    /// The rows as a vector of their own.
    #[must_use]
    pub fn into_vec(self) -> Vec<T> {
        match self.storage {
            Storage::Spilled(rows) | Storage::Heap(rows) => rows,
            // SAFETY: as in `as_slice`; the region's slot is held until the copy is made.
            Storage::Resident(region) => {
                unsafe { std::slice::from_raw_parts(region.base.as_ptr(), region.len) }.to_vec()
            }
        }
    }
}

impl<T: Copy> Default for Rows<T> {
    fn default() -> Self {
        Self::new()
    }
}

/// A heap copy, holding no slot: a clone can never wait on an empty arena or return a slot twice.
impl<T: Copy> Clone for Rows<T> {
    fn clone(&self) -> Self {
        self.as_slice().to_vec().into()
    }
}

impl<T: Copy> Deref for Rows<T> {
    type Target = [T];

    fn deref(&self) -> &[T] {
        self.as_slice()
    }
}

impl<T: Copy> DerefMut for Rows<T> {
    fn deref_mut(&mut self) -> &mut [T] {
        self.as_mut_slice()
    }
}

impl<T: Copy + fmt::Debug> fmt::Debug for Rows<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self.as_slice(), f)
    }
}

impl<T: Copy> From<Vec<T>> for Rows<T> {
    fn from(rows: Vec<T>) -> Self {
        Self {
            storage: Storage::Heap(rows),
        }
    }
}

impl<T: Copy> From<&[T]> for Rows<T> {
    fn from(rows: &[T]) -> Self {
        rows.to_vec().into()
    }
}

impl<T: Copy, const N: usize> From<[T; N]> for Rows<T> {
    fn from(rows: [T; N]) -> Self {
        Vec::from(rows).into()
    }
}

impl<T: Copy> FromIterator<T> for Rows<T> {
    fn from_iter<I: IntoIterator<Item = T>>(rows: I) -> Self {
        rows.into_iter().collect::<Vec<T>>().into()
    }
}

impl<T: Copy> Extend<T> for Rows<T> {
    fn extend<I: IntoIterator<Item = T>>(&mut self, rows: I) {
        if let Storage::Spilled(heap) | Storage::Heap(heap) = &mut self.storage {
            heap.extend(rows);
            return;
        }
        for row in rows {
            self.push(row);
        }
    }
}

impl<'a, T: Copy + 'a> Extend<&'a T> for Rows<T> {
    fn extend<I: IntoIterator<Item = &'a T>>(&mut self, rows: I) {
        self.extend(rows.into_iter().copied());
    }
}

impl<T: Copy> IntoIterator for Rows<T> {
    type Item = T;
    type IntoIter = std::vec::IntoIter<T>;

    fn into_iter(self) -> Self::IntoIter {
        self.into_vec().into_iter()
    }
}

impl<'a, T: Copy> IntoIterator for &'a Rows<T> {
    type Item = &'a T;
    type IntoIter = std::slice::Iter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.as_slice().iter()
    }
}

impl<'a, T: Copy> IntoIterator for &'a mut Rows<T> {
    type Item = &'a mut T;
    type IntoIter = std::slice::IterMut<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.as_mut_slice().iter_mut()
    }
}

impl<T: Copy + PartialEq<U>, U: Copy> PartialEq<Rows<U>> for Rows<T> {
    fn eq(&self, other: &Rows<U>) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl<T: Copy + Eq> Eq for Rows<T> {}

impl<T: Copy + PartialEq<U>, U> PartialEq<Vec<U>> for Rows<T> {
    fn eq(&self, other: &Vec<U>) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl<T: PartialEq<U>, U: Copy> PartialEq<Rows<U>> for Vec<T> {
    fn eq(&self, other: &Rows<U>) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl<T: Copy + PartialEq<U>, U> PartialEq<[U]> for Rows<T> {
    fn eq(&self, other: &[U]) -> bool {
        self.as_slice() == other
    }
}

impl<T: Copy + PartialEq<U>, U> PartialEq<&[U]> for Rows<T> {
    fn eq(&self, other: &&[U]) -> bool {
        self.as_slice() == *other
    }
}

impl<T: Copy + PartialEq<U>, U, const N: usize> PartialEq<[U; N]> for Rows<T> {
    fn eq(&self, other: &[U; N]) -> bool {
        self.as_slice() == other.as_slice()
    }
}

/// As the vector of its rows, so a history serializes as it did when its tables were vectors.
impl<T: Copy + Serialize> Serialize for Rows<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.as_slice().serialize(serializer)
    }
}

/// Onto the heap.
impl<'de, T: Copy + Deserialize<'de>> Deserialize<'de> for Rows<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Vec::<T>::deserialize(deserializer).map(Self::from)
    }
}
