use crate::compiler::recursion::{ir::Block, types::Address};
use p3_field::PrimeField64;
use std::sync::Arc;
use vec_map::{Entry, VecMap};

#[derive(Debug, Clone, Default)]
pub struct MemoryEntry<F> {
    pub val: Block<F>,
    pub mult: F,
}

pub trait Memory<F> {
    /// Allocates memory with at least the given capacity.
    fn with_capacity(capacity: usize) -> Self;

    /// Read from a memory address.
    ///
    /// # Panics
    /// Panics if the address is unassigned.
    fn mr(&self, addr: Address<F>) -> &MemoryEntry<F>;

    /// Write to a memory address, setting the given value and mult.
    ///
    /// # Panics
    /// Panics if the address is already assigned **in this view's own table**. A forked or joined
    /// view also holds tables behind `bases`, and a write colliding with one of those is caught
    /// only by a `debug_assert`: checking it in release would put a lookup on the interpreter's
    /// write path for a collision the builder's monotone bump allocator cannot produce.
    fn mw(&mut self, addr: Address<F>, val: Block<F>, mult: F) -> &mut MemoryEntry<F>;
}

/// The recursion emulator's memory: address to value, written once and read back.
///
/// **A read changes nothing in the table**, which is what lets two children share a base table
/// through an `Arc`. Reads used to decrement `MemoryEntry::mult`, a value nothing ever read back
/// -- the table is dropped when `run()` returns -- so the decrement was a store on the
/// interpreter's innermost operation and a write where a read belonged.
///
/// `mr` takes `&self`, so the invariant is the signature rather than a promise in prose.
#[derive(Debug, Default)]
pub struct MemVecMap<F> {
    pub map: VecMap<MemoryEntry<F>>,

    /// Where a read that misses `map` looks next, in order.
    ///
    /// Set on a forked view. A combine program is prologue | child 0 | child 1 | merge; running
    /// the prologue and hoisting the constant writes out of both children leaves a table the two
    /// children only read, so it is shared behind an `Arc` while each child writes its own `map`.
    /// Their address ranges cannot collide: the builder's allocator is a strictly monotone bump.
    ///
    /// Two levels, because the merge tail afterwards needs to see all three tables and copying
    /// the children's back into one costs more than the tail's ~8 k instructions save by having
    /// a single lookup. Consulted only after `map` misses, so the hot path never walks it.
    pub bases: [Option<Arc<VecMap<MemoryEntry<F>>>>; 2],

    /// Lowest and highest address this table has written, or `None` if it has written nothing
    /// **or is not a forked view** — tracking is gated on `bases` being set at all, so an
    /// unsplit run leaves it `None` and pays nothing for it. Gated on `any`, not on slot 0:
    /// every other reader treats the array as unordered, and coupling to a slot would let a
    /// reordered `fork` silently switch the join's disjointness check off.
    ///
    /// Two forked children must write disjoint addresses. Nothing in `mw` can see that: while
    /// they run, neither holds the other in `bases`, so a shared address is accepted by both and
    /// the fold afterwards keeps one silently — the only way the split produces a *different*
    /// record rather than a crash. The builder's allocator is a strictly monotone bump, so their
    /// windows cannot overlap, but that is a property of code elsewhere; this records enough to
    /// check it after the join for the price of two comparisons per write.
    pub written: Option<(usize, usize)>,
}

impl<F: PrimeField64> Memory<F> for MemVecMap<F> {
    fn with_capacity(capacity: usize) -> Self {
        Self {
            map: VecMap::with_capacity(capacity),
            bases: [None, None],
            written: None,
        }
    }

    fn mr(&self, addr: Address<F>) -> &MemoryEntry<F> {
        let index = addr.as_usize();
        // One lookup, not `contains_key` then an index: this is the emulator's innermost
        // operation, ~1 M per combine node, and a node's emulation sits on the combine tree's
        // serial carry chain. `bases` is consulted only when `map` misses, which on an unforked
        // run is never.
        if let Some(entry) = self.map.get(index) {
            return entry;
        }
        match self.bases.iter().flatten().find_map(|b| b.get(index)) {
            Some(entry) => entry,
            None => panic!("tried to read from unassigned address: {addr:?}"),
        }
    }

    fn mw(&mut self, addr: Address<F>, val: Block<F>, mult: F) -> &mut MemoryEntry<F> {
        let index = addr.as_usize();
        debug_assert!(
            self.bases.iter().flatten().all(|b| !b.contains_key(index)),
            "forked view wrote {index}, which the shared base already holds"
        );
        // Only a forked view needs this, and only the join reads it. Gated so an unsplit run —
        // every run today, the knob being off by default — pays one predictable test rather than
        // three stores on the interpreter's write path.
        if self.bases.iter().any(Option::is_some) {
            self.written = Some(match self.written {
                Some((lo, hi)) => (lo.min(index), hi.max(index)),
                None => (index, index),
            });
        }
        match self.map.entry(index) {
            Entry::Occupied(entry) => {
                panic!(
                    "tried to write to assigned address {}: {:?}",
                    index,
                    entry.get()
                )
            }
            Entry::Vacant(entry) => entry.insert(MemoryEntry { val, mult }),
        }
    }
}
