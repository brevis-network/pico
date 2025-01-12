use crate::compiler::riscv::opcode::RangeCheckOpcode;
use hashbrown::HashMap;
use itertools::Itertools;
use p3_field::PrimeField32;
use p3_maybe_rayon::prelude::{
    IndexedParallelIterator, IntoParallelRefIterator, IntoParallelRefMutIterator, ParallelIterator,
};
use serde::{Deserialize, Serialize};
use std::iter;

/// Range Lookup Event.
///
/// This object encapsulates the information needed to prove a range lookup operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct RangeLookupEvent {
    /// The opcode.
    pub opcode: RangeCheckOpcode,
    /// The value to be looked up
    pub value: u16,
    /// The chunk number, set to None for recursion.
    pub chunk: Option<u32>,
}

/// A type that can record range lookup events.
pub trait RangeRecordBehavior {
    /// Adds a new [`RangeLookupEvent`] to the record.
    fn add_range_lookup_event(&mut self, event: RangeLookupEvent);

    /// Adds a list of `RangeLookupEvent`s to the record.
    #[inline]
    fn add_range_lookup_events(&mut self, rlu_events: Vec<RangeLookupEvent>) {
        for rlu_event in rlu_events {
            self.add_range_lookup_event(rlu_event);
        }
    }

    fn all_range_lookup_events(&self) -> Box<dyn Iterator<Item = (RangeLookupEvent, usize)> + '_>;

    fn range_lookup_events(
        &self,
        chunk: Option<u32>,
    ) -> Box<dyn Iterator<Item = (RangeLookupEvent, usize)> + '_>;

    /// Adds a `RangeLookupEvent` to verify `a` and `b` are indeed bytes to the chunk.
    fn add_u8_range_check(&mut self, a: u8, chunk: Option<u32>) {
        self.add_range_lookup_event(RangeLookupEvent::new(RangeCheckOpcode::U8, a as u16, chunk));
    }

    /// Adds a `RangeLookupEvent` to verify `a` is indeed u16.
    fn add_u16_range_check(&mut self, a: u16, chunk: Option<u32>) {
        self.add_range_lookup_event(RangeLookupEvent::new(RangeCheckOpcode::U16, a, chunk));
    }

    /// Adds `ByteLookupEvent`s to verify that all the bytes in the input slice are indeed bytes.
    fn add_u8_range_checks(&mut self, bytes: impl IntoIterator<Item = u8>, chunk: Option<u32>) {
        for byte in bytes {
            self.add_u8_range_check(byte, chunk);
        }
    }

    /// Adds `RangeLookupEvent`s to verify that all the field elements in the input slice are indeed
    /// bytes.
    fn add_u8_range_checks_field<F: PrimeField32>(
        &mut self,
        field_values: &[F],
        chunk: Option<u32>,
    ) {
        self.add_u8_range_checks(
            field_values.iter().map(|x| x.as_canonical_u32() as u8),
            chunk,
        );
    }

    /// Adds `ByteLookupEvent`s to verify that all the bytes in the input slice are indeed bytes.
    fn add_u16_range_checks(&mut self, ls: &[u16], chunk: Option<u32>) {
        ls.iter().for_each(|x| self.add_u16_range_check(*x, chunk));
    }
}

impl RangeLookupEvent {
    pub fn new(opcode: RangeCheckOpcode, value: u16, chunk: Option<u32>) -> Self {
        Self {
            opcode,
            value,
            chunk,
        }
    }
}

impl RangeRecordBehavior for () {
    fn add_range_lookup_event(&mut self, _event: RangeLookupEvent) {}
    fn all_range_lookup_events(&self) -> Box<dyn Iterator<Item = (RangeLookupEvent, usize)> + '_> {
        Box::new(iter::empty())
    }
    fn range_lookup_events(
        &self,
        _chunk: Option<u32>,
    ) -> Box<dyn Iterator<Item = (RangeLookupEvent, usize)>> {
        Box::new(iter::empty())
    }
}

impl RangeRecordBehavior for Vec<RangeLookupEvent> {
    fn add_range_lookup_event(&mut self, event: RangeLookupEvent) {
        self.push(event);
    }
    fn all_range_lookup_events(&self) -> Box<dyn Iterator<Item = (RangeLookupEvent, usize)> + '_> {
        Box::new(self.iter().copied().zip(std::iter::repeat(1)))
    }
    fn range_lookup_events(
        &self,
        _chunk: Option<u32>,
    ) -> Box<dyn Iterator<Item = (RangeLookupEvent, usize)> + '_> {
        Box::new(self.iter().copied().zip(std::iter::repeat(1)))
    }
}

impl RangeRecordBehavior for HashMap<RangeLookupEvent, usize> {
    fn add_range_lookup_event(&mut self, event: RangeLookupEvent) {
        *self.entry(event).or_insert(0) += 1;
    }
    fn all_range_lookup_events(&self) -> Box<dyn Iterator<Item = (RangeLookupEvent, usize)> + '_> {
        Box::new(self.iter().map(move |(event, v)| (*event, *v)))
    }
    fn range_lookup_events(
        &self,
        chunk: Option<u32>,
    ) -> Box<dyn Iterator<Item = (RangeLookupEvent, usize)> + '_> {
        Box::new(self.iter().filter_map(move |(event, v)| {
            if event.chunk == chunk {
                Some((*event, *v))
            } else {
                None
            }
        }))
    }
}

// Add new chunked range events.
pub fn add_chunked_range_lookup_events(
    chunked_events: &mut HashMap<u32, HashMap<RangeLookupEvent, usize>>,
    new_events: Vec<&HashMap<u32, HashMap<RangeLookupEvent, usize>>>,
) {
    // `new_chunked_map`` is a map of `chunk -> Vec<map of lookup event -> multiplicities>`.
    // We want to collect the new events in this format so that we can do parallel aggregation
    // per chunk.
    let mut new_chunked_map: HashMap<u32, Vec<&HashMap<RangeLookupEvent, usize>>> = HashMap::new();
    for new_chunked_events in new_events {
        for (chunk, new_map) in new_chunked_events {
            new_chunked_map
                .entry(*chunk)
                .or_insert(Vec::new())
                .push(new_map);
        }
    }

    // Collect all the chunk numbers.
    let chunks: Vec<u32> = new_chunked_map.keys().copied().collect_vec();

    // Move ownership of self's per chunk maps into a vec. This is so that we can do
    // parallel aggregation per chunk.
    let mut self_maps: Vec<HashMap<RangeLookupEvent, usize>> = Vec::new();
    for chunk in &chunks {
        let tuple = chunked_events.remove(chunk);

        match tuple {
            Some(tuple) => {
                self_maps.push(tuple);
            }
            None => {
                self_maps.push(HashMap::new());
            }
        }
    }

    // Increment self's lookup events multiplicity.
    chunks
        .par_iter()
        .zip_eq(self_maps.par_iter_mut())
        .for_each(|(chunk, self_map)| {
            let map_vec = new_chunked_map.get(chunk).unwrap();
            for map in map_vec.iter() {
                for (event, multi) in map.iter() {
                    *self_map.entry(*event).or_insert(0) += multi;
                }
            }
        });

    // Move ownership of the maps back to self.
    for (chunk, tuple) in chunks.into_iter().zip(self_maps.into_iter()) {
        chunked_events.insert(chunk, tuple);
    }
}
