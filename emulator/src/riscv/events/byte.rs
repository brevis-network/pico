use hashbrown::HashMap;
use itertools::Itertools;
use p3_field::PrimeField32;
use p3_maybe_rayon::prelude::{
    IndexedParallelIterator, IntoParallelRefIterator, IntoParallelRefMutIterator, ParallelIterator,
};
use pico_compiler::opcode::ByteOpcode;
use serde::{Deserialize, Serialize};
use std::hash::Hash;

/// Byte Lookup Event.
///
/// This object encapsulates the information needed to prove a byte lookup operation. This includes
/// the chunk, channel, opcode, operands, and other relevant information.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct ByteLookupEvent {
    /// The chunk number.
    pub chunk: u32,
    /// The channel number.
    pub channel: u8,
    /// The opcode.
    pub opcode: ByteOpcode,
    /// The first operand.
    pub a1: u16,
    /// The second operand.
    pub a2: u8,
    /// The third operand.
    pub b: u8,
    /// The fourth operand.
    pub c: u8,
}

/// A type that can record byte lookup events.
pub trait ByteRecordBehavior {
    /// Adds a new [`ByteLookupEvent`] to the record.
    fn add_byte_lookup_event(&mut self, blu_event: ByteLookupEvent);

    /// Adds a list of chunked [`ByteLookupEvent`]s to the record.
    fn add_chunked_byte_lookup_events(
        &mut self,
        chunked_blu_events_vec: Vec<&HashMap<u32, HashMap<ByteLookupEvent, usize>>>,
    );

    /// Adds a list of `ByteLookupEvent`s to the record.
    #[inline]
    fn add_byte_lookup_events(&mut self, blu_events: Vec<ByteLookupEvent>) {
        for blu_event in blu_events {
            self.add_byte_lookup_event(blu_event);
        }
    }

    /// Adds a `ByteLookupEvent` to verify `a` and `b` are indeed bytes to the chunk.
    fn add_u8_range_check(&mut self, chunk: u32, channel: u8, a: u8, b: u8) {
        self.add_byte_lookup_event(ByteLookupEvent {
            chunk,
            channel,
            opcode: ByteOpcode::U8Range,
            a1: 0,
            a2: 0,
            b: a,
            c: b,
        });
    }

    /// Adds a `ByteLookupEvent` to verify `a` is indeed u16.
    fn add_u16_range_check(&mut self, chunk: u32, channel: u8, a: u16) {
        self.add_byte_lookup_event(ByteLookupEvent {
            chunk,
            channel,
            opcode: ByteOpcode::U16Range,
            a1: a,
            a2: 0,
            b: 0,
            c: 0,
        });
    }

    /// Adds `ByteLookupEvent`s to verify that all the bytes in the input slice are indeed bytes.
    fn add_u8_range_checks(&mut self, chunk: u32, channel: u8, bytes: &[u8]) {
        let mut index = 0;
        while index + 1 < bytes.len() {
            self.add_u8_range_check(chunk, channel, bytes[index], bytes[index + 1]);
            index += 2;
        }
        if index < bytes.len() {
            // If the input slice's length is odd, we need to add a check for the last byte.
            self.add_u8_range_check(chunk, channel, bytes[index], 0);
        }
    }

    /// Adds `ByteLookupEvent`s to verify that all the field elements in the input slice are indeed
    /// bytes.
    fn add_u8_range_checks_field<F: PrimeField32>(
        &mut self,
        chunk: u32,
        channel: u8,
        field_values: &[F],
    ) {
        self.add_u8_range_checks(
            chunk,
            channel,
            &field_values
                .iter()
                .map(|x| x.as_canonical_u32() as u8)
                .collect::<Vec<_>>(),
        );
    }

    /// Adds `ByteLookupEvent`s to verify that all the bytes in the input slice are indeed bytes.
    fn add_u16_range_checks(&mut self, chunk: u32, channel: u8, ls: &[u16]) {
        ls.iter()
            .for_each(|x| self.add_u16_range_check(chunk, channel, *x));
    }

    /// Adds a `ByteLookupEvent` to compute the bitwise OR of the two input values.
    fn lookup_or(&mut self, chunk: u32, channel: u8, b: u8, c: u8) {
        self.add_byte_lookup_event(ByteLookupEvent {
            chunk,
            channel,
            opcode: ByteOpcode::OR,
            a1: (b | c) as u16,
            a2: 0,
            b,
            c,
        });
    }
}

impl ByteLookupEvent {
    /// Creates a new `ByteLookupEvent`.
    #[must_use]
    pub fn new(chunk: u32, channel: u8, opcode: ByteOpcode, a1: u16, a2: u8, b: u8, c: u8) -> Self {
        Self {
            chunk,
            channel,
            opcode,
            a1,
            a2,
            b,
            c,
        }
    }
}

impl ByteRecordBehavior for Vec<ByteLookupEvent> {
    fn add_byte_lookup_event(&mut self, blu_event: ByteLookupEvent) {
        self.push(blu_event);
    }

    fn add_chunked_byte_lookup_events(
        &mut self,
        _: Vec<&HashMap<u32, HashMap<ByteLookupEvent, usize>>>,
    ) {
        todo!()
    }
}

impl ByteRecordBehavior for HashMap<u32, HashMap<ByteLookupEvent, usize>> {
    #[inline]
    fn add_byte_lookup_event(&mut self, blu_event: ByteLookupEvent) {
        self.entry(blu_event.chunk)
            .or_default()
            .entry(blu_event)
            .and_modify(|e| *e += 1)
            .or_insert(1);
    }

    fn add_chunked_byte_lookup_events(
        &mut self,
        new_events: Vec<&HashMap<u32, HashMap<ByteLookupEvent, usize>>>,
    ) {
        add_chunked_byte_lookup_events(self, new_events);
    }
}

pub fn add_chunked_byte_lookup_events(
    chunked_blu_events: &mut HashMap<u32, HashMap<ByteLookupEvent, usize>>,
    new_events: Vec<&HashMap<u32, HashMap<ByteLookupEvent, usize>>>,
) {
    // new_chunked_blu_map is a map of chunk -> Vec<map of byte lookup event -> multiplicities>.
    // We want to collect the new events in this format so that we can do parallel aggregation
    // per chunk.
    let mut new_chunked_blu_map: HashMap<u32, Vec<&HashMap<ByteLookupEvent, usize>>> =
        HashMap::new();
    for new_chunked_blu_events in new_events {
        for (chunk, new_blu_map) in new_chunked_blu_events {
            new_chunked_blu_map
                .entry(*chunk)
                .or_insert(Vec::new())
                .push(new_blu_map);
        }
    }

    // Collect all the chunk numbers.
    let chunks: Vec<u32> = new_chunked_blu_map.keys().copied().collect_vec();

    // Move ownership of self's per chunk blu maps into a vec.  This is so that we
    // can do parallel aggregation per chunk.
    let mut self_blu_maps: Vec<HashMap<ByteLookupEvent, usize>> = Vec::new();
    for chunk in &chunks {
        let blu = chunked_blu_events.remove(chunk);

        match blu {
            Some(blu) => {
                self_blu_maps.push(blu);
            }
            None => {
                self_blu_maps.push(HashMap::new());
            }
        }
    }

    // Increment self's byte lookup events multiplicity.
    chunks
        .par_iter()
        .zip_eq(self_blu_maps.par_iter_mut())
        .for_each(|(chunk, self_blu_map)| {
            let blu_map_vec = new_chunked_blu_map.get(chunk).unwrap();
            for blu_map in blu_map_vec.iter() {
                for (blu_event, count) in blu_map.iter() {
                    *self_blu_map.entry(*blu_event).or_insert(0) += count;
                }
            }
        });

    // Move ownership of the blu maps back to self.
    for (chunk, blu) in chunks.into_iter().zip(self_blu_maps.into_iter()) {
        chunked_blu_events.insert(chunk, blu);
    }
}
