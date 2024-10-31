use crate::compiler::riscv::opcode::RangeCheckOpcode;
use hashbrown::HashMap;
use p3_field::PrimeField32;
use serde::{Deserialize, Serialize};

/// Range Lookup Event.
///
/// This object encapsulates the information needed to prove a range lookup operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct RangeLookupEvent {
    /// The opcode.
    pub opcode: RangeCheckOpcode,
    /// The value to be looked up
    pub value: u16,
}

/// A type that can record range lookup events.
pub trait RangeRecordBehavior {
    /// Adds a new [`RangeLookupEvent`] to the record.
    fn add_range_lookup_event(&mut self, event: RangeLookupEvent);

    fn range_lookup_events(&self) -> impl Iterator<Item = (RangeLookupEvent, usize)> {
        std::iter::empty()
    }

    /// Adds a `RangeLookupEvent` to verify `a` and `b` are indeed bytes to the chunk.
    fn add_u8_range_check(&mut self, a: u8) {
        self.add_range_lookup_event(RangeLookupEvent::new(RangeCheckOpcode::U8, a as u16));
    }

    /// Adds a `RangeLookupEvent` to verify `a` is indeed u16.
    fn add_u16_range_check(&mut self, _chunk: u32, _channel: u8, a: u16) {
        self.add_range_lookup_event(RangeLookupEvent::new(RangeCheckOpcode::U16, a));
    }

    /// Adds `ByteLookupEvent`s to verify that all the bytes in the input slice are indeed bytes.
    fn add_u8_range_checks(
        &mut self,
        _chunk: u32,
        _channel: u8,
        bytes: impl IntoIterator<Item = u8>,
    ) {
        for byte in bytes {
            self.add_u8_range_check(byte);
        }
    }

    /// Adds `RangeLookupEvent`s to verify that all the field elements in the input slice are indeed
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
            field_values.iter().map(|x| x.as_canonical_u32() as u8),
        );
    }

    /// Adds `ByteLookupEvent`s to verify that all the bytes in the input slice are indeed bytes.
    fn add_u16_range_checks(&mut self, chunk: u32, channel: u8, ls: &[u16]) {
        ls.iter()
            .for_each(|x| self.add_u16_range_check(chunk, channel, *x));
    }
}

impl RangeLookupEvent {
    pub fn new(opcode: RangeCheckOpcode, value: u16) -> Self {
        Self { opcode, value }
    }
}

impl RangeRecordBehavior for () {
    fn add_range_lookup_event(&mut self, _event: RangeLookupEvent) {}
}

impl RangeRecordBehavior for Vec<RangeLookupEvent> {
    fn add_range_lookup_event(&mut self, event: RangeLookupEvent) {
        self.push(event);
    }

    fn range_lookup_events(&self) -> impl Iterator<Item = (RangeLookupEvent, usize)> {
        self.iter().copied().zip(std::iter::repeat(1))
    }
}

impl RangeRecordBehavior for HashMap<RangeLookupEvent, usize> {
    fn add_range_lookup_event(&mut self, event: RangeLookupEvent) {
        *self.entry(event).or_insert(0) += 1;
    }

    fn range_lookup_events(&self) -> impl Iterator<Item = (RangeLookupEvent, usize)> {
        self.iter().map(|(k, v)| (*k, *v))
    }
}
