use crate::compiler::riscv::opcode::ByteOpcode;
use itertools::Itertools;
use p3_field::PrimeField32;
use serde::{Deserialize, Serialize};
use std::hash::Hash;

/// Byte Lookup Event.
///
/// This object encapsulates the information needed to prove a byte lookup operation. This includes
/// the opcode, operands, and other relevant information.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct ByteLookupEvent {
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

    /// Adds a list of `ByteLookupEvent`s to the record.
    #[inline]
    fn add_byte_lookup_events(&mut self, blu_events: Vec<ByteLookupEvent>) {
        for blu_event in blu_events {
            self.add_byte_lookup_event(blu_event);
        }
    }

    /// Adds a `ByteLookupEvent` to verify `a` and `b` are indeed bytes.
    fn add_u8_range_check(&mut self, b: u8, c: u8) {
        self.add_byte_lookup_event(ByteLookupEvent::new(ByteOpcode::U8Range, 0, 0, b, c));
    }

    /// Adds a `ByteLookupEvent` to verify `a` is indeed u16.
    fn add_u16_range_check(&mut self, a: u16) {
        let b = a >> 8;
        let c = a & u8::MAX as u16;
        self.add_byte_lookup_event(ByteLookupEvent::new(
            ByteOpcode::U16Range,
            0,
            0,
            b as u8,
            c as u8,
        ));
    }

    /// Adds `ByteLookupEvent`s to verify that all the bytes in the input slice are indeed bytes.
    fn add_u8_range_checks(&mut self, bytes: impl IntoIterator<Item = u8>) {
        for mut pair in &bytes.into_iter().chunks(2) {
            let b = pair.next().unwrap();
            let c = pair.next().unwrap_or_default();
            self.add_u8_range_check(b, c);
        }
    }

    /// Adds `ByteLookupEvent`s to verify that all the field elements in the input slice are indeed
    /// bytes.
    fn add_u8_range_checks_field<F: PrimeField32>(&mut self, field_values: &[F]) {
        self.add_u8_range_checks(field_values.iter().map(|x| x.as_canonical_u32() as u8));
    }

    /// Adds `ByteLookupEvent`s to verify that all the bytes in the input slice are indeed bytes.
    fn add_u16_range_checks(&mut self, ls: &[u16]) {
        ls.iter().for_each(|x| self.add_u16_range_check(*x));
    }
}

impl ByteLookupEvent {
    /// Creates a new `ByteLookupEvent`.
    #[must_use]
    pub fn new(opcode: ByteOpcode, a1: u16, a2: u8, b: u8, c: u8) -> Self {
        Self {
            opcode,
            a1,
            a2,
            b,
            c,
        }
    }
}

impl ByteRecordBehavior for () {
    fn add_byte_lookup_event(&mut self, _event: ByteLookupEvent) {}
}

impl ByteRecordBehavior for Vec<ByteLookupEvent> {
    fn add_byte_lookup_event(&mut self, blu_event: ByteLookupEvent) {
        self.push(blu_event);
    }
}
