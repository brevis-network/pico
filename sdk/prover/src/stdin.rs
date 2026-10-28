//! Guest input. One host method per guest `io` read.

use pico_vm::{
    compiler::riscv::program::Program, configs::stark_config::KoalaBearPoseidon2,
    emulator::stdin::EmulatorStdin,
};
use serde::Serialize;

/// What the guest reads, in the order it reads it.
///
/// | host | guest |
/// |---|---|
/// | [`Stdin::write`] | `pico_sdk::io::read_as::<T>()` |
/// | [`Stdin::write_bytes`] | `pico_sdk::io::read_vec()` |
///
/// ```
/// # use pico_prover::Stdin;
/// let mut stdin = Stdin::new();
/// stdin.write(&10u32).write_bytes(&[1, 2, 3]);
/// ```
#[derive(Debug, Clone, Default)]
pub struct Stdin {
    elements: Vec<Vec<u8>>,
    /// The first element that would not serialize, reported by the next `prove` or `execute`.
    /// Held rather than returned: the setters chain, and a `Result` per call would make the
    /// common case — a type whose encoding cannot fail — read like one that can.
    failed: Option<(usize, String)>,
}

impl Stdin {
    pub fn new() -> Self {
        Self::default()
    }

    /// Serialize `value` as one element the guest reads with `read_as::<T>()`.
    ///
    /// A `Serialize` impl that fails leaves this element out and is reported by the next
    /// [`crate::Prover::prove`] or [`crate::Prover::execute`] as
    /// [`crate::ProveError::InvalidInput`] — nothing in this crate aborts on caller input.
    pub fn write<T: Serialize>(&mut self, value: &T) -> &mut Self {
        let mut bytes = Vec::new();
        match bincode::serialize_into(&mut bytes, value) {
            Ok(()) => self.elements.push(bytes),
            Err(e) => {
                if self.failed.is_none() {
                    self.failed = Some((self.elements.len(), e.to_string()));
                }
            }
        }
        self
    }

    /// Push raw bytes as one element the guest reads with `read_vec()`.
    pub fn write_bytes(&mut self, bytes: &[u8]) -> &mut Self {
        self.elements.push(bytes.to_vec());
        self
    }

    /// How many elements the guest can read.
    pub fn len(&self) -> usize {
        self.elements.len()
    }

    pub fn is_empty(&self) -> bool {
        self.elements.is_empty()
    }

    /// The first element that would not serialize, if any.
    pub(crate) fn failure(&self) -> Option<(usize, &str)> {
        self.failed
            .as_ref()
            .map(|(index, message)| (*index, message.as_str()))
    }

    /// Hand the elements to the emulator.
    ///
    /// `KoalaBearPoseidon2` is the builder's phantom type parameter, discarded by `finalize`.
    pub(crate) fn into_emulator_stdin(self) -> EmulatorStdin<Program, Vec<u8>> {
        let mut builder = EmulatorStdin::<Program, Vec<u8>>::new_builder::<KoalaBearPoseidon2>();
        for element in self.elements {
            builder.write_slice(&element);
        }
        builder.finalize()
    }
}

impl<T: Serialize> From<&T> for Stdin {
    fn from(value: &T) -> Self {
        let mut stdin = Self::new();
        stdin.write(value);
        stdin
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `write` must produce exactly what the guest's `read_as` decodes, which is plain bincode with
    /// no framing of its own. Asserted against fixed bytes rather than against a round trip through
    /// the same serializer, which would only show bincode is self-consistent.
    #[test]
    fn write_matches_the_guests_encoding_byte_for_byte() {
        let mut stdin = Stdin::new();
        stdin.write(&10u32);
        stdin.write(&(7u64, true));
        stdin.write_bytes(&[0xAA, 0xBB]);

        assert_eq!(stdin.elements[0], vec![10, 0, 0, 0]);
        assert_eq!(stdin.elements[1], vec![7, 0, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(stdin.elements[2], vec![0xAA, 0xBB]);
    }

    /// A `Serialize` impl of the caller's can fail, and this crate has no abort available to it:
    /// the element is dropped and the first failure waits for the next `prove` or `execute`.
    #[test]
    fn a_value_that_will_not_serialize_is_recorded_rather_than_fatal() {
        struct Unserializable;

        impl Serialize for Unserializable {
            fn serialize<S: serde::Serializer>(&self, _: S) -> Result<S::Ok, S::Error> {
                Err(serde::ser::Error::custom("this type cannot be encoded"))
            }
        }

        let mut stdin = Stdin::new();
        stdin
            .write(&10u32)
            .write(&Unserializable)
            .write(&11u32)
            .write(&Unserializable);

        assert_eq!(stdin.len(), 2, "the failing elements must not be written");
        let (index, message) = stdin.failure().expect("the failure is held for the prover");
        assert_eq!(index, 1);
        assert!(message.contains("cannot be encoded"), "{message}");
    }

    #[test]
    fn from_a_reference_writes_one_element() {
        let stdin = Stdin::from(&10u32);
        assert_eq!(stdin.len(), 1);
        assert_eq!(stdin.elements[0], vec![10, 0, 0, 0]);
    }

    #[test]
    fn elements_reach_the_emulator_in_order() {
        let mut stdin = Stdin::new();
        stdin.write_bytes(&[1]).write_bytes(&[2, 3]);
        let emulator_stdin = stdin.into_emulator_stdin();
        assert_eq!(
            emulator_stdin.inputs.to_vec(),
            vec![vec![1u8], vec![2u8, 3u8]]
        );
    }
}
