//! Proof-authenticated guest output.

use bincode::Options as _;
use serde::de::DeserializeOwned;

use crate::error::ReadError;

/// The bytes the guest committed, in commit order, reachable only from a verified proof.
///
/// | host | guest |
/// |---|---|
/// | [`CommittedValues::read`] | `pico_sdk::io::commit(&T)` |
/// | [`CommittedValues::as_bytes`] | `pico_sdk::io::commit_bytes(&[u8])` |
///
/// [`crate::Proof::committed`] is the only constructor, and a `Proof` exists only after the
/// proof verified and these bytes hashed to its `committed_value_digest`. Bytes sitting next to a
/// proof are not proof-authenticated output, and this type is what keeps the two apart.
///
/// What the verified proof attests to still varies by phase:
/// [`crate::Proof::binds_complete_execution`] says whether these bytes are the output of one whole
/// execution or of a set of separately proved chunks.
#[derive(Debug, Clone)]
pub struct CommittedValues {
    bytes: Vec<u8>,
    cursor: usize,
}

impl CommittedValues {
    pub(crate) fn new(bytes: Vec<u8>) -> Self {
        Self { bytes, cursor: 0 }
    }

    /// Decode the next value, advancing past it. Mirrors one guest `io::commit(&T)`.
    ///
    /// Bounded by what is left to read. `T` is the caller's, but the bytes are the guest's, and
    /// bincode reserves a string or byte buffer at its length prefix before it has read the bytes
    /// behind it — so an unbounded decode of a prefix claiming 2^60 is an allocation failure, which
    /// aborts rather than returns. The encoding is `bincode::deserialize_from`'s own, plus the
    /// limit.
    pub fn read<T: DeserializeOwned>(&mut self) -> Result<T, ReadError> {
        let remaining = &self.bytes[self.cursor..];
        let mut reader = std::io::Cursor::new(remaining);
        let value = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_limit(remaining.len() as u64)
            .deserialize_from(&mut reader)
            .map_err(|source| ReadError::Decode {
                offset: self.cursor,
                source,
            })?;
        self.cursor += reader.position() as usize;
        Ok(value)
    }

    /// Everything the guest committed, undecoded. Mirrors `io::commit_bytes`, which frames nothing.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The bytes not yet consumed by [`Self::read`].
    pub fn remaining(&self) -> &[u8] {
        &self.bytes[self.cursor..]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The reader consumes exactly what the guest's `commit` wrote, one value at a time. The input
    /// is a fixed byte string rather than the output of this crate's own writer.
    #[test]
    fn read_consumes_one_value_at_a_time() {
        let bytes = vec![10, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 1];
        let mut committed = CommittedValues::new(bytes);

        assert_eq!(committed.read::<u32>().unwrap(), 10);
        assert_eq!(committed.read::<(u64, bool)>().unwrap(), (7, true));
        assert!(committed.remaining().is_empty());
    }

    #[test]
    fn reading_past_the_end_reports_the_offset() {
        let mut committed = CommittedValues::new(vec![10, 0, 0, 0]);
        assert_eq!(committed.read::<u32>().unwrap(), 10);
        match committed.read::<u32>().unwrap_err() {
            ReadError::Decode { offset, .. } => assert_eq!(offset, 4),
        }
    }

    /// A length prefix is the cheapest thing in a byte stream to get wrong, and the guest's output
    /// travels in the same container as the proof. A lie must come back as an error, not as an
    /// allocation failure: a `String` is reserved at its claimed length unless the read is
    /// bounded.
    #[test]
    fn a_length_prefix_larger_than_the_stream_is_an_error() {
        // An 8-byte length prefix claiming 2^60, and nothing behind it.
        let prefix = (1u64 << 60).to_le_bytes().to_vec();
        assert!(CommittedValues::new(prefix.clone())
            .read::<Vec<u64>>()
            .is_err());
        assert!(CommittedValues::new(prefix).read::<String>().is_err());
    }

    /// `as_bytes` is the whole stream, not the unread tail — `commit_bytes` output has no framing
    /// and a caller mixing the two would otherwise silently lose the prefix.
    #[test]
    fn as_bytes_ignores_the_cursor() {
        let mut committed = CommittedValues::new(vec![10, 0, 0, 0, 99]);
        let _ = committed.read::<u32>().unwrap();
        assert_eq!(committed.as_bytes(), &[10, 0, 0, 0, 99]);
        assert_eq!(committed.remaining(), &[99]);
    }
}
