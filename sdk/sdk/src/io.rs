use std::io::Write;

#[cfg(feature = "coprocessor")]
use coprocessor_sdk::{data_types::hash_out::HashBytes, sdk::SDK};

#[cfg(feature = "coprocessor")]
use pico_patch_libs::io::FD_COPROCESSOR_OUTPUTS;

use pico_patch_libs::io::{SyscallWriter, FD_PUBLIC_VALUES};
use serde::{de::DeserializeOwned, Serialize};

/// Read a deserializable object from the input stream.
///
/// ### Examples
/// ```ignore
/// use serde::{Deserialize, Serialize};
///
/// #[derive(Serialize, Deserialize)]
/// struct MyStruct {
///     a: u32,
///     b: u32,
/// }
///
/// let data: MyStruct = pico_sdk::io::read_vec();
/// ```
pub fn read_vec() -> Vec<u8> {
    pico_patch_libs::io::read_vec()
}

/// Reads a buffer from the input stream and deserializes it into a type `T`.
///
/// ### Examples
/// ``` ignore
/// let data: Vec<u8> = pico_sdk::io::read_as();
/// ```
pub fn read_as<T: DeserializeOwned>() -> T {
    let vec = read_vec();
    bincode::deserialize(&vec).expect("deserialization failed")
}

/// Commit a serializable object to the public values stream.
///
/// ### Examples
/// ```ignore
/// use serde::{Deserialize, Serialize};
///
/// #[derive(Serialize, Deserialize)]
/// struct MyStruct {
///     a: u32,
///     b: u32,
/// }
///
/// let data = MyStruct {
///     a: 1,
///     b: 2,
/// };
/// pico_sdk::io::commit(&data);
/// ```
pub fn commit<T: Serialize>(value: &T) {
    let writer = SyscallWriter {
        fd: FD_PUBLIC_VALUES,
    };
    bincode::serialize_into(writer, value).expect("serialization failed");
}

// commit a coprocessor serializable object to the coprocessor output stream
#[cfg(feature = "coprocessor")]
fn commit_coprocessor_output<T: Serialize>(value: &T) {
    let writer = SyscallWriter {
        fd: FD_COPROCESSOR_OUTPUTS,
    };
    bincode::serialize_into(writer, value).expect("serialization failed");
}

/// Commit bytes to the public values stream.
///
/// ### Examples
/// ```ignore
/// let data = vec![1, 2, 3, 4];
/// pico_sdk::io::commit_bytes(&data);
/// ```
pub fn commit_bytes(buf: &[u8]) {
    let mut my_writer = SyscallWriter {
        fd: FD_PUBLIC_VALUES,
    };
    my_writer.write_all(buf).unwrap();
}

// Commit bytes to the coprocessor output stream.
#[cfg(feature = "coprocessor")]
fn commit_coprocessor_output_bytes(buf: &[u8]) {
    let mut my_writer = SyscallWriter {
        fd: FD_COPROCESSOR_OUTPUTS,
    };
    my_writer.write_all(buf).unwrap();
}

/// Commit a coprocessor serializable object to the public values stream.
#[cfg(feature = "coprocessor")]
pub fn commit_coprocessor_value<T: Serialize>(coprocessor_sdk: &mut SDK, value: &T) {
    if !coprocessor_sdk.is_commited() {
        let input_commitment = coprocessor_sdk.input_commitments.to_be_bytes();
        let receipt_dummy = coprocessor_sdk
            .dummy_commitments
            .receipt_dummy_commitment
            .to_be_bytes();
        let storage_dummy = coprocessor_sdk
            .dummy_commitments
            .storage_dummy_commitment
            .to_be_bytes();
        let tx_dummy = coprocessor_sdk
            .dummy_commitments
            .tx_dummy_commitment
            .to_be_bytes();
        let concat_buf = [input_commitment, receipt_dummy, storage_dummy, tx_dummy].concat();
        // commit input commitments and dummy commitments to the public values stream
        commit_bytes(&concat_buf);
        // commit coprocessor output to the coprocessor output stream
        commit_coprocessor_output(value);
        coprocessor_sdk.set_commited_status(true);
    } else {
        // commit coprocessor output to the coprocessor output stream when the input commitments and dummy commitments are already commited
        commit_coprocessor_output(value);
    }
}

/// Commit coprocessor bytes to the public values stream.
#[cfg(feature = "coprocessor")]
pub fn commit_coprocessor_bytes(coprocessor_sdk: &mut SDK, buf: &mut [u8]) {
    if !coprocessor_sdk.is_commited() {
        let coprocessor_buf = coprocessor_sdk.input_commitments.to_be_bytes();
        let receipt_dummy = coprocessor_sdk
            .dummy_commitments
            .receipt_dummy_commitment
            .to_be_bytes();
        let storage_dummy = coprocessor_sdk
            .dummy_commitments
            .storage_dummy_commitment
            .to_be_bytes();
        let tx_dummy = coprocessor_sdk
            .dummy_commitments
            .tx_dummy_commitment
            .to_be_bytes();
        let concat_buf = [coprocessor_buf, receipt_dummy, storage_dummy, tx_dummy].concat();
        // commit input commitments and dummy commitments to the public values stream
        commit_bytes(&concat_buf);
        // commit coprocessor output bytes to the coprocessor output stream
        commit_coprocessor_output_bytes(buf);
        coprocessor_sdk.set_commited_status(true);
    } else {
        // commit coprocessor output bytes to the coprocessor output stream when the input commitments and dummy commitments are already commited
        commit_coprocessor_output_bytes(buf);
    }
}
