#![allow(unused_unsafe)]
use crate::{syscall_hint_len, syscall_hint_read, syscall_write};
use serde::{de::DeserializeOwned, Serialize};
use std::{
    alloc::Layout,
    io::{Result, Write},
};

/// The file descriptor for public values.
pub const FD_PUBLIC_VALUES: u32 = 3;

/// The file descriptor for hints.
pub const FD_HINT: u32 = 4;

/// The file descriptor for the `ecreover` hook.
pub const FD_ECRECOVER_HOOK: u32 = 5;

/// The file descriptor through which to access `hook_ecrecover_2`.
pub const FD_ECRECOVER_HOOK_2: u32 = 7;

/// The file descriptor through which to access `hook_ed_decompress`.
pub const FD_EDDECOMPRESS: u32 = 8;

/// The file descriptor for brevis coprocessor outputs.
pub const FD_COPROCESSOR_OUTPUTS: u32 = 9;

/// A writer that writes to a file descriptor inside the zkVM.
pub struct SyscallWriter {
    pub fd: u32,
}

impl Write for SyscallWriter {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        let nbytes = buf.len();
        let write_buf = buf.as_ptr();
        unsafe {
            syscall_write(self.fd, write_buf, nbytes);
        }
        Ok(nbytes)
    }

    fn flush(&mut self) -> Result<()> {
        Ok(())
    }
}

#[repr(C)]
pub struct ReadVecResult {
    pub ptr: *mut u8,
    pub len: usize,
    pub capacity: usize,
}

/// Read a buffer from the input stream.
///
/// The buffer is read into uninitialized memory.
#[no_mangle]
pub extern "C" fn read_vec_raw() -> ReadVecResult {
    // Get the length of the input buffer.
    let len = unsafe { syscall_hint_len() };

    // If the length is u32::MAX, then the input stream is exhausted.
    if len == usize::MAX {
        return ReadVecResult {
            ptr: std::ptr::null_mut(),
            len: 0,
            capacity: 0,
        };
    }

    // Round up to multiple of 8 for whole-word alignment.
    let capacity = len.div_ceil(8) * 8;

    // Allocate a buffer of the required length that is 8 byte aligned.
    let layout = Layout::from_size_align(capacity, 8).expect("vec is too large");

    // SAFETY: The layout was made through the checked constructor.
    let ptr = unsafe { std::alloc::alloc(layout) };

    // Read the vec into uninitialized memory. The syscall assumes the memory is
    // uninitialized, which is true because the bump allocator does not dealloc, so a new
    // alloc is always fresh.
    unsafe {
        syscall_hint_read(ptr, len);
    }

    // Return the result.
    ReadVecResult { ptr, len, capacity }
}

/// Read a buffer from the input stream.
///
/// ### Examples
/// ```ignore
/// let data: Vec<u8> = pico_sdk::io::read_vec();
/// ```
pub fn read_vec() -> Vec<u8> {
    let ReadVecResult { ptr, len, capacity } = unsafe { read_vec_raw() };

    if ptr.is_null() {
        panic!(
            "Tried to read from the input stream, but it was empty @ {} \n
            Was the correct data written into Stdin?",
            std::panic::Location::caller(),
        )
    }

    unsafe { Vec::from_raw_parts(ptr, len, capacity) }
}

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
/// let data: MyStruct = pico_sdk::io::read();
/// ```
pub fn read<T: DeserializeOwned>() -> T {
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

/// Commit bytes to the public values stream.
///
/// ### Examples
/// ```ignore
/// let data = vec![1, 2, 3, 4];
/// pico_sdk::io::commit_slice(&data);
/// ```
pub fn commit_slice(buf: &[u8]) {
    let mut my_writer = SyscallWriter {
        fd: FD_PUBLIC_VALUES,
    };
    my_writer.write_all(buf).unwrap();
}

/// Hint a serializable object to the hint stream.
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
/// pico_sdk::io::hint(&data);
/// ```
pub fn hint<T: Serialize>(value: &T) {
    let writer = SyscallWriter { fd: FD_HINT };
    bincode::serialize_into(writer, value).expect("serialization failed");
}

/// Hint bytes to the hint stream.
///
/// ### Examples
/// ```ignore
/// let data = vec![1, 2, 3, 4];
/// pico_sdk::io::hint_slice(&data);
/// ```
pub fn hint_slice(buf: &[u8]) {
    let mut my_reader = SyscallWriter { fd: FD_HINT };
    my_reader.write_all(buf).unwrap();
}

/// Write the data `buf` to the file descriptor `fd`.
///
/// ### Examples
/// ```ignore
/// let data = vec![1, 2, 3, 4];
/// pico_sdk::io::write(3, &data);
/// ```
pub fn write(fd: u32, buf: &[u8]) {
    SyscallWriter { fd }.write_all(buf).unwrap();
}
