//! The zkevm-standards IO interface (`zkvm_io.h`), with C ABI: `read_input` and `write_output`.
//!
//! A guest written to the standard, such as a C guest or an EIP-8025 guest built through ere's
//! platform crate, reads its private input as one block and writes its public output as the
//! concatenation of every `write_output` call. On the host, `pico_prover::Stdin::from_input`
//! hands over the block, and the run's committed bytes are the output.
//!
//! **Input.** The block is the next element of the input stream. The first `read_input` call reads
//! it into a buffer of its own, and every later call returns the same pointer and length.
//! Reading on the first call, not in `_start`, leaves the stream alone for a guest that never
//! calls `read_input`, so a Rust guest on `pico_sdk::io::read_vec` still reads from the first
//! element. The buffer comes from the bump allocator, so a C guest needs no allocator of its own.
//! The input can be as large as what is left of the heap (`pico.ld`'s `_heap_start` to
//! `_heap_end`) when `read_input` first runs. With no element left, the run fails
//! (`EmulationError::InsufficientInput`): the host always hands over one, empty for an empty input.
//!
//! **Output.** `write_output` writes to the public-values descriptor, like
//! `pico_sdk::io::commit_bytes`. The bytes therefore go into the SHA-256 that `_start` commits at
//! the halt.

/// The input block: read on the first call, the same pointer and length on every call.
#[cfg(target_os = "zkvm")]
pub(crate) fn input_block() -> (*const u8, usize) {
    use pico_patch_libs::{sys_alloc_aligned, syscall_hint_len, syscall_hint_read};

    /// The block, once read. The guest has one thread.
    static mut INPUT: Option<(*const u8, usize)> = None;

    // SAFETY: one thread, and the buffer is neither freed nor written after the read.
    unsafe {
        if let Some(block) = core::ptr::addr_of!(INPUT).read() {
            return block;
        }
        let len = syscall_hint_len();
        // `HINT_READ` needs an 8-byte-aligned destination that nothing has written, which the bump
        // allocator's fresh memory is. At least one word, so that an empty block has a real
        // pointer too.
        let ptr = sys_alloc_aligned(len.div_ceil(8).max(1) * 8, 8);
        syscall_hint_read(ptr, len);
        core::ptr::addr_of_mut!(INPUT).write(Some((ptr, len)));
        (ptr, len)
    }
}

#[cfg(not(target_os = "zkvm"))]
pub(crate) fn input_block() -> (*const u8, usize) {
    unreachable!("the input exists only on the zkVM target")
}

/// `void read_input(const uint8_t** buf_ptr, size_t* buf_size)`: the private input, whole.
///
/// # Safety
///
/// `buf_ptr` and `buf_size` must be valid for writes.
#[cfg(target_os = "zkvm")]
#[no_mangle]
pub unsafe extern "C" fn read_input(buf_ptr: *mut *const u8, buf_size: *mut usize) {
    let (ptr, len) = input_block();
    *buf_ptr = ptr;
    *buf_size = len;
}

/// `void write_output(const uint8_t* output, size_t size)`: appends `size` bytes to the public
/// output.
///
/// # Safety
///
/// `output` must be valid for `size` bytes of reads. With `size` 0 it may be anything, NULL
/// included.
#[cfg(target_os = "zkvm")]
#[no_mangle]
pub unsafe extern "C" fn write_output(output: *const u8, size: usize) {
    // `syscall_write` hashes the bytes through a slice, and a slice may not start at NULL even
    // when it is empty; `write_output(NULL, 0)` is allowed.
    if size == 0 {
        return;
    }
    pico_patch_libs::syscall_write(pico_patch_libs::io::FD_PUBLIC_VALUES, output, size);
}
