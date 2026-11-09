// Copyright 2023 RISC Zero, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// The heap `pico.ld` reserves, between the program image and the stack guard: `_heap_start` to
// `_heap_end`. One bump pointer serves both the Rust allocator (`sys_alloc_aligned`) and a C
// library's `malloc` (through `sbrk`, in `c_runtime`), so the two never hand out the same memory.
extern "C" {
    static _heap_start: u8;
    static _heap_end: u8;
}

/// The next free heap address, or 0 before the first allocation. The guest has one thread.
static mut HEAP_POS: usize = 0;

fn heap_pos() -> usize {
    // SAFETY: one thread; `HEAP_POS` is only read and written here and in `set_heap_pos`.
    match unsafe { core::ptr::addr_of!(HEAP_POS).read() } {
        0 => unsafe { (&_heap_start) as *const u8 as usize },
        pos => pos,
    }
}

fn set_heap_pos(pos: usize) {
    unsafe { core::ptr::addr_of_mut!(HEAP_POS).write(pos) }
}

fn heap_end() -> usize {
    unsafe { (&_heap_end) as *const u8 as usize }
}

#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn sys_alloc_aligned(bytes: usize, align: usize) -> *mut u8 {
    let mut heap_pos = heap_pos();

    let offset = heap_pos & (align - 1);
    if offset != 0 {
        heap_pos += align - offset;
    }

    let ptr = heap_pos as *mut u8;
    let (heap_pos, overflowed) = heap_pos.overflowing_add(bytes);

    if overflowed || heap_end() < heap_pos {
        // Not a panic: the panic machinery may allocate. Report it and halt as out of memory.
        const MSG: &str = "Memory limit exceeded: the heap is full\n";
        super::sys_write(2, MSG.as_ptr(), MSG.len());
        super::halt_with_reason(super::exit_code::ABORT, super::halt_reason::OUT_OF_MEMORY);
    }

    set_heap_pos(heap_pos);
    ptr
}

/// `sbrk(increment)` over the same bump pointer: the old break, or `None` if the heap cannot grow
/// by `increment`. A negative increment is refused: what lies below the break may be the Rust
/// allocator's, which never gives memory back.
#[cfg(target_os = "zkvm")]
pub(crate) fn sbrk(increment: isize) -> Option<*mut u8> {
    let pos = heap_pos();
    let increment = usize::try_from(increment).ok()?;
    let end = pos
        .checked_add(increment)
        .filter(|&end| end <= heap_end())?;
    set_heap_pos(end);
    Some(pos as *mut u8)
}
