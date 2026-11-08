//! libatomic's `__atomic_*` functions for the guest. The toolchain's prebuilt `std` calls them,
//! since the target has no `A` extension and that `std` was not built with `lower-atomic`. A guest
//! runs on one thread, so each is a plain read or write. Weak, so a guest that links its own
//! libatomic keeps it. Goes away once the toolchain's `std` is built with `-C passes=lower-atomic`.

macro_rules! atomics {
    ($t:ty, $load:ident, $store:ident, $exchange:ident, $cas:ident,
     $add:ident, $sub:ident, $and:ident, $or:ident, $xor:ident, $nand:ident) => {
        #[no_mangle]
        #[linkage = "weak"]
        pub unsafe extern "C" fn $load(ptr: *const $t, _order: i32) -> $t {
            ptr.read_volatile()
        }

        #[no_mangle]
        #[linkage = "weak"]
        pub unsafe extern "C" fn $store(ptr: *mut $t, value: $t, _order: i32) {
            ptr.write_volatile(value)
        }

        #[no_mangle]
        #[linkage = "weak"]
        pub unsafe extern "C" fn $exchange(ptr: *mut $t, value: $t, _order: i32) -> $t {
            let old = ptr.read_volatile();
            ptr.write_volatile(value);
            old
        }

        #[no_mangle]
        #[linkage = "weak"]
        pub unsafe extern "C" fn $cas(
            ptr: *mut $t,
            expected: *mut $t,
            desired: $t,
            _success: i32,
            _failure: i32,
        ) -> bool {
            let old = ptr.read_volatile();
            if old == expected.read() {
                ptr.write_volatile(desired);
                true
            } else {
                expected.write(old);
                false
            }
        }

        atomics!(@rmw $t, $add, |a: $t, b: $t| a.wrapping_add(b));
        atomics!(@rmw $t, $sub, |a: $t, b: $t| a.wrapping_sub(b));
        atomics!(@rmw $t, $and, |a: $t, b: $t| a & b);
        atomics!(@rmw $t, $or, |a: $t, b: $t| a | b);
        atomics!(@rmw $t, $xor, |a: $t, b: $t| a ^ b);
        atomics!(@rmw $t, $nand, |a: $t, b: $t| !(a & b));
    };
    (@rmw $t:ty, $name:ident, $op:expr) => {
        /// Returns the value before the operation.
        #[no_mangle]
        #[linkage = "weak"]
        pub unsafe extern "C" fn $name(ptr: *mut $t, value: $t, _order: i32) -> $t {
            let old = ptr.read_volatile();
            ptr.write_volatile($op(old, value));
            old
        }
    };
}

atomics!(
    u8,
    __atomic_load_1,
    __atomic_store_1,
    __atomic_exchange_1,
    __atomic_compare_exchange_1,
    __atomic_fetch_add_1,
    __atomic_fetch_sub_1,
    __atomic_fetch_and_1,
    __atomic_fetch_or_1,
    __atomic_fetch_xor_1,
    __atomic_fetch_nand_1
);
atomics!(
    u16,
    __atomic_load_2,
    __atomic_store_2,
    __atomic_exchange_2,
    __atomic_compare_exchange_2,
    __atomic_fetch_add_2,
    __atomic_fetch_sub_2,
    __atomic_fetch_and_2,
    __atomic_fetch_or_2,
    __atomic_fetch_xor_2,
    __atomic_fetch_nand_2
);
atomics!(
    u32,
    __atomic_load_4,
    __atomic_store_4,
    __atomic_exchange_4,
    __atomic_compare_exchange_4,
    __atomic_fetch_add_4,
    __atomic_fetch_sub_4,
    __atomic_fetch_and_4,
    __atomic_fetch_or_4,
    __atomic_fetch_xor_4,
    __atomic_fetch_nand_4
);
atomics!(
    u64,
    __atomic_load_8,
    __atomic_store_8,
    __atomic_exchange_8,
    __atomic_compare_exchange_8,
    __atomic_fetch_add_8,
    __atomic_fetch_sub_8,
    __atomic_fetch_and_8,
    __atomic_fetch_or_8,
    __atomic_fetch_xor_8,
    __atomic_fetch_nand_8
);

// libatomic's generic forms, which C reaches for an object of any size; Rust never emits them.

/// Copies the `size` bytes at `src` to `dest`.
#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn __atomic_load(size: usize, src: *const u8, dest: *mut u8, _order: i32) {
    core::ptr::copy(src, dest, size)
}

/// Copies the `size` bytes at `src` to `dest`.
#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn __atomic_store(size: usize, dest: *mut u8, src: *const u8, _order: i32) {
    core::ptr::copy(src, dest, size)
}

/// Copies the `size` bytes at `ptr` to `ret`, then those at `value` to `ptr`.
#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn __atomic_exchange(
    size: usize,
    ptr: *mut u8,
    value: *const u8,
    ret: *mut u8,
    _order: i32,
) {
    core::ptr::copy(ptr, ret, size);
    core::ptr::copy(value, ptr, size)
}

/// Writes `desired` to `ptr` if its `size` bytes equal `expected`'s; otherwise copies them to
/// `expected`. Returns whether it wrote.
#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn __atomic_compare_exchange(
    size: usize,
    ptr: *mut u8,
    expected: *mut u8,
    desired: *const u8,
    _success: i32,
    _failure: i32,
) -> bool {
    let current = core::slice::from_raw_parts(ptr, size);
    if current == core::slice::from_raw_parts(expected, size) {
        core::ptr::copy(desired, ptr, size);
        true
    } else {
        core::ptr::copy(ptr, expected, size);
        false
    }
}

/// Every size is lock-free on one thread.
#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn __atomic_is_lock_free(_size: usize, _ptr: *const u8) -> bool {
    true
}
