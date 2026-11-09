//! A store lands on no byte of the program's code.
//!
//! The emulator ends the run with `StoreToCode` when a store's bytes `[addr, addr + width)` meet
//! the code, `[code_start, code_end)`, and so does a precompile when a dword it writes does. The
//! chips that write guest memory refuse to prove such a write with these columns: either it ends at
//! or below the code's start, or it starts at or above its end. They are the two memory chips, one
//! check per store, and every precompile chip, one check over the contiguous dwords its event
//! writes. The code's range is the Program table's, which `program_commit` fixes, and a writing
//! row looks it up from there ([`code_range_lookups`] counts the lookups). The range is exact
//! rather than one-sided because a program built with an older runtime keeps its stack just under
//! the code.
//!
//! The distance from the store to the code is proven non-negative limb by limb. Addresses reach
//! `0x7800_0000` and KoalaBear's modulus is `0x7f00_0001`, so the difference of two addresses has
//! no single field element that tells its sign: every equation below stays within `2^18` of zero.

use crate::{
    chips::chips::byte::event::ByteRecordBehavior,
    compiler::riscv::opcode::ByteOpcode,
    emulator::riscv::{history_view::store_count, record::EmulationRecord},
    machine::{
        builder::{ChipBuilder, ChipLookupBuilder},
        lookup::{LookupScope, LookupType, SymbolicLookup},
    },
};
use core::ops::Range;
#[cfg(feature = "cuda")]
use cudart::{
    memory_pools::{CudaMemPool, DevicePoolAllocation},
    slice::{CudaSlice, CudaSliceMut},
    stream::CudaStream,
};
#[cfg(feature = "cuda")]
use cudart_sys::{cudaMemcpyAsync, CudaMemoryCopyKind};
use p3_air::AirBuilder;
use p3_field::{Field, PrimeCharacteristicRing};
#[cfg(feature = "cuda")]
use p3_koala_bear::KoalaBear;
use pico_derive::AlignedBorrow;
#[cfg(feature = "cuda")]
use pico_gpu_api::cuda_code_range_fill;

/// The columns of one store's check.
#[derive(AlignedBorrow, Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C)]
pub struct CodeRangeCols<T> {
    /// The code's first byte, as two u16 limbs: the Program table's.
    pub code_start: [T; 2],
    /// One past the code's last byte, as two u16 limbs: the Program table's.
    pub code_end: [T; 2],
    /// The store lies below the code; it lies at or above the code's end when 0.
    pub below: T,
    /// The borrow out of the distance's low limb: 0, 1, or 2 when a write that starts in the last
    /// bytes of a 64 KiB block runs past it.
    pub borrow: T,
    /// The distance from the store to the code, as two u16 limbs: `code_start - (addr + width)`
    /// below it, `addr - code_end` above it.
    pub distance: [T; 2],
}

/// The message a writing row sends to the Program table, which answers with the code's range: its
/// four limbs. Four elements, so it cannot meet the table's instruction messages on the bus.
pub fn code_range_message<E: Clone>(code_start: [E; 2], code_end: [E; 2]) -> Vec<E> {
    code_start.into_iter().chain(code_end).collect()
}

/// How many rows of `record` look the code's range up: one per store, aligned or not, and one per
/// precompile event, whose chip checks the dwords it writes on the event's one row (the controller
/// of SHA-256 and Keccak). The Program table answers all of them on its first row.
#[must_use]
pub fn code_range_lookups(record: &EmulationRecord) -> usize {
    store_count(record) + record.precompile_events.all_events().count()
}

/// The limbs of a 32-bit address.
fn limbs(value: u64) -> [u16; 2] {
    [value as u16, (value >> 16) as u16]
}

impl<F: Field> CodeRangeCols<F> {
    /// The check for a write of `width` bytes at `addr`, the code being `code`; `width` is below
    /// 2^16. A write that meets the code gets columns no assignment of which satisfies the AIR.
    pub fn populate(
        &mut self,
        addr: u64,
        width: u64,
        code: &Range<u64>,
        blu: &mut impl ByteRecordBehavior,
    ) {
        let (start, end) = (limbs(code.start), limbs(code.end));
        self.code_start = start.map(F::from_u16);
        self.code_end = end.map(F::from_u16);
        let below = addr + width <= code.start;
        // A store into the code has no non-negative distance: wrap, and the range checks then
        // refuse the row.
        let distance = if below {
            code.start.wrapping_sub(addr + width)
        } else {
            addr.wrapping_sub(code.end)
        };
        let (low, high) = (limbs(distance)[0], limbs(distance)[1]);
        let low_operand = if below {
            i64::from(start[0]) - (addr & 0xffff) as i64 - width as i64
        } else {
            (addr & 0xffff) as i64 - i64::from(end[0])
        };
        // What makes the low limb of the distance the low operand plus whole 2^16s.
        let borrow = ((i64::from(low) - low_operand) >> 16).clamp(0, 2);
        self.below = F::from_bool(below);
        self.borrow = F::from_u8(borrow as u8);
        self.distance = [F::from_u16(low), F::from_u16(high)];
        blu.add_u16_range_check(low);
        blu.add_u16_range_check(high);
    }

    /// Constrains a write of `width` bytes at `addr`, two u16 limbs, to lie off the code, on a row
    /// where `is_store` is 1. `width` is below 2^16, and `is_store` must be boolean; on other rows
    /// the columns are free, and the lookups send nothing.
    pub fn eval<CB: ChipBuilder<F>>(
        builder: &mut CB,
        cols: &CodeRangeCols<CB::Var>,
        addr: [CB::Expr; 2],
        width: CB::Expr,
        is_store: CB::Expr,
    ) {
        builder.looking(SymbolicLookup::new(
            code_range_message(cols.code_start, cols.code_end)
                .into_iter()
                .map(Into::into)
                .collect(),
            is_store.clone(),
            LookupType::Program,
            LookupScope::Regional,
        ));
        builder.assert_bool(cols.below);
        let borrow: CB::Expr = cols.borrow.into();
        builder.assert_zero(
            borrow.clone() * (borrow.clone() - CB::Expr::ONE) * (borrow - CB::Expr::TWO),
        );

        // The distance, limb by limb, on the side `below` names. With the limbs u16s, the width
        // below 2^16 and the borrow at most 2, each side of the two equations lies in
        // (-2^18, 2^18), so they hold in the integers, and `distance[0] + 2^16 distance[1]` is the
        // distance itself: a non-negative integer, once both limbs pass their range checks. A
        // borrow of 2 covers the lowest the low operand reaches, `-(2^16 - 1) - width`.
        let below: CB::Expr = cols.below.into();
        let above = CB::Expr::ONE - below.clone();
        let [addr_low, addr_high] = addr;
        let low = below.clone() * (CB::Expr::ZERO + cols.code_start[0] - addr_low.clone() - width)
            + above.clone() * (addr_low - cols.code_end[0]);
        let high = below * (CB::Expr::ZERO + cols.code_start[1] - addr_high.clone())
            + above * (addr_high - cols.code_end[1]);
        let two_16 = CB::Expr::from_u32(1 << 16);
        builder
            .when(is_store.clone())
            .assert_eq(cols.distance[0], low + two_16 * cols.borrow);
        builder
            .when(is_store.clone())
            .assert_eq(cols.distance[1], high - cols.borrow);
        for limb in cols.distance {
            builder.looking_rangecheck(
                ByteOpcode::U16Range,
                limb,
                CB::Expr::ZERO,
                CB::Expr::ZERO,
                CB::Expr::ZERO,
                is_store.clone(),
            );
        }
    }
}

/// The columns [`fill_on_device`] fills.
pub const NUM_CODE_RANGE_COLS: usize = core::mem::size_of::<CodeRangeCols<u8>>();

/// A precompile kernel's own columns: each `width`-wide row of `values` without the code range at
/// column `offset`, which [`fill_on_device`] writes after the kernel. A test that runs a chip's
/// kernel alone holds these to the host's trace; `device_code_ranges_are_the_hosts` holds the fill.
#[cfg(all(test, feature = "cuda"))]
pub(crate) fn kernel_columns<T: Copy>(values: &[T], width: usize, offset: usize) -> Vec<T> {
    values
        .chunks(width)
        .flat_map(|row| {
            row[..offset]
                .iter()
                .chain(&row[offset + NUM_CODE_RANGE_COLS..])
                .copied()
        })
        .collect()
}

/// A precompile's code range, filled on the device after its kernel: row `i`'s
/// [`CodeRangeCols`], at column `offset` of `d_trace`, for the write of `width` bytes from
/// `writes[i]`, the distance's range checks added to `d_byte_trace`. A precompile kernel leaves
/// these columns, the last of its chip's own, zero, and its CUDA mirror stops short of them; the
/// values are [`CodeRangeCols::populate`]'s, so the trace is the host's.
#[cfg(feature = "cuda")]
#[allow(clippy::too_many_arguments)]
pub fn fill_on_device(
    d_trace: &mut DevicePoolAllocation<'_, KoalaBear>,
    num_cols: usize,
    offset: usize,
    writes: &[u64],
    width: u64,
    code: &Range<u64>,
    d_byte_trace: &mut DevicePoolAllocation<'_, KoalaBear>,
    pool: &CudaMemPool,
    stream: &CudaStream,
) {
    if writes.is_empty() {
        return;
    }
    let mut d_writes =
        DevicePoolAllocation::<u64>::alloc_from_pool_async(writes.len(), pool, stream).unwrap();
    let err = unsafe {
        let _ = cudaMemcpyAsync(
            d_writes.as_mut_c_void_ptr(),
            writes.as_c_void_ptr(),
            size_of_val(writes),
            CudaMemoryCopyKind::HostToDevice,
            stream.into(),
        );
        cuda_code_range_fill(
            d_trace.as_mut_ptr() as *mut _,
            num_cols,
            offset,
            d_writes.as_ptr() as *const _,
            writes.len(),
            width,
            code.start,
            code.end,
            d_byte_trace.as_mut_ptr() as *mut _,
            stream.into(),
        )
    };
    assert_eq!(err.code, 0, "cuda_code_range_fill failed: {err}");
    // `d_writes` is freed on `stream`, behind the fill.
}
