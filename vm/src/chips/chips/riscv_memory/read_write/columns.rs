use crate::{
    chips::{
        chips::{riscv_cpu::event::CpuEvent, riscv_memory::event::MemoryRecordEnum},
        ffi::FfiOption,
    },
    compiler::{riscv::opcode::Opcode, word::Word},
    primitives::consts::MEMORY_RW_DATAPAR,
};
use p3_field::Field;
use pico_derive::AlignedBorrow;
use std::mem::size_of;

// RISC-V X0 register
const REGISTER_X0: u8 = 0;

pub const NUM_MEMORY_CHIP_COLS: usize = size_of::<MemoryChipCols<u8>>();

#[derive(AlignedBorrow, Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct MemoryChipCols<F> {
    pub values: [MemoryChipValueCols<F>; MEMORY_RW_DATAPAR],
}

pub const NUM_MEMORY_CHIP_VALUE_COLS: usize = size_of::<MemoryChipValueCols<u8>>();

// Pinned on both sides: the CUDA mirror (pico-gpu's `src/tracegen/riscv/memory_read_write.cuh`,
// and the second hand-written mirror in `src/tracegen/riscv/packed_tracegen.cuh`) asserts the
// same width, so a field added or removed on one side only fails the build instead of silently
// shifting every column.
const _: () = assert!(NUM_MEMORY_CHIP_VALUE_COLS == 49);

#[derive(AlignedBorrow, Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct MemoryChipValueCols<F> {
    /// The current chunk
    pub chunk: F,
    /// The clock cycle value for memory offset
    pub clk: F,

    // ---- Address (2 u16 limbs: the guest address space lies below 2^32) ----
    /// The full unaligned address as 2 u16 limbs:
    /// addr_word[0] + addr_word[1]*2^16 = full 32-bit address.
    ///
    /// Limbs 2 and 3 (bits 32..64) are not materialized. The addition op_b + op_c is proven
    /// in-chip by a carry chain whose 3rd and 4th result limbs are literal 0s (see
    /// `eval_memory_address_and_access`); the carries are expressions, not columns, and the
    /// chain has no solution when the true sum's upper half is non-zero (fail-closed: an access
    /// at an address of 2^32 or above cannot be proven, and trace generation asserts the same
    /// bound). Limb 1 is U16Range-checked in-chip; limb 0 is bounded by the BitRange(13) offset
    /// lookup.
    ///
    /// The aligned lookup address is no longer a materialized `addr_aligned` witness.
    /// It is derived in-constraint as `[addr_word[0] - offset_sum, addr_word[1], 0]`
    /// (degree 1), so it is bound to this add-checked `addr_word` and cannot be forged.
    pub addr_word: [F; 2],

    /// The 3 binary offset bits: addr[0] & 1, (addr[0]>>1) & 1, (addr[0]>>2) & 1.
    /// These replace the old one-hot offset_is_one/two/three flags.
    ///
    /// The one-hot limb selector `[(1-bit1)(1-bit2), bit1(1-bit2), (1-bit1)bit2, bit1 bit2]`
    /// is not committed: the constraints use those degree-2 products directly
    /// (`MemoryReadWriteChip::limb_select_exprs`), and every consumer multiplies a selector
    /// entry by one more degree-1 factor at most, so the degree bound of 3 holds.
    pub offset_bit: [F; 3],

    /// Inverse of addr_word[1] for the stack guard constraint
    /// `addr_limb1_inv * addr_word[1] == is_mem`: a real access has a non-zero limb 1, i.e. an
    /// address >= 2^16 (not in register space). Zero on padding rows.
    pub addr_limb1_inv: F,

    // ---- Memory access ----
    /// The data access. Lite layout: no committed `prev_clk`, the AIR defines it from the two
    /// difference limbs (see `MemoryAccessLiteCols`).
    pub memory_access: MemoryReadWriteLiteCols<F>,

    // ---- Load auxiliary columns ----
    /// The u16 limb selected by (bit1, bit2) from the memory value (ungated definition, so it
    /// is `prev[0]` on padding rows). Used by LB/LBU/LH/LHU/SB/SH, and as the low half of an
    /// LW/LWU result: word alignment forces bit1 = 0 there, so the selected limb is exactly
    /// `(1-bit2)*prev[0] + bit2*prev[2]`.
    pub selected_limb: F,
    /// LB: the final selected byte (from bit0 selection)
    pub selected_byte: F,
    /// The MSB (sign bit) extracted from the selected sub-word.
    /// LB: bit7 of selected_byte. LH: bit15 of selected_limb. LW: bit15 of lhw_val.
    pub msb: F,
    /// Shared U16MSB operand -- `selected_limb` on LH rows, the high half of the selected word
    /// `(1-bit2)*prev[1] + bit2*prev[3]` on LW *and* LWU rows, `256 * selected_byte` on LB rows
    /// (when-gated definitions), 0 elsewhere. It also feeds the LW/LWU limb-1 load value. Lets
    /// LH, LW and LB share ONE U16Range lookup (`2*lhw_val - msb*2^16`, mult
    /// `is_lh + is_lw + is_lb`) instead of one each: the lookup message must stay affine, so
    /// the mux lives in a committed column rather than a flag-weighted expression.
    pub lhw_val: F,

    // ---- Store auxiliary columns ----
    /// SB: the low byte of the register value (`op_a[0] & 0xFF`), pinned by the U8Range lookup
    /// on `(register_low_byte, (op_a[0] - register_low_byte) / 256)`; unconstrained on every
    /// other row (trace generation writes 0).
    pub register_low_byte: F,
    /// The low byte of the selected memory limb: the limb an SB row modifies, or the limb an
    /// LB/LBU row reads. One U8Range lookup on `(mem_limb_low_byte, (selected_limb -
    /// mem_limb_low_byte) / 256)` with count `is_sb + is_lb + is_lbu` pins the split on all
    /// three row kinds.
    pub mem_limb_low_byte: F,
    /// The value added to the selected limb by a sub-limb store, pinned by an ungated
    /// definition: `is_sh*(op_a[0] - selected_limb) + is_sb*increment`, where `increment` is the
    /// SB byte patch `(1-bit0)*(reg_low - mem_low) + bit0*(256*reg_low - selected_limb +
    /// mem_low)`. Zero on load, SW/SD and padding rows; may be a field-negative value on SH/SB
    /// rows. Committed so the four unified store equations stay at degree 3 with the degree-2
    /// limb selector.
    pub shift: F,
    // `store_value` is de-materialized. One unified equation per limb pins the committed
    // post-store value `memory_access.value()` for SB/SH/SW/SD and loads alike; the old
    // "store_value == value" bridging constraint is gone with it.

    // ---- Load result ----
    // `unsigned_mem_val` is de-materialized. One unified equation per limb pins op_a to
    // the loaded value (variant selected by the one-hot flags, sign extension by `msb`); see
    // eval_memory_load.
    /// Memory instructions
    pub instruction: MemoryInstructionCols<F>,
}

impl<F: Copy> MemoryChipValueCols<F> {
    /// Gets the value of the first operand.
    pub fn op_a_val(&self) -> Word<F> {
        self.instruction.op_a_val()
    }

    /// Gets the value of the second operand.
    pub fn op_b_val(&self) -> Word<F> {
        self.instruction.op_b_val()
    }

    /// Gets the value of the third operand.
    pub fn op_c_val(&self) -> Word<F> {
        self.instruction.op_c_val()
    }
}

#[derive(AlignedBorrow, Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct MemoryInstructionCols<T> {
    /// The `opcode` column is de-materialized. The dispatch-lookup message
    /// element is the degree-1 expression sum(flag_i * OPCODE_i) (see
    /// `MemoryReadWriteChip::opcode_expr`), which the lookup balance binds to the Cpu
    /// chip's program-backed opcode; the flag one-hot constraints make that binding
    /// uniquely identify the variant. Padding rows have expression 0 and multiplicity 0.

    /// Flags to indicate if op_a is register 0.
    pub op_a_0: T,

    /// Memory Instructions.
    pub is_lb: T,
    pub is_lbu: T,
    pub is_lh: T,
    pub is_lhu: T,
    pub is_lw: T,
    pub is_lwu: T, // New for RV64
    pub is_ld: T,  // New for RV64
    pub is_sb: T,
    pub is_sh: T,
    pub is_sw: T,
    pub is_sd: T, // New for RV64

    /// Register-operand values.
    ///
    /// These used to be full `MemoryReadWriteCols`/`MemoryReadCols` access structs
    /// (31 cols), but only the 4-limb value words were ever constrained here: the
    /// register accesses themselves are proven on the Cpu chip's rows, and the
    /// values are bound to the Cpu chip via the 17-wide dispatch lookup. The
    /// unused prev_value/timestamp aux columns (19 cols) were dead weight.
    pub op_a_value: Word<T>,
    pub op_b_value: Word<T>,
    pub op_c_value: Word<T>,
}

impl<F: Field> MemoryInstructionCols<F> {
    pub fn populate(&mut self, event: &CpuEvent) {
        let opcode = event.instruction.opcode;
        self.op_a_0 = F::from_bool(event.instruction.op_a == REGISTER_X0);

        match opcode {
            Opcode::LB => self.is_lb = F::ONE,
            Opcode::LBU => self.is_lbu = F::ONE,
            Opcode::LHU => self.is_lhu = F::ONE,
            Opcode::LH => self.is_lh = F::ONE,
            Opcode::LW => self.is_lw = F::ONE,
            Opcode::LWU => self.is_lwu = F::ONE,
            Opcode::LD => self.is_ld = F::ONE,
            Opcode::SB => self.is_sb = F::ONE,
            Opcode::SH => self.is_sh = F::ONE,
            Opcode::SW => self.is_sw = F::ONE,
            Opcode::SD => self.is_sd = F::ONE,
            _ => unreachable!(),
        }

        // For u64 upgrade: values are no longer narrowed to u32.
        // op_a/b/c are now native u64 → Word (4×u16).
        self.op_a_value = event.a.into();
        self.op_b_value = event.b.into();
        self.op_c_value = event.c.into();

        // Overwrite with the memory-record values for a, b, and c. The dispatch
        // lookup binds these to the Cpu chip's committed operand values, which
        // are record-derived, so the same record values must be committed here.
        if let FfiOption::Some(record) = event.a_record {
            self.op_a_value = record.value().into();
        }
        if let FfiOption::Some(MemoryRecordEnum::Read(record)) = event.b_record {
            self.op_b_value = record.value.into();
        }
        if let FfiOption::Some(MemoryRecordEnum::Read(record)) = event.c_record {
            self.op_c_value = record.value.into();
        }
    }
}

impl<T: Copy> MemoryInstructionCols<T> {
    /// Gets the value of the first operand.
    pub fn op_a_val(&self) -> Word<T> {
        self.op_a_value
    }

    /// Gets the value of the second operand.
    pub fn op_b_val(&self) -> Word<T> {
        self.op_b_value
    }

    /// Gets the value of the third operand.
    pub fn op_c_val(&self) -> Word<T> {
        self.op_c_value
    }
}

/// Memory read access.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy, Eq, PartialEq)]
#[repr(C)]
pub struct MemoryReadCols<T> {
    pub access: MemoryAccessCols<T>,
}

/// Memory write access.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy, Eq, PartialEq)]
#[repr(C)]
pub struct MemoryWriteCols<T> {
    pub prev_value: Word<T>,
    pub access: MemoryAccessCols<T>,
}

/// Memory read-write access.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy, Eq, PartialEq)]
#[repr(C)]
pub struct MemoryReadWriteCols<T> {
    pub prev_value: Word<T>,
    pub access: MemoryAccessCols<T>,
}

#[derive(AlignedBorrow, Default, Debug, Clone, Copy, Eq, PartialEq)]
#[repr(C)]
#[allow(clippy::empty_line_after_doc_comments)]
pub struct MemoryAccessCols<T> {
    /// The value of the memory access.
    pub value: Word<T>,

    /// The `clk` of the previous access to this address, **within this chunk**.
    ///
    /// The previous access's `chunk` is no longer committed, and neither is a flag selecting
    /// which of the two to compare: the previous access is always in this chunk, so the
    /// comparison is unconditionally on `clk`. When the previous access was in an *earlier*
    /// chunk there is no in-chunk predecessor to name, and this carries the sentinel `0` —
    /// which is exactly the label `MemoryLocalChip` puts on the state a chunk inherits.
    /// `CHUNK_CLK_START` keeps every real access above the sentinel.
    pub prev_clk: T,

    /// The least significant 16 bit limb of `clk - prev_clk - 1`.
    pub diff_16bit_limb: T,

    /// Bits 16..25 of that difference, in a single 9-bit limb range-checked via `BitRange(9)`.
    /// Together with the 16-bit limb this pins the difference to the 25-bit chunk-clk budget.
    pub diff_hi9: T,
}

/// The common columns for all memory access types.
pub trait MemoryCols<T> {
    fn access(&self) -> &MemoryAccessCols<T>;

    fn access_mut(&mut self) -> &mut MemoryAccessCols<T>;

    fn prev_value(&self) -> &Word<T>;

    fn prev_value_mut(&mut self) -> &mut Word<T>;

    fn value(&self) -> &Word<T>;

    fn value_mut(&mut self) -> &mut Word<T>;
}

impl<T> MemoryCols<T> for MemoryReadCols<T> {
    fn access(&self) -> &MemoryAccessCols<T> {
        &self.access
    }

    fn access_mut(&mut self) -> &mut MemoryAccessCols<T> {
        &mut self.access
    }

    fn prev_value(&self) -> &Word<T> {
        &self.access.value
    }

    fn prev_value_mut(&mut self) -> &mut Word<T> {
        &mut self.access.value
    }

    fn value(&self) -> &Word<T> {
        &self.access.value
    }

    fn value_mut(&mut self) -> &mut Word<T> {
        &mut self.access.value
    }
}

impl<T> MemoryCols<T> for MemoryWriteCols<T> {
    fn access(&self) -> &MemoryAccessCols<T> {
        &self.access
    }

    fn access_mut(&mut self) -> &mut MemoryAccessCols<T> {
        &mut self.access
    }

    fn prev_value(&self) -> &Word<T> {
        &self.prev_value
    }

    fn prev_value_mut(&mut self) -> &mut Word<T> {
        &mut self.prev_value
    }

    fn value(&self) -> &Word<T> {
        &self.access.value
    }

    fn value_mut(&mut self) -> &mut Word<T> {
        &mut self.access.value
    }
}

impl<T> MemoryCols<T> for MemoryReadWriteCols<T> {
    fn access(&self) -> &MemoryAccessCols<T> {
        &self.access
    }

    fn access_mut(&mut self) -> &mut MemoryAccessCols<T> {
        &mut self.access
    }

    fn prev_value(&self) -> &Word<T> {
        &self.prev_value
    }

    fn prev_value_mut(&mut self) -> &mut Word<T> {
        &mut self.prev_value
    }

    fn value(&self) -> &Word<T> {
        &self.access.value
    }

    fn value_mut(&mut self) -> &mut Word<T> {
        &mut self.access.value
    }
}

// ---------------------------------------------------------------------------
// Lite access layout: no committed `prev_clk` (Cpu register accesses, MemoryReadWrite)
// ---------------------------------------------------------------------------

/// Memory read access without a committed `prev_clk`.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy, Eq, PartialEq)]
#[repr(C)]
pub struct MemoryReadLiteCols<T> {
    pub access: MemoryAccessLiteCols<T>,
}

/// Memory read-write access without a committed `prev_clk`.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy, Eq, PartialEq)]
#[repr(C)]
pub struct MemoryReadWriteLiteCols<T> {
    pub prev_value: Word<T>,
    pub access: MemoryAccessLiteCols<T>,
}

/// [`MemoryAccessCols`] without the `prev_clk` column.
///
/// The previous access's clk is not a witness: the AIR defines it from the two difference
/// limbs as `clk - (diff_16bit_limb + diff_hi9 * 2^16) - 1`
/// (`RiscVMemoryBuilder::eval_memory_access_lite`), so no decomposition equation is needed and
/// the two range lookups carry the timestamp argument alone. Trace generation computes the same
/// in-chunk predecessor clk
/// (sentinel `0` when the previous touch was in an earlier chunk) and commits only its
/// difference from `clk`.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy, Eq, PartialEq)]
#[repr(C)]
pub struct MemoryAccessLiteCols<T> {
    /// The value of the memory access.
    pub value: Word<T>,

    /// The least significant 16 bit limb of `clk - prev_clk - 1`.
    pub diff_16bit_limb: T,

    /// Bits 16..25 of that difference, in a single 9-bit limb range-checked via `BitRange(9)`.
    pub diff_hi9: T,
}

/// The common columns for the lite memory access types.
pub trait MemoryLiteCols<T> {
    fn access(&self) -> &MemoryAccessLiteCols<T>;

    fn access_mut(&mut self) -> &mut MemoryAccessLiteCols<T>;

    fn prev_value(&self) -> &Word<T>;

    fn prev_value_mut(&mut self) -> &mut Word<T>;

    fn value(&self) -> &Word<T>;

    fn value_mut(&mut self) -> &mut Word<T>;
}

impl<T> MemoryLiteCols<T> for MemoryReadLiteCols<T> {
    fn access(&self) -> &MemoryAccessLiteCols<T> {
        &self.access
    }

    fn access_mut(&mut self) -> &mut MemoryAccessLiteCols<T> {
        &mut self.access
    }

    fn prev_value(&self) -> &Word<T> {
        &self.access.value
    }

    fn prev_value_mut(&mut self) -> &mut Word<T> {
        &mut self.access.value
    }

    fn value(&self) -> &Word<T> {
        &self.access.value
    }

    fn value_mut(&mut self) -> &mut Word<T> {
        &mut self.access.value
    }
}

impl<T> MemoryLiteCols<T> for MemoryReadWriteLiteCols<T> {
    fn access(&self) -> &MemoryAccessLiteCols<T> {
        &self.access
    }

    fn access_mut(&mut self) -> &mut MemoryAccessLiteCols<T> {
        &mut self.access
    }

    fn prev_value(&self) -> &Word<T> {
        &self.prev_value
    }

    fn prev_value_mut(&mut self) -> &mut Word<T> {
        &mut self.prev_value
    }

    fn value(&self) -> &Word<T> {
        &self.access.value
    }

    fn value_mut(&mut self) -> &mut Word<T> {
        &mut self.access.value
    }
}

/// A utility method to convert a slice of memory access columns into a vector of values.
/// This is useful for comparing the values of a memory access to limbs.
pub fn value_as_limbs<T: Clone, M: MemoryCols<T>>(memory: &[M]) -> Vec<T> {
    memory
        .iter()
        .flat_map(|m| m.value().clone().into_iter())
        .collect()
}

// ---------------------------------------------------------------------------
// U8 wrapper types for precompile chips (Method B)
// ---------------------------------------------------------------------------

use crate::chips::gadgets::u16_to_u8::U16ToU8Gadget;

/// Memory write access with U16→U8 auxiliary columns.
///
/// Used by precompile chips (e.g. WeierstrassAdd) that need byte-level limbs
/// from u16 word values. The `prev_value_u8` gadget stores the low bytes of
/// the previous value's u16 limbs; the high bytes are derived in eval via
/// `(u16_limb - low_byte) / 256`.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy, Eq, PartialEq)]
#[repr(C)]
pub struct MemoryWriteColsU8<T> {
    pub inner: MemoryWriteCols<T>,
    pub prev_value_u8: U16ToU8Gadget<T>,
}

/// Memory read access with U16→U8 auxiliary columns.
///
/// Same pattern as `MemoryWriteColsU8` but for read-only access.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy, Eq, PartialEq)]
#[repr(C)]
pub struct MemoryReadColsU8<T> {
    pub inner: MemoryReadCols<T>,
    pub prev_value_u8: U16ToU8Gadget<T>,
}
