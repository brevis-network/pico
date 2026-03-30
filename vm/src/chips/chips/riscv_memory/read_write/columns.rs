use crate::{
    chips::chips::{riscv_cpu::event::CpuEvent, riscv_memory::event::MemoryRecordEnum},
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

#[derive(AlignedBorrow, Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct MemoryChipValueCols<F> {
    /// The current chunk
    pub chunk: F,
    /// The clock cycle value for memory offset
    pub clk: F,

    // ---- Address (upgraded: scalar u32 → 3×u16 limbs) ----
    /// The full unaligned address as 3 u16 limbs.
    /// addr[0] + addr[1]*2^16 + addr[2]*2^32 = full 48-bit address.
    /// NOTE: We store addr as a 4-limb Word from ALU ADD result, then extract the low 3 limbs.
    /// The 4th limb is constrained to be zero.
    pub addr_word: Word<F>,

    /// This is the aligned memory address used for memory lookups, it's muliple of 8, since uint64.
    /// TODO: add constraints to fix soundness
    pub addr_aligned: Word<F>,

    /// The 3 binary offset bits: addr[0] & 1, (addr[0]>>1) & 1, (addr[0]>>2) & 1.
    /// These replace the old one-hot offset_is_one/two/three flags.
    pub offset_bit: [F; 3],

    /// One-hot limb selector derived from (bit1, bit2).
    /// limb_select[0] = (1-bit1)*(1-bit2), limb_select[1] = bit1*(1-bit2),
    /// limb_select[2] = (1-bit1)*bit2, limb_select[3] = bit1*bit2.
    /// Pre-computed witness column to keep constraint degree ≤ 3.
    pub limb_select: [F; 4],

    /// Inverse of (addr[1] + addr[2]) for stack guard constraint.
    /// Ensures address >= 2^16 (not in register space).
    pub addr_top_two_limb_inv: F,

    // ---- Memory access (unchanged) ----
    pub memory_access: MemoryReadWriteCols<F>,

    // ---- Load auxiliary columns (new/changed) ----
    /// The u16 limb selected by (bit1, bit2) from memory value. Used by LB/LBU/LH/LHU/SB/SH.
    pub selected_limb: F,
    /// LB: low byte of selected_limb
    pub selected_limb_low_byte: F,
    /// LB: the final selected byte (from bit0 selection)
    pub selected_byte: F,
    /// LW: the 2 u16 limbs selected by bit2
    pub selected_word: [F; 2],
    /// The MSB (sign bit) extracted from the selected sub-word.
    /// LB: bit7 of selected_byte. LH: bit15 of selected_limb. LW: bit15 of selected_word[1].
    pub msb: F,

    // ---- Store auxiliary columns (new) ----
    /// SB: low byte of the register value (op_a[0] & 0xFF)
    pub register_low_byte: F,
    /// SB: low byte of the memory limb being modified
    pub mem_limb_low_byte: F,
    /// SB: the byte-level increment value
    pub increment: F,
    /// SB/SH/SW: the computed full store value after masking
    pub store_value: Word<F>,

    // ---- Load result (changed: Word is now 4×u16) ----
    /// The unsigned memory value after offset/sub-word selection logic.
    pub unsigned_mem_val: Word<F>,
    /// Flag: load instruction where value is positive and not writing to x0.
    pub mem_value_is_pos_not_x0: F,
    /// Flag: load instruction where value is negative and not writing to x0.
    pub mem_value_is_neg_not_x0: F,

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

    /// Gets the 3×u16 address from addr_word (low 3 limbs).
    pub fn addr(&self) -> [F; 3] {
        [
            self.addr_word.0[0],
            self.addr_word.0[1],
            self.addr_word.0[2],
        ]
    }
}

#[derive(AlignedBorrow, Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct MemoryInstructionCols<T> {
    /// The opcode for this cycle.
    pub opcode: T,

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

    pub op_a_access: MemoryReadWriteCols<T>,
    pub op_b_access: MemoryReadCols<T>,
    pub op_c_access: MemoryReadCols<T>,
}

impl<F: Field> MemoryInstructionCols<F> {
    pub fn populate(&mut self, event: &CpuEvent) {
        let opcode = event.instruction.opcode;
        self.opcode = opcode.as_field::<F>();
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
        *self.op_a_access.value_mut() = event.a.into();
        *self.op_b_access.value_mut() = event.b.into();
        *self.op_c_access.value_mut() = event.c.into();

        // Set memory accesses for a, b, and c.
        if let Some(record) = event.a_record {
            *self.op_a_access.value_mut() = record.value().into();
        }
        if let Some(MemoryRecordEnum::Read(record)) = event.b_record {
            *self.op_b_access.value_mut() = record.value.into();
        }
        if let Some(MemoryRecordEnum::Read(record)) = event.c_record {
            *self.op_c_access.value_mut() = record.value.into();
        }
    }
}

impl<T: Copy> MemoryInstructionCols<T> {
    /// Gets the value of the first operand.
    pub fn op_a_val(&self) -> Word<T> {
        *self.op_a_access.value()
    }

    /// Gets the value of the second operand.
    pub fn op_b_val(&self) -> Word<T> {
        *self.op_b_access.value()
    }

    /// Gets the value of the third operand.
    pub fn op_c_val(&self) -> Word<T> {
        *self.op_c_access.value()
    }
}

/// Memory read access.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct MemoryReadCols<T> {
    pub access: MemoryAccessCols<T>,
}

/// Memory write access.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct MemoryWriteCols<T> {
    pub prev_value: Word<T>,
    pub access: MemoryAccessCols<T>,
}

/// Memory read-write access.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct MemoryReadWriteCols<T> {
    pub prev_value: Word<T>,
    pub access: MemoryAccessCols<T>,
}

#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
#[allow(clippy::empty_line_after_doc_comments)]
pub struct MemoryAccessCols<T> {
    /// The value of the memory access.
    pub value: Word<T>,

    /// The previous chunk and timestamp that this memory access is being read from.
    pub prev_chunk: T,
    pub prev_clk: T,

    /// This will be true if the current chunk == prev_access's chunk, else false.
    pub compare_clk: T,

    /// The following columns are decomposed limbs for the difference between the current access's
    /// timestamp and the previous access's timestamp.  Note the actual value of the timestamp
    /// is either the accesses' chunk or clk depending on the value of compare_clk.

    /// This column is the least significant 16 bit limb of current access timestamp - prev access
    /// timestamp.
    pub diff_16bit_limb: T,

    /// This column is the most significant 8 bit limb of current access timestamp - prev access
    /// timestamp.
    pub diff_8bit_limb: T,
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
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct MemoryWriteColsU8<T> {
    pub inner: MemoryWriteCols<T>,
    pub prev_value_u8: U16ToU8Gadget<T>,
}

/// Memory read access with U16→U8 auxiliary columns.
///
/// Same pattern as `MemoryWriteColsU8` but for read-only access.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct MemoryReadColsU8<T> {
    pub inner: MemoryReadCols<T>,
    pub prev_value_u8: U16ToU8Gadget<T>,
}
