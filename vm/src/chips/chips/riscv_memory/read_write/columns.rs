use crate::{
    chips::{
        chips::{riscv_cpu::event::CpuEvent, riscv_memory::event::MemoryRecordEnum},
        gadgets::field_range_check::word_range::FieldWordRangeChecker,
    },
    compiler::{riscv::opcode::Opcode, word::Word},
    primitives::consts::MEMORY_RW_DATAPAR,
};
use p3_field::Field;
use pico_derive::AlignedBorrow;
use std::mem::size_of;

// RISC-V X0 register
const REGISTER_X0: u32 = 0;

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

    // An addr that we are reading from or writing to as a word. We are guaranteed that this does
    // not overflow the field when reduced.

    // The relationships among addr_word, addr_aligned, and addr_offset is as follows:
    // addr_aligned = addr_word - addr_offset
    // addr_offset = addr_word % 4
    // Note that this all needs to be verified in the AIR
    pub addr_word: Word<F>,
    pub addr_word_range_checker: FieldWordRangeChecker<F>,
    pub addr_aligned: F,

    /// The LE bit decomp of the least significant byte of address aligned.
    pub aa_least_sig_byte_decomp: [F; 6],
    pub addr_offset: F,

    pub memory_access: MemoryReadWriteCols<F>,
    pub offset_is_one: F,
    pub offset_is_two: F,
    pub offset_is_three: F,

    // LE bit decomposition for the most significant byte of memory value.  This is used to
    // determine the sign for that value (used for LB and LH).
    pub most_sig_byte_decomp: [F; 8],

    /// The unsigned memory value is the value after the offset logic is applied. Used for the load
    /// memory opcodes (i.e. LB, LH, LW, LBU, and LHU).
    pub unsigned_mem_val: Word<F>,
    /// Flag for load mem instructions where the value is positive and not writing to x0.
    /// More formally, it is
    ///
    /// (
    ///     ((is_lb | is_lh) & (most_sig_byte_decomp[7] == 0)) |
    ///     is_lbu | is_lhu | is_lw
    /// ) &
    /// (not writing to x0)
    pub mem_value_is_pos_not_x0: F,
    /// Flag for load mem instructions where the value is negative and not writing to x0.
    /// More formally, it is
    ///
    /// > (is_lb | is_lh) & (most_sig_byte_decomp[7] == 1) & (not writing to x0)
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
    pub is_sb: T,
    pub is_sh: T,
    pub is_sw: T,

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
            Opcode::SB => self.is_sb = F::ONE,
            Opcode::SH => self.is_sh = F::ONE,
            Opcode::SW => self.is_sw = F::ONE,
            _ => unreachable!(),
        }

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

    /// This column is the most signficant 8 bit limb of current access timestamp - prev access
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
