use crate::{
    chips::gadgets::{
        field_range_check::word_range::FieldWordRangeChecker, is_zero::IsZeroGadget,
        u16_to_u8::U16ToU8Gadget,
    },
    compiler::word::Word,
    primitives::consts::PV_DIGEST_NUM_WORDS,
};
use pico_derive::AlignedBorrow;
use std::mem::size_of;

pub const NUM_ECALL_CHIP_COLS: usize = size_of::<EcallChipCols<u8>>();
// Pinned so the GPU mirror (`EcallChipColsU64`) cannot drift silently: both sides derive their
// width from `sizeof`.
const _: () = assert!(NUM_ECALL_CHIP_COLS == 60);

/// The syscall-decode gadget block (moved verbatim from the Cpu chip's former
/// `opcode_specific` union).
#[derive(AlignedBorrow, Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct EcallCols<T> {
    /// u16 → u8 decomposition of op_a prev_value (syscall code).
    /// Produces 8 bytes from the 4 u16 limbs of the Word.
    pub syscall_code_bytes: U16ToU8Gadget<T>,

    /// Whether the current ecall is ENTER_UNCONSTRAINED.
    pub is_enter_unconstrained: IsZeroGadget<T>,

    /// Whether the current ecall is HINT_LEN.
    pub is_hint_len: IsZeroGadget<T>,

    /// Whether the current ecall is HALT.
    pub is_halt: IsZeroGadget<T>,

    /// Whether the current ecall is a COMMIT.
    pub is_commit: IsZeroGadget<T>,

    /// Whether the current ecall is a COMMIT_DEFERRED_PROOFS.
    pub is_commit_deferred_proofs: IsZeroGadget<T>,

    /// Field to store the word index passed into the COMMIT ecall.  index_bitmap[word index]
    /// should be set to 1 and everything else set to 0.
    pub index_bitmap: [T; PV_DIGEST_NUM_WORDS],

    // TODO: check if operand is u32 for halt and commit_deferred_proofs
    /// Columns to range check the halt/commit_deferred_proofs operand.
    pub operand_range_check_cols: FieldWordRangeChecker<T>,

    // TODO: check if operand is u32 for halt and commit_deferred_proofs
    /// The operand value to range check.
    pub operand_to_check: Word<T>,
}

/// The whole column layout for the Ecall chip: the fat-message fields received from the Cpu
/// chip, followed by the decode gadget block.
#[derive(AlignedBorrow, Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct EcallChipCols<T: Copy> {
    /// The current chunk (message element 0).
    pub chunk: T,

    /// The clock cycle of the ecall (message element 1).
    pub clk: T,

    /// op_a prev_value — the syscall code word (message elements 2..6).
    pub op_a_prev_value: Word<T>,

    /// op_a value after the ecall (message elements 6..10).
    pub op_a_value: Word<T>,

    /// op_b value (message elements 10..14).
    pub op_b_value: Word<T>,

    /// op_c value (message elements 14..18).
    pub op_c_value: Word<T>,

    /// The Cpu-committed extra-clock scalar; constrained here to equal byte 2 of the syscall
    /// code (message element 18).
    pub num_extra_clk: T,

    /// The Cpu-committed halt flag; constrained here to equal the derived HALT indicator
    /// (message element 19).
    pub is_halt: T,

    /// send_to_table byte × is_real (successor of the Cpu chip's `ecall_mul_send_to_table`):
    /// the multiplicity of the syscall-table send, unconditionally constrained so padding rows
    /// cannot emit syscall lookups.
    pub send_to_table: T,

    /// (is_halt ∨ is_commit_deferred_proofs) × is_real (successor of the Cpu chip's
    /// `ecall_range_check_operand`): gates the operand range check, unconditionally constrained.
    pub range_check_operand: T,

    /// is_hint_len × is_real: the multiplicity of the u16 range check on `op_a_value`. HINT_LEN
    /// is the one ecall whose written register word is pinned to nothing else (the others keep
    /// the previous word or write zero), and the Cpu chip range-checks only the jump rows'
    /// return address, so the Ecall chip certifies this one. Materialized for the same reason as
    /// `range_check_operand`: an interaction count must be affine in current-row columns.
    pub hint_len_mul: T,

    /// The four bytes of the `committed_value_digest` public-value word selected by
    /// `ecall.index_bitmap`, mirrored into the main trace.
    ///
    /// The mirror exists because an interaction message must be *affine in current-row
    /// main/preprocessed columns* (`machine/utils.rs::eval_symbolic_to_virtual_pair` panics
    /// otherwise), and `index_word_array(public_values.committed_value_digest, index_bitmap)`
    /// is a public value times a main column. Only meaningful on COMMIT rows; unconstrained
    /// elsewhere.
    pub commit_digest_bytes: Word<T>,

    /// `is_real × is_commit`: the multiplicity of the digest-byte range check, materialized for
    /// the same reason `range_check_operand` above is — an interaction *count* must also be
    /// affine in current-row columns, and that product is degree 2.
    pub commit_mul: T,

    /// `is_real × is_commit_deferred_proofs`, and the running count and `Σ 2^word_index` of such
    /// rows up to this one. The last row's pair is the chunk's published tally.
    pub deferred_commit_mul: T,
    pub deferred_commits: T,
    pub deferred_commit_mask: T,

    /// The syscall-decode machinery.
    pub ecall: EcallCols<T>,

    /// Whether this row is an actual ecall (multiplicity of the looked message).
    pub is_real: T,
}
