use super::super::{columns::CpuCols, CpuChip};
use crate::{
    chips::chips::riscv_memory::event::MemoryAccessPosition,
    machine::builder::{ChipBuilder, ChipWordBuilder, RiscVMemoryBuilder},
};
use p3_air::AirBuilder;
use p3_field::{Field, PrimeCharacteristicRing};

impl<F: Field> CpuChip<F> {
    /// Computes whether the opcode is a branch instruction.
    /// `chunk` is the proof's `execution_chunk` public value: the memory-argument messages
    /// carry it directly, there is no committed chunk column.
    pub(crate) fn eval_registers<CB: ChipBuilder<F>>(
        &self,
        builder: &mut CB,
        local: &CpuCols<CB::Var>,
        chunk: CB::Expr,
        is_branch_instruction: CB::Expr,
    ) {
        // Load immediates into b and c, if the immediate flags are on.
        //
        // The Program table stores an operand as its two low limbs plus a sign bit
        // (`SignExtImm`): every transpiled operand has bits 32..64 all zero or all one, so the
        // operand word's limbs 2 and 3 are both `0xFFFF * sign`. Pinning them to that is the
        // whole content of the high-limb equality.
        let op_b_val = local.op_b_val();
        let op_b_imm = local.instruction.op_b;
        let imm_b = local.opcode_selector.imm_b;
        builder.when(imm_b).assert_eq(op_b_val[0], op_b_imm.limb[0]);
        builder.when(imm_b).assert_eq(op_b_val[1], op_b_imm.limb[1]);
        let fill_b: CB::Expr = op_b_imm.sign * CB::Expr::from_u32(0xFFFF);
        builder.when(imm_b).assert_eq(op_b_val[2], fill_b.clone());
        builder.when(imm_b).assert_eq(op_b_val[3], fill_b);

        let op_c_val = local.op_c_val();
        let op_c_imm = local.instruction.op_c;
        let imm_c = local.opcode_selector.imm_c;
        builder.when(imm_c).assert_eq(op_c_val[0], op_c_imm.limb[0]);
        builder.when(imm_c).assert_eq(op_c_val[1], op_c_imm.limb[1]);
        let fill_c: CB::Expr = op_c_imm.sign * CB::Expr::from_u32(0xFFFF);
        builder.when(imm_c).assert_eq(op_c_val[2], fill_c.clone());
        builder.when(imm_c).assert_eq(op_c_val[3], fill_c);

        // If they are not immediates, read `b` and `c` from memory.
        // `clk` is the committed clk column (`clk_expr`).
        // `1 - imm_*` is boolean by construction (Program-table selector on real rows, 1 on
        // padding rows), so the unchecked variant skips the redundant `assert_bool`.
        let clk = Self::clk_expr::<CB>(local);
        builder.eval_memory_access_lite_unchecked(
            chunk.clone(),
            clk.clone() + CB::Expr::from_u32(MemoryAccessPosition::B as u32),
            [
                local.instruction.op_b.limb[0].into(),
                CB::Expr::ZERO,
                CB::Expr::ZERO,
            ],
            &local.op_b_access,
            CB::Expr::ONE - local.opcode_selector.imm_b,
        );

        builder.eval_memory_access_lite_unchecked(
            chunk.clone(),
            clk.clone() + CB::Expr::from_u32(MemoryAccessPosition::C as u32),
            [
                local.instruction.op_c.limb[0].into(),
                CB::Expr::ZERO,
                CB::Expr::ZERO,
            ],
            &local.op_c_access,
            CB::Expr::ONE - local.opcode_selector.imm_c,
        );

        // If we are writing to register 0, then the new value should be zero.
        builder
            .when(local.instruction.op_a_0)
            .assert_word_zero(local.op_a_access.access.value);

        // Write the `a` or the result to the first register described in the instruction unless
        // we are performing a branch or a store.
        builder.eval_memory_access_lite(
            chunk,
            clk + CB::Expr::from_u32(MemoryAccessPosition::A as u32),
            [
                local.instruction.op_a.into(),
                CB::Expr::ZERO,
                CB::Expr::ZERO,
            ],
            &local.op_a_access,
            local.is_real,
        );

        // The register file's u16-limb invariant is inductive over the write paths; it is not
        // re-checked on every row, and no row class needs a range check of its own here.
        //
        // A jump row writes `pc + 4` through `Pc::add_limb_with_carry` (`jump/constraints.rs`):
        // `op_a[0] = pc[0] + 4 - 2^16 * pc_carry`, `op_a[1] = pc[1] + pc_carry`, `op_a[2] = 0`,
        // and `op_a[3]` is asserted zero there. `pc_carry` travels in the Program message, so on
        // every real row the lookup pins it to the preprocessed table's `[pc[0] >= 0xFFFC]`
        // (`riscv_program/columns.rs`). A table pc is 4-aligned, so limb 0 is `pc[0] + 4 <=
        // 0xFFFF` when the carry is 0 and exactly 0 when it is 1 (`pc[0] == 0xFFFC`); limb 1 is
        // `pc[1] + carry <= 0x7800` because a Program-table pc stays below 0x7800_0000 (asserted
        // at keygen in `riscv_program/traces.rs`). All four limbs are canonical.
        //
        // Every other row class writes a word that is canonical already: `rd = x0` rows are
        // pinned to zero above; ALU rows receive the result word from an ALU chip, which
        // range-checks its own result limbs; load rows are pinned to the loaded value, built from
        // memory limbs, u8-checked bytes and sign fills (`read_write/constraints.rs`); branch and
        // store rows carry the previous value, checked when it was written or, for a value
        // inherited from an earlier chunk, by the MemoryLocal entry that carries it (limbs 0 and
        // 1 u16-checked there, limb 2 a checked byte pair, limb 3 u16-checked by the Global
        // chip); ecall rows keep the previous value, write
        // zero, or -- HINT_LEN only -- a word the Ecall chip range-checks itself
        // (`riscv_ecall/constraints.rs`). Memory limbs are canonical because every writer
        // (MemoryReadWrite stores and every precompile) writes checked limbs and the initial
        // memory is u16-checked by MemoryInitialize.

        // If we are performing a branch or a store, then the value of `a` is the previous value.
        builder
            .when(
                is_branch_instruction.clone()
                    + self.is_store_instruction::<CB>(&local.opcode_selector),
            )
            .assert_word_eq(local.op_a_val(), local.op_a_access.prev_value);
    }
}
