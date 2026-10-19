use super::super::{columns::CpuCols, CpuChip};
use crate::{compiler::addr::Addr, machine::builder::ChipBuilder};
use p3_air::AirBuilder;
use p3_field::{Field, PrimeCharacteristicRing};

impl<F: Field> CpuChip<F> {
    /// Constraints related to jump operations.
    pub(crate) fn eval_jump_ops<CB: ChipBuilder<F>>(
        &self,
        builder: &mut CB,
        local: &CpuCols<CB::Var>,
    ) {
        let is_jump_instruction = local.opcode_selector.is_jal + local.opcode_selector.is_jalr;

        // Verify that the local.pc + 4 is saved in op_a for both jump instructions.
        // When op_a is set to register X0, the RISC-V spec states that the jump instruction will
        // not have a return destination address (it is effectively a GOTO command).  In this case,
        // we shouldn't verify the return address.
        //
        // Use the `Pc` carry gadget over the 2-limb pc and the low 3 limbs of op_a (its limb 2
        // is pinned to zero there, a pc having none). The 4th limb of op_a (bits 48..64) is
        // separately asserted zero below, so pc + 4 = op_a is fully constrained without a
        // redundant 4th carry witness.
        //
        // The carry column `pc_carry` is not asserted boolean here or anywhere else in the chip:
        // it travels in the Program message, so on every real row the lookup pins it to the
        // preprocessed table's `[pc[0] >= 0xFFFC]` (`riscv_program/columns.rs`), and on padding
        // rows the gate below is zero.
        let op_a = local.op_a_val();
        let op_a_addr = Addr([op_a[0], op_a[1], op_a[2]]);
        let condition = is_jump_instruction.clone() * (CB::Expr::ONE - local.instruction.op_a_0);
        local.pc.add_limb_with_carry(
            builder,
            condition,
            CB::Expr::from_u8(4),
            op_a_addr,
            local.pc_carry,
        );

        // The hand-off to the successor's `pc` is not repeated here: the row chain pins it limb
        // by limb (`eval_row_chain`, N1).

        // Assert that the 4th limb (bits 48-63) is 0.
        builder
            .when(is_jump_instruction.clone())
            .assert_zero(local.op_a_val()[3].into());

        // Verify that the new pc is calculated correctly for JAL instructions.
        //
        // Same shape as the branch target (see `branch/constraints.rs`): `op_b` is the J-type
        // offset sign-extended to 64 bits, so the 64-bit wrap collapses to
        //
        //     next_pc = pc + (op_b[0] + op_b[1]*2^16) - sign*2^32
        //
        // exact in the field because both sides sit in `[0, 2^31) ⊂ [0, p)`. The sign is the
        // Program table's `op_b.sign` bit: a JAL row is an immediate-b row (gate below), so
        // `register/constraints.rs` pins `op_b_val()`'s limbs 2 and 3 to `0xFFFF * sign` and the
        // shape of the sign fill needs no check of its own here. `next_pc`'s canonicity comes
        // from membership: the row chain (`eval_row_chain`, N1) ties a row with a real successor
        // to that successor's Program-table `pc`, and the last real row's becomes PV.next_pc,
        // which the recursion chain pins.
        let op_b = local.op_b_val();
        let jal_sign: CB::Expr = local.instruction.op_b.sign.into();
        builder.when(local.opcode_selector.is_jal).assert_eq(
            local.next_pc.reduce::<CB>(),
            local.pc.reduce::<CB>()
                + op_b[0]
                + Into::<CB::Expr>::into(op_b[1]) * CB::Expr::from_u32(1 << 16)
                - jal_sign * CB::Expr::from_u64(1u64 << 32),
        );
        // Fail-closed: the target equation above reads the sign off the preprocessed operand,
        // which describes `op_b_val()` only on an immediate row. The transpiler builds every JAL
        // with `imm_b = true` (`rrs.rs`, `process_jal`); a hand-built Program with a
        // register-operand JAL is rejected here instead of being proven with an unrelated sign.
        builder
            .when(local.opcode_selector.is_jal)
            .assert_zero(CB::Expr::ONE - local.opcode_selector.imm_b);

        // Verify that the new pc is calculated correctly for JALR instructions.
        //
        // RISC-V clears bit 0 of the target, and the emulator does so (`next_pc = (b + c) & !1`),
        // so `local.next_pc` is the *masked* value and `next_pc[0] + jalr_lsb` is the unmasked
        // low limb. The 64-bit sum `b + c` is proven in place, limb by limb, with the carry chain
        // of `read_write/constraints.rs` (and `gadgets/add.rs`): the carries are expressions,
        // not columns, and each must be boolean,
        //
        //     k1 = (b0 + c0 - (next_pc[0] + lsb)) * 2^-16
        //     k2 = (b1 + c1 + k1 - next_pc[1])    * 2^-16
        //     k3 = (b2 + c2 + k2)                 * 2^-16
        //     k4 = (b3 + c3 + k3)                 * 2^-16
        //
        // with `b = op_b_val()`, `c = op_c_val()`. Every operand limb is in `[0, 2^16)`: a
        // register word has canonical limbs (the register file's u16-limb invariant,
        // `register/constraints.rs`) and an immediate is pinned to the Program table's
        // `SignExtImm` limbs and `0xFFFF * sign` fill. `next_pc` is a Program-table pc: the row
        // chain (N1) makes it the successor's `pc`, whose own Program lookup pins it to a
        // preprocessed row `Pc::try_from(pc_base + 4i)`, and the last real row's becomes
        // PV.next_pc, which the recursion pins to the next chunk's row-0 pc. So `next_pc[0] <=
        // 0xFFFC`, `next_pc[0] + lsb <= 0xFFFD` and `next_pc[1] < 2^16`. Each bracket is then an
        // integer in `(-2^16, 2^17)`, an interval on which `k * (k - 1) = 0` in the field forces
        // the bracket to be exactly 0 or 2^16, so the chain is the exact schoolbook addition
        // `(next_pc[0] + lsb, next_pc[1], 0, 0) = b + c mod 2^64`; `k4 = 1` is the 64-bit wrap
        // of a negative offset. A target at or above 2^32 (a non-zero third or fourth sum limb)
        // has no solution: fail-closed. The Add chip's own U16 check of its result is not needed
        // for this: the limbs of `next_pc` are canonical by membership, as above.
        //
        // No range check pins `jalr_lsb`; membership does. Of the two witnesses `(lsb = 0, S)`
        // and `(lsb = 1, S - 1)` that reproduce the low limb `S` the chain fixes, at most one is
        // `≡ pc_base (mod 4)` (`pc_base` is 4-aligned, `riscv_program/traces.rs`), and a target
        // that is 2 or 3 (mod 4) -- a misaligned fetch RISC-V traps on -- matches no table row.
        //
        // Degree: each `k` is linear, `assert_bool` squares it and the `is_jalr` gate makes 3.
        builder.assert_bool(local.jalr_lsb);
        let op_c = local.op_c_val();
        let inv_2_16 = CB::F::from_u32(1 << 16).inverse();
        let k1: CB::Expr =
            (CB::Expr::ZERO + op_b[0] + op_c[0] - local.next_pc[0] - local.jalr_lsb) * inv_2_16;
        let k2: CB::Expr =
            (CB::Expr::ZERO + op_b[1] + op_c[1] + k1.clone() - local.next_pc[1]) * inv_2_16;
        let k3: CB::Expr = (CB::Expr::ZERO + op_b[2] + op_c[2] + k2.clone()) * inv_2_16;
        let k4: CB::Expr = (CB::Expr::ZERO + op_b[3] + op_c[3] + k3.clone()) * inv_2_16;
        let mut jalr = builder.when(local.opcode_selector.is_jalr);
        jalr.assert_bool(k1);
        jalr.assert_bool(k2);
        jalr.assert_bool(k3);
        jalr.assert_bool(k4);
    }
}
