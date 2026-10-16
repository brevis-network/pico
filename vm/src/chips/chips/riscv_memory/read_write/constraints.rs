#![allow(clippy::assign_op_pattern)]

use super::{
    columns::{MemoryChipCols, MemoryInstructionCols, NUM_MEMORY_CHIP_COLS},
    MemoryReadWriteChip,
};
use crate::{
    chips::chips::riscv_memory::{
        event::MemoryAccessPosition,
        read_write::columns::{MemoryChipValueCols, MemoryLiteCols},
    },
    compiler::riscv::opcode::{ByteOpcode, Opcode},
    machine::{
        builder::{ChipBuilder, ChipLookupBuilder, RiscVMemoryBuilder},
        lookup::{LookupScope, LookupType, SymbolicLookup},
    },
};
use core::borrow::Borrow;
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};

impl<F: Field> BaseAir<F> for MemoryReadWriteChip<F> {
    fn width(&self) -> usize {
        NUM_MEMORY_CHIP_COLS
    }
}

impl<F: Field, CB: ChipBuilder<F>> Air<CB> for MemoryReadWriteChip<F>
where
    CB::Var: Sized,
{
    fn eval(&self, builder: &mut CB) {
        let main = builder.main();
        let local = main.current_slice();
        let local: &MemoryChipCols<CB::Var> = (*local).borrow();

        for local_memory_chip_value_cols in local.values {
            let is_memory_instruction: CB::Expr =
                self.is_memory_instruction::<CB>(&local_memory_chip_value_cols.instruction);

            // The 11 per-variant flags are private witness columns of this chip (the Cpu
            // chip only sends a single `is_memory` selector), so they must be self-proven.
            // There is no materialized `opcode` column anymore; the returned
            // degree-1 expression sum(flag_i * OPCODE_i) plays its role in the dispatch
            // message, and the lookup balance binds it to the Cpu chip's opcode.
            let opcode_expr = self
                .eval_instruction_flags::<CB>(builder, &local_memory_chip_value_cols.instruction);

            // CPU Lookup: receive instruction parameters via looked lookup.
            // The message is opcode + a/b/c values + op_a_0 + is_memory + chunk + clk (17 wide);
            // the `is_memory` slot is the flag sum, which the constraints above force to be
            // boolean and consistent with the opcode.
            //
            // `chunk` and `clk` (base clk, no position offset) are appended so this
            // chip's free `chunk`/`clk` witnesses are bound by the lookup to the Cpu chip's
            // program-order clk (an integer bounded by the Cpu row chain, `riscv_cpu/chunk_clk`)
            // and chunk (bounded by the convert
            // circuit's check on the proof's public value). Order must match the Cpu send side:
            // ... op_a_0, is_memory, chunk, clk.
            use core::iter::once;
            let mut values: Vec<CB::Expr> = vec![opcode_expr];
            values.extend(
                local_memory_chip_value_cols
                    .instruction
                    .op_a_val()
                    .into_iter()
                    .chain(local_memory_chip_value_cols.instruction.op_b_val())
                    .chain(local_memory_chip_value_cols.instruction.op_c_val())
                    .chain(once(local_memory_chip_value_cols.instruction.op_a_0))
                    .map(Into::into),
            );
            values.push(is_memory_instruction.clone());
            values.push(local_memory_chip_value_cols.chunk.into());
            values.push(local_memory_chip_value_cols.clk.into());

            builder.looked(SymbolicLookup::new(
                values,
                is_memory_instruction.clone(),
                LookupType::Memory,
                LookupScope::Regional,
            ));

            self.eval_memory_address_and_access::<CB>(
                builder,
                &local_memory_chip_value_cols,
                is_memory_instruction.clone(),
            );
            self.eval_memory_load::<CB>(builder, &local_memory_chip_value_cols);
            self.eval_memory_store::<CB>(builder, &local_memory_chip_value_cols);
        }
    }
}

impl<F: Field> MemoryReadWriteChip<F> {
    /// Computes whether the opcode is a load instruction.
    pub(crate) fn is_load_instruction<CB: ChipBuilder<F>>(
        &self,
        instruction: &MemoryInstructionCols<CB::Var>,
    ) -> CB::Expr {
        instruction.is_lb
            + instruction.is_lbu
            + instruction.is_lh
            + instruction.is_lhu
            + instruction.is_lw
            + instruction.is_lwu
            + instruction.is_ld
    }

    /// Computes whether the opcode is a store instruction.
    pub(crate) fn is_store_instruction<CB: ChipBuilder<F>>(
        &self,
        instruction: &MemoryInstructionCols<CB::Var>,
    ) -> CB::Expr {
        instruction.is_sb + instruction.is_sh + instruction.is_sw + instruction.is_sd
    }

    /// Computes whether the opcode is a memory instruction.
    pub(crate) fn is_memory_instruction<CB: ChipBuilder<F>>(
        &self,
        instruction: &MemoryInstructionCols<CB::Var>,
    ) -> CB::Expr {
        self.is_load_instruction::<CB>(instruction) + self.is_store_instruction::<CB>(instruction)
    }

    /// The full 4-wide one-hot limb selector as degree-2 expressions of the two offset bits:
    /// `[(1-bit1)(1-bit2), bit1(1-bit2), (1-bit1)bit2, bit1 bit2]`.
    ///
    /// No committed entries: witnesses would be pinned to exactly these products anyway,
    /// and every consumer (`selected_limb`, the four store equations) multiplies an
    /// entry by one more degree-1 factor at most, so the chip stays at degree 3. Both
    /// offset bits are asserted boolean, which makes the four entries a one-hot vector.
    pub(crate) fn limb_select_exprs<CB: ChipBuilder<F>>(
        &self,
        local: &MemoryChipValueCols<CB::Var>,
    ) -> [CB::Expr; 4] {
        let b1: CB::Expr = CB::Expr::ZERO + local.offset_bit[1];
        let b2: CB::Expr = CB::Expr::ZERO + local.offset_bit[2];
        [
            (CB::Expr::ONE - b1.clone()) * (CB::Expr::ONE - b2.clone()),
            b1.clone() * (CB::Expr::ONE - b2.clone()),
            (CB::Expr::ONE - b1.clone()) * b2.clone(),
            b1 * b2,
        ]
    }

    /// Self-derivation constraints for the per-variant memory flags.
    ///
    /// The Cpu chip no longer sends the 11 flags through the dispatch lookup (only a
    /// single `is_memory` selector), so this chip must prove its own flags:
    /// 1. each flag is boolean (degree 2),
    /// 2. the flag sum is boolean, i.e. at most one flag is set; rows with no flag set
    ///    are padding rows and send no lookup (degree 2).
    ///
    /// The sum alone would not do: `{-1, +1}` sums to a boolean 0, dropping the row off the
    /// memory bus while the byte lookups still fire at multiplicity -1.
    ///
    /// Returns the degree-1 opcode expression sum(flag_i * OPCODE_i). It replaces the
    /// old materialized `opcode` column : used as the first dispatch
    /// message element, the lookup balance binds it to the program-backed Cpu opcode,
    /// and since the opcodes are pairwise distinct and the flags one-hot, the value
    /// uniquely identifies the variant. On padding rows the expression is 0 and the
    /// message multiplicity (flag sum) is 0.
    pub(crate) fn eval_instruction_flags<CB: ChipBuilder<F>>(
        &self,
        builder: &mut CB,
        instruction: &MemoryInstructionCols<CB::Var>,
    ) -> CB::Expr {
        let flags = [
            (instruction.is_lb, Opcode::LB),
            (instruction.is_lbu, Opcode::LBU),
            (instruction.is_lh, Opcode::LH),
            (instruction.is_lhu, Opcode::LHU),
            (instruction.is_lw, Opcode::LW),
            (instruction.is_lwu, Opcode::LWU),
            (instruction.is_ld, Opcode::LD),
            (instruction.is_sb, Opcode::SB),
            (instruction.is_sh, Opcode::SH),
            (instruction.is_sw, Opcode::SW),
            (instruction.is_sd, Opcode::SD),
        ];

        let mut weighted_sum = CB::Expr::ZERO;
        for (flag, opcode) in flags {
            builder.assert_bool(flag);
            weighted_sum = weighted_sum + (CB::Expr::ZERO + flag) * opcode.as_field::<CB::F>();
        }
        // Same expression tree as `is_memory_instruction` (and the memory-access gate), so the
        // DAG shares it instead of building a second sum.
        builder.assert_bool(self.is_memory_instruction::<CB>(instruction));
        weighted_sum
    }

    // ========================================================================
    // C1 + C2 + C3: Address calculation, offset, timestamp (C4 "a load leaves memory
    // unchanged" lives in the unified store equation of `eval_memory_store`)
    // ========================================================================

    pub(crate) fn eval_memory_address_and_access<CB: ChipBuilder<F>>(
        &self,
        builder: &mut CB,
        local: &MemoryChipValueCols<CB::Var>,
        is_memory_instruction: CB::Expr,
    ) {
        let is_mem = is_memory_instruction.clone();

        // ---- C1: Address calculation ----

        // 1. In-chip addition: addr_word = low 2 limbs of (op_b + op_c) mod 2^64, with the 3rd
        // and 4th sum limbs literal 0s. Same carry chain as `AddGadget::eval` (`gadgets/add.rs`):
        // the carries are expressions, not columns, and each must be boolean,
        //   k_{i+1} = (b_i + c_i + k_i - a_i) * 2^-16,   k_0 = 0,   a_2 = a_3 = 0.
        // With b_i, c_i in [0, 2^16) -- an inherited external fact, not proved here: the operands
        // are Cpu-bound (17-wide dispatch) and every register/immediate Word is limb-bounded by
        // the Cpu register invariant and the Program table, exactly as the former Add-row
        // dispatch assumed -- and a_i in [0, 2^16) (range-checked below), each bracket is an integer in (-2^16, 2^17), so a boolean k in F means the
        // bracket is exactly 0 or 2^16 and the chain is the exact schoolbook addition. k_4 = 1
        // is the wrap (b + c >= 2^64 with a zero upper half), exactly what the former Add-row
        // dispatch with `value[3] = 0` accepted; a true sum with a non-zero 3rd or 4th limb has
        // no solution -- fail-closed for addr >= 2^32. The guest address space ends at
        // 0x7800_0000, and trace generation asserts the same bound.
        // Ungated on purpose: padding rows are all-zero, so every k_i is 0 there and
        // `assert_bool` holds; on real rows is_mem = 1 and a gate would only add degree.
        let op_b = local.op_b_val();
        let op_c = local.op_c_val();
        let inv_2_16 = CB::F::from_u32(1 << 16).inverse();
        let k1: CB::Expr = (CB::Expr::ZERO + op_b[0] + op_c[0] - local.addr_word[0]) * inv_2_16;
        builder.assert_bool(k1.clone());
        let k2: CB::Expr =
            (CB::Expr::ZERO + op_b[1] + op_c[1] + k1 - local.addr_word[1]) * inv_2_16;
        builder.assert_bool(k2.clone());
        let k3: CB::Expr = (CB::Expr::ZERO + op_b[2] + op_c[2] + k2) * inv_2_16;
        builder.assert_bool(k3.clone());
        let k4: CB::Expr = (CB::Expr::ZERO + op_b[3] + op_c[3] + k3) * inv_2_16;
        builder.assert_bool(k4);

        // 2. Limb bounds. addr_word[0] needs no U16Range of its own: the BitRange(13) lookup in
        // C2 proves (addr_word[0] - offset) / 8 < 2^13 with offset in [0, 7], so addr_word[0] =
        // 8k + offset < 2^16 exactly. addr_word[1] is range-checked here; the stack guard below
        // and the memory-argument lookup address in C3 both rely on it.
        builder.looking_rangecheck(
            ByteOpcode::U16Range,
            local.addr_word[1],
            CB::Expr::ZERO,
            CB::Expr::ZERO,
            CB::Expr::ZERO,
            is_mem.clone(),
        );

        // 3. Stack guard: addr[1] != 0 → addr >= 2^16. The implication needs both limbs to be
        // below 2^16 (the U16Range lookup in 2 for limb 1, the BitRange(13) lookup in C2 for
        // limb 0) -- do not reuse this trick anywhere the limbs are not range-checked.
        builder.assert_eq(
            CB::Expr::ZERO + local.addr_limb1_inv * local.addr_word[1],
            is_mem.clone(),
        );

        // ---- C2: Offset decomposition + alignment ----

        // 1. offset bits are bool
        // Ungated: every real row of this chip is a memory instruction and padding rows are
        // all-zero, so the gate on `is_mem` bought nothing but degree. The one-hot limb
        // selector is a set of products of these two bits (`limb_select_exprs`), not committed
        // columns, so this is also what makes it one-hot.
        for i in 0..3 {
            builder.assert_bool(local.offset_bit[i]);
        }

        // 2. Bind offset_bit to addr[0]: (addr[0] - offset) must be divisible by 8.
        //    Method: looking_byte(BitRange, (addr[0]-offset)/8, 13, 0, is_mem).
        //    Max value of (addr[0]-offset)/8 = (65535-0)/8 = 8191 = 2^13-1, so 13 bits suffice.
        //    If offset_bit is wrong, (addr[0]-offset)/8 is not an integer and the
        //    field element will be > 2^13 (since p >> 2^13), failing the range check.
        let offset_sum: CB::Expr = CB::Expr::ZERO
            + local.offset_bit[0]
            + CB::Expr::TWO * local.offset_bit[1]
            + CB::Expr::from_u8(4) * local.offset_bit[2];
        // Aligned low limb = addr_word[0] with its low 3 offset bits cleared,
        // expressed as a degree-1 combination of add-checked witnesses instead of a free
        // `addr_aligned` column. The BitRange lookup below proves this value is a multiple of 8
        // in [0, 2^16), so it is exactly the aligned limb (no field borrow). It is reused
        // verbatim as the low limb of the memory-argument lookup address (see C3).
        let aligned_addr0: CB::Expr = CB::Expr::ZERO + local.addr_word[0] - offset_sum;
        let inv_8 = CB::F::from_u8(8).inverse();
        builder.looking_byte(
            CB::Expr::from_u8(ByteOpcode::BitRange as u8),
            aligned_addr0.clone() * CB::Expr::from(inv_8),
            CB::Expr::from_u8(13),
            CB::Expr::ZERO,
            is_mem.clone(),
        );

        // 4. Alignment constraints
        // Half-word alignment: bit0 == 0
        builder
            .when(local.instruction.is_lh + local.instruction.is_lhu + local.instruction.is_sh)
            .assert_zero(local.offset_bit[0]);
        // Word alignment: bit0 == 0, bit1 == 0
        builder
            .when(local.instruction.is_lw + local.instruction.is_lwu + local.instruction.is_sw)
            .assert_zero(CB::Expr::ZERO + local.offset_bit[0] + local.offset_bit[1]);
        // Double-word alignment: bit0 == 0, bit1 == 0, bit2 == 0
        builder
            .when(local.instruction.is_ld + local.instruction.is_sd)
            .assert_zero(
                CB::Expr::ZERO + local.offset_bit[0] + local.offset_bit[1] + local.offset_bit[2],
            );

        // ---- C3: Timestamp + Regional Lookup ----
        // addr_aligned is computed inline as addr_word - offset, avoiding a free witness column.
        // eval_memory_access_lite handles timestamp monotonicity (the predecessor clk is defined
        // from the two committed difference limbs, no `prev_clk` column) and the 9-element
        // Regional lookup. The memory-argument lookup address is derived from the add-checked
        // `addr_word` (aligned low limb + high limbs), not a free `addr_aligned` witness.
        builder.eval_memory_access_lite(
            local.chunk,
            local.clk + CB::F::from_u32(MemoryAccessPosition::Memory as u32),
            [
                aligned_addr0,
                CB::Expr::ZERO + local.addr_word[1],
                CB::Expr::ZERO,
            ],
            &local.memory_access,
            is_mem.clone(),
        );

        // C4 ("a load leaves memory unchanged") is the all-flags-zero case of the unified
        // store equation in `eval_memory_store`.
    }

    // ========================================================================
    // C5 + C6 + C7 + C8: Load sub-word selection, unified load value (sign extension
    // included) and x0 handling
    // ========================================================================

    pub(crate) fn eval_memory_load<CB: ChipBuilder<F>>(
        &self,
        builder: &mut CB,
        local: &MemoryChipValueCols<CB::Var>,
    ) {
        let mem_val = *local.memory_access.prev_value();

        // ---- C5: Limb selection (4-choose-1 via the one-hot limb selector) ----
        // selected_limb = mem_val[2*bit2 + bit1]. The selector entries are degree-2 products of
        // the offset bits, so this equation is degree 3.
        let bit0 = local.offset_bit[0];
        let bit2 = local.offset_bit[2];

        let ls = self.limb_select_exprs::<CB>(local);
        let expected_limb: CB::Expr = CB::Expr::ZERO
            + ls[0].clone() * mem_val[0]
            + ls[1].clone() * mem_val[1]
            + ls[2].clone() * mem_val[2]
            + ls[3].clone() * mem_val[3];
        builder.assert_eq(local.selected_limb, expected_limb);

        // ---- C6: Load sub-word extraction ----

        // LB/LBU: split selected_limb into 2 bytes, select one via bit0. The low byte lives in
        // `mem_limb_low_byte`, the slot the SB rows use for the low byte of the memory limb they
        // modify: both row kinds split the selected memory limb, so the one U8Range lookup in
        // `eval_memory_store` (count `is_sb + is_lb + is_lbu`) pins both splits.
        let inv_256 = CB::F::from_u16(256).inverse();
        let byte0: CB::Expr = CB::Expr::ZERO + local.mem_limb_low_byte;
        let byte1: CB::Expr = (CB::Expr::ZERO + local.selected_limb - local.mem_limb_low_byte)
            * CB::Expr::from(inv_256);

        let is_byte_load: CB::Expr = local.instruction.is_lb + local.instruction.is_lbu;
        builder.when(is_byte_load.clone()).assert_eq(
            local.selected_byte,
            CB::Expr::ZERO + bit0 * byte1 + (CB::Expr::ONE - bit0) * byte0,
        );

        // Both bytes of selected_limb are range-checked by the shared memory-limb split lookup
        // in `eval_memory_store` (the high byte is the affine `(selected_limb -
        // mem_limb_low_byte) / 256`); with both bytes in U8 and selected_limb < 2^16 < p the
        // split is unique, which is what bounds `selected_byte`.

        // `unsigned_mem_val` is de-materialized: the per-variant load values feed the single
        // unified `op_a == lv` equation below (C7/C8), so only the shared selections are
        // materialized here.
        //
        // LW/LWU: the selected word is `[selected_limb, lhw_val]`. Word alignment pins
        // `bit0 = bit1 = 0` on these rows, so `selected_limb` is already
        // `(1-bit2)*mem[0] + bit2*mem[2]`; the high half `(1-bit2)*mem[1] + bit2*mem[3]` is
        // pinned into `lhw_val` below, next to the LH definition of that column.
        let is_word_load: CB::Expr = local.instruction.is_lw + local.instruction.is_lwu;

        // ---- C7/C8 unified: op_a is the loaded value, sign extension included ----
        //
        // One equation per limb instead of the four per-variant "positive" word equalities and
        // the three "negative" sign-extension word equalities (each behind the pos/neg composite
        // gates). The flags are one-hot, so on a load row exactly one variant term is live; `msb`
        // is pinned per variant below (the U16MSB lookup on LH, LW and LB -- LB through
        // `lhw_val = 256 * selected_byte` -- and zero on the unsigned loads and LD), so the
        // 0xFF00*msb / 0xFFFF*msb fill terms are exactly the sign extension and vanish for
        // positive values. Store rows reduce to `op_a == op_a`; x0 rows
        // are ungated as before; padding rows (all zero) hold trivially.
        let ins = &local.instruction;
        let is_half_load: CB::Expr = ins.is_lh + ins.is_lhu;
        let is_store: CB::Expr = ins.is_sb + ins.is_sh + ins.is_sw + ins.is_sd;
        let msb: CB::Expr = local.msb.into();
        let fill = |flags: CB::Expr| flags * msb.clone() * CB::Expr::from_u16(0xFFFF);
        let a = local.op_a_val();
        let lv: [CB::Expr; 4] = [
            is_byte_load.clone() * local.selected_byte
                + is_half_load * local.selected_limb
                + is_word_load.clone() * local.selected_limb
                + ins.is_ld * mem_val[0]
                + is_store.clone() * a[0]
                + ins.is_lb * msb.clone() * CB::Expr::from_u16(0xFF00),
            is_word_load.clone() * local.lhw_val
                + ins.is_ld * mem_val[1]
                + is_store.clone() * a[1]
                + fill(ins.is_lb + ins.is_lh),
            ins.is_ld * mem_val[2]
                + is_store.clone() * a[2]
                + fill(ins.is_lb + ins.is_lh + ins.is_lw),
            ins.is_ld * mem_val[3] + is_store * a[3] + fill(ins.is_lb + ins.is_lh + ins.is_lw),
        ];
        let not_x0: CB::Expr = CB::Expr::ONE - ins.op_a_0;
        for i in 0..4 {
            builder.when(not_x0.clone()).assert_eq(a[i], lv[i].clone());
        }

        // --- msb independent verification ----

        // LB: `msb` is bit 7 of `selected_byte`. Instead of an MSB lookup of its own, the row
        // pins `lhw_val = 256 * selected_byte` and rides the LH/LW U16MSB lookup below: with
        // `selected_byte` in [0, 256) (the byte-split lookup) and `msb` boolean,
        // `2 * lhw_val - msb * 2^16 = 512 * b - msb * 2^16` lies in [0, 2^16) exactly when
        // `msb = bit7(b)`.
        builder
            .when(local.instruction.is_lb)
            .assert_eq(local.lhw_val, CB::Expr::from_u32(256) * local.selected_byte);
        // `msb` is boolean on every row (loads: the sign bit; stores and padding: 0) and zero on
        // the unsigned loads and LD; one bool plus one zero constraint replace the five gated
        // per-variant checks.
        builder.assert_bool(local.msb);
        builder
            .when(
                local.instruction.is_lbu
                    + local.instruction.is_lhu
                    + local.instruction.is_lwu
                    + local.instruction.is_ld,
            )
            .assert_zero(local.msb);

        // LH: U16MSBOperation -- verify msb == bit15 of selected_limb.
        // LH, LW and LB share ONE U16Range lookup below through the committed mux
        // column `lhw_val` (the flags are mutually exclusive; lookup messages must stay
        // affine, so the operand mux is a column, not a flag-weighted expression).
        builder
            .when(local.instruction.is_lh)
            .assert_eq(local.lhw_val, local.selected_limb);

        // LW/LWU: `lhw_val` is the high half of the selected word, `(1-bit2)*mem[1] +
        // bit2*mem[3]`. One equation for both variants: it is the limb-1 load value on either
        // (see `lv` above), and on LW it is also the U16MSB operand whose bit 15 is `msb`. On
        // LWU rows this pins `lhw_val` as well; trace generation writes it
        // unconditionally on the shared LW/LWU arm.
        let expected_sw1: CB::Expr =
            (CB::Expr::ONE - bit2) * mem_val[1] + (CB::Expr::ZERO + bit2) * mem_val[3];
        builder
            .when(is_word_load)
            .assert_eq(local.lhw_val, expected_sw1);
        // Merged LH/LW/LB U16MSB range check (one instance, mult = is_lh + is_lw + is_lb).
        builder.looking_byte(
            CB::Expr::from_u8(ByteOpcode::U16Range as u8),
            CB::Expr::TWO * local.lhw_val
                - CB::Expr::ZERO
                - local.msb * CB::Expr::from_u32(1 << 16),
            CB::Expr::ZERO,
            CB::Expr::ZERO,
            local.instruction.is_lh + local.instruction.is_lw + local.instruction.is_lb,
        );
        // ---- C8: x0 flag (the load value itself is pinned by the unified equation above) ----

        builder.assert_bool(local.instruction.op_a_0);
    }

    // ========================================================================
    // C7: Store sub-word writing (increment pattern)
    // ========================================================================

    pub(crate) fn eval_memory_store<CB: ChipBuilder<F>>(
        &self,
        builder: &mut CB,
        local: &MemoryChipValueCols<CB::Var>,
    ) {
        let a_val = local.op_a_val();
        let mem_val = *local.memory_access.value();
        let prev_mem_val = *local.memory_access.prev_value();
        let bit0 = local.offset_bit[0];
        let bit2 = local.offset_bit[2];

        // ---- SB: byte-split range checks (P0-3) ----
        // Split register op_a[0] into 2 bytes, range check both → binds register_low_byte.
        // The high byte is the affine expression `(op_a[0] - register_low_byte) / 256`, so the
        // lookup message stays degree 1 without a committed slot. The byte-load rows split the
        // selected memory limb instead, through the shared `mem_limb_low_byte` lookup below.
        let inv_256 = CB::F::from_u16(256).inverse();
        builder.looking_rangecheck(
            ByteOpcode::U8Range,
            CB::Expr::ZERO,
            CB::Expr::ZERO,
            local.register_low_byte,
            (CB::Expr::ZERO + a_val[0] - local.register_low_byte) * CB::Expr::from(inv_256),
            local.instruction.is_sb,
        );
        // Split selected_limb (the memory limb an SB row modifies, or the one an LB/LBU row
        // reads) into 2 bytes -> binds mem_limb_low_byte on all three row kinds; the LB/LBU
        // `selected_byte` definition in `eval_memory_load` reads the same split.
        let mem_high_byte: CB::Expr = (CB::Expr::ZERO + local.selected_limb
            - local.mem_limb_low_byte)
            * CB::Expr::from(inv_256);
        builder.looking_rangecheck(
            ByteOpcode::U8Range,
            CB::Expr::ZERO,
            CB::Expr::ZERO,
            local.mem_limb_low_byte,
            mem_high_byte.clone(),
            local.instruction.is_sb + local.instruction.is_lb + local.instruction.is_lbu,
        );

        // ---- SB / SH: the sub-limb shift ----
        //
        //   shift = is_sh*(a_0 - selected_limb) + is_sb*(inc_low + inc_high)
        //   inc_low  = (1 - bit0) * (reg_low - mem_low)
        //   inc_high = bit0 * (256*reg_low - selected_limb + mem_low)
        //
        // Ungated definition of the committed `shift` column: the SB byte patch, the SH limb
        // replacement, and 0 on every other row (loads, SW/SD, padding). Committed because the
        // limb selector below is degree 2 and `ls_i * shift` must stay at degree 3.
        let ins = &local.instruction;
        let inc_low: CB::Expr = (CB::Expr::ONE - bit0)
            * (CB::Expr::ZERO + local.register_low_byte - local.mem_limb_low_byte);
        let inc_high: CB::Expr = (CB::Expr::ZERO + bit0)
            * ((CB::Expr::ZERO + local.register_low_byte) * CB::Expr::from_u16(256)
                - local.selected_limb
                + local.mem_limb_low_byte);
        builder.assert_eq(
            local.shift,
            ins.is_sh * (a_val[0] - local.selected_limb) + ins.is_sb * (inc_low + inc_high),
        );

        // ---- Unified post-store value (SB / SH / SW / SD / loads) ----
        //
        //   value_i = prev_i + ls_i*shift + is_sd*(a_i - prev_i) + swsel_i*(a_{i mod 2} - prev_i)
        //   swsel   = is_sw*(1 - bit2) for limbs 0,1 and is_sw*bit2 for limbs 2,3
        //
        // Flags are one-hot, so per row at most one term is live and each case is the old
        // per-variant equation: SB patches the selected limb by the byte increment; SH replaces
        // it (ls is one-hot and `selected_limb = sum ls_e*prev_e`, so `ls_i*selected_limb =
        // ls_i*prev_i`); SW replaces the selected half; SD replaces the word. On a load row all
        // terms vanish and the equation is the old "a load leaves memory unchanged" (C4);
        // padding rows are all zero. Four equations replace the sixteen store checks plus the
        // four C4 checks; the degree stays 3 (`ls_i*shift` with a degree-2 `ls_i`,
        // `swsel_i*(a - prev)`).
        let ls = self.limb_select_exprs::<CB>(local);
        let shift: CB::Expr = local.shift.into();
        let not_bit2: CB::Expr = CB::Expr::ONE - bit2;
        let swsel: [CB::Expr; 4] = [
            ins.is_sw * not_bit2.clone(),
            ins.is_sw * not_bit2,
            ins.is_sw * bit2,
            ins.is_sw * bit2,
        ];
        for i in 0..4usize {
            builder.assert_eq(
                mem_val[i],
                prev_mem_val[i]
                    + ls[i].clone() * shift.clone()
                    + ins.is_sd * (a_val[i] - prev_mem_val[i])
                    + swsel[i].clone() * (a_val[i % 2] - prev_mem_val[i]),
            );
        }
    }
}
