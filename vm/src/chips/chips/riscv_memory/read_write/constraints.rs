#![allow(clippy::assign_op_pattern)]

use super::{
    columns::{MemoryChipCols, MemoryInstructionCols, NUM_MEMORY_CHIP_COLS},
    MemoryReadWriteChip,
};
use crate::{
    chips::chips::riscv_memory::{
        event::MemoryAccessPosition,
        read_write::columns::{MemoryChipValueCols, MemoryCols},
    },
    compiler::{
        riscv::opcode::{ByteOpcode, Opcode},
        word::Word,
    },
    machine::{
        builder::{
            ChipBuilder, ChipLookupBuilder, ChipRangeBuilder, ChipWordBuilder, RiscVMemoryBuilder,
        },
        lookup::{LookupScope, LookupType, SymbolicLookup},
    },
};
use core::borrow::Borrow;
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{Field, FieldAlgebra};
use p3_matrix::Matrix;

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
        let local = main.row_slice(0);
        let local: &MemoryChipCols<CB::Var> = (*local).borrow();

        for local_memory_chip_value_cols in local.values {
            let is_memory_instruction: CB::Expr =
                self.is_memory_instruction::<CB>(&local_memory_chip_value_cols.instruction);

            // CPU Lookup: receive instruction parameters via looked lookup.
            // Now includes 11 selector flags (8 original + 3 new: is_lwu, is_ld, is_sd).
            use core::iter::once;
            let values = once(local_memory_chip_value_cols.instruction.opcode)
                .chain(local_memory_chip_value_cols.instruction.op_a_val())
                .chain(local_memory_chip_value_cols.instruction.op_b_val())
                .chain(local_memory_chip_value_cols.instruction.op_c_val())
                .chain(once(local_memory_chip_value_cols.instruction.op_a_0))
                .chain(once(local_memory_chip_value_cols.instruction.is_lb))
                .chain(once(local_memory_chip_value_cols.instruction.is_lbu))
                .chain(once(local_memory_chip_value_cols.instruction.is_lh))
                .chain(once(local_memory_chip_value_cols.instruction.is_lhu))
                .chain(once(local_memory_chip_value_cols.instruction.is_lw))
                .chain(once(local_memory_chip_value_cols.instruction.is_lwu))
                .chain(once(local_memory_chip_value_cols.instruction.is_ld))
                .chain(once(local_memory_chip_value_cols.instruction.is_sb))
                .chain(once(local_memory_chip_value_cols.instruction.is_sh))
                .chain(once(local_memory_chip_value_cols.instruction.is_sw))
                .chain(once(local_memory_chip_value_cols.instruction.is_sd))
                .map(Into::into);

            builder.looked(SymbolicLookup::new(
                values.collect(),
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

    // ========================================================================
    // C1 + C2 + C3 + C4: Address calculation, offset, timestamp, load-no-write
    // ========================================================================

    pub(crate) fn eval_memory_address_and_access<CB: ChipBuilder<F>>(
        &self,
        builder: &mut CB,
        local: &MemoryChipValueCols<CB::Var>,
        is_memory_instruction: CB::Expr,
    ) {
        let is_mem = is_memory_instruction.clone();

        // ---- C1: Address calculation ----

        // 1. ALU ADD lookup: addr_word = op_b + op_c (ALU supports 4×u16)
        builder.looking_alu(
            CB::Expr::from_canonical_u32(Opcode::ADD as u32),
            local.addr_word,
            local.op_b_val(),
            local.op_c_val(),
            is_mem.clone(),
        );

        // 2. addr is the low 3 limbs; constrain 4th limb = 0 (addr fits 48 bits)
        builder
            .when(is_mem.clone())
            .assert_zero(local.addr_word.0[3]);

        // 3. u16 range check on addr limbs
        builder.slice_range_check_u16(&local.addr_word.0[0..3], is_mem.clone());

        // 4. Stack guard: addr[1] + addr[2] != 0 → addr >= 2^16
        let sum_top: CB::Expr = local.addr_word.0[1] + local.addr_word.0[2];
        builder.assert_eq(
            CB::Expr::ZERO + local.addr_top_two_limb_inv * sum_top,
            is_mem.clone(),
        );

        // ---- C2: Offset decomposition + alignment ----

        // 1. offset bits are bool
        for i in 0..3 {
            builder
                .when(is_mem.clone())
                .assert_bool(local.offset_bit[i]);
        }

        // 1b. Constrain limb_select as one-hot derived from (bit1, bit2).
        // Each is when(deg1) × max(deg1, deg2) = degree 3.
        let ls_b1: CB::Expr = CB::Expr::ZERO + local.offset_bit[1];
        let ls_b2: CB::Expr = CB::Expr::ZERO + local.offset_bit[2];
        builder.when(is_mem.clone()).assert_eq(
            local.limb_select[0],
            (CB::Expr::ONE - ls_b1.clone()) * (CB::Expr::ONE - ls_b2.clone()),
        );
        builder.when(is_mem.clone()).assert_eq(
            local.limb_select[1],
            ls_b1.clone() * (CB::Expr::ONE - ls_b2.clone()),
        );
        builder.when(is_mem.clone()).assert_eq(
            local.limb_select[2],
            (CB::Expr::ONE - ls_b1.clone()) * ls_b2.clone(),
        );
        builder
            .when(is_mem.clone())
            .assert_eq(local.limb_select[3], ls_b1 * ls_b2);

        // 2. Bind offset_bit to addr[0]: (addr[0] - offset) must be divisible by 8.
        //    Method: looking_byte(BitRange, (addr[0]-offset)/8, 13, 0, is_mem).
        //    Max value of (addr[0]-offset)/8 = (65535-0)/8 = 8191 = 2^13-1, so 13 bits suffice.
        //    If offset_bit is wrong, (addr[0]-offset)/8 is not an integer and the
        //    field element will be > 2^13 (since p >> 2^13), failing the range check.
        let offset_sum: CB::Expr = CB::Expr::ZERO
            + local.offset_bit[0]
            + CB::Expr::TWO * local.offset_bit[1]
            + CB::Expr::from_canonical_u8(4) * local.offset_bit[2];
        let inv_8 = CB::F::from_canonical_u8(8).inverse();
        builder.looking_byte(
            CB::Expr::from_canonical_u8(ByteOpcode::BitRange as u8),
            (CB::Expr::ZERO + local.addr_word.0[0] - offset_sum.clone()) * CB::Expr::from(inv_8),
            CB::Expr::from_canonical_u8(13),
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
        // eval_memory_access handles timestamp monotonicity and 9-element Regional lookup.
        builder.eval_memory_access(
            local.chunk,
            local.clk + CB::F::from_canonical_u32(MemoryAccessPosition::Memory as u32),
            [
                CB::Expr::ZERO + local.addr_word.0[0] - offset_sum,
                local.addr_word.0[1].into(),
                local.addr_word.0[2].into(),
            ],
            &local.memory_access,
            is_mem.clone(),
        );

        // ---- C4: Load doesn't change memory ----
        builder
            .when(self.is_load_instruction::<CB>(&local.instruction))
            .assert_word_eq(
                *local.memory_access.value(),
                *local.memory_access.prev_value(),
            );
    }

    // ========================================================================
    // C5 + C6 + C8: Load sub-word selection + sign extension + x0 handling
    // ========================================================================

    pub(crate) fn eval_memory_load<CB: ChipBuilder<F>>(
        &self,
        builder: &mut CB,
        local: &MemoryChipValueCols<CB::Var>,
    ) {
        let mem_val = *local.memory_access.prev_value();
        let is_mem = self.is_memory_instruction::<CB>(&local.instruction);

        // ---- C5: Limb selection (4-choose-1 via limb_select one-hot) ----
        // selected_limb = mem_val[2*bit2 + bit1]
        // Uses pre-computed limb_select[i] (Var, degree 1) instead of
        // algebraic bit products (degree 2) to keep total degree ≤ 3.
        let bit0 = local.offset_bit[0];
        let bit2 = local.offset_bit[2];

        let expected_limb: CB::Expr = CB::Expr::ZERO
            + local.limb_select[0] * mem_val[0]
            + local.limb_select[1] * mem_val[1]
            + local.limb_select[2] * mem_val[2]
            + local.limb_select[3] * mem_val[3];
        builder
            .when(is_mem.clone())
            .assert_eq(local.selected_limb, expected_limb);

        // ---- C6: Load sub-word extraction ----

        // LB/LBU: split selected_limb into 2 bytes, select one via bit0
        let inv_256 = CB::F::from_canonical_u16(256).inverse();
        let byte0: CB::Expr = CB::Expr::ZERO + local.selected_limb_low_byte;
        let byte1: CB::Expr = (CB::Expr::ZERO + local.selected_limb - local.selected_limb_low_byte)
            * CB::Expr::from(inv_256);

        let is_byte_load: CB::Expr = local.instruction.is_lb + local.instruction.is_lbu;
        builder.when(is_byte_load.clone()).assert_eq(
            local.selected_byte,
            CB::Expr::ZERO + bit0 * byte1 + (CB::Expr::ONE - bit0) * byte0,
        );

        // Range check: both bytes of selected_limb ∈ [0, 255].
        // The high byte is never a witness column — it is computed inline as
        // (selected_limb - selected_limb_low_byte) * inv_256. Without this check
        // a prover can supply a fake selected_limb_low_byte that makes the high
        // byte an arbitrary field element, breaking the u8 bound on selected_byte.
        let high_byte: CB::Expr = (CB::Expr::ZERO + local.selected_limb
            - local.selected_limb_low_byte)
            * CB::Expr::from(inv_256);
        builder.looking_rangecheck(
            ByteOpcode::U8Range,
            CB::Expr::ZERO,
            CB::Expr::ZERO,
            local.selected_limb_low_byte,
            high_byte,
            is_byte_load.clone(),
        );

        // LB/LBU: unsigned_mem_val = [selected_byte, 0, 0, 0]
        let byte_word = Word([
            CB::Expr::ZERO + local.selected_byte,
            CB::Expr::ZERO,
            CB::Expr::ZERO,
            CB::Expr::ZERO,
        ]);
        builder
            .when(is_byte_load)
            .assert_word_eq(local.unsigned_mem_val.map(|x| x.into()), byte_word);

        // LH/LHU: unsigned_mem_val = [selected_limb, 0, 0, 0]
        let half_word = Word([
            CB::Expr::ZERO + local.selected_limb,
            CB::Expr::ZERO,
            CB::Expr::ZERO,
            CB::Expr::ZERO,
        ]);
        builder
            .when(local.instruction.is_lh + local.instruction.is_lhu)
            .assert_word_eq(local.unsigned_mem_val.map(|x| x.into()), half_word);

        // LW/LWU: selected_word selection via bit2 (algebraic approach)
        let is_word_load: CB::Expr = local.instruction.is_lw + local.instruction.is_lwu;
        // selected_word[0] = (1-bit2)*mem[0] + bit2*mem[2]
        // selected_word[1] = (1-bit2)*mem[1] + bit2*mem[3]
        let expected_sw0: CB::Expr =
            (CB::Expr::ONE - bit2) * mem_val[0] + (CB::Expr::ZERO + bit2) * mem_val[2];
        let expected_sw1: CB::Expr =
            (CB::Expr::ONE - bit2) * mem_val[1] + (CB::Expr::ZERO + bit2) * mem_val[3];
        builder
            .when(is_word_load.clone())
            .assert_eq(local.selected_word[0], expected_sw0);
        builder
            .when(is_word_load.clone())
            .assert_eq(local.selected_word[1], expected_sw1);

        // LW/LWU: unsigned_mem_val = [word[0], word[1], 0, 0]
        let word_val = Word([
            CB::Expr::ZERO + local.selected_word[0],
            CB::Expr::ZERO + local.selected_word[1],
            CB::Expr::ZERO,
            CB::Expr::ZERO,
        ]);
        builder
            .when(is_word_load)
            .assert_word_eq(local.unsigned_mem_val.map(|x| x.into()), word_val);

        // LD: unsigned_mem_val = mem_val (all 4 limbs)
        builder
            .when(local.instruction.is_ld)
            .assert_word_eq(local.unsigned_mem_val, mem_val);

        // --- msb independent verification ----

        // LB: verify msb == bit7 of selected_byte via ByteOpcode::MSB lookup
        builder.looking_byte(
            CB::Expr::from_canonical_u8(ByteOpcode::MSB as u8),
            local.msb,           // a = msb result
            local.selected_byte, // b = byte value
            CB::Expr::ZERO,      // c = 0
            local.instruction.is_lb,
        );
        // LBU: msb forced to 0
        builder
            .when(local.instruction.is_lbu)
            .assert_zero(local.msb);

        // LH: U16MSBOperation — verify msb == bit15 of selected_limb
        //   assert_bool(msb), then check 2*selected_limb - msb*2^16 ∈ [0, 2^16)
        builder.when(local.instruction.is_lh).assert_bool(local.msb);
        builder.looking_byte(
            CB::Expr::from_canonical_u8(ByteOpcode::U16Range as u8),
            CB::Expr::TWO * local.selected_limb
                - CB::Expr::ZERO
                - local.msb * CB::Expr::from_canonical_u32(1 << 16),
            CB::Expr::ZERO,
            CB::Expr::ZERO,
            local.instruction.is_lh,
        );
        // LHU: msb forced to 0
        builder
            .when(local.instruction.is_lhu)
            .assert_zero(local.msb);

        // LW: U16MSBOperation — verify msb == bit15 of selected_word[1]
        builder.when(local.instruction.is_lw).assert_bool(local.msb);
        builder.looking_byte(
            CB::Expr::from_canonical_u8(ByteOpcode::U16Range as u8),
            CB::Expr::TWO * local.selected_word[1]
                - CB::Expr::ZERO
                - local.msb * CB::Expr::from_canonical_u32(1 << 16),
            CB::Expr::ZERO,
            CB::Expr::ZERO,
            local.instruction.is_lw,
        );
        // LWU/LD: msb forced to 0 (no sign extension)
        builder
            .when(local.instruction.is_lwu + local.instruction.is_ld)
            .assert_zero(local.msb);

        // ---- C8: x0 handling + sign extension ----

        builder.assert_bool(local.instruction.op_a_0);

        // When rd = x0, pin op_a to zero regardless of load type.
        for i in 0..4 {
            builder.assert_eq(
                local.instruction.op_a_0 * local.op_a_val()[i],
                CB::Expr::ZERO,
            );
        }

        // mem_value_is_neg_not_x0 = (is_lb + is_lh + is_lw) * msb * (1 - op_a_0)
        builder.assert_eq(
            local.mem_value_is_neg_not_x0,
            (local.instruction.is_lb + local.instruction.is_lh + local.instruction.is_lw)
                * local.msb
                * (CB::Expr::ONE - local.instruction.op_a_0),
        );

        // mem_value_is_pos_not_x0
        let mem_value_is_pos: CB::Expr = local.instruction.is_lbu
            + local.instruction.is_lhu
            + local.instruction.is_lwu
            + local.instruction.is_ld
            + (local.instruction.is_lb + local.instruction.is_lh + local.instruction.is_lw)
                * (CB::Expr::ONE - local.msb);
        builder.assert_eq(
            local.mem_value_is_pos_not_x0,
            mem_value_is_pos * (CB::Expr::ONE - local.instruction.op_a_0),
        );

        // Sign extension via direct limb fill:
        let msb_expr: CB::Expr = CB::Expr::ZERO + local.msb;
        let fill_ffff: CB::Expr = CB::Expr::from_canonical_u16(0xFFFF) * msb_expr.clone();

        // LB sign extension: op_a = [byte + 0xFF00*msb, 0xFFFF*msb, 0xFFFF*msb, 0xFFFF*msb]
        let lb_sign_ext = Word([
            CB::Expr::ZERO
                + local.selected_byte
                + CB::Expr::from_canonical_u16(0xFF00) * msb_expr.clone(),
            fill_ffff.clone(),
            fill_ffff.clone(),
            fill_ffff.clone(),
        ]);
        builder
            .when(local.mem_value_is_neg_not_x0)
            .when(local.instruction.is_lb)
            .assert_word_eq(local.op_a_val().map(|x| x.into()), lb_sign_ext);

        // LH sign extension: op_a = [selected_limb, 0xFFFF*msb, ...]
        let lh_sign_ext = Word([
            CB::Expr::ZERO + local.selected_limb,
            fill_ffff.clone(),
            fill_ffff.clone(),
            fill_ffff.clone(),
        ]);
        builder
            .when(local.mem_value_is_neg_not_x0)
            .when(local.instruction.is_lh)
            .assert_word_eq(local.op_a_val().map(|x| x.into()), lh_sign_ext);

        // LW sign extension: op_a = [word[0], word[1], 0xFFFF*msb, 0xFFFF*msb]
        let lw_sign_ext = Word([
            CB::Expr::ZERO + local.selected_word[0],
            CB::Expr::ZERO + local.selected_word[1],
            fill_ffff.clone(),
            fill_ffff,
        ]);
        builder
            .when(local.mem_value_is_neg_not_x0)
            .when(local.instruction.is_lw)
            .assert_word_eq(local.op_a_val().map(|x| x.into()), lw_sign_ext);

        // When positive and not x0: op_a = unsigned_mem_val
        builder
            .when(local.mem_value_is_pos_not_x0)
            .assert_word_eq(local.unsigned_mem_val, local.op_a_val());
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
        // Split register op_a[0] into 2 bytes, range check both → binds register_low_byte
        let inv_256 = CB::F::from_canonical_u16(256).inverse();
        let reg_high_byte: CB::Expr =
            (CB::Expr::ZERO + a_val[0] - local.register_low_byte) * CB::Expr::from(inv_256);
        builder.looking_rangecheck(
            ByteOpcode::U8Range,
            CB::Expr::ZERO,
            CB::Expr::ZERO,
            local.register_low_byte,
            reg_high_byte,
            local.instruction.is_sb,
        );
        // Split selected_limb (target mem limb) into 2 bytes → binds mem_limb_low_byte
        let mem_high_byte: CB::Expr = (CB::Expr::ZERO + local.selected_limb
            - local.mem_limb_low_byte)
            * CB::Expr::from(inv_256);
        builder.looking_rangecheck(
            ByteOpcode::U8Range,
            CB::Expr::ZERO,
            CB::Expr::ZERO,
            local.mem_limb_low_byte,
            mem_high_byte.clone(),
            local.instruction.is_sb,
        );

        // ---- SB: increment pattern ----
        let inc_low: CB::Expr = (CB::Expr::ONE - bit0)
            * (CB::Expr::ZERO + local.register_low_byte - local.mem_limb_low_byte);
        let inc_high: CB::Expr = (CB::Expr::ZERO + bit0)
            * ((CB::Expr::ZERO + local.register_low_byte) * CB::Expr::from_canonical_u16(256)
                - local.selected_limb
                + local.mem_limb_low_byte);
        builder
            .when(local.instruction.is_sb)
            .assert_eq(local.increment, inc_low + inc_high);

        // store_value[i] = prev[i] + increment * limb_select[i]
        // Uses limb_select[i] (Var, degree 1) instead of bit products (degree 2)
        // to keep total degree ≤ 3.
        for i in 0..4usize {
            builder.when(local.instruction.is_sb).assert_eq(
                local.store_value[i],
                CB::Expr::ZERO
                    + prev_mem_val[i]
                    + (CB::Expr::ZERO + local.increment) * local.limb_select[i],
            );
        }

        // ---- SH: increment pattern ----
        let store_limb_sh: CB::Expr = CB::Expr::ZERO + a_val[0];
        for i in 0..4usize {
            builder.when(local.instruction.is_sh).assert_eq(
                local.store_value[i],
                CB::Expr::ZERO
                    + prev_mem_val[i]
                    + (store_limb_sh.clone() - prev_mem_val[i]) * local.limb_select[i],
            );
        }

        // ---- SW: increment pattern ----
        let not_bit2: CB::Expr = CB::Expr::ONE - bit2;
        let bit2_expr: CB::Expr = CB::Expr::ZERO + bit2;
        builder.when(local.instruction.is_sw).assert_eq(
            local.store_value[0],
            CB::Expr::ZERO
                + prev_mem_val[0]
                + (CB::Expr::ZERO + a_val[0] - prev_mem_val[0]) * not_bit2.clone(),
        );
        builder.when(local.instruction.is_sw).assert_eq(
            local.store_value[1],
            CB::Expr::ZERO
                + prev_mem_val[1]
                + (CB::Expr::ZERO + a_val[1] - prev_mem_val[1]) * not_bit2,
        );
        builder.when(local.instruction.is_sw).assert_eq(
            local.store_value[2],
            CB::Expr::ZERO
                + prev_mem_val[2]
                + (CB::Expr::ZERO + a_val[0] - prev_mem_val[2]) * bit2_expr.clone(),
        );
        builder.when(local.instruction.is_sw).assert_eq(
            local.store_value[3],
            CB::Expr::ZERO
                + prev_mem_val[3]
                + (CB::Expr::ZERO + a_val[1] - prev_mem_val[3]) * bit2_expr,
        );

        // ---- SD: store_value = op_a (complete write) ----
        builder
            .when(local.instruction.is_sd)
            .assert_word_eq(local.store_value.map(|x| x.into()), a_val.map(|x| x.into()));

        // ---- Assert store_value == memory_access.value() for all store instructions ----
        let is_store = self.is_store_instruction::<CB>(&local.instruction);
        builder.when(is_store).assert_word_eq(
            mem_val.map(|x| x.into()),
            local.store_value.map(|x| x.into()),
        );
    }
}
