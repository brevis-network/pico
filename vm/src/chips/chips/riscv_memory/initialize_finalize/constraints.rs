use super::{
    columns::{MemoryInitializeFinalizeCols, NUM_MEMORY_INITIALIZE_FINALIZE_COLS},
    MemoryChipType, MemoryInitializeFinalizeChip,
};
use crate::{
    chips::gadgets::{is_zero::IsZeroGadget, lt_word_u16::LtWordU16Gadget},
    compiler::word::Word,
    emulator::riscv::public_values::PublicValues,
    machine::{
        builder::{ChipBaseBuilder, ChipBuilder, ChipRangeBuilder},
        lookup::{LookupScope, LookupType, SymbolicLookup},
    },
    primitives::consts::MAX_NUM_PVS,
};
use core::borrow::Borrow;
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{Field, FieldAlgebra};
use p3_matrix::Matrix;
use std::array;

impl<F: Field> BaseAir<F> for MemoryInitializeFinalizeChip<F> {
    fn width(&self) -> usize {
        NUM_MEMORY_INITIALIZE_FINALIZE_COLS
    }
}

impl<F: Field, CB: ChipBuilder<F>> Air<CB> for MemoryInitializeFinalizeChip<F>
where
    CB::Var: Sized,
{
    fn eval(&self, builder: &mut CB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &MemoryInitializeFinalizeCols<CB::Var> = (*local).borrow();
        let next = main.row_slice(1);
        let next: &MemoryInitializeFinalizeCols<CB::Var> = (*next).borrow();

        builder.assert_bool(local.is_real);
        builder.assert_bool(local.is_comp);

        // ──────────────────────────────────────────────────
        // Range checks: addr, prev_addr, value as u16 limbs
        // ──────────────────────────────────────────────────
        builder.slice_range_check_u16(&local.value.0, local.is_real);
        builder.slice_range_check_u16(&local.prev_addr, local.is_real);
        builder.slice_range_check_u16(&local.addr, local.is_real);

        // ──────────────────────────────────────────────
        // packing: value.0[2] = value_lower + value_upper * 256
        // ──────────────────────────────────────────────
        builder.assert_eq(
            local.value.0[2],
            local.value_lower + local.value_upper * CB::F::from_canonical_u32(256),
        );
        // Range check value_lower and value_upper as u8
        builder.slice_range_check_u8(&[local.value_lower, local.value_upper], local.is_real);

        // ──────────────────────────────────────────────
        // Global message construction (8-slot packed format)
        // ──────────────────────────────────────────────

        // v0 + v2_lower<<16, v1 + v2_upper<<16, v3
        let slot5: CB::Expr =
            local.value.0[0].into() + local.value_lower * CB::F::from_canonical_u32(1 << 16);
        let slot6: CB::Expr =
            local.value.0[1].into() + local.value_upper * CB::F::from_canonical_u32(1 << 16);
        let slot7: CB::Expr = local.value.0[3].into();

        if self.kind == MemoryChipType::Initialize {
            // Initialize: send interaction. chunk=0, timestamp=0 (initial state).
            builder.looking(SymbolicLookup::new(
                vec![
                    CB::Expr::ZERO,       // slot0: chunk = 0
                    CB::Expr::ZERO,       // slot1: timestamp = 0
                    local.addr[0].into(), // slot2: addr[0]
                    local.addr[1].into(), // slot3: addr[1]
                    local.addr[2].into(), // slot4: addr[2]
                    slot5.clone(),        // slot5: v0 + v2_lower<<16
                    slot6.clone(),        // slot6: v1 + v2_upper<<16
                    slot7.clone(),        // slot7: v3
                    CB::Expr::ONE,        // is_send = 1
                    CB::Expr::ZERO,       // is_receive = 0
                    CB::Expr::from_canonical_u8(LookupType::Memory as u8),
                ],
                local.is_real.into(),
                LookupType::Global,
                LookupScope::Regional,
            ));
        } else {
            // Finalize: receive interaction. Uses actual chunk and timestamp.
            builder.looking(SymbolicLookup::new(
                vec![
                    local.chunk.into(),     // slot0: chunk
                    local.timestamp.into(), // slot1: timestamp
                    local.addr[0].into(),   // slot2: addr[0]
                    local.addr[1].into(),   // slot3: addr[1]
                    local.addr[2].into(),   // slot4: addr[2]
                    slot5.clone(),          // slot5: v0 + v2_lower<<16
                    slot6.clone(),          // slot6: v1 + v2_upper<<16
                    slot7.clone(),          // slot7: v3
                    CB::Expr::ZERO,         // is_send = 0
                    CB::Expr::ONE,          // is_receive = 1
                    CB::Expr::from_canonical_u8(LookupType::Memory as u8),
                ],
                local.is_real.into(),
                LookupType::Global,
                LookupScope::Regional,
            ));
        }

        // ──────────────────────────────────────────────
        // Address ordering: prev_addr < addr when is_comp == 1
        // ──────────────────────────────────────────────

        // Wrap addr and prev_addr into Word<Expr> for LtWordU16Gadget.
        // 4th limb is Expr::ZERO (addresses are 48-bit).
        let prev_addr_word = Word([
            local.prev_addr[0].into(),
            local.prev_addr[1].into(),
            local.prev_addr[2].into(),
            CB::Expr::ZERO,
        ]);
        let addr_word = Word([
            local.addr[0].into(),
            local.addr[1].into(),
            local.addr[2].into(),
            CB::Expr::ZERO,
        ]);

        LtWordU16Gadget::<CB::F>::eval(
            builder,
            prev_addr_word,
            addr_word,
            local.lt_cols,
            local.is_comp.into(),
        );

        // ──────────────────────────────────────────────
        // is_prev_addr_zero: check if prev_addr is all zeros
        // ──────────────────────────────────────────────
        // SAFETY: u16 limbs sum can't overflow (max = 3 * 65535 = 196605 < p).
        let prev_addr_sum: CB::Expr =
            local.prev_addr[0].into() + local.prev_addr[1].into() + local.prev_addr[2].into();

        let is_first_row = builder.is_first_row();
        IsZeroGadget::<CB::F>::eval(
            builder,
            prev_addr_sum,
            local.is_prev_addr_zero,
            is_first_row,
        );

        // ──────────────────────────────────────────────
        // Row ordering constraints (Pico's when_transition style)
        // ──────────────────────────────────────────────

        // On transition rows where next.is_real: next.prev_addr == local.addr
        for i in 0..3 {
            builder
                .when_transition()
                .when(next.is_real)
                .assert_eq(next.prev_addr[i], local.addr[i]);
        }

        // On transition rows: next.is_comp == next.is_real (all non-first real rows do comparison)
        builder
            .when_transition()
            .assert_eq(next.is_comp, next.is_real);

        // Real rows are padded to the top (no padding→real transition).
        builder
            .when_transition()
            .when_not(local.is_real)
            .assert_zero(next.is_real);

        // Ensure at least one real row.
        builder.when_first_row().assert_one(local.is_real);

        // ──────────────────────────────────────────────
        // First row constraints: prev_addr from public values
        // ──────────────────────────────────────────────

        let public_values_array: [CB::Expr; MAX_NUM_PVS] =
            array::from_fn(|i| builder.public_values()[i].into());
        let public_values: &PublicValues<Word<CB::Expr>, CB::Expr> =
            public_values_array.as_slice().borrow();

        let prev_addr_limbs = match self.kind {
            MemoryChipType::Initialize => &public_values.previous_init_addr_limbs,
            MemoryChipType::Finalize => &public_values.previous_finalize_addr_limbs,
        };

        // First row: prev_addr must match PV u16 limbs directly.
        for i in 0..3 {
            builder
                .when_first_row()
                .assert_eq(local.prev_addr[i], prev_addr_limbs[i].clone());
        }

        // NOTE: PV prev_addr limbs are transitively range-checked:
        //   PV limb == local.prev_addr[i] (assert_eq above) → u16 range check

        // First row: is_comp = is_real * (1 - is_prev_addr_zero.result)
        //   If prev_addr == 0, no comparison needed (addr could be 0 for x0 register).
        builder.when_first_row().assert_eq(
            local.is_comp,
            local.is_real * (CB::Expr::ONE - local.is_prev_addr_zero.result),
        );

        // When prev_addr == 0 on first row: addr must also be 0 (x0 register initialization).
        builder
            .when_first_row()
            .when(local.is_prev_addr_zero.result)
            .assert_zero(local.addr[0] + local.addr[1] + local.addr[2]);

        // When prev_addr == 0 on first row: the next row must also be real, and comparison enabled.
        builder
            .when_first_row()
            .when(local.is_prev_addr_zero.result)
            .assert_one(next.is_real);
        builder
            .when_first_row()
            .when(local.is_prev_addr_zero.result)
            .assert_one(next.is_comp);

        // ──────────────────────────────────────────────
        // Initialize chip: timestamp must be 1 (initial timestamp)
        // ──────────────────────────────────────────────
        if self.kind == MemoryChipType::Initialize {
            builder
                .when(local.is_real)
                .assert_eq(local.timestamp, CB::F::ONE);
        }

        // ──────────────────────────────────────────────
        // x0 register constraint: value must be 0 when is_comp == 0
        // ──────────────────────────────────────────────
        // When is_comp==0 (meaning prev_addr==0 on first row, i.e., this is address 0),
        // the value must be zero. This enforces the RISC-V invariant that x0 == 0.
        for i in 0..4 {
            builder
                .when_first_row()
                .when_not(local.is_comp)
                .assert_zero(local.value.0[i]);
        }

        // ──────────────────────────────────────────────
        // Last address → public values connection
        // ──────────────────────────────────────────────
        let last_addr_limbs = match self.kind {
            MemoryChipType::Initialize => &public_values.last_init_addr_limbs,
            MemoryChipType::Finalize => &public_values.last_finalize_addr_limbs,
        };

        // The last real row's addr must match the PV last_addr.
        // "Last real row" = either last row & is_real, or transition where is_real but next not.
        let is_last_addr: CB::Expr = local.is_real * (CB::Expr::ONE - next.is_real);

        for i in 0..3 {
            builder
                .when_last_row()
                .when(local.is_real)
                .assert_eq(local.addr[i], last_addr_limbs[i].clone());
        }

        for i in 0..3 {
            builder
                .when_transition()
                .when(is_last_addr.clone())
                .assert_eq(local.addr[i], last_addr_limbs[i].clone());
        }

        // NOTE: PV last_addr limbs are transitively range-checked:
        //   PV limb == local.addr[i] (assert_eq above) → u16 range check
    }
}
