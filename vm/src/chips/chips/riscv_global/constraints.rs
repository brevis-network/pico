use super::{
    columns::{GlobalCols, NUM_GLOBAL_COLS},
    GlobalChip,
};
use crate::{
    compiler::riscv::opcode::ByteOpcode,
    machine::{
        builder::{ChipBuilder, ChipLookupBuilder, ChipRangeBuilder},
        lookup::{LookupScope, LookupType, SymbolicLookup},
    },
};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};
use std::borrow::Borrow;

impl<F: Field> BaseAir<F> for GlobalChip<F> {
    fn width(&self) -> usize {
        NUM_GLOBAL_COLS
    }
}

impl<F: Field, CB: ChipBuilder<F>> Air<CB> for GlobalChip<F> {
    fn eval(&self, builder: &mut CB) {
        let main = builder.main();
        let local = main.current_slice();
        let local: &GlobalCols<CB::Var> = (*local).borrow();
        eval_global_row(builder, local);
    }
}

/// The constraints of one Global row. They read the row alone, so the MLE machine's Global AIR,
/// which holds the event table in a partition of its own, applies them to the row it assembles
/// from its two partitions.
///
/// - **Direction and multiplicity.** `is_real`, `is_send` and `is_receive` are boolean and
///   `is_send + is_receive = is_real`, so a real row has exactly one direction and a padding row
///   none; `mu = is_send - is_receive` is then `+1`, `-1` or `0` accordingly. Without the sum, a
///   sender passing both directions would give a real row with `mu = 0`: an event the chunk
///   balances against its senders and the global LogUp never sees.
/// - **The regional bus.** The row receives `[message, is_send, is_receive, kind]` with
///   multiplicity `is_real`. Every sender passes the direction bits and the kind as literal
///   constants, so the multiset pins `is_send`, `is_receive`, `kind` and the message of each real
///   row to what a sender sent.
/// - **Range checks the senders rely on**, on real rows: `message[0]` is 25 bits (the chunk of a
///   memory message, the clk of a syscall message), `message[1]` is 25 bits (the clk of a memory
///   message), `message[7]` is 16 bits.
pub fn eval_global_row<F: Field, CB: ChipBuilder<F>>(
    builder: &mut CB,
    local: &GlobalCols<CB::Var>,
) {
    builder.assert_bool(local.is_real);
    builder.assert_bool(local.is_send);
    builder.assert_bool(local.is_receive);
    builder.assert_eq(local.is_send + local.is_receive, local.is_real);
    builder.assert_eq(local.mu, local.is_send - local.is_receive);

    builder.looked(SymbolicLookup::new(
        vec![
            local.message[0].into(),
            local.message[1].into(),
            local.message[2].into(),
            local.message[3].into(),
            local.message[4].into(),
            local.message[5].into(),
            local.message[6].into(),
            local.message[7].into(),
            local.is_send.into(),
            local.is_receive.into(),
            local.kind.into(),
        ],
        local.is_real.into(),
        LookupType::Global,
        LookupScope::Regional,
    ));

    // message[0] = message_0_16bit_limb + message_0_8bit_limb * 2^16 + message_0_high_bit * 2^24,
    // with a u16 limb, a u8 limb and a boolean high bit: 25 bits.
    builder
        .when(local.is_real)
        .assert_bool(local.message_0_high_bit);
    builder.when(local.is_real).assert_eq(
        local.message[0],
        local.message_0_16bit_limb
            + local.message_0_8bit_limb * CB::F::from_u32(1 << 16)
            + local.message_0_high_bit * CB::F::from_u32(1 << 24),
    );
    builder.looking_byte(
        CB::Expr::from_u8(ByteOpcode::U16Range as u8),
        local.message_0_16bit_limb,
        CB::Expr::ZERO,
        CB::Expr::ZERO,
        local.is_real,
    );
    // Slot order is load-bearing: trace generation emits (b = message_0_8bit_limb, c = 0).
    builder.looking_byte(
        CB::Expr::from_u8(ByteOpcode::U8Range as u8),
        CB::Expr::ZERO,
        local.message_0_8bit_limb,
        CB::Expr::ZERO,
        local.is_real,
    );

    // message[1] is 25 bits. On a memory message it is the clk, which is bound otherwise only by
    // the sends and receives cancelling on this bus; the direct check keeps memory consistency
    // from resting on that argument. Every sender is in range honestly: a clk is within the
    // 25-bit chunk-clk budget, a syscall message carries `syscall_id + 2^8 * arg1[0]` (u8 and
    // u16, checked by the Syscall chip), and MemoryInitialize sends 0.
    builder.range_check_u25_16_9(
        local.message[1],
        local.message_1_16bit_limb,
        local.message_1_hi9,
        local.is_real,
    );

    builder.looking_byte(
        CB::Expr::from_u8(ByteOpcode::U16Range as u8),
        local.message[7],
        CB::Expr::ZERO,
        CB::Expr::ZERO,
        local.is_real,
    );
}
