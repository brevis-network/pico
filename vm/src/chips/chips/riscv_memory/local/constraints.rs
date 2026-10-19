use super::{
    columns::{MemoryLocalCols, NUM_MEMORY_LOCAL_INIT_COLS},
    MemoryLocalChip,
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

impl<F: Field> BaseAir<F> for MemoryLocalChip<F> {
    fn width(&self) -> usize {
        NUM_MEMORY_LOCAL_INIT_COLS
    }
}

impl<F: Field, CB: ChipBuilder<F>> Air<CB> for MemoryLocalChip<F>
where
    CB::Var: Sized,
{
    fn eval(&self, builder: &mut CB) {
        let main = builder.main();
        let local = main.current_slice();
        let local: &MemoryLocalCols<CB::Var> = (*local).borrow();

        for local in local.memory_local_entries.iter() {
            builder.assert_bool(local.is_real);

            // Whether the entry receives its initial state from the Global bus or declares it.
            //
            // G1 / G2: `has_initial` is boolean and zero off real rows, so it can serve as the
            // degree-1 multiplicity of the Global receive below and a padding row receives
            // nothing. G4: a real entry that does not receive (`is_real - has_initial`, which
            // G1 / G2 make 1 exactly on a fresh entry) declares the initial value zero -- the
            // only initial state a word outside the image that no MemoryInitialize row covers
            // can honestly have (`riscv_memory/event.rs`, `is_fresh_local_mem`). The packing
            // equation and u8 checks below then zero `initial_value_lower / upper` too.
            //
            // Soundness: per address, the Global multiset's kind-Memory senders are the
            // MemoryInitialize row, the image digest and (implicitly, as the missing receive)
            // this declaration; the only receiver that is not itself an entry's receive is the
            // MemoryFinalize row, at most one per address. Every `has_initial = 1` entry nets
            // zero (one receive, one send), a fresh entry nets +1 (send only), so
            // `MemInit(X) + image(X) + fresh(X) = MemFinal(X) <= 1`: hiding a predecessor,
            // declaring an image word or a register fresh (its MemoryInitialize row or the
            // digest then has no receiver), or declaring twice all unbalance the sum. The
            // declared value is pinned to zero, while a MemoryInitialize row's value is the
            // prover's choice today (range-checked only), so the accepted set does not grow;
            // in particular a register declared fresh with no MemoryInitialize chip at all
            // still starts at zero, which is x0's only legal initial value.
            builder.assert_bool(local.has_initial);
            builder
                .when_not(local.is_real)
                .assert_zero(local.has_initial);
            let declares_initial = local.is_real.into() - local.has_initial.into();
            for limb in local.initial_value.0.iter() {
                builder.when(declares_initial.clone()).assert_zero(*limb);
            }

            // Which of the two shapes this entry has, and the `clk` that follows from it.
            //
            // `initial_in_chunk` is pinned to zero off real rows so it can serve as a degree-1
            // lookup multiplicity below (`is_real * initial_in_chunk` would be degree 2, which
            // a lookup message rejects).
            builder.assert_bool(local.initial_in_chunk);
            builder
                .when_not(local.is_real)
                .assert_zero(local.initial_in_chunk);
            let starts_earlier = local.is_real.into() - local.initial_in_chunk.into();

            // Starts in this chunk: same chunk, and the bus carries the real `initial_clk`.
            builder
                .when(local.initial_in_chunk)
                .assert_eq(local.initial_chunk, local.final_chunk);
            builder
                .when(local.initial_in_chunk)
                .assert_eq(local.initial_clk_regional, local.initial_clk);

            // Starts earlier: the bus carries the sentinel, and the chunk must strictly advance
            // — strictly as an *integer*, because the step is bounded to u16 here while the
            // Global bus range-checks the chunk slot to 25 bits at both ends (slot 0 carries
            // `initial_chunk` on one message and `final_chunk` on the other), so the subtraction
            // cannot wrap. That integer ordering is what a forged entry cannot escape.
            builder
                .when(starts_earlier.clone())
                .assert_zero(local.initial_clk_regional);
            builder.looking_rangecheck(
                ByteOpcode::U16Range,
                local.final_chunk.into() - local.initial_chunk.into() - CB::Expr::ONE,
                CB::Expr::ZERO,
                CB::Expr::ZERO,
                CB::Expr::ZERO,
                starts_earlier,
            );

            // On entries that start in this chunk, `initial_clk < final_clk`. True for honest
            // entries by construction: an interval's initial state is the predecessor of its
            // first access and its final state is its last. It also rules out the entry whose
            // two Global messages carry the same payload (equal clk and equal values), whose
            // digest contributions cancel and which would otherwise be free to add.
            builder.range_check_u25_16_9(
                local.final_clk.into() - local.initial_clk.into() - CB::Expr::ONE,
                local.clk_diff_16bit_limb,
                local.clk_diff_hi9,
                local.initial_in_chunk,
            );

            // Regional lookup: 9 elements [chunk, clk, addr[0], addr[1], addr[2], v0, v1, v2, v3]
            // The regional side is normalized: `final_chunk` (the predecessor is in this chunk
            // by construction) and the sentinel-or-real `clk`. The Global side below keeps the
            // real `(initial_chunk, initial_clk)`, so the cross-chunk chain is unchanged.
            let initial_regional = vec![
                local.final_chunk.into(),
                local.initial_clk_regional.into(),
                local.addr[0].into(),
                local.addr[1].into(),
                local.addr[2].into(),
                local.initial_value[0].into(),
                local.initial_value[1].into(),
                local.initial_value[2].into(),
                local.initial_value[3].into(),
            ];
            // Looked initial values for Regional scope.
            builder.looked(SymbolicLookup::new(
                initial_regional,
                local.is_real.into(),
                LookupType::Memory,
                LookupScope::Regional,
            ));

            // v2 packing constraints: value[2] = value_lower + value_upper * 256
            builder.when(local.is_real).assert_eq(
                local.initial_value[2],
                CB::Expr::from_u32(256) * local.initial_value_upper + local.initial_value_lower,
            );
            builder.when(local.is_real).assert_eq(
                local.final_value[2],
                CB::Expr::from_u32(256) * local.final_value_upper + local.final_value_lower,
            );

            // Range checks for soundness.
            // v2 packing columns must be u8.
            builder.slice_range_check_u8(
                &[local.initial_value_lower, local.initial_value_upper],
                local.is_real,
            );
            builder.slice_range_check_u8(
                &[local.final_value_lower, local.final_value_upper],
                local.is_real,
            );
            // Only `initial_value[0]` and `[1]` are range-checked here. The Global messages
            // below pack them as `v + 2^16 * byte`, and that slot is injective only for
            // `v < 2^16` (the byte is a u8 by the pair lookups above), so a cross-chunk initial
            // state could otherwise be decoded as a non-canonical limb and enter the memory bus
            // as a predecessor value. Every other limb of this entry is bound to a memory-bus
            // peer that bounds it itself: `initial_value[2]` is `lower + 256 * upper`;
            // `initial_value[3]` travels in an unpacked Global slot that the receiving GlobalChip
            // range-checks when the entry receives, and is pinned to zero by G4 when it does not
            // (a fresh entry sends no initial message, so on it every `initial_value` limb is
            // the canonical 0); `final_value` equals the last access's written value (every memory
            // writer range-checks what it writes) or, when this entry's final state pairs with
            // another entry's initial state of this chip, that entry's `initial_value`, which
            // the same reasoning bounds -- a read carries its predecessor's value unchanged, so
            // the chain of predecessors ends at a write or at an entry's initial state; `addr`
            // equals the accessing chip's
            // address, which every accessor range-checks itself (Program-table register index,
            // the MemoryReadWrite address limbs, `AddrAddGadget` in the precompiles). An entry
            // whose tuples pair only with other entries of this chip never meets an access and
            // changes no memory state, so its limbs need no bound.
            builder.slice_range_check_u16(&local.initial_value.0[..2], local.is_real);

            // Global lookup: 11 elements [chunk, clk, addr[0..2], v0+v2_lower<<16, v1+v2_upper<<16, v3, is_send, is_receive, kind]
            // Send the "receive interaction" to the global table (initial values). G3: the
            // multiplicity is `has_initial`, not `is_real` -- a fresh entry declares its initial
            // state (zero, G4 above) and receives nothing.
            builder.looking(SymbolicLookup::new(
                vec![
                    local.initial_chunk.into(),
                    local.initial_clk.into(),
                    local.addr[0].into(),
                    local.addr[1].into(),
                    local.addr[2].into(),
                    local.initial_value[0].into()
                        + CB::Expr::from_u32(1 << 16) * local.initial_value_lower,
                    local.initial_value[1].into()
                        + CB::Expr::from_u32(1 << 16) * local.initial_value_upper,
                    local.initial_value[3].into(),
                    CB::Expr::ZERO,
                    CB::Expr::ONE,
                    CB::Expr::from_u8(LookupType::Memory as u8),
                ],
                local.has_initial.into(),
                LookupType::Global,
                LookupScope::Regional,
            ));

            // Send the "send interaction" to the global table (final values).
            builder.looking(SymbolicLookup::new(
                vec![
                    local.final_chunk.into(),
                    local.final_clk.into(),
                    local.addr[0].into(),
                    local.addr[1].into(),
                    local.addr[2].into(),
                    local.final_value[0].into()
                        + CB::Expr::from_u32(1 << 16) * local.final_value_lower,
                    local.final_value[1].into()
                        + CB::Expr::from_u32(1 << 16) * local.final_value_upper,
                    local.final_value[3].into(),
                    CB::Expr::ONE,
                    CB::Expr::ZERO,
                    CB::Expr::from_u8(LookupType::Memory as u8),
                ],
                local.is_real.into(),
                LookupType::Global,
                LookupScope::Regional,
            ));

            // Looking final values for Regional scope.
            let final_regional = vec![
                local.final_chunk.into(),
                local.final_clk.into(),
                local.addr[0].into(),
                local.addr[1].into(),
                local.addr[2].into(),
                local.final_value[0].into(),
                local.final_value[1].into(),
                local.final_value[2].into(),
                local.final_value[3].into(),
            ];
            builder.looking(SymbolicLookup::new(
                final_regional,
                local.is_real.into(),
                LookupType::Memory,
                LookupScope::Regional,
            ));
        }
    }
}
