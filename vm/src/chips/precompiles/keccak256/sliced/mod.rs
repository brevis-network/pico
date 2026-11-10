//! The Keccak-f permutation AIR in a sliced lookup layout (after ZisK's `keccakf`
//! `lanes_per_row = 25` variant): two permutations A and B share one 27-row slot, every state
//! cell holds A's bit plus 8 times B's bit, and the non-linear steps go through two fixed lookup
//! tables ([`KeccakTables`]) instead of bit-level constraints.
//!
//! # Layout
//!
//! | row     | `state[1600]`                                    | `c[320]`                           |
//! |---------|--------------------------------------------------|------------------------------------|
//! | 0       | A's input bits                                   | A's input limbs, B's input limbs   |
//! | 1 + r   | round-`r` input, sliced `v = a + 8·b` (r = 0..24) | sliced column parities (r < 24)   |
//! | 25      | the output, sliced                               | B's output limbs (`100..200`)      |
//! | 26      | A's output bits                                  | A's output limbs (`0..100`)        |
//!
//! Rows 1..=24 are round rows. Each sends 80 xor5 lookups (the column sums of four positions,
//! packed base 64, against the committed sliced parities `c`) and 320 chi lookups (one per
//! `(y, z)`: the five sliced theta outputs packed base 28 plus the iota bit, against the next
//! row's five cells). Theta, rho and pi are degree-1 expressions. B's bits on the boundary rows
//! are `(v - a) / 8`.
//!
//! `KeccakControlChip` sends each permutation's input and output on the `KeccakPermute` state
//! bus as `[chunk, clk, tag, 100 u16 limbs]`; this AIR receives them, A's on rows 0 and 26, B's
//! on rows 0 and 25.
//!
//! # Soundness
//!
//! Per slot with `in_use_a = 1`:
//!
//! 1. *Clock.* `clk` is `e_0` on the first row and rotates by one on every transition, so it is
//!    the one-hot `e_{row mod 27}` everywhere: the slot boundaries are fixed, not prover-chosen.
//!    `in_use_a`, `in_use_b` and `ctx` are boolean / constant across a slot, `in_use_b` only with
//!    `in_use_a`.
//! 2. *Every state cell is a slice.* Row 0 has `a ∈ {0,1}` and, with `v` the row-1 cell,
//!    `v - a ∈ {0, 8}`, so row 1 is `a + 8b` with bits `a, b`. Rows 2..=25 are the output columns
//!    of chi lookups, and every chi table output is `a + 8b` with bits. Row 26 has `a ∈ {0,1}`
//!    and row 25 `a - v ∈ {0, -8}`, which recovers B's output bit. So on every row a cell decodes
//!    to one (A, B) bit pair.
//! 3. *Parities.* A round row's `c` cells are the value columns of the xor5 lookups, so each is
//!    the sliced parity of its column: a column sum `sA + 8·sB` has `sA, sB ≤ 5`, at most 45,
//!    so four of them packed base 64 cannot carry into each other (the largest key,
//!    `45·(1 + 64 + 64² + 64³)`, is far below the field order) and the key names one table row.
//! 4. *Chi and iota.* Each theta output `s + c[x-1][z] + c[x+1][z-1]` is `tA + 8·tB` with
//!    `tA, tB ≤ 3` (three slices), at most 27, so five of them packed base 28 plus `rc·28⁵` are
//!    injective (the top key, `2·28⁵`, is far below the field order) and the lookup output is
//!    exactly chi of the rotated, permuted theta row, with the round constant's bit folded into
//!    lane (0, 0). The round constant is selected by the one-hot clock, so round `r` gets `RC[r]`.
//!    The table rows are fixed preprocessed columns, and the multiplicities are prover-chosen but
//!    only a lookup to an existing row balances (LogUp, one bus per table kind).
//! 5. So rows 1..=25 hold the 24 round states of both permutations, and rows 0 / 25 / 26 tie
//!    them to the input and output bits.
//! 6. *State bus.* On rows 0 and 26 `c[w]` for A, and on rows 0 and 25 `c[100 + w]` for B, are
//!    bound to the 16-bit recomposition of that word's bits (B's as the row difference over 8,
//!    with sign by row). The bits are boolean (step 2), so each limb is in `[0, 2^16)`: this AIR
//!    is the range check `KeccakControlChip` relies on. A message carries `ctx` and the
//!    output-row flag as the tag, so an input cannot stand in for an output, and the key is the
//!    same on both rows of a permutation.
//!
//! Slots with `in_use_a = 0` send nothing (all multiplicities carry `in_use_a` or `in_use_b`).
//! A slot cut short by the end of the trace keeps rows 0.. of its schedule: if a prover marks it
//! in use, row 0 receives an input message for which no output message can ever be received
//! (the output row is past the end), and the control chip's send of that output is then
//! unmatched, so the bus does not balance. The constraints that read `next` hold on the last row
//! too (its `next` is row 0); [`sliced_height`] never picks a height whose last row is a clk-25
//! row, the one position where the honest dummy slot (A = the first input, B = zero) would
//! violate them.
//!
//! Tables are one preprocessed AIR ([`KeccakTables`]) of 2^20 rows: the riscv machine commits each
//! AIR's preprocessed trace on its own, and every such commitment adds a fixed set of Merkle
//! openings to the convert program that verifies the chunk.

use core::borrow::Borrow;
use std::{marker::PhantomData, mem::size_of};

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing, PrimeField32};
use p3_keccak_air::{NUM_ROUNDS, RC};
use pico_derive::AlignedBorrow;
use pico_mle_core::{BaseAirWithPublicValues, PartitionedBaseAir};

use super::{KECCAK_STATE_BUS_INPUT_TAG, KECCAK_STATE_BUS_OUTPUT_TAG};
use crate::machine::{
    builder::ChipBuilder,
    lookup::{LookupScope, LookupType, SymbolicLookup},
};

mod chip;
mod tables;
mod trace;

pub use tables::{KeccakTables, TABLES_MAIN_COLS, TABLES_PREP_COLS, TABLE_ROWS};
pub use trace::{sliced_counts, sliced_height, sliced_trace, SlicedPerm, SlicedTrace};

#[cfg(test)]
mod tests;

/// Rows per slot: A's input bits, 25 sliced round groups, A's output bits.
pub const SLOT_ROWS: usize = 1 + (NUM_ROUNDS + 1) + 1;
const STATE_BITS: usize = 1600;
const PARITIES: usize = 320;
/// Column sums per xor5 lookup.
const XOR5_BATCH: usize = 4;
const XOR5_LOOKUPS: usize = PARITIES / XOR5_BATCH;
/// A batch position holds `sA + 8·sB <= 45`, so base 64 packs a batch without carries.
const XOR5_KEY_BASE: u32 = 64;
/// `(sA, sB) ∈ [0,5]²` per position.
const XOR5_VALUES: usize = 36;
/// Distinct xor5 rows, `36⁴ = 1_679_616`; the table repeats them up to [`XOR5_TABLE_ROWS`].
const XOR5_TABLE_SIZE: usize = XOR5_VALUES.pow(XOR5_BATCH as u32);
const XOR5_TABLE_ROWS: usize = 1 << 21;
/// A sliced theta output holds `tA + 8·tB` with `tA, tB ∈ [0,3]`, at most 27: base 28.
const CHI_BASE: u32 = 28;
const CHI_SPAN: u32 = 28 * 28 * 28 * 28 * 28;
/// `rc ∈ {0,1}` times 16 values `(tA, tB)` per position over five positions: 2·16⁵ = 2²¹.
const CHI_TABLE_ROWS: usize = 2 << 20;
const SLICE: u32 = 8;

/// Rotation offsets of rho, `R[x][y]`.
const R: [[u32; 5]; 5] = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
];

/// Cell of bit `z` of lane `(x, y)`: lane `5y + x`, as in the spec's `s[w(5y + x) + z]`.
const fn bit_pos(x: usize, y: usize, z: usize) -> usize {
    (5 * y + x) * 64 + z
}

/// The `(x, y)` whose rotated theta output lands at `B[X][Y]`: pi sends `(x, y)` to
/// `(y, (2x + 3y) % 5)`.
fn pi_src(bx: usize, by: usize) -> (usize, usize) {
    let y = bx;
    let x = (0..5).find(|&x| (2 * x + 3 * y) % 5 == by).unwrap();
    (x, y)
}

/// Whether bit `z` of round `r`'s constant is set.
fn rc_bit(r: usize, z: usize) -> bool {
    (RC[r] >> z) & 1 == 1
}

#[derive(AlignedBorrow, Debug)]
#[repr(C)]
pub struct KeccakSlicedCols<T> {
    /// One-hot row-in-slot flags; rotated forward by one on every transition.
    pub clk: [T; SLOT_ROWS],
    pub in_use_a: T,
    pub in_use_b: T,
    /// State-bus context `[chunk_A, clk_A, chunk_B, clk_B]`, constant across a slot.
    pub ctx: [T; 4],
    pub state: [T; STATE_BITS],
    /// Round rows: sliced column parities `pA + 8·pB` of the round input, at `x·64 + z`.
    /// Boundary rows: the state-bus limbs, A's at `0..100` (rows 0, 26), B's at `100..200`
    /// (rows 0, 25).
    pub c: [T; PARITIES],
}

pub const NUM_SLICED_COLS: usize = size_of::<KeccakSlicedCols<u8>>();

/// The sliced compute AIR, proved under the `KeccakPermute` name (the shapes, the AIR-id table and
/// the precompile pool key on it). Receives the four `KeccakPermute` state-bus messages of a slot
/// (A in/out, B in/out) that [`super::KeccakControlChip`] sends.
pub struct KeccakSlicedChip<F>(PhantomData<fn(F) -> F>);

impl<F> Default for KeccakSlicedChip<F> {
    fn default() -> Self {
        Self(PhantomData)
    }
}

impl<F> BaseAir<F> for KeccakSlicedChip<F> {
    fn width(&self) -> usize {
        NUM_SLICED_COLS
    }
}
impl<F: Field> PartitionedBaseAir<F> for KeccakSlicedChip<F> {}
impl<F: Field> BaseAirWithPublicValues<F> for KeccakSlicedChip<F> {}

impl<F: PrimeField32, CB: ChipBuilder<F>> Air<CB> for KeccakSlicedChip<F> {
    fn eval(&self, builder: &mut CB) {
        let main = builder.main();
        let (local, next) = (main.current_slice(), main.next_slice());
        let local: &KeccakSlicedCols<CB::Var> = (*local).borrow();
        let next: &KeccakSlicedCols<CB::Var> = (*next).borrow();
        let one = CB::Expr::ONE;

        // Clock: the first row starts the slot schedule and every transition rotates it.
        builder.when_first_row().assert_one(local.clk[0]);
        for i in 1..SLOT_ROWS {
            builder.when_first_row().assert_zero(local.clk[i]);
        }
        for i in 0..SLOT_ROWS {
            builder
                .when_transition()
                .assert_eq(next.clk[(i + 1) % SLOT_ROWS], local.clk[i]);
        }

        // Slot use flags: boolean, B only with A, constant across a slot.
        builder.assert_bool(local.in_use_a);
        builder.assert_bool(local.in_use_b);
        builder.assert_zero(CB::Expr::from(local.in_use_b) * (one.clone() - local.in_use_a));
        let not_slot_end = one.clone() - local.clk[SLOT_ROWS - 1];
        builder
            .when_transition()
            .when(not_slot_end.clone())
            .assert_eq(next.in_use_a, local.in_use_a);
        builder
            .when_transition()
            .when(not_slot_end)
            .assert_eq(next.in_use_b, local.in_use_b);

        // Boundary rows, two families per bit with disjoint anchors:
        //   F1: row 0  a_in ∈ {0,1}           | row 25  a_out - v_out ∈ {0, -8}
        //   F2: row 0  v_in - a_in ∈ {0, 8}   | row 26  a_out ∈ {0,1}
        // with d = next - local. Booleanity of a and of 8b decodes both instances uniquely.
        let clk0: CB::Expr = local.clk[0].into();
        let clk25: CB::Expr = local.clk[SLOT_ROWS - 2].into();
        let clk26: CB::Expr = local.clk[SLOT_ROWS - 1].into();
        let eight = CB::Expr::from_u32(SLICE);
        for i in 0..STATE_BITS {
            let s: CB::Expr = local.state[i].into();
            let d: CB::Expr = CB::Expr::from(next.state[i]) - s.clone();
            let boolean = s.clone() * (one.clone() - s);
            builder.assert_zero(
                clk0.clone() * boolean.clone()
                    + clk25.clone() * d.clone() * (eight.clone() + d.clone()),
            );
            builder.assert_zero(
                clk26.clone() * boolean + clk0.clone() * d.clone() * (eight.clone() - d),
            );
        }

        // Context `[chunk_A, clk_A, chunk_B, clk_B]`, constant across a slot, so a
        // permutation's input and output messages carry the same key. A slot can pair events
        // of two different CPU chunks, hence a chunk per instance.
        let not_end = one.clone() - local.clk[SLOT_ROWS - 1];
        for k in 0..4 {
            builder
                .when_transition()
                .when(not_end.clone())
                .assert_eq(next.ctx[k], local.ctx[k]);
        }
        // State bus, `[chunk, clk, tag, 100 u16 limbs]` as `KeccakControlChip` sends it (word
        // `i = 5y + x`, limb `l` = bits `16l..16l+16`). The limbs are parked in the `c` columns
        // of the boundary rows, which the round constraints never read there: A's in
        // `c[0..100]` on rows 0 and 26, B's in `c[100..200]` on rows 0 and 25. Binding them is
        // zerocheck work, and the messages read bare columns. Recomposing inside the messages
        // instead put ~16-24k nodes on the logup side, which the GKR input and the round-0
        // logup both evaluate on every row (+5.7 us per permutation on the bench).
        let recompose = |cells: &dyn Fn(usize) -> CB::Expr| -> Vec<CB::Expr> {
            (0..100)
                .map(|w| {
                    let base = (w / 4) * 64 + (w % 4) * 16;
                    (0..16)
                        .rev()
                        .fold(CB::Expr::ZERO, |acc, k| acc.double() + cells(base + k))
                })
                .collect()
        };
        let r_local = recompose(&|i| CB::Expr::from(local.state[i]));
        let r_next = recompose(&|i| CB::Expr::from(next.state[i]));
        let inv8 = CB::F::from_u32(SLICE).inverse();
        let clk25: CB::Expr = local.clk[SLOT_ROWS - 2].into();
        let a_rows = clk0.clone() + clk26.clone();
        let b_rows = clk0.clone() + clk25.clone();
        // B's word at row 0 is (R(next) - R(local)) / 8 and at row 25 the negation, so one
        // family: (clk0 + clk25)·cB - (clk0 - clk25)·(R(next) - R(local))/8.
        let b_sign = clk0.clone() - clk25.clone();
        for w in 0..100 {
            builder.assert_zero(a_rows.clone() * (CB::Expr::from(local.c[w]) - r_local[w].clone()));
            builder.assert_zero(
                b_rows.clone() * local.c[100 + w]
                    - b_sign.clone() * (r_next[w].clone() - r_local[w].clone()) * inv8,
            );
        }
        // One interaction per instance: the input (row 0) and the output (row 25 / 26) share
        // the columns they read, and two interactions reading the same 100 columns kept them
        // live across each other (interpreter buffer 5 -> 103, onto the global-memory
        // variant). The tag is the output-row flag, so it is 0 on row 0 and 1 on the output row;
        // the anchors are disjoint, so the multiplicity stays boolean.
        let msg = |chunk: CB::Var, clk: CB::Var, tag: CB::Expr, off: usize| -> Vec<CB::Expr> {
            let mut m = vec![chunk.into(), clk.into(), tag];
            m.extend((0..100).map(|w| CB::Expr::from(local.c[off + w])));
            m
        };
        debug_assert_eq!(KECCAK_STATE_BUS_INPUT_TAG, 0);
        debug_assert_eq!(KECCAK_STATE_BUS_OUTPUT_TAG, 1);
        for (values, mult) in [
            (
                msg(local.ctx[0], local.ctx[1], clk26.clone(), 0),
                a_rows * local.in_use_a,
            ),
            (
                msg(local.ctx[2], local.ctx[3], clk25, 100),
                b_rows * local.in_use_b,
            ),
        ] {
            builder.looked(SymbolicLookup::new(
                values,
                mult,
                LookupType::KeccakPermute,
                LookupScope::Regional,
            ));
        }

        // Round rows: 1..=24, active slots only. The multiplicity is boolean, as `looking` needs.
        let rounds_clk: CB::Expr = (1..=NUM_ROUNDS).map(|g| CB::Expr::from(local.clk[g])).sum();
        let sel = CB::Expr::from(local.in_use_a) * rounds_clk;

        // theta, step 1: committed sliced parities against the packed column sums.
        for g in 0..XOR5_LOOKUPS {
            let mut key = CB::Expr::ZERO;
            let mut values = vec![CB::Expr::ZERO];
            for k in 0..XOR5_BATCH {
                let p = g * XOR5_BATCH + k;
                let (x, z) = (p / 64, p % 64);
                let col_sum: CB::Expr = (0..5)
                    .map(|y| CB::Expr::from(local.state[bit_pos(x, y, z)]))
                    .sum();
                key += col_sum * CB::Expr::from_u32(XOR5_KEY_BASE.pow(k as u32));
                values.push(local.c[p].into());
            }
            values[0] = key;
            builder.looking(SymbolicLookup::new(
                values,
                sel.clone(),
                LookupType::KeccakXor5,
                LookupScope::Regional,
            ));
        }

        // theta, step 2: outputs from the clean parities, each slot in [0,3].
        let theta: Vec<CB::Expr> = (0..STATE_BITS)
            .map(|i| {
                let (lane, z) = (i / 64, i % 64);
                let x = lane % 5;
                CB::Expr::from(local.state[i])
                    + local.c[((x + 4) % 5) * 64 + z]
                    + local.c[((x + 1) % 5) * 64 + (z + 63) % 64]
            })
            .collect();

        // rho + pi + chi + iota: one lookup per chi row (Y, z) against the next row's cells.
        for by in 0..5 {
            for z in 0..64 {
                let mut pack = CB::Expr::ZERO;
                for bx in 0..5 {
                    let (x, y) = pi_src(bx, by);
                    let zz = (z + 64 - R[x][y] as usize) % 64;
                    pack += theta[bit_pos(x, y, zz)].clone()
                        * CB::Expr::from_u32(CHI_BASE.pow(bx as u32));
                }
                if by == 0 {
                    let wrc: CB::Expr = (0..NUM_ROUNDS)
                        .filter(|&r| rc_bit(r, z))
                        .map(|r| CB::Expr::from(local.clk[1 + r]))
                        .sum();
                    pack += wrc * CB::Expr::from_u32(CHI_SPAN);
                }
                let mut values = vec![pack];
                values.extend((0..5).map(|bx| next.state[bit_pos(bx, by, z)].into()));
                builder.looking(SymbolicLookup::new(
                    values,
                    sel.clone(),
                    LookupType::KeccakChi,
                    LookupScope::Regional,
                ));
            }
        }
    }
}
