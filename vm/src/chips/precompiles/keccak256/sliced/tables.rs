//! The two lookup tables of the sliced Keccak AIR, as one preprocessed AIR.

use std::marker::PhantomData;

use p3_air::{Air, BaseAir, WindowAccess};
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use p3_maybe_rayon::prelude::*;
use pico_mle_core::{BaseAirWithPublicValues, PartitionedBaseAir};

use super::{CHI_BASE, CHI_SPAN, SLICE, XOR5_BATCH, XOR5_KEY_BASE, XOR5_TABLE_SIZE, XOR5_VALUES};
use crate::machine::{
    builder::ChipBuilder,
    lookup::{LookupScope, LookupType, SymbolicLookup},
};

/// Height of [`KeccakTables`]: each 2^21-row table is laid out as two side-by-side halves, so the
/// riscv machine still keygens at `log_stacked_height = 20`, the SDK's small setting.
pub const TABLE_ROWS: usize = 1 << 20;

/// Both lookup tables in ONE preprocessed AIR of 2^20 rows, each table as two side-by-side
/// halves: row `i` holds chi rows `i` and `2^20 + i` and xor5 rows `i` and `2^20 + i`, with one
/// multiplicity column per half and one looked lookup per half.
///
/// - chi, `[key, out0..out4]`: the chi row of both instances plus iota, keyed by
///   `rc·28⁵ + Σ_X 28ˣ·(tA_X + 8·tB_X)`;
/// - xor5, `[key, c0..c3]`: sliced parities of four column sums, keyed by
///   `Σ_k 64ᵏ·(sA_k + 8·sB_k)` (rows past 36⁴ repeat entries, multiplicity 0).
///
/// One AIR rather than four: the riscv machine commits each AIR's preprocessed trace on its own,
/// and every such commitment adds a fixed set of Merkle openings to the convert program that
/// verifies the chunk (about 5k DigestSelect and 4k UnpackBlock rows each, whatever its height),
/// which four separate tables pushed past the last convert row.
#[derive(Default)]
pub struct KeccakTables<F>(PhantomData<fn(F) -> F>);

const CHI_PREP_COLS: usize = 6;
const XOR5_PREP_COLS: usize = 1 + XOR5_BATCH;

pub(super) fn chi_table_row(idx: usize) -> [u32; CHI_PREP_COLS] {
    let rc = (idx >> 20) as u32;
    let d: [u32; 5] = core::array::from_fn(|bx| ((idx >> (4 * bx)) & 15) as u32);
    let (ta, tb): ([u32; 5], [u32; 5]) = (d.map(|v| v & 3), d.map(|v| v >> 2));
    let mut key = rc * CHI_SPAN;
    for bx in 0..5 {
        key += CHI_BASE.pow(bx as u32) * (ta[bx] + SLICE * tb[bx]);
    }
    let chi = |t: [u32; 5], bx: usize| {
        let b = |i: usize| t[i % 5] & 1;
        let out = b(bx) ^ ((1 - b(bx + 1)) & b(bx + 2));
        if bx == 0 {
            out ^ rc
        } else {
            out
        }
    };
    let mut row = [key, 0, 0, 0, 0, 0];
    for bx in 0..5 {
        row[1 + bx] = chi(ta, bx) + SLICE * chi(tb, bx);
    }
    row
}

pub(super) fn xor5_table_row(idx: usize) -> [u32; XOR5_PREP_COLS] {
    let idx = idx % XOR5_TABLE_SIZE;
    let mut row = [0u32; XOR5_PREP_COLS];
    for k in 0..XOR5_BATCH {
        let w = (idx / XOR5_VALUES.pow(k as u32)) % XOR5_VALUES;
        let (sa, sb) = ((w % 6) as u32, (w / 6) as u32);
        row[0] += XOR5_KEY_BASE.pow(k as u32) * (sa + SLICE * sb);
        row[1 + k] = (sa & 1) + SLICE * (sb & 1);
    }
    row
}

fn table_prep<F: PrimeField32, const W: usize>(
    rows: usize,
    f: impl Fn(usize) -> [u32; W] + Sync,
) -> RowMajorMatrix<F> {
    let mut values = F::zero_vec(rows * W);
    values.par_chunks_mut(W).enumerate().for_each(|(i, row)| {
        for (dst, v) in row.iter_mut().zip(f(i)) {
            *dst = F::from_u32(v);
        }
    });
    RowMajorMatrix::new(values, W)
}

/// Preprocessed columns of [`KeccakTables`]: chi half 0, chi half 1, xor5 half 0, xor5 half 1.
pub const TABLES_PREP_COLS: usize = 2 * CHI_PREP_COLS + 2 * XOR5_PREP_COLS;
/// Main columns of [`KeccakTables`]: the four halves' multiplicities, in the same order.
pub const TABLES_MAIN_COLS: usize = 4;

fn tables_row(i: usize) -> [u32; TABLES_PREP_COLS] {
    let mut row = [0u32; TABLES_PREP_COLS];
    row[..CHI_PREP_COLS].copy_from_slice(&chi_table_row(i));
    row[CHI_PREP_COLS..2 * CHI_PREP_COLS].copy_from_slice(&chi_table_row(TABLE_ROWS + i));
    let x = 2 * CHI_PREP_COLS;
    row[x..x + XOR5_PREP_COLS].copy_from_slice(&xor5_table_row(i));
    row[x + XOR5_PREP_COLS..].copy_from_slice(&xor5_table_row(TABLE_ROWS + i));
    row
}

impl<F: PrimeField32> BaseAir<F> for KeccakTables<F> {
    fn width(&self) -> usize {
        TABLES_MAIN_COLS
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        Some(table_prep::<F, TABLES_PREP_COLS>(TABLE_ROWS, tables_row))
    }
}
impl<F: PrimeField32> PartitionedBaseAir<F> for KeccakTables<F> {}
impl<F: PrimeField32> BaseAirWithPublicValues<F> for KeccakTables<F> {}
impl<F: PrimeField32, CB: ChipBuilder<F>> Air<CB> for KeccakTables<F>
where
    CB::Var: Sized,
{
    fn eval(&self, builder: &mut CB) {
        let main = builder.main();
        let mult = main.current_slice();
        let prep = builder.preprocessed().clone();
        let prep = prep.current_slice();
        let x = 2 * CHI_PREP_COLS;
        for (m, (cols, kind)) in [
            (0..CHI_PREP_COLS, LookupType::KeccakChi),
            (CHI_PREP_COLS..x, LookupType::KeccakChi),
            (x..x + XOR5_PREP_COLS, LookupType::KeccakXor5),
            (x + XOR5_PREP_COLS..TABLES_PREP_COLS, LookupType::KeccakXor5),
        ]
        .into_iter()
        .enumerate()
        {
            builder.looked(SymbolicLookup::new(
                prep[cols].iter().map(|&v| v.into()).collect(),
                mult[m].into(),
                kind,
                LookupScope::Regional,
            ));
        }
    }
}

/// [`KeccakTables`]' main trace from the two full 2^21-row multiplicity columns: row `i` is
/// `[chi[i], chi[2^20 + i], xor5[i], xor5[2^20 + i]]`.
pub(super) fn tables_main<F: PrimeField32>(
    chi: &RowMajorMatrix<F>,
    xor5: &RowMajorMatrix<F>,
) -> RowMajorMatrix<F> {
    let mut values = F::zero_vec(TABLE_ROWS * TABLES_MAIN_COLS);
    values
        .par_chunks_mut(TABLES_MAIN_COLS)
        .enumerate()
        .for_each(|(i, row)| {
            row[0] = chi.values[i];
            row[1] = chi.values[TABLE_ROWS + i];
            row[2] = xor5.values[i];
            row[3] = xor5.values[TABLE_ROWS + i];
        });
    RowMajorMatrix::new(values, TABLES_MAIN_COLS)
}
