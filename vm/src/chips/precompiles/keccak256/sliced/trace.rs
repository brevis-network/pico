//! Host trace generation for the sliced Keccak AIR and its tables (the device path is
//! `gpu-api/cuda/keccak_sliced.cu`, which must match it row for row).

use core::borrow::BorrowMut;
use std::sync::atomic::{AtomicU32, Ordering};

use p3_field::PrimeField32;
use p3_keccak_air::{NUM_ROUNDS, RC};
use p3_matrix::dense::RowMajorMatrix;
use p3_maybe_rayon::prelude::*;

use super::{
    bit_pos, pi_src, rc_bit, KeccakSlicedCols, CHI_TABLE_ROWS, NUM_SLICED_COLS, R, SLICE,
    SLOT_ROWS, XOR5_BATCH, XOR5_LOOKUPS, XOR5_TABLE_ROWS, XOR5_VALUES,
};

/// One Keccak-f round on lanes indexed `x + 5y`.
fn keccak_round(a: &mut [u64; 25], r: usize) {
    let c: [u64; 5] = core::array::from_fn(|x| a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20]);
    let d: [u64; 5] = core::array::from_fn(|x| c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1));
    for (i, lane) in a.iter_mut().enumerate() {
        *lane ^= d[i % 5];
    }
    let mut b = [0u64; 25];
    for x in 0..5 {
        for y in 0..5 {
            b[y + 5 * ((2 * x + 3 * y) % 5)] = a[x + 5 * y].rotate_left(R[x][y]);
        }
    }
    for y in 0..5 {
        for x in 0..5 {
            a[x + 5 * y] = b[x + 5 * y] ^ (!b[(x + 1) % 5 + 5 * y] & b[(x + 2) % 5 + 5 * y]);
        }
    }
    a[0] ^= RC[r];
}

/// The 25 round inputs of one permutation; `[24]` is the output.
pub(super) fn round_states(input: &[u64; 25]) -> [[u64; 25]; NUM_ROUNDS + 1] {
    let mut out = [[0u64; 25]; NUM_ROUNDS + 1];
    out[0] = *input;
    for r in 0..NUM_ROUNDS {
        let mut s = out[r];
        keccak_round(&mut s, r);
        out[r + 1] = s;
    }
    out
}

fn bit(state: &[u64; 25], x: usize, y: usize, z: usize) -> u32 {
    ((state[x + 5 * y] >> z) & 1) as u32
}

fn parities(state: &[u64; 25]) -> [u64; 5] {
    core::array::from_fn(|x| (0..5).fold(0, |acc, y| acc ^ state[x + 5 * y]))
}

/// The sliced main trace plus the two tables' multiplicity columns.
pub struct SlicedTrace<F> {
    pub main: RowMajorMatrix<F>,
    pub chi_mult: RowMajorMatrix<F>,
    pub xor5_mult: RowMajorMatrix<F>,
}

/// Fills one slot's 27 rows; counts its lookups when `counts` is given.
fn fill_slot<F: PrimeField32>(
    rows: &mut [F],
    a_in: &[u64; 25],
    b_in: &[u64; 25],
    in_use_b: bool,
    ctx: [u32; 4],
    counts: Option<(&[AtomicU32], &[AtomicU32])>,
) {
    let (sa, sb) = (round_states(a_in), round_states(b_in));
    debug_assert!({
        let mut t = *a_in;
        tiny_keccak::keccakf(&mut t);
        t == sa[NUM_ROUNDS]
    });
    for (g, row) in rows.chunks_mut(NUM_SLICED_COLS).enumerate() {
        let cols: &mut KeccakSlicedCols<F> = row.borrow_mut();
        cols.clk[g] = F::ONE;
        cols.in_use_a = F::from_bool(counts.is_some());
        cols.in_use_b = F::from_bool(counts.is_some() && in_use_b);
        cols.ctx = ctx.map(F::from_u32);
        match g {
            0 | 26 => {
                let st = if g == 0 { &sa[0] } else { &sa[NUM_ROUNDS] };
                for y in 0..5 {
                    for x in 0..5 {
                        for z in 0..64 {
                            cols.state[bit_pos(x, y, z)] = F::from_u32(bit(st, x, y, z));
                        }
                    }
                }
                let limb = |s: &[u64; 25], w: usize| {
                    F::from_u32(((s[w / 4] >> (16 * (w % 4))) & 0xffff) as u32)
                };
                for w in 0..100 {
                    cols.c[w] = limb(st, w);
                    if g == 0 {
                        cols.c[100 + w] = limb(&sb[0], w);
                    }
                }
            }
            _ => {
                let r = g - 1;
                let (a, b) = (&sa[r], &sb[r]);
                for y in 0..5 {
                    for x in 0..5 {
                        for z in 0..64 {
                            cols.state[bit_pos(x, y, z)] =
                                F::from_u32(bit(a, x, y, z) + SLICE * bit(b, x, y, z));
                        }
                    }
                }
                if r == NUM_ROUNDS {
                    // Row 25: B's output limbs.
                    for w in 0..100 {
                        cols.c[100 + w] = F::from_u32(
                            ((sb[NUM_ROUNDS][w / 4] >> (16 * (w % 4))) & 0xffff) as u32,
                        );
                    }
                }
                if r < NUM_ROUNDS {
                    let (pa, pb) = (parities(a), parities(b));
                    let par = |p: &[u64; 5], x: usize, z: usize| ((p[x] >> z) & 1) as u32;
                    for x in 0..5 {
                        for z in 0..64 {
                            cols.c[x * 64 + z] =
                                F::from_u32(par(&pa, x, z) + SLICE * par(&pb, x, z));
                        }
                    }
                    if let Some((chi, xor5)) = counts {
                        // xor5: four (sA, sB) column sums per key.
                        for g5 in 0..XOR5_LOOKUPS {
                            let mut idx = 0usize;
                            for k in 0..XOR5_BATCH {
                                let p = g5 * XOR5_BATCH + k;
                                let (x, z) = (p / 64, p % 64);
                                let s_a: u32 = (0..5).map(|y| bit(a, x, y, z)).sum();
                                let s_b: u32 = (0..5).map(|y| bit(b, x, y, z)).sum();
                                idx += XOR5_VALUES.pow(k as u32) * (s_a + 6 * s_b) as usize;
                            }
                            xor5[idx].fetch_add(1, Ordering::Relaxed);
                        }
                        // chi: the theta outputs feeding each chi row, per instance in [0,3].
                        let t = |s: &[u64; 25], p: &[u64; 5], x: usize, y: usize, z: usize| {
                            bit(s, x, y, z)
                                + par(p, (x + 4) % 5, z)
                                + par(p, (x + 1) % 5, (z + 63) % 64)
                        };
                        for by in 0..5 {
                            for z in 0..64 {
                                let rc = by == 0 && rc_bit(r, z);
                                let mut idx = (rc as usize) << 20;
                                for bx in 0..5 {
                                    let (x, y) = pi_src(bx, by);
                                    let zz = (z + 64 - R[x][y] as usize) % 64;
                                    let d = t(a, &pa, x, y, zz) + 4 * t(b, &pb, x, y, zz);
                                    idx |= (d as usize) << (4 * bx);
                                }
                                chi[idx].fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                }
            }
        }
    }
}

/// One permutation's input and its state-bus key.
#[derive(Clone, Copy, Debug)]
pub struct SlicedPerm {
    pub state: [u64; 25],
    pub chunk: u32,
    pub clk: u32,
}

/// The height of a sliced trace for `n` permutations: `ceil(n / 2)` slots of 27 rows, padded to a
/// power of two, doubled when the last row would land on a clk-25 row (whose `next` is row 0).
pub fn sliced_height(n: usize) -> usize {
    let mut h = (n.div_ceil(2) * SLOT_ROWS).next_power_of_two().max(32);
    if (h - 1) % SLOT_ROWS == SLOT_ROWS - 2 {
        h *= 2;
    }
    h
}

fn slot_of(perms: &[SlicedPerm], j: usize) -> (&[u64; 25], &[u64; 25], bool, [u32; 4]) {
    const ZERO: [u64; 25] = [0; 25];
    let a = &perms[2 * j];
    match perms.get(2 * j + 1) {
        Some(b) => (&a.state, &b.state, true, [a.chunk, a.clk, b.chunk, b.clk]),
        None => (&a.state, &ZERO, false, [a.chunk, a.clk, 0, 0]),
    }
}

/// Sliced rows for `perms` at `height`, events paired `(2j, 2j + 1)` in order; the rows after the
/// last real slot are dummy slots (A = the first input, B = zero, not in use), which keeps the
/// boundary families and the bus bindings satisfied across the wrap to row 0.
pub fn sliced_trace<F: PrimeField32>(perms: &[SlicedPerm], height: usize) -> SlicedTrace<F> {
    let slots = perms.len().div_ceil(2);
    assert!(
        slots * SLOT_ROWS <= height,
        "{} slots do not fit {height} rows",
        slots
    );
    // The last row's `next` is row 0. A dummy-prefix last row at clk 25 would pair a sliced output
    // with row 0's input bits; every other position is satisfied by the dummy = inputs[0] choice.
    assert_ne!(
        (height - 1) % SLOT_ROWS,
        SLOT_ROWS - 2,
        "height {height} ends on a clk-25 row"
    );
    let chi: Vec<AtomicU32> = (0..CHI_TABLE_ROWS).map(|_| AtomicU32::new(0)).collect();
    let xor5: Vec<AtomicU32> = (0..XOR5_TABLE_ROWS).map(|_| AtomicU32::new(0)).collect();
    let mut values = F::zero_vec(height * NUM_SLICED_COLS);
    let slot_len = SLOT_ROWS * NUM_SLICED_COLS;
    let dummy_in = perms.first().map_or([0u64; 25], |p| p.state);
    values
        .par_chunks_mut(slot_len)
        .enumerate()
        .for_each(|(j, rows)| {
            if j < slots {
                let (a, b, use_b, ctx) = slot_of(perms, j);
                fill_slot(rows, a, b, use_b, ctx, Some((&chi, &xor5)));
            } else {
                // B is the zero state: when the trace ends on a clk-0 row (heights = 1 mod 27,
                // e.g. 2^18), that row's `next` is row 0, and B's row-0 bus binding then asks
                // for `cB = (R(row 0) - R(this row)) / 8 = 0`.
                let mut dummy = F::zero_vec(slot_len);
                fill_slot(&mut dummy, &dummy_in, &[0u64; 25], false, [0; 4], None);
                rows.copy_from_slice(&dummy[..rows.len()]);
            }
        });
    let mult = |c: Vec<AtomicU32>| {
        RowMajorMatrix::new(
            c.into_iter().map(|v| F::from_u32(v.into_inner())).collect(),
            1,
        )
    };
    SlicedTrace {
        main: RowMajorMatrix::new(values, NUM_SLICED_COLS),
        chi_mult: mult(chi),
        xor5_mult: mult(xor5),
    }
}

/// The two tables' multiplicities for `perms` under the same pairing as [`sliced_trace`], without
/// keeping the main trace (one slot of scratch per task).
pub fn sliced_counts<F: PrimeField32>(
    perms: &[SlicedPerm],
) -> (RowMajorMatrix<F>, RowMajorMatrix<F>) {
    let chi: Vec<AtomicU32> = (0..CHI_TABLE_ROWS).map(|_| AtomicU32::new(0)).collect();
    let xor5: Vec<AtomicU32> = (0..XOR5_TABLE_ROWS).map(|_| AtomicU32::new(0)).collect();
    let slot_len = SLOT_ROWS * NUM_SLICED_COLS;
    (0..perms.len().div_ceil(2)).into_par_iter().for_each(|j| {
        let mut scratch = F::zero_vec(slot_len);
        let (a, b, use_b, ctx) = slot_of(perms, j);
        fill_slot(&mut scratch, a, b, use_b, ctx, Some((&chi, &xor5)));
    });
    let mult = |c: Vec<AtomicU32>| {
        RowMajorMatrix::new(
            c.into_iter().map(|v| F::from_u32(v.into_inner())).collect(),
            1,
        )
    };
    (mult(chi), mult(xor5))
}
