//! `Blake2bRoundChip`: one row per BLAKE2b round.
//!
//! A row receives the working vector `v` entering round `k` of a call and the message block in
//! the round's schedule order, computes the round's eight mixes, and sends `v` entering round
//! `k + 1`. All three are `LookupType::Blake2bRound` messages keyed by the call's `(chunk, clk)`;
//! see the module docs of [`super`] for the control chip's end of them.
//!
//! # Layout
//!
//! A mix `G(a, b, c, d; x, y)` is eight steps (RFC 7693 §3.1). Each step's result is a column of
//! eight bytes, with the rotation applied by reading those bytes in another order:
//!
//! | column | value                    | then                     |
//! |--------|--------------------------|--------------------------|
//! | `a1`   | `a + b + x`              |                          |
//! | `dx1`  | `d ^ a1`                 | `d1 = dx1 >>> 32`        |
//! | `c1`   | `c + d1`                 |                          |
//! | `bx1`  | `b ^ c1`                 | `b1 = bx1 >>> 24`        |
//! | `a2`   | `a1 + b1 + y`            |                          |
//! | `dx2`  | `d1 ^ a2`                | `d2 = dx2 >>> 16`        |
//! | `c2`   | `c1 + d2`                |                          |
//! | `bx2`  | `b1 ^ c2`                | `b2 = bx2 >>> 63`        |
//!
//! The rotations by 32, 24 and 16 are byte reorders. The one by 63, a rotation left by one bit,
//! takes the top bit of each byte (`column_msb`): byte `i` of `b2` is `2 bx2[i] - 256 h[i] +
//! h[i - 1]`. A diagonal mix's `b2` leaves the row, and is only ever read as u16 limbs, in which
//! the top bits of the low bytes cancel: limb `j` is `2 L[j] - 2^16 H[j] + H[j - 1]` with `L` the
//! limbs of `bx2` and `H` their top bits (`diagonal_msb`).
//!
//! The `v` a row receives holds the words a mix first adds (`a`, `c`) as u16 limbs and the ones it
//! first XORs (`b`, `d`) as bytes.
//!
//! # Soundness
//!
//! 1. *Bytes.* Every XOR is eight byte-table lookups `(XOR, out, in1, in2)`, which pin all three
//!    to bytes and `out` to `in1 ^ in2`. Every adder output (`a1, c1, a2, c2`) is the `in2` of
//!    the XOR that follows it, so it is a byte; `dx*` and `bx*` are lookup outputs. The received
//!    `b` and `d` bytes are XOR inputs.
//! 2. *Adds.* An adder's inputs are u16 limbs (step 1, and steps 4 and 5 for the received
//!    limbs), so a limb sum is at most `3 (2^16 - 1) + 2`. Each limb's carry is the expression
//!    `(sum + carry_in - out) / 2^16`, constrained to `{0, 1, 2}` (three inputs) or `{0, 1}`
//!    (two): with `out` a u16, that is the integer carry, and `out` is the sum mod 2^16, so the
//!    eight bytes are the 64-bit sum.
//! 3. *Rotation by 63.* The `h` are boolean. A column mix's `b2` byte is the input of a diagonal
//!    mix's XOR, so a byte: `2 bx2[i] + h[i - 1] - 256 h[i]` is in `[0, 256)` only for `h[i]` the
//!    top bit of `bx2[i]`. A diagonal mix's `b2` limb is in `[0, 2^16)` (step 4) only for `H[j]`
//!    the top bit of `L[j]`, by the same argument a limb wide.
//! 4. *What leaves the row.* `v` entering round `k + 1` is sent as limbs: `a2`, `c2` and `d2`
//!    from bytes (step 1), `b2` as in step 3. The receiver is the next round row, which holds the
//!    `b` words as bytes, or the control row, which range-checks them; either pins the `b2` limbs
//!    to u16. The message words and the `a`, `c` limbs a row receives equal what was sent, which
//!    the control row read from memory or a round row computed: u16 limbs either way.
//! 5. *The chain.* A row is an edge from `(k, s, v)` to `(k + 1, s', round_s(v))` on its call's
//!    key, and the multiset of edges, the control row's start `(0, 0, v_in)` and its end
//!    `(n, n % 10, v_out)` balances. Since `k` grows by one on every edge and there are fewer rows
//!    than the field order, the edges with one key form a single path from start to end: exactly
//!    `n` rounds, in order, with `v_out` their result.
//! 6. *The schedule row.* A row's message query names `s`, and the control row offers the message
//!    for `s` in `0..10` only, so `s` is in `0..10`. `wrap` is boolean and `s' = s + 1 - 10
//!    wrap`, which the next row's query (or the control row's end, at `n % 10`) holds in `0..10`
//!    too: so `s' = (s + 1) mod 10`, and from the start's `s = 0` every round reads the message
//!    in its own schedule order.
//!
//! Padding rows are all zero, which satisfies every constraint; every interaction is gated by
//! `is_real`.

use super::{
    Blake2bRoundChip, BUS_MESSAGE_TAG, BUS_STATE_TAG, MESSAGE_DWORDS, MIX_INDICES, SIGMA,
    STATE_DWORDS,
};
use crate::{
    chips::{
        chips::byte::event::ByteLookupEvent, precompiles::checked_u64_to_u32,
        utils::next_power_of_two,
    },
    compiler::riscv::{opcode::ByteOpcode, program::Program},
    emulator::riscv::{
        record::EmulationRecord,
        syscalls::{
            precompiles::{Blake2bRoundsEvent, PrecompileEvent},
            SyscallCode,
        },
    },
    iter::{IntoPicoIterator, PicoIterator},
    machine::{
        builder::{ChipBuilder, ChipLookupBuilder},
        chip::ChipBehavior,
        lookup::{LookupScope, LookupType, SymbolicLookup},
    },
};
use core::{
    array,
    borrow::{Borrow, BorrowMut},
    mem::size_of,
};
use p3_air::{Air, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;
use pico_derive::AlignedBorrow;

pub const NUM_BLAKE2B_ROUND_COLS: usize = size_of::<Blake2bRoundCols<u8>>();

/// The eight steps of one mix, each the bytes of a u64; see the module docs.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct MixCols<T> {
    pub a1: [T; 8],
    pub dx1: [T; 8],
    pub c1: [T; 8],
    pub bx1: [T; 8],
    pub a2: [T; 8],
    pub dx2: [T; 8],
    pub c2: [T; 8],
    pub bx2: [T; 8],
}

#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct Blake2bRoundCols<T> {
    /// The call's key, carried on every message.
    pub chunk: T,
    pub clk: T,
    /// The round's index within its call, from 0.
    pub k: T,
    /// Its schedule row, `k % 10`.
    pub s: T,
    /// Whether `s` is 9, after which the schedule starts over.
    pub wrap: T,
    pub is_real: T,
    /// `v` entering the round: words 0..4 (`a`) and 8..12 (`c`) as u16 limbs, words 4..8 (`b`)
    /// and 12..16 (`d`) as bytes.
    pub v_a: [[T; 4]; 4],
    pub v_b: [[T; 8]; 4],
    pub v_c: [[T; 4]; 4],
    pub v_d: [[T; 8]; 4],
    /// The message block in schedule order `s`, as u16 limbs: word `j` is `m[SIGMA[s][j]]`, and
    /// mix `i` takes words `2i` and `2i + 1`.
    pub m: [[T; 4]; MESSAGE_DWORDS],
    /// The four column mixes, then the four diagonal ones.
    pub mix: [MixCols<T>; 8],
    /// The top bit of each byte of a column mix's `bx2`.
    pub column_msb: [[T; 8]; 4],
    /// The top bit of each u16 limb of a diagonal mix's `bx2`.
    pub diagonal_msb: [[T; 4]; 4],
}

impl<F> BaseAir<F> for Blake2bRoundChip<F> {
    fn width(&self) -> usize {
        NUM_BLAKE2B_ROUND_COLS
    }
}

/// The eight values one mix's columns hold, `[a1, dx1, c1, bx1, a2, dx2, c2, bx2]`, computed as
/// [`super::g`] computes the mix, which it updates `v` with.
pub(crate) fn mix_steps(v: &mut [u64; 16], [a, b, c, d]: [usize; 4], x: u64, y: u64) -> [u64; 8] {
    let a1 = v[a].wrapping_add(v[b]).wrapping_add(x);
    let dx1 = v[d] ^ a1;
    let d1 = dx1.rotate_right(32);
    let c1 = v[c].wrapping_add(d1);
    let bx1 = v[b] ^ c1;
    let b1 = bx1.rotate_right(24);
    let a2 = a1.wrapping_add(b1).wrapping_add(y);
    let dx2 = d1 ^ a2;
    let d2 = dx2.rotate_right(16);
    let c2 = c1.wrapping_add(d2);
    let bx2 = b1 ^ c2;
    v[a] = a2;
    v[b] = bx2.rotate_right(63);
    v[c] = c2;
    v[d] = d2;
    [a1, dx1, c1, bx1, a2, dx2, c2, bx2]
}

/// The XOR byte lookups of the trace, as counts indexed by `(in1 << 8) | in2`: the only byte
/// lookups the chip raises.
pub(crate) type XorCounts = Vec<u32>;

fn count_xor(counts: &mut XorCounts, in1: u64, in2: u64) {
    for (p, q) in in1.to_le_bytes().into_iter().zip(in2.to_le_bytes()) {
        counts[(usize::from(p) << 8) | usize::from(q)] += 1;
    }
}

/// The counts as byte-lookup events with their multiplicities.
pub(crate) fn xor_lookups(
    counts: &XorCounts,
) -> impl Iterator<Item = (ByteLookupEvent, usize)> + '_ {
    counts
        .iter()
        .enumerate()
        .filter(|(_, n)| **n > 0)
        .map(|(i, n)| {
            let (p, q) = ((i >> 8) as u8, i as u8);
            (
                ByteLookupEvent::new(ByteOpcode::XOR, u16::from(p ^ q), 0, p, q),
                *n as usize,
            )
        })
}

fn limbs<F: PrimeCharacteristicRing>(x: u64) -> [F; 4] {
    array::from_fn(|j| F::from_u16((x >> (16 * j)) as u16))
}

fn bytes<F: PrimeCharacteristicRing>(x: u64) -> [F; 8] {
    x.to_le_bytes().map(F::from_u8)
}

/// One round of a call: fills `row` (when given), counts its XOR lookups, and advances `v`.
fn round_row<F: PrimeField32>(
    row: Option<&mut Blake2bRoundCols<F>>,
    counts: &mut XorCounts,
    (chunk, clk): (u32, u32),
    k: u32,
    v: &mut [u64; 16],
    m: &[u64; 16],
) {
    let s = (k % 10) as usize;
    let mp: [u64; 16] = array::from_fn(|j| m[SIGMA[s][j]]);
    let v_in = *v;
    let mut steps = [[0u64; 8]; 8];
    for (i, idx) in MIX_INDICES.iter().enumerate() {
        let (b_in, d_in) = (v[idx[1]], v[idx[3]]);
        let st = mix_steps(v, *idx, mp[2 * i], mp[2 * i + 1]);
        let [a1, dx1, c1, bx1, a2, _, c2, _] = st;
        count_xor(counts, d_in, a1);
        count_xor(counts, b_in, c1);
        count_xor(counts, dx1.rotate_right(32), a2);
        count_xor(counts, bx1.rotate_right(24), c2);
        steps[i] = st;
    }
    let Some(row) = row else { return };

    row.chunk = F::from_u32(chunk);
    row.clk = F::from_u32(clk);
    row.k = F::from_u32(k);
    row.s = F::from_u32(s as u32);
    row.wrap = F::from_bool(s == 9);
    row.is_real = F::ONE;
    for w in 0..4 {
        row.v_a[w] = limbs(v_in[w]);
        row.v_b[w] = bytes(v_in[4 + w]);
        row.v_c[w] = limbs(v_in[8 + w]);
        row.v_d[w] = bytes(v_in[12 + w]);
    }
    for (j, word) in mp.iter().enumerate() {
        row.m[j] = limbs(*word);
    }
    for (i, st) in steps.iter().enumerate() {
        let cols = &mut row.mix[i];
        for (col, value) in [
            &mut cols.a1,
            &mut cols.dx1,
            &mut cols.c1,
            &mut cols.bx1,
            &mut cols.a2,
            &mut cols.dx2,
            &mut cols.c2,
            &mut cols.bx2,
        ]
        .into_iter()
        .zip(st)
        {
            *col = bytes(*value);
        }
        let bx2 = st[7];
        if i < 4 {
            row.column_msb[i] = array::from_fn(|b| F::from_bool((bx2 >> (8 * b + 7)) & 1 == 1));
        } else {
            row.diagonal_msb[i - 4] =
                array::from_fn(|j| F::from_bool((bx2 >> (16 * j + 15)) & 1 == 1));
        }
    }
}

impl<F: PrimeField32> Blake2bRoundChip<F> {
    /// The call events of a record.
    fn events(input: &EmulationRecord) -> Vec<&Blake2bRoundsEvent> {
        input
            .get_precompile_events(SyscallCode::BLAKE2B_ROUNDS)
            .iter()
            .map(|(_, event)| {
                let PrecompileEvent::Blake2bRounds(event) = event else {
                    unreachable!()
                };
                event
            })
            .collect()
    }

    /// The trace (padded to the record's shape) and the XOR lookup counts, or the counts alone.
    /// Calls fill disjoint row ranges in parallel; the trace of a call is sequential, each round
    /// starting from the one before.
    pub(crate) fn trace_and_counts(
        &self,
        input: &EmulationRecord,
        with_trace: bool,
    ) -> (Option<RowMajorMatrix<F>>, XorCounts) {
        let events = Self::events(input);
        let rows: usize = events.iter().map(|e| e.rounds as usize).sum();
        let height = next_power_of_two(rows, input.shape_chip_size(&self.name()));
        let mut values = vec![
            F::ZERO;
            if with_trace {
                height * NUM_BLAKE2B_ROUND_COLS
            } else {
                0
            }
        ];

        // Each call's slice of the trace, empty when only the counts are wanted.
        let mut work = Vec::with_capacity(events.len());
        let mut rest = values.as_mut_slice();
        for event in &events {
            let len = if with_trace {
                event.rounds as usize * NUM_BLAKE2B_ROUND_COLS
            } else {
                0
            };
            let (head, tail) = rest.split_at_mut(len);
            work.push((*event, head));
            rest = tail;
        }

        let counts = work
            .into_pico_iter()
            .pico_fold(
                || vec![0u32; 1 << 16],
                |mut counts, (event, slice)| {
                    let key = (
                        event.chunk,
                        checked_u64_to_u32(event.clk, "BLAKE2b rounds clk"),
                    );
                    let mut v = event.v_in;
                    let mut rows = slice.as_chunks_mut::<NUM_BLAKE2B_ROUND_COLS>().0.iter_mut();
                    for k in 0..event.rounds {
                        let row = rows.next().map(|r| {
                            let cols: &mut Blake2bRoundCols<F> = r.as_mut_slice().borrow_mut();
                            cols
                        });
                        round_row(row, &mut counts, key, k, &mut v, &event.m);
                    }
                    assert_eq!(
                        v, event.v_out,
                        "BLAKE2b rounds: the trace's result is not the event's"
                    );
                    counts
                },
            )
            .pico_reduce(
                || vec![0u32; 1 << 16],
                |mut a, b| {
                    a.iter_mut().zip(b).for_each(|(x, y)| *x += y);
                    a
                },
            );

        let trace = with_trace.then(|| RowMajorMatrix::new(values, NUM_BLAKE2B_ROUND_COLS));
        (trace, counts)
    }
}

impl<F: PrimeField32> ChipBehavior<F> for Blake2bRoundChip<F> {
    type Record = EmulationRecord;
    type Program = Program;

    fn name(&self) -> String {
        "Blake2bRound".to_string()
    }

    fn generate_main(
        &self,
        input: &EmulationRecord,
        output: &mut EmulationRecord,
    ) -> RowMajorMatrix<F> {
        let (trace, counts) = self.trace_and_counts(input, true);
        for (event, n) in xor_lookups(&counts) {
            *output.byte_lookups.entry(event).or_insert(0) += n;
        }
        trace.unwrap()
    }

    fn extra_record(&self, input: &Self::Record, extra: &mut Self::Record) {
        let (_, counts) = self.trace_and_counts(input, false);
        for (event, n) in xor_lookups(&counts) {
            *extra.byte_lookups.entry(event).or_insert(0) += n;
        }
    }

    fn is_active(&self, record: &Self::Record) -> bool {
        if let Some(shape) = record.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            !record
                .get_precompile_events(SyscallCode::BLAKE2B_ROUNDS)
                .is_empty()
        }
    }

    fn local_only(&self) -> bool {
        true
    }
}

/// A u64 in the AIR: its u16 limbs, and its bytes where the row has them.
#[derive(Clone)]
struct Dword<E> {
    limbs: [E; 4],
    bytes: Option<[E; 8]>,
}

impl<E: PrimeCharacteristicRing + Clone> Dword<E> {
    fn from_bytes(bytes: [E; 8]) -> Self {
        let limbs =
            array::from_fn(|j| bytes[2 * j].clone() + bytes[2 * j + 1].clone() * E::from_u32(256));
        Self {
            limbs,
            bytes: Some(bytes),
        }
    }

    fn from_limbs(limbs: [E; 4]) -> Self {
        Self { limbs, bytes: None }
    }

    fn bytes(&self) -> &[E; 8] {
        self.bytes
            .as_ref()
            .expect("a mix XORs a word the row holds as limbs only")
    }
}

/// Bytes read `8 n` bits rotated right.
fn rotr_bytes<E: Clone>(x: &[E; 8], n: usize) -> [E; 8] {
    array::from_fn(|i| x[(i + n) % 8].clone())
}

fn to_exprs<CB: ChipBuilder<F>, F: Field, const N: usize>(x: &[CB::Var; N]) -> [CB::Expr; N] {
    array::from_fn(|i| x[i].into())
}

/// `out = Σ inputs mod 2^64`, limb by limb with the carry an expression (soundness step 2).
fn eval_add<F: Field, CB: ChipBuilder<F>>(
    builder: &mut CB,
    inputs: &[[CB::Expr; 4]],
    out: &[CB::Expr; 8],
) {
    let inv = CB::F::from_u32(1 << 16).inverse();
    let mut carry = CB::Expr::ZERO;
    for j in 0..4 {
        let sum = inputs
            .iter()
            .fold(carry.clone(), |acc, x| acc + x[j].clone());
        let out_limb = out[2 * j].clone() + out[2 * j + 1].clone() * CB::Expr::from_u32(256);
        carry = (sum - out_limb) * inv;
        let mut vanishing = carry.clone();
        for c in 1..inputs.len() as u32 {
            vanishing *= carry.clone() - CB::Expr::from_u32(c);
        }
        builder.assert_zero(vanishing);
    }
}

/// `out = in1 ^ in2`, byte by byte against the byte table.
fn eval_xor<F: Field, CB: ChipBuilder<F>>(
    builder: &mut CB,
    in1: &[CB::Expr; 8],
    in2: &[CB::Expr; 8],
    out: &[CB::Var; 8],
    is_real: &CB::Expr,
) {
    for i in 0..8 {
        builder.looking_byte(
            ByteOpcode::XOR.as_field::<CB::F>(),
            out[i],
            in1[i].clone(),
            in2[i].clone(),
            is_real.clone(),
        );
    }
}

/// The top bits of a mix's `bx2` that its rotation by 63 needs.
enum Msb<'a, V> {
    Column(&'a [V; 8]),
    Diagonal(&'a [V; 4]),
}

/// One mix on `v` with the message words `[x, y]`, which it updates `v` with.
fn eval_mix<F: Field, CB: ChipBuilder<F>>(
    builder: &mut CB,
    v: &mut [Dword<CB::Expr>],
    [a, b, c, d]: [usize; 4],
    [x, y]: [[CB::Expr; 4]; 2],
    cols: &MixCols<CB::Var>,
    msb: Msb<'_, CB::Var>,
    is_real: &CB::Expr,
) {
    let a1 = Dword::from_bytes(to_exprs::<CB, F, 8>(&cols.a1));
    eval_add(
        builder,
        &[v[a].limbs.clone(), v[b].limbs.clone(), x],
        a1.bytes(),
    );
    eval_xor(builder, v[d].bytes(), a1.bytes(), &cols.dx1, is_real);
    let d1 = Dword::from_bytes(rotr_bytes(&to_exprs::<CB, F, 8>(&cols.dx1), 4));

    let c1 = Dword::from_bytes(to_exprs::<CB, F, 8>(&cols.c1));
    eval_add(builder, &[v[c].limbs.clone(), d1.limbs.clone()], c1.bytes());
    eval_xor(builder, v[b].bytes(), c1.bytes(), &cols.bx1, is_real);
    let b1 = Dword::from_bytes(rotr_bytes(&to_exprs::<CB, F, 8>(&cols.bx1), 3));

    let a2 = Dword::from_bytes(to_exprs::<CB, F, 8>(&cols.a2));
    eval_add(
        builder,
        &[a1.limbs.clone(), b1.limbs.clone(), y],
        a2.bytes(),
    );
    eval_xor(builder, d1.bytes(), a2.bytes(), &cols.dx2, is_real);
    let d2 = Dword::from_bytes(rotr_bytes(&to_exprs::<CB, F, 8>(&cols.dx2), 2));

    let c2 = Dword::from_bytes(to_exprs::<CB, F, 8>(&cols.c2));
    eval_add(builder, &[c1.limbs.clone(), d2.limbs.clone()], c2.bytes());
    eval_xor(builder, b1.bytes(), c2.bytes(), &cols.bx2, is_real);

    // `b2 = bx2 >>> 63` (soundness step 3).
    let bx2 = to_exprs::<CB, F, 8>(&cols.bx2);
    let two = CB::Expr::TWO;
    let b2 = match msb {
        Msb::Column(h) => {
            for bit in h {
                builder.assert_bool(*bit);
            }
            let h = to_exprs::<CB, F, 8>(h);
            Dword::from_bytes(array::from_fn(|i| {
                bx2[i].clone() * two.clone() - h[i].clone() * CB::Expr::from_u32(256)
                    + h[(i + 7) % 8].clone()
            }))
        }
        Msb::Diagonal(h) => {
            for bit in h {
                builder.assert_bool(*bit);
            }
            let h = to_exprs::<CB, F, 4>(h);
            Dword::from_limbs(array::from_fn(|j| {
                (bx2[2 * j].clone() + bx2[2 * j + 1].clone() * CB::Expr::from_u32(256))
                    * two.clone()
                    - h[j].clone() * CB::Expr::from_u32(1 << 16)
                    + h[(j + 3) % 4].clone()
            }))
        }
    };

    v[a] = a2;
    v[b] = b2;
    v[c] = c2;
    v[d] = d2;
}

/// The `LookupType::Blake2bRound` message `[chunk, clk, tag, k, s, 64 limbs]`.
pub(crate) fn bus_message<E: Clone>(
    chunk: E,
    clk: E,
    tag: E,
    k: E,
    s: E,
    limbs: impl IntoIterator<Item = E>,
) -> Vec<E> {
    let mut values = vec![chunk, clk, tag, k, s];
    values.extend(limbs);
    debug_assert_eq!(values.len(), 5 + 4 * STATE_DWORDS);
    values
}

impl<F, CB> Air<CB> for Blake2bRoundChip<F>
where
    F: Field,
    CB: ChipBuilder<F>,
{
    fn eval(&self, builder: &mut CB) {
        let main = builder.main();
        let local = main.current_slice();
        let local: &Blake2bRoundCols<CB::Var> = (*local).borrow();
        let is_real: CB::Expr = local.is_real.into();
        builder.assert_bool(local.is_real);
        builder.assert_bool(local.wrap);

        let mut v: Vec<Dword<CB::Expr>> = (0..STATE_DWORDS)
            .map(|w| match w / 4 {
                0 => Dword::from_limbs(to_exprs::<CB, F, 4>(&local.v_a[w % 4])),
                1 => Dword::from_bytes(to_exprs::<CB, F, 8>(&local.v_b[w % 4])),
                2 => Dword::from_limbs(to_exprs::<CB, F, 4>(&local.v_c[w % 4])),
                _ => Dword::from_bytes(to_exprs::<CB, F, 8>(&local.v_d[w % 4])),
            })
            .collect();
        let v_in: Vec<CB::Expr> = v.iter().flat_map(|w| w.limbs.clone()).collect();

        for (i, idx) in MIX_INDICES.iter().enumerate() {
            let msb = if i < 4 {
                Msb::Column(&local.column_msb[i])
            } else {
                Msb::Diagonal(&local.diagonal_msb[i - 4])
            };
            eval_mix::<F, CB>(
                builder,
                &mut v,
                *idx,
                [
                    to_exprs::<CB, F, 4>(&local.m[2 * i]),
                    to_exprs::<CB, F, 4>(&local.m[2 * i + 1]),
                ],
                &local.mix[i],
                msb,
                &is_real,
            );
        }
        let v_out: Vec<CB::Expr> = v.iter().flat_map(|w| w.limbs.clone()).collect();

        let chunk: CB::Expr = local.chunk.into();
        let clk: CB::Expr = local.clk.into();
        let k: CB::Expr = local.k.into();
        let s: CB::Expr = local.s.into();
        let wrap: CB::Expr = local.wrap.into();
        let state_tag = CB::Expr::from_u32(BUS_STATE_TAG);
        // `v` entering this round.
        builder.looked(SymbolicLookup::new(
            bus_message(
                chunk.clone(),
                clk.clone(),
                state_tag.clone(),
                k.clone(),
                s.clone(),
                v_in,
            ),
            is_real.clone(),
            LookupType::Blake2bRound,
            LookupScope::Regional,
        ));
        // The message block in this round's schedule order.
        builder.looking(SymbolicLookup::new(
            bus_message(
                chunk.clone(),
                clk.clone(),
                CB::Expr::from_u32(BUS_MESSAGE_TAG),
                CB::Expr::ZERO,
                s.clone(),
                local.m.iter().flat_map(|w| to_exprs::<CB, F, 4>(w)),
            ),
            is_real.clone(),
            LookupType::Blake2bRound,
            LookupScope::Regional,
        ));
        // `v` entering the next round.
        builder.looking(SymbolicLookup::new(
            bus_message(
                chunk,
                clk,
                state_tag,
                k + CB::Expr::ONE,
                s + CB::Expr::ONE - wrap * CB::Expr::from_u32(10),
                v_out,
            ),
            is_real,
            LookupType::Blake2bRound,
            LookupScope::Regional,
        ));
    }
}

#[cfg(feature = "cuda")]
impl<F: PrimeField32> crate::machine::chip::GpuChipBehavior<F> for Blake2bRoundChip<F> {
    /// The GPU prover generates this trace on the host, and adds its byte lookups to the device
    /// table, as for the BLS12-381 G2 chips.
    fn gpu_generate_extra_record_and_main(
        &self,
        _device_id: usize,
        input: &Self::Record,
        _prepared_gpu_events: &crate::instances::preparer::PreparedGpuEvents,
        preallocated_gpu_memory: &mut crate::instances::preparer::PreallocatedGpuMemory,
    ) -> crate::chips::trace::TraceData<'_, F> {
        let (trace, counts) = self.trace_and_counts(input, true);
        crate::instances::preparer::gpu_add_host_byte_lookups(
            xor_lookups(&counts),
            preallocated_gpu_memory,
        )
        .expect("BLAKE2b round: adding the byte lookups to the device table failed");
        crate::chips::trace::TraceData::Cpu(trace.unwrap())
    }

    fn is_active_for_extra_record(
        &self,
        record: &crate::instances::preparer::PreparedGpuEvents,
    ) -> bool {
        if let Some(shape) = record.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            record
                .event_counter
                .get_precompile_event_num(SyscallCode::BLAKE2B_ROUNDS)
                > 0
        }
    }
}
