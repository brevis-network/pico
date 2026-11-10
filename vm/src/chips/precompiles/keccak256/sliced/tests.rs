use core::borrow::{Borrow, BorrowMut};
use std::{marker::PhantomData, mem::size_of, sync::Arc};

use p3_air::{Air, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing, PrimeField32};
use p3_koala_bear::KoalaBear;
use p3_matrix::dense::RowMajorMatrix;
use p3_maybe_rayon::prelude::*;
use pico_derive::AlignedBorrow;
use pico_mle_core::{
    config::riscv_params_with_128_bits_security,
    prover::{AirProvingContext, DeviceDataTransporter, ProvingContext},
    AirRef, BaseAirWithPublicValues, PartitionedBaseAir, StarkEngine,
};

use super::{
    tables::{chi_table_row, tables_main, xor5_table_row},
    trace::round_states,
    *,
};
use crate::{
    machine::{
        builder::ChipBuilder,
        lookup::{LookupScope, LookupType, SymbolicLookup},
    },
    mle::machine::riscv::{ctx_to_engine, Engine, Kb, Sc},
};

/// Sends what `KeccakControlChip` sends on the state bus, one row per permutation: `[chunk, clk,
/// tag, 100 limbs]` for the input and the output, multiplicity `is_real`. It balances the sliced
/// chip's receives without the control chip's memory and syscall side.
#[derive(Default)]
struct KeccakBusSink<F>(PhantomData<fn(F) -> F>);

#[derive(AlignedBorrow)]
#[repr(C)]
struct KeccakBusSinkCols<T> {
    pub chunk: T,
    pub clk: T,
    pub is_real: T,
    pub input: [T; 100],
    pub output: [T; 100],
}
const NUM_SINK_COLS: usize = size_of::<KeccakBusSinkCols<u8>>();

impl<F> BaseAir<F> for KeccakBusSink<F> {
    fn width(&self) -> usize {
        NUM_SINK_COLS
    }
}
impl<F: Field> PartitionedBaseAir<F> for KeccakBusSink<F> {}
impl<F: Field> BaseAirWithPublicValues<F> for KeccakBusSink<F> {}

impl<F: PrimeField32, CB: ChipBuilder<F>> Air<CB> for KeccakBusSink<F> {
    fn eval(&self, builder: &mut CB) {
        let main = builder.main();
        let local: &KeccakBusSinkCols<CB::Var> = (*main.current_slice()).borrow();
        builder.assert_bool(local.is_real);
        for (tag, words) in [
            (KECCAK_STATE_BUS_INPUT_TAG, &local.input),
            (KECCAK_STATE_BUS_OUTPUT_TAG, &local.output),
        ] {
            let mut values = vec![
                local.chunk.into(),
                local.clk.into(),
                CB::Expr::from_u32(tag),
            ];
            values.extend(words.iter().map(|&w| w.into()));
            builder.looking(SymbolicLookup::new(
                values,
                local.is_real.into(),
                LookupType::KeccakPermute,
                LookupScope::Regional,
            ));
        }
    }
}

/// Sink rows for `inputs`: permutation `p` at `chunk = 1, clk = 4p + 1`, the keys of [`perms`].
fn sink_trace<F: PrimeField32>(inputs: &[[u64; 25]]) -> RowMajorMatrix<F> {
    let height = inputs.len().next_power_of_two().max(16);
    let mut values = F::zero_vec(height * NUM_SINK_COLS);
    values
        .par_chunks_mut(NUM_SINK_COLS)
        .zip(inputs.par_iter())
        .enumerate()
        .for_each(|(p, (row, input))| {
            let cols: &mut KeccakBusSinkCols<F> = row.borrow_mut();
            let mut output = *input;
            tiny_keccak::keccakf(&mut output);
            cols.chunk = F::ONE;
            cols.clk = F::from_u32(4 * p as u32 + 1);
            cols.is_real = F::ONE;
            for w in 0..100 {
                let (lane, limb) = (w / 4, w % 4);
                cols.input[w] = F::from_u32(((input[lane] >> (16 * limb)) & 0xffff) as u32);
                cols.output[w] = F::from_u32(((output[lane] >> (16 * limb)) & 0xffff) as u32);
            }
        });
    RowMajorMatrix::new(values, NUM_SINK_COLS)
}
/// Permutations at chunk 1, clk `4p + 1` (the sink uses the same keys).
fn perms(inputs: &[[u64; 25]]) -> Vec<SlicedPerm> {
    inputs
        .iter()
        .enumerate()
        .map(|(p, &state)| SlicedPerm {
            state,
            chunk: 1,
            clk: 4 * p as u32 + 1,
        })
        .collect()
}

fn inputs(n: usize, seed: u64) -> Vec<[u64; 25]> {
    (0..n as u64)
        .map(|k| {
            core::array::from_fn(|i| {
                (k + seed + 1).wrapping_mul(0x9e37_79b9_7f4a_7c15) ^ (i as u64).rotate_left(17)
            })
        })
        .collect()
}

/// The round function matches tiny-keccak, and every table row decodes as documented.
#[test]
fn sliced_reference_and_tables() {
    for input in inputs(64, 0) {
        let mut expect = input;
        tiny_keccak::keccakf(&mut expect);
        assert_eq!(
            round_states(&input)[NUM_ROUNDS],
            expect,
            "round function != keccakf"
        );
    }
    assert_eq!(NUM_SLICED_COLS, 1953);
    // Keys are unique within each table, and the top keys sit far below the field order.
    let mut keys: Vec<u32> = (0..CHI_TABLE_ROWS).map(|i| chi_table_row(i)[0]).collect();
    keys.sort_unstable();
    keys.dedup();
    assert_eq!(keys.len(), CHI_TABLE_ROWS);
    let mut keys: Vec<u32> = (0..XOR5_TABLE_SIZE).map(|i| xor5_table_row(i)[0]).collect();
    keys.sort_unstable();
    keys.dedup();
    assert_eq!(keys.len(), XOR5_TABLE_SIZE);
    const {
        assert!(CHI_SPAN * 2 < KoalaBear::ORDER_U32);
        assert!(45 * (1 + 64 + 64 * 64 + 64 * 64 * 64) < KoalaBear::ORDER_U32);
    }
}

/// No height ends on a clk-25 row, every count fits, and the heights are the documented ones.
#[test]
fn sliced_heights() {
    for n in 1..=40_000usize {
        let h = sliced_height(n);
        assert!(h.is_power_of_two() && h >= 32);
        assert!(n.div_ceil(2) * SLOT_ROWS <= h, "n={n} h={h}");
        assert_ne!((h - 1) % SLOT_ROWS, SLOT_ROWS - 2, "n={n} h={h}");
    }
    // 2^9 ends on clk 25 and is skipped: n = 19..=74 all take 2^10.
    assert_eq!(sliced_height(18), 1 << 8);
    assert_eq!(sliced_height(19), 1 << 10);
    assert_eq!(sliced_height(74), 1 << 10);
    // The full chunk the record splitter cuts: 2 * floor(2^19 / 27) permutations.
    assert_eq!(sliced_height(2 * ((1 << 19) / SLOT_ROWS)), 1 << 19);
}

/// Sliced traces with the state bus, balanced by the sink, prove and verify: odd counts (B absent
/// in the last slot), the smallest height and the 2^9 -> 2^10 bump.
#[test]
fn sliced_trace_proves_with_the_bus() {
    let mut airs: Vec<AirRef<Sc>> = vec![Arc::new(KeccakSlicedChip::<Kb>::default())];
    airs.push(Arc::new(KeccakTables::<Kb>::default()));
    airs.push(Arc::new(KeccakBusSink::<Kb>::default()));
    let engine: Engine = StarkEngine::new(riscv_params_with_128_bits_security(23));
    let (pk, vk) = engine.keygen(&airs);
    let d_pk = engine.device().transport_pk_to_device(&pk);
    for n in [1usize, 2, 7, 19] {
        let inputs = inputs(n, n as u64);
        let t = sliced_trace::<Kb>(&perms(&inputs), sliced_height(n));
        let traces = [
            t.main,
            tables_main(&t.chi_mult, &t.xor5_mult),
            sink_trace(&inputs),
        ];
        let ctx = ProvingContext::new(
            traces
                .into_iter()
                .enumerate()
                .map(|(i, m)| (i, AirProvingContext::simple_no_pis(m)))
                .collect(),
        );
        let proof = engine.prove(&d_pk, ctx_to_engine(ctx)).expect("prove");
        engine
            .verify(&vk, &proof)
            .unwrap_or_else(|e| panic!("n={n}: verify failed: {e:?}"));
    }
}

/// [`sliced_counts`] is the multiplicity half of [`sliced_trace`].
#[test]
fn sliced_counts_match_the_trace() {
    let p = perms(&inputs(5, 3));
    let t = sliced_trace::<Kb>(&p, sliced_height(p.len()));
    let (chi, xor5) = sliced_counts::<Kb>(&p);
    assert!(chi.values == t.chi_mult.values);
    assert!(xor5.values == t.xor5_mult.values);
}
