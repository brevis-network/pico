use super::{
    columns::{KeccakMemCols, NUM_KECCAK_MEM_COLS},
    KeccakPermuteChip, STATE_SIZE,
};
use crate::{
    chips::precompiles::checked_u64_to_u32,
    compiler::riscv::program::Program,
    emulator::{
        record::RecordBehavior,
        riscv::{
            record::EmulationRecord,
            syscalls::{
                precompiles::{KeccakPermuteEvent, PrecompileEvent},
                SyscallCode,
            },
        },
    },
    iter::{PicoBridge, PicoIterator},
    machine::chip::ChipBehavior,
};
use p3_air::BaseAir;
use p3_field::PrimeField32;
use p3_keccak_air::{
    generate_trace_rows, KeccakCols as UpstreamKeccakCols, NUM_KECCAK_COLS, NUM_ROUNDS,
};
use p3_matrix::dense::RowMajorMatrix;
use std::borrow::{Borrow, BorrowMut};
use tracing::debug;

impl<F> BaseAir<F> for KeccakPermuteChip<F> {
    fn width(&self) -> usize {
        NUM_KECCAK_MEM_COLS
    }
}

impl<F: PrimeField32> ChipBehavior<F> for KeccakPermuteChip<F> {
    type Record = EmulationRecord;
    type Program = Program;

    fn name(&self) -> String {
        "KeccakPermute".to_string()
    }

    fn generate_preprocessed(&self, _program: &Self::Program) -> Option<RowMajorMatrix<F>> {
        None
    }

    // No `extra_record`: this AIR emits no byte lookups any more (the address gadgets and the
    // memory accesses moved to `KeccakControlChip`).

    fn generate_main(&self, input: &Self::Record, _output: &mut Self::Record) -> RowMajorMatrix<F> {
        let events: Vec<_> = input
            .get_precompile_events(SyscallCode::KECCAK_PERMUTE)
            .iter()
            .filter_map(|(_, event)| {
                if let PrecompileEvent::KeccakPermute(event) = event {
                    Some(event)
                } else {
                    unreachable!()
                }
            })
            .collect();
        debug!(
            "record {} keccak precompile events {:?}",
            input.chunk_index(),
            events.len()
        );
        let num_events = events.len();
        // Honor a record shape (the MLE coarse bucket / FRI pad shape); the dummy-chunk padding
        // below fills whatever tail the target height leaves.
        let num_rows = match input.shape_chip_size(&self.name()) {
            Some(log) => {
                let padded = 1usize << log;
                assert!(
                    padded >= num_events * NUM_ROUNDS,
                    "KeccakPermute shape height {padded} < {} real rows (shape bucket too small)",
                    num_events * NUM_ROUNDS
                );
                padded
            }
            None => (num_events * NUM_ROUNDS).next_power_of_two(),
        };
        let chunk_size = 8;
        let values = vec![0u32; num_rows * NUM_KECCAK_MEM_COLS];
        let mut values = unsafe { std::mem::transmute::<Vec<u32>, Vec<F>>(values) };

        // A dummy permutation: the upstream rows for the zero state, projected onto the local
        // layout; `chunk / clk / is_real / export_in` stay zero.
        let dummy_keccak_rows = generate_trace_rows::<F>(vec![[0; STATE_SIZE]], 0);
        let mut dummy_chunk = Vec::new();
        for i in 0..NUM_ROUNDS {
            let src: &UpstreamKeccakCols<F> =
                dummy_keccak_rows.values[i * NUM_KECCAK_COLS..(i + 1) * NUM_KECCAK_COLS].borrow();
            let mut row = [F::ZERO; NUM_KECCAK_MEM_COLS];
            let cols: &mut KeccakMemCols<F> = row.as_mut_slice().borrow_mut();
            cols.keccak.copy_from_upstream(src);
            dummy_chunk.extend_from_slice(&row);
        }

        values
            .chunks_mut(chunk_size * NUM_KECCAK_MEM_COLS * NUM_ROUNDS)
            .enumerate()
            .pico_bridge()
            .for_each(|(i, rows)| {
                rows.chunks_mut(NUM_ROUNDS * NUM_KECCAK_MEM_COLS)
                    .enumerate()
                    .for_each(|(j, rounds)| {
                        let idx = i * chunk_size + j;
                        if idx < num_events {
                            Self::populate_chunk(events[idx], rounds);
                        } else {
                            rounds.copy_from_slice(&dummy_chunk[..rounds.len()]);
                        }
                    });
            });

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(values, NUM_KECCAK_MEM_COLS)
    }

    fn is_active(&self, record: &Self::Record) -> bool {
        if let Some(shape) = record.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            !record
                .get_precompile_events(SyscallCode::KECCAK_PERMUTE)
                .is_empty()
        }
    }
}

impl<F: PrimeField32> KeccakPermuteChip<F> {
    /// The 24 rows of one permutation: the p3 rows for `pre_state` projected onto the local layout
    /// (no `preimage`), tagged with the VM context. `export_in` is set on the first step and
    /// `export` (p3's multiset-export flag, which p3's generator leaves at 0) on the final step:
    /// those rows carry the permutation's input (`a`) and output (`a'''`) onto the `KeccakPermute`
    /// state bus (`constraint.rs`). Mirrored by `keccak_populate.hpp` on the GPU.
    pub fn populate_chunk(event: &KeccakPermuteEvent, rounds: &mut [F]) {
        let start_clk = event.clk;
        let chunk = event.chunk;

        let p3_keccak_trace = generate_trace_rows::<F>(vec![event.pre_state], 0);

        // Create all the rows for the permutation.
        for i in 0..NUM_ROUNDS {
            let src: &UpstreamKeccakCols<F> =
                p3_keccak_trace.values[i * NUM_KECCAK_COLS..(i + 1) * NUM_KECCAK_COLS].borrow();
            let row = &mut rounds[i * NUM_KECCAK_MEM_COLS..(i + 1) * NUM_KECCAK_MEM_COLS];
            let cols: &mut KeccakMemCols<F> = row.borrow_mut();
            cols.keccak.copy_from_upstream(src);

            cols.chunk = F::from_u32(chunk);
            cols.clk = F::from_u32(checked_u64_to_u32(start_clk, "keccak clk"));
            cols.is_real = F::ONE;
            if i == 0 {
                cols.export_in = F::ONE;
            }
            if i == NUM_ROUNDS - 1 {
                cols.keccak.export = F::ONE;
            }
        }
    }
}
