use core::fmt::Debug;
use p3_matrix::dense::DenseMatrix;
use std::{fs::File, io::Write, marker::PhantomData};

pub mod columns;
mod constraint;
pub mod control;
mod p3_eval;
mod traces;

pub(crate) const STATE_SIZE: usize = 25;

// The permutation state is 25 u64's.  Our word size is 64 bits, so it is 25 words.
pub const STATE_NUM_WORDS: usize = STATE_SIZE;

/// Tags of the two `LookupType::KeccakPermute` messages. The bus carries the pre- and the
/// post-permutation state as two separate messages `[chunk, clk, tag, 100 limbs]` (one message of
/// both would be 203 elements with the bus, over the logUp `max_message_length` of 128); the tag
/// keeps the two multisets apart so an input cannot be matched against an output.
pub(crate) const KECCAK_STATE_BUS_INPUT_TAG: u32 = 0;
pub(crate) const KECCAK_STATE_BUS_OUTPUT_TAG: u32 = 1;

/// The Keccak-f permutation AIR. The permutation constraints live in `p3_eval::eval_keccak`, a
/// local copy of the `p3_keccak_air` evaluator with a regrouped theta step and without the
/// `preimage` block; the column layout is the local `columns::KeccakCols` (upstream minus
/// `preimage`); the chip-level constraints and the two lookups are in `constraint.rs`; the trace
/// rows come from the `p3_keccak_air` generator, projected onto the local layout.
#[derive(Debug)]
pub struct KeccakPermuteChip<F> {
    _marker: PhantomData<fn(F) -> F>,
}

impl<T: Default> Default for KeccakPermuteChip<T> {
    fn default() -> Self {
        KeccakPermuteChip {
            _marker: PhantomData,
        }
    }
}

/// One row per `KECCAK_PERMUTE` syscall: syscall receive, state pointer checks and the 25 u64
/// state reads / writes. Talks to [`KeccakPermuteChip`] over the `LookupType::KeccakPermute` bus.
#[derive(Default)]
pub struct KeccakControlChip<F>(PhantomData<F>);

pub fn print_dense_matrix<T: Debug, V: AsRef<[T]>>(matrix: &DenseMatrix<T, V>) {
    println!("DenseMatrix (width = {})", matrix.width);
    let values = matrix.values.as_ref();
    let height = values.len() / matrix.width;
    for row in 0..height {
        let start = row * matrix.width;
        let end = start + matrix.width;
        let row_values = &values[start..end];
        println!("{:?}", row_values);
    }
}

pub fn dump_dense_matrix_csv<T: Debug + ToString, V: AsRef<[T]>>(
    matrix: &DenseMatrix<T, V>,
    path: &str,
) -> std::io::Result<()> {
    let mut f = File::create(path)?;
    let vals = matrix.values.as_ref();
    let h = vals.len() / matrix.width;
    for r in 0..h {
        let start = r * matrix.width;
        let row = &vals[start..start + matrix.width];
        let line = row
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",");
        writeln!(f, "{line}")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
