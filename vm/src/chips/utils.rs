use crate::primitives::consts::{BYTE_SIZE, WORD_SIZE};
use std::{
    fmt::Display,
    iter::{Map, Peekable},
};

use rand::{thread_rng, Rng};

pub const fn indices_arr<const N: usize>() -> [usize; N] {
    let mut indices_arr = [0; N];
    let mut i = 0;
    while i < N {
        indices_arr[i] = i;
        i += 1;
    }
    indices_arr
}

pub const fn get_msb(a: [u8; WORD_SIZE]) -> u8 {
    (a[WORD_SIZE - 1] >> (BYTE_SIZE - 1)) & 1
}

/// Creates a new ALU lookup id.
#[must_use]
pub fn create_alu_lookup_id() -> u128 {
    let mut rng = thread_rng();
    rng.gen()
}

/// Creates a new ALU lookup ids.
#[must_use]
pub fn create_alu_lookups() -> [u128; 6] {
    let mut rng = thread_rng();
    [
        rng.gen(),
        rng.gen(),
        rng.gen(),
        rng.gen(),
        rng.gen(),
        rng.gen(),
    ]
}

/// Returns sorted and formatted rows of a table of counts (e.g. `opcode_counts`).
///
/// The table is sorted first by count (descending) and then by label (ascending).
/// The first column consists of the counts, is right-justified, and is padded precisely
/// enough to fit all the numbers. The second column consists of the labels (e.g. `OpCode`s).
/// The columns are separated by a single space character.
#[allow(clippy::type_complexity)]
pub fn sorted_table_lines<'a, K, V>(
    table: impl IntoIterator<Item = (K, V)> + 'a,
) -> Map<
    Peekable<Map<std::vec::IntoIter<(K, V)>, impl FnMut((K, V)) -> (String, String)>>,
    impl FnMut((String, String)) -> String,
>
where
    K: Ord + Display + 'a,
    V: Ord + Display + 'a,
{
    let mut entries = table.into_iter().collect::<Vec<_>>();
    // Sort table by count (descending), then the name order (ascending).
    entries.sort_unstable_by(|a, b| a.1.cmp(&b.1).reverse().then_with(|| a.0.cmp(&b.0)));
    // Convert counts to `String`s to prepare them for printing and to measure their width.
    let mut table_with_string_counts = entries
        .into_iter()
        .map(|(label, ct)| (label.to_string().to_lowercase(), ct.to_string()))
        .peekable();
    // Calculate width for padding the counts.
    let width = table_with_string_counts
        .peek()
        .map(|(_, b)| b.len())
        .unwrap_or_default();
    table_with_string_counts.map(move |(label, count)| format!("{count:>width$} {label}"))
}
