use crate::chips::{
    chips::riscv_memory::read_write::columns::MemoryCols, gadgets::utils::limbs::Limbs,
};
use hybrid_array::ArraySize;

/// Row count to pad up to: a power of two, at least 16, or the fixed size when one is given.
///
/// `row_width` is only for the panic message, which otherwise names no chip at all.
fn padded_row_count(n_rows: usize, log_size: Option<usize>, row_width: usize) -> usize {
    let n_real_rows = n_rows.max(16);

    if let Some(log) = log_size {
        let specified_size = 1 << log; // 2^log
        if specified_size < n_real_rows {
            panic!(
                "log_size is smaller than real rows num: real rows num {} > 2^{}={} \
                 (row width N={})",
                n_real_rows, log, specified_size, row_width
            );
        }
        specified_size
    } else {
        n_real_rows.next_power_of_two()
    }
}

pub fn pad_to_power_of_two<const N: usize, T: Clone + Default>(
    values: &mut Vec<T>,
    log_size: Option<usize>,
) {
    debug_assert!(values.len().is_multiple_of(N));
    let target_rows = padded_row_count(values.len() / N, log_size, N);

    values.resize(target_rows * N, T::default());
}

/// Pad by repeating the first row instead of filling with zeros.
///
/// For a preprocessed table that is looked up by key, a zero-filled pad row is not inert: it
/// is a syntactically valid entry, and anything that can be looked up can be claimed. Repeating
/// row 0 keeps every row a genuine entry, so the set of lookupable keys stays exactly the set
/// of real ones.
pub fn pad_to_power_of_two_repeating_first_row<const N: usize, T: Clone + Default>(
    values: &mut Vec<T>,
    log_size: Option<usize>,
) {
    debug_assert!(values.len().is_multiple_of(N));
    let n_rows = values.len() / N;
    let target_rows = padded_row_count(n_rows, log_size, N);

    if n_rows == 0 {
        // Nothing to repeat; fall back to the zero fill.
        values.resize(target_rows * N, T::default());
        return;
    }

    let first_row: Vec<T> = values[..N].to_vec();
    values.reserve((target_rows - n_rows) * N);
    for _ in n_rows..target_rows {
        values.extend_from_slice(&first_row);
    }
}

pub fn pad_to_power_of_two_noconst<T: Clone + Default>(
    n: usize,
    values: &mut Vec<T>,
    log_size: Option<usize>,
) {
    debug_assert!(values.len().is_multiple_of(n));
    let target_rows = padded_row_count(values.len() / n, log_size, n);

    values.resize(target_rows * n, T::default());
}

pub fn limbs_from_prev_access<T: Copy, N: ArraySize, M: MemoryCols<T>>(cols: &[M]) -> Limbs<T, N> {
    let vec = cols
        .iter()
        .flat_map(|access| access.prev_value().0)
        .collect::<Vec<T>>();

    let sized = (&*vec)
        .try_into()
        .unwrap_or_else(|_| panic!("failed to convert to limbs"));
    Limbs(sized)
}

pub fn limbs_from_access<T: Copy, N: ArraySize, M: MemoryCols<T>>(cols: &[M]) -> Limbs<T, N> {
    let vec = cols
        .iter()
        .flat_map(|access| access.value().0)
        .collect::<Vec<T>>();

    let sized = (&*vec)
        .try_into()
        .unwrap_or_else(|_| panic!("failed to convert to limbs"));
    Limbs(sized)
}
