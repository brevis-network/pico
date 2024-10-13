use p3_maybe_rayon::prelude::{ParallelBridge, ParallelIterator};

pub fn pad_rows_fixed<R: Clone>(
    rows: &mut Vec<R>,
    row_fn: impl Fn() -> R,
    size_log2: Option<usize>,
) {
    let nb_rows = rows.len();
    let dummy_row = row_fn();
    rows.resize(next_power_of_two(nb_rows, size_log2), dummy_row);
}

/// Returns the next power of two that is >= `n` and >= 16. If `fixed_power` is set, it will return
/// `2^fixed_power` after checking that `n <= 2^fixed_power`.
/// TODO: Re-evaluate if necessary
pub fn next_power_of_two(n: usize, fixed_power: Option<usize>) -> usize {
    match fixed_power {
        Some(power) => {
            let padded_nb_rows = 1 << power;
            if n * 2 < padded_nb_rows {
                tracing::warn!(
                    "fixed log2 rows can be potentially reduced: got {}, expected {}",
                    n,
                    padded_nb_rows
                );
            }
            if n > padded_nb_rows {
                panic!(
                    "fixed log2 rows is too small: got {}, expected {}",
                    n, padded_nb_rows
                );
            }
            padded_nb_rows
        }
        None => {
            let mut padded_nb_rows = n.next_power_of_two();
            if padded_nb_rows < 16 {
                padded_nb_rows = 16;
            }
            padded_nb_rows
        }
    }
}

pub fn par_for_each_row<P, F>(vec: &mut [F], num_elements_per_event: usize, processor: P)
where
    F: Send,
    P: Fn(usize, &mut [F]) + Send + Sync,
{
    // Split the vector into `num_cpus` chunks, but at least `num_cpus` rows per chunk.
    assert!(vec.len() % num_elements_per_event == 0);
    let len = vec.len() / num_elements_per_event;
    let cpus = num_cpus::get();
    let ceil_div = (len + cpus - 1) / cpus;
    let chunk_size = std::cmp::max(ceil_div, cpus);

    vec.chunks_mut(chunk_size * num_elements_per_event)
        .enumerate()
        .par_bridge()
        .for_each(|(i, chunk)| {
            chunk
                .chunks_mut(num_elements_per_event)
                .enumerate()
                .for_each(|(j, row)| {
                    assert!(row.len() == num_elements_per_event);
                    processor(i * chunk_size + j, row);
                });
        });
}
