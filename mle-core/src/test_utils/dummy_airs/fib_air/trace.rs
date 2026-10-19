use p3_field::Field;
use p3_matrix::dense::RowMajorMatrix;

use super::columns::NUM_FIBONACCI_COLS;

/// n is number of rows in the trace
pub fn generate_trace_rows<F: Field>(a: u64, b: u64, n: usize) -> RowMajorMatrix<F> {
    assert!(n.is_power_of_two());

    let mut rows = vec![vec![F::from_u64(a), F::from_u64(b)]];

    for i in 1..n {
        rows.push(vec![rows[i - 1][1], rows[i - 1][0] + rows[i - 1][1]]);
    }

    RowMajorMatrix::new(rows.concat(), NUM_FIBONACCI_COLS)
}
