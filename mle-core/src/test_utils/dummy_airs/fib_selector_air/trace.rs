use p3_field::Field;
use p3_matrix::dense::RowMajorMatrix;

use crate::test_utils::dummy_airs::fib_air::columns::NUM_FIBONACCI_COLS;

/// sels contain boolean selectors to enable the fibonacci gate
pub fn generate_trace_rows<F: Field>(a: u64, b: u64, sels: &[bool]) -> RowMajorMatrix<F> {
    let n = sels.len();
    assert!(n.is_power_of_two());

    let mut rows = vec![vec![F::from_u64(a), F::from_u64(b)]];

    for i in 1..n {
        if sels[i - 1] {
            rows.push(vec![rows[i - 1][1], rows[i - 1][0] + rows[i - 1][1]]);
        } else {
            rows.push(vec![rows[i - 1][0], rows[i - 1][1]]);
        }
    }

    RowMajorMatrix::new(rows.concat(), NUM_FIBONACCI_COLS)
}
