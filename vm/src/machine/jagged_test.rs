#[cfg(test)]
mod tests {
    use p3_baby_bear::BabyBear;
    use p3_field::FieldAlgebra;
    use p3_matrix::{dense::RowMajorMatrix, Matrix};

    #[test]
    fn test_jagged_trace_conversion() {
        // Create a sparse trace for testing
        let sparse_data = vec![
            BabyBear::from_canonical_u32(1),
            BabyBear::from_canonical_u32(0), // Zero
            BabyBear::from_canonical_u32(2),
            BabyBear::from_canonical_u32(0), // Zero
            BabyBear::from_canonical_u32(3),
        ];

        let trace = RowMajorMatrix::new(sparse_data, 1); // 1 column, 5 rows

        // Test conversion to Jagged
        let result = crate::machine::jagged_trace::convert_traces_to_jagged(
            &[trace],
            0.9, // High threshold - should convert since we have 40% zeros
        );

        assert!(
            result.is_some(),
            "Jagged conversion should succeed for sparse traces"
        );

        let (jagged_trace, metadata) = result.unwrap();
        assert!(
            jagged_trace.compression_ratio() < 0.9,
            "Compression should be beneficial"
        );
        assert!(
            jagged_trace.is_compression_beneficial(),
            "Should be beneficially compressed"
        );

        // Test reconstruction
        let reconstructed = crate::machine::jagged_trace::reconstruct_traces_from_jagged(
            &jagged_trace,
            metadata.original_dimensions,
        );

        assert_eq!(reconstructed.len(), 1, "Should reconstruct one trace");
        assert_eq!(
            reconstructed[0].height() * reconstructed[0].width(),
            5,
            "Should maintain size"
        );
    }

    #[test]
    fn test_jagged_not_used_for_dense_traces() {
        // Create a dense trace
        let dense_data = vec![
            BabyBear::from_canonical_u32(1),
            BabyBear::from_canonical_u32(2),
            BabyBear::from_canonical_u32(3),
            BabyBear::from_canonical_u32(4),
            BabyBear::from_canonical_u32(5),
        ];

        let trace = RowMajorMatrix::new(dense_data, 1); // 1 column, 5 rows

        // Test conversion - should not convert dense traces
        let result = crate::machine::jagged_trace::convert_traces_to_jagged(
            &[trace],
            0.3, // Low threshold - should not convert since we have no zeros
        );

        assert!(
            result.is_none(),
            "Jagged conversion should not succeed for dense traces"
        );
    }

    #[test]
    fn test_commit_modes() {
        use crate::machine::proof::CommitmentMode;

        // Test that we can create commitments in different modes
        let mode = CommitmentMode::Traditional;
        assert_eq!(mode as u8, 0, "Traditional mode should be 0");

        let mode = CommitmentMode::Jagged;
        assert_eq!(mode as u8, 1, "Jagged mode should be 1");

        let mode = CommitmentMode::Hybrid;
        assert_eq!(mode as u8, 2, "Hybrid mode should be 2");
    }
}
