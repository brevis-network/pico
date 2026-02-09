use p3_field::Field;
use p3_matrix::dense::RowMajorMatrix;
use serde::{Deserialize, Serialize};

/// Jagged trace MLE representation for sparse trace optimization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JaggedTraceMle<F> {
    /// The jagged-assisted MLE data
    pub jagged_mle: JaggedAssistMle<F>,
    /// Log size of the original trace
    pub log_original_size: usize,
    /// Compression ratio achieved
    pub compression_ratio: f32,
}

/// Simplified JaggedAssistMle wrapper
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JaggedAssistMle<F> {
    /// MLE data
    pub data: Vec<F>,
    /// Number of variables
    pub num_vars: usize,
    /// Sparsity information
    pub sparsity: SparsityInfo,
}

/// Sparsity information for Jagged traces
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SparsityInfo {
    /// Number of non-zero entries
    pub nonzero_count: usize,
    /// Total entries
    pub total_count: usize,
    /// Pattern of sparsity
    pub pattern: SparsityPattern,
}

/// Pattern of sparsity in traces
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SparsityPattern {
    /// Random sparsity
    Random,
    /// Structured sparsity (blocks)
    Structured,
    /// Mostly dense
    MostlyDense,
    /// Mostly sparse
    MostlySparse,
}

/// Metadata for jagged trace conversion
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JaggedMetadata {
    /// Original trace dimensions
    pub original_dimensions: (usize, usize),
    /// Compressed dimensions
    pub compressed_dimensions: (usize, usize),
    /// Number of jagged segments
    pub num_segments: usize,
    /// Average segment size
    pub avg_segment_size: f32,
}

impl<F> JaggedTraceMle<F> {
    /// Create a new jagged trace MLE
    pub fn new(
        data: Vec<F>,
        num_vars: usize,
        sparsity: SparsityInfo,
        metadata: JaggedMetadata,
    ) -> Self {
        let compression_ratio = sparsity.nonzero_count as f32 / sparsity.total_count as f32;

        Self {
            jagged_mle: JaggedAssistMle {
                data,
                num_vars,
                sparsity,
            },
            log_original_size: metadata.original_dimensions.0 + metadata.original_dimensions.1,
            compression_ratio,
        }
    }

    /// Get the compression ratio
    pub fn compression_ratio(&self) -> f32 {
        self.compression_ratio
    }

    /// Check if compression is beneficial
    pub fn is_compression_beneficial(&self) -> bool {
        self.compression_ratio < 0.8
    }
}

/// Convert traditional traces to jagged format
pub fn convert_traces_to_jagged<F: Field>(
    traces: &[RowMajorMatrix<F>],
    threshold: f32,
) -> Option<(JaggedTraceMle<F>, JaggedMetadata)> {
    if traces.is_empty() {
        return None;
    }

    use p3_matrix::Matrix;

    // Analyze sparsity
    let total_elements: usize = traces.iter().map(|t| t.height() * t.width()).sum();
    let nonzero_elements: usize = traces
        .iter()
        .map(|t| t.values.iter().filter(|&&v| v != F::ZERO).count())
        .sum();

    let sparsity_ratio = nonzero_elements as f32 / total_elements as f32;

    // Only use jagged if there's significant sparsity
    if sparsity_ratio > threshold {
        return None;
    }

    // Create flattened data
    let mut flattened_data = Vec::with_capacity(nonzero_elements);
    for trace in traces {
        for value in trace.values.iter() {
            if !value.is_zero() {
                flattened_data.push(*value);
            }
        }
    }

    let sparsity_info = SparsityInfo {
        nonzero_count: nonzero_elements,
        total_count: total_elements,
        pattern: if sparsity_ratio < 0.1 {
            SparsityPattern::MostlySparse
        } else if sparsity_ratio > 0.9 {
            SparsityPattern::MostlyDense
        } else {
            SparsityPattern::Structured
        },
    };

    let metadata = JaggedMetadata {
        original_dimensions: (total_elements, traces.len()),
        compressed_dimensions: (nonzero_elements, traces.len()),
        num_segments: traces.len(),
        avg_segment_size: nonzero_elements as f32 / traces.len() as f32,
    };

    let num_vars = (total_elements.next_power_of_two() as u32).ilog2() as usize + 1;

    Some((
        JaggedTraceMle::new(flattened_data, num_vars, sparsity_info, metadata.clone()),
        metadata,
    ))
}

/// Reconstruct traditional traces from jagged format
pub fn reconstruct_traces_from_jagged<F: Field + Clone + Send + Sync>(
    jagged_trace: &JaggedTraceMle<F>,
    original_dims: (usize, usize),
) -> Vec<RowMajorMatrix<F>> {
    // This is a simplified reconstruction - in practice, you'd need
    // to store the original positions of non-zero elements
    let (total_elements, num_traces) = original_dims;
    let elements_per_trace = total_elements / num_traces;

    let mut reconstructed = Vec::with_capacity(num_traces);
    let mut data_idx = 0;

    for _ in 0..num_traces {
        let mut trace_data = vec![F::ZERO; elements_per_trace];

        // Fill non-zero elements (simplified - assumes first elements are non-zero)
        let nonzero_in_trace =
            (jagged_trace.jagged_mle.data.len() / num_traces).min(elements_per_trace);
        for i in 0..nonzero_in_trace {
            if data_idx < jagged_trace.jagged_mle.data.len() {
                trace_data[i] = jagged_trace.jagged_mle.data[data_idx].clone();
                data_idx += 1;
            }
        }

        reconstructed.push(RowMajorMatrix::new(
            trace_data,
            elements_per_trace.next_power_of_two().ilog2() as usize,
        ));
    }

    reconstructed
}
