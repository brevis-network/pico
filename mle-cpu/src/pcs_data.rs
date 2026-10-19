//! [CpuStackedPcsData] — CPU-backend PCS data with RowMajor Merkle tree backing.
//!
//! The eval matrix stays `ColMajor` because stacked reduction accesses it
//! column-by-column (each unstacked trace column maps to a contiguous slice
//! in a stacked column).
//!
//! The Merkle tree uses `RowMajor` backing for cache-friendly row hashing
//! and contiguous row access in query answering.

use pico_mle_core::{
    poly::matrix::ColMajorMatrix,
    protocol::stacking::{StackedLayout, StackedPcsError},
};

use crate::merkle::CpuMerkleTree;

/// CPU-backend PCS data with RowMajor Merkle tree backing.
#[derive(Clone, Debug)]
pub struct CpuStackedPcsData<F, Digest> {
    /// Layout of the unstacked collection of matrices within the stacked matrix.
    pub layout: StackedLayout,
    /// Stacked evaluation matrix (ColMajor for column-oriented access in stacked reduction).
    pub matrix: ColMajorMatrix<F>,
    /// Merkle tree with RowMajor RS codeword backing.
    pub tree: CpuMerkleTree<F, Digest>,
}

impl<F, Digest: Clone> CpuStackedPcsData<F, Digest> {
    pub fn new(
        layout: StackedLayout,
        matrix: ColMajorMatrix<F>,
        tree: CpuMerkleTree<F, Digest>,
    ) -> Self {
        Self {
            layout,
            matrix,
            tree,
        }
    }

    /// Returns the root of the Merkle tree.
    pub fn commit(&self) -> Result<Digest, StackedPcsError> {
        self.tree.root()
    }
}

#[cfg(test)]
mod tests {
    use p3_matrix::dense::RowMajorMatrix;

    use super::*;
    use crate::merkle::rs_encode_and_merkle_cpu;
    use p3_field::PrimeCharacteristicRing;
    use pico_mle_core::{
        config::koala_bear_poseidon2::{default_koalabear_poseidon2_16, F},
        hasher::Hasher,
        p3_symmetric::{PaddingFreeSponge, TruncatedPermutation},
        prover::stacked_pcs::{rs_code_matrix, ColMajorMerkleTree},
    };

    /// Minimal smoke test: construct a CpuStackedPcsData and call `commit`.
    #[test]
    fn test_cpu_stacked_pcs_data_commit() {
        // Minimal StackedLayout (1 column, height 2)
        let layout = StackedLayout::new(0, 1, vec![(1, 1)]).unwrap();

        // ColMajor eval matrix: 1 column x 2 rows
        let matrix = ColMajorMatrix::new(vec![1u32, 2], 1);

        // Minimal CpuMerkleTree
        let rm = RowMajorMatrix::new(vec![10u32, 20], 1);
        let digest_layers = vec![vec![100u32], vec![42]];
        let tree = CpuMerkleTree::from_raw_parts(rm, digest_layers, 2);

        let data = CpuStackedPcsData::new(layout, matrix, tree);
        assert_eq!(data.commit().unwrap(), 42);
    }

    /// The fused CPU path (`rs_encode_and_merkle_cpu`, row-major backing) commits to the same
    /// root as the reference path (`rs_code_matrix` + col-major `ColMajorMerkleTree`), so
    /// `CpuStackedPcsData::commit` is interchangeable with `StackedPcsData::commit`.
    #[test]
    fn test_cpu_commit_matches_reference_root() {
        let perm = default_koalabear_poseidon2_16();
        let hasher = Hasher::new(
            PaddingFreeSponge::<_, 16, 8, 8>::new(perm.clone()),
            TruncatedPermutation::<_, 2, 8, 16>::new(perm),
        );
        let (l_skip, log_blowup, rows_per_query) = (2usize, 1, 4);
        let (width, height) = (2usize, 16);
        let values: Vec<F> = (0..(width * height) as u32)
            .map(|v| F::from_u32(v + 1))
            .collect();
        let eval_matrix = ColMajorMatrix::new(values, width);

        let reference_root = {
            let rs = rs_code_matrix(l_skip, log_blowup, &eval_matrix).unwrap();
            ColMajorMerkleTree::new(&hasher, rs, rows_per_query)
                .unwrap()
                .root()
                .unwrap()
        };

        let layout = StackedLayout::new(l_skip, 4, vec![(width, 4)]).unwrap();
        let tree =
            rs_encode_and_merkle_cpu(&hasher, l_skip, log_blowup, &eval_matrix, rows_per_query);
        let data = CpuStackedPcsData::new(layout, eval_matrix, tree);
        assert_eq!(data.commit().unwrap(), reference_root);
    }
}
