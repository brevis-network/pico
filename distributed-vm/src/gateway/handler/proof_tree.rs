use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fmt, ops::Bound, sync::Arc};

// chunk index of this proof
type ProofIndex = usize;

// proof value saved in a node
// template parameter P is a proof type (as MetaProof<SC>), it's easy for testing
// proof could be returned for combine between threads (transfer from gateway thread to grpc)
// type Proof<P> = Arc<P>;

/// Generic proof wrapper holding a contiguous chunk range `[start, end]`.
/// Note: start_chunk and end_chunk are only used for logging, not for task scheduling
// #[derive(Clone)]
#[derive(Serialize, Deserialize)]
pub struct IndexedProof<P> {
    pub inner: Arc<P>,
    /// First chunk covered by this proof (inclusive)
    pub start_chunk: usize,
    /// Last chunk covered by this proof (inclusive)
    pub end_chunk: usize,
}

impl<P> Clone for IndexedProof<P> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            start_chunk: self.start_chunk,
            end_chunk: self.end_chunk,
        }
    }
}

impl<P> IndexedProof<P> {
    /// Creates a new `IndexedProof` from a proof and chunk range.
    pub fn new(proof: P, start_chunk: usize, end_chunk: usize) -> Self {
        Self {
            inner: Arc::new(proof),
            start_chunk,
            end_chunk,
        }
    }

    /// Returns a clone of the inner Arc-wrapped proof.
    pub fn get_inner(&self) -> Arc<P> {
        Arc::clone(&self.inner)
    }

    /// Create from an existing Arc
    pub fn from_arc(proof: Arc<P>, start_chunk: usize, end_chunk: usize) -> Self {
        Self {
            inner: proof,
            start_chunk,
            end_chunk,
        }
    }
}

// node in proof tree
#[allow(dead_code)]
enum ProofNode<P> {
    // proving in process, it includes the sub-proofs which could also be used to retry if any error
    // occurred during proving
    InProgress(Vec<IndexedProof<P>>),
    // proof has been generated in this node, wait for the next process
    Proved(IndexedProof<P>),
}

impl<P> fmt::Display for ProofNode<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InProgress(proofs) => {
                if proofs.len() == 2 {
                    write!(
                        f,
                        "in-progress (combining [{}, {}] and [{}, {}])",
                        proofs[0].start_chunk,
                        proofs[0].end_chunk,
                        proofs[1].start_chunk,
                        proofs[1].end_chunk
                    )
                } else {
                    write!(f, "in-progress ({} parts)", proofs.len())
                }
            }
            Self::Proved(proof) => {
                write!(f, "proved [{}, {}]", proof.start_chunk, proof.end_chunk)
            }
        }
    }
}

#[allow(dead_code)]
impl<P> ProofNode<P> {
    fn init() -> Self {
        // init and wait for generating the convert proof
        Self::InProgress(vec![])
    }

    fn is_in_progress(&self) -> bool {
        matches!(self, Self::InProgress(_))
    }

    fn is_proved(&self) -> bool {
        matches!(self, Self::Proved(_))
    }

    fn proof(&self) -> Option<IndexedProof<P>> {
        match self {
            // no generated proof if in-progress
            Self::InProgress { .. } => None,
            Self::Proved(proof) => Some(proof.clone()),
        }
    }
}

pub struct ProofTree<P, EmbedP> {
    tree: BTreeMap<ProofIndex, ProofNode<P>>,
    embed: Option<ProofNode<EmbedP>>,
}

impl<P, EmbedP> fmt::Display for ProofTree<P, EmbedP> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "=== Start of ProofTree ===")?;

        self.tree
            .iter()
            .try_for_each(|(i, n)| writeln!(f, "\t{i}: {n}"))?;

        self.embed
            .iter()
            .try_for_each(|p| writeln!(f, "\tembed: {p}"))?;

        writeln!(f, "=== End of ProofTree ===")
    }
}

impl<P, EmbedP> Default for ProofTree<P, EmbedP> {
    fn default() -> Self {
        Self {
            tree: BTreeMap::new(),
            embed: None,
        }
    }
}

impl<P, EmbedP> ProofTree<P, EmbedP> {
    pub fn is_empty(&self) -> bool {
        self.tree.is_empty() && self.embed.is_none()
    }

    pub fn len(&self) -> usize {
        self.tree.len() + if self.embed.is_some() { 1 } else { 0 }
    }

    /// Get the chunk range of the single proof when proof tree has exactly 1 node
    /// Returns None if tree has multiple nodes
    /// Note: Returns range regardless of whether node is Proved or InProgress
    pub fn get_single_proof_range(&self) -> Option<(usize, usize)> {
        if self.tree.len() != 1 {
            return None;
        }

        match self.tree.values().next() {
            Some(ProofNode::Proved(proof)) => Some((proof.start_chunk, proof.end_chunk)),
            Some(ProofNode::InProgress(proofs)) if proofs.len() == 2 => {
                // InProgress with 2 proofs being combined - return combined range
                Some((proofs[0].start_chunk, proofs[1].end_chunk))
            }
            _ => None,
        }
    }

    /// Get the chunk range only when the tree has exactly one proved node.
    /// Returns None for InProgress or multi-node states.
    pub fn get_single_proved_range(&self) -> Option<(usize, usize)> {
        if self.tree.len() != 1 {
            return None;
        }

        match self.tree.values().next() {
            Some(ProofNode::Proved(proof)) => Some((proof.start_chunk, proof.end_chunk)),
            _ => None,
        }
    }

    pub fn complete(&self, done_until_combine: bool) -> bool {
        if !done_until_combine {
            // wait for embed when this flag is false
            matches!(self.embed, Some(ProofNode::Proved(..)))
        } else if self.tree.len() == 1 {
            // combine is done when the proof tree collapses to 1 proof
            matches!(self.tree.iter().next(), Some((_, ProofNode::Proved(..))))
        } else {
            false
        }
    }

    pub fn final_proof(&self) -> Option<Arc<EmbedP>> {
        if let Some(ProofNode::Proved(p)) = &self.embed {
            Some(p.get_inner())
        } else {
            None
        }
    }

    pub fn final_combine_proof(&self) -> Option<Arc<P>> {
        assert_eq!(
            self.tree.len(),
            1,
            "proof tree has not collapsed to a single node"
        );

        match self.tree.values().next() {
            Some(ProofNode::Proved(ip)) => Some(Arc::clone(&ip.inner)),
            _ => None,
        }
    }

    pub fn get_proof(&self, index: ProofIndex) -> Option<IndexedProof<P>> {
        self.tree.get(&index).and_then(|node| node.proof())
    }

    pub fn init_node(&mut self, index: ProofIndex) {
        let node = ProofNode::init();

        let old = self.tree.insert(index, node);
        assert!(old.is_none(), "proof node must be initialized once in tree");

        // log for debugging proof tree
        tracing::info!("after init_node:\n{self}");
    }

    pub fn set_embed_proof(&mut self, proof: IndexedProof<EmbedP>) {
        self.embed = Some(ProofNode::Proved(proof));
    }

    // return two adjacent nodes for combine proving if any
    pub fn set_proof(
        &mut self,
        index: ProofIndex,
        proof: IndexedProof<P>,
    ) -> Option<Vec<IndexedProof<P>>> {
        let current_proof = proof.clone();

        // 1. Try to combine with Previous (Left)
        // We capture the candidate in a separate scope to avoid keeping the immutable borrow on self.tree active
        let left_candidate = if let Some((prev_index, ProofNode::Proved(prev_proof))) =
            self.tree.range(..index).next_back()
        {
            if prev_proof.end_chunk + 1 == proof.start_chunk {
                Some((*prev_index, prev_proof.clone()))
            } else {
                None
            }
        } else {
            None
        };

        if let Some((left_index, left_proof)) = left_candidate {
            // Found valid Left neighbor
            let proofs = vec![left_proof.clone(), current_proof.clone()];

            // Update Left node to InProgress
            self.tree
                .insert(left_index, ProofNode::InProgress(proofs.clone()));

            // Remove current index if it exists
            if self.tree.contains_key(&index) {
                self.tree.remove(&index);
            }

            tracing::info!(
                "set_proof: combined [{}, {}] with left neighbor [{}, {}] -> stored at {}",
                proof.start_chunk,
                proof.end_chunk,
                left_proof.start_chunk,
                left_proof.end_chunk,
                left_index
            );
            tracing::info!("after set_proof:\n{self}");

            return Some(proofs);
        }

        // 2. Try to combine with Next (Right)
        let right_candidate = if let Some((next_index, ProofNode::Proved(next_proof))) = self
            .tree
            .range((Bound::Excluded(index), Bound::Unbounded))
            .next()
        {
            if proof.end_chunk + 1 == next_proof.start_chunk {
                Some((*next_index, next_proof.clone()))
            } else {
                None
            }
        } else {
            None
        };

        if let Some((next_index, next_proof)) = right_candidate {
            // Found valid Right neighbor
            let proofs = vec![current_proof.clone(), next_proof.clone()];

            // Update Current index to InProgress
            self.tree
                .insert(index, ProofNode::InProgress(proofs.clone()));

            // Remove Right node
            self.tree.remove(&next_index);

            tracing::info!(
                "set_proof: combined [{}, {}] with right neighbor [{}, {}] -> stored at {}",
                proof.start_chunk,
                proof.end_chunk,
                next_proof.start_chunk,
                next_proof.end_chunk,
                index
            );
            tracing::info!("after set_proof:\n{self}");

            return Some(proofs);
        }

        // 3. No combine possible. Just store the Proved node at index.
        if !self.tree.contains_key(&index) {
            tracing::debug!(
                "set_proof on absent index {}, auto-init for external proof",
                index
            );
            self.init_node(index);
        }

        self.tree.insert(index, ProofNode::Proved(current_proof));

        tracing::info!("after set_proof:\n{self}");

        None
    }
}

// #[cfg(test)]
// mod tests {
//     use super::*;
//
//     #[test]
//     fn test_gateway_proof_tree() {
//         let mut tree = ProofTree::<String>::new();
//
//         // it's uncomplete if tree is empty
//         assert!(!tree.complete());
//
//         // init 3 pending nodes first for convert
//         // [(0, in-progress), (1, in-progress), (2, in-progress)]
//         (0..=2).for_each(|i| tree.init_node(i));
//         assert_eq!(tree.tree.len(), 3);
//         (0..=2).for_each(|i| {
//             assert!(tree.tree[&i].is_in_progress());
//         });
//
//         // return convert proof of index-1, no combine task
//         // [(0, in-progress), (1, proved), (2, in-progress)]
//         let no_proofs_to_combine = tree.set_proof(1, "proof-1".to_string());
//         assert!(no_proofs_to_combine.is_none());
//         assert!(tree.tree[&0].is_in_progress());
//         assert!(tree.tree[&1].is_proved());
//         assert!(tree.tree[&2].is_in_progress());
//
//         // return convert proof of index-2, should generate a combine task for proof-1 and proof-2
//         // [(0, in-progress), (2, combine-in-progress)]
//         let proofs_to_combine = tree.set_proof(2, "proof-2".to_string());
//         assert_eq!(
//             proofs_to_combine,
//             Some(
//                 ["proof-1", "proof-2"]
//                     .iter()
//                     .map(|p| Arc::new(p.to_string()))
//                     .collect()
//             ),
//         );
//         // index-1 should be removed
//         assert_eq!(tree.tree.len(), 2);
//         assert!(!tree.tree.contains_key(&1));
//         assert!(tree.tree[&0].is_in_progress());
//         assert!(tree.tree[&2].is_in_progress());
//
//         // init another 2 pending nodes for convert
//         // [(0, in-progress), (2, combine-in-progress), (3, in-progress), (4, in-progress)]
//         (3..=4).for_each(|i| tree.init_node(i));
//         assert_eq!(tree.tree.len(), 4);
//         (3..=4).for_each(|i| {
//             assert!(tree.tree[&i].is_in_progress());
//         });
//
//         // return convert proof of index-4, no combine task
//         // [(0, in-progress), (2, combine-in-progress), (3, in-progress), (4, proved)]
//         let no_proofs_to_combine = tree.set_proof(4, "proof-4".to_string());
//         assert!(no_proofs_to_combine.is_none());
//
//         // return combine proof of index-1 and index-2, should no combine task
//         // [(0, in-progress), (2, proved), (3, in-progress), (4, proved)]
//         let no_proofs_to_combine = tree.set_proof(2, "proof-1-2".to_string());
//         assert!(no_proofs_to_combine.is_none());
//         assert!(tree.tree[&0].is_in_progress());
//         assert!(tree.tree[&2].is_proved());
//         assert!(tree.tree[&3].is_in_progress());
//         assert!(tree.tree[&4].is_proved());
//
//         // return convert proof of index-3, should generate a combine task for proof-1-2 and
//         // proof-3
//         // [(0, in-progress), (3, combine-in-progress), (4, proved)]
//         let proofs_to_combine = tree.set_proof(3, "proof-3".to_string());
//         assert_eq!(
//             proofs_to_combine,
//             Some(
//                 ["proof-1-2", "proof-3"]
//                     .iter()
//                     .map(|p| Arc::new(p.to_string()))
//                     .collect()
//             ),
//         );
//         assert_eq!(tree.tree.len(), 3);
//
//         // return convert proof of index-0, should no combine task
//         // [(0, proved), (3, combine-in-progress), (4, proved)]
//         let no_proofs_to_combine = tree.set_proof(0, "proof-0".to_string());
//         assert!(no_proofs_to_combine.is_none());
//
//         // return combine proof of index-3, should generate a combine task for proof-0 and
//         // proof-1-2-3
//         // [(3, combine-in-progress), (4, proved)]
//         let proofs_to_combine = tree.set_proof(3, "proof-1-2-3".to_string());
//         assert_eq!(
//             proofs_to_combine,
//             Some(
//                 ["proof-0", "proof-1-2-3"]
//                     .iter()
//                     .map(|p| Arc::new(p.to_string()))
//                     .collect()
//             ),
//         );
//         assert_eq!(tree.tree.len(), 2);
//
//         // return combine proof of index-3, should generate the final combine task for
//         // proof-0-1-2-3 and proof-4
//         // [(3, combine-in-progress)]
//         let proofs_to_combine = tree.set_proof(3, "proof-0-1-2-3".to_string());
//         assert_eq!(
//             proofs_to_combine,
//             Some(
//                 ["proof-0-1-2-3", "proof-4"]
//                     .iter()
//                     .map(|p| Arc::new(p.to_string()))
//                     .collect()
//             ),
//         );
//         assert_eq!(tree.tree.len(), 1);
//         assert!(!tree.complete());
//
//         // return the final combine proof
//         // [(3, proved)]
//         let no_proofs_to_combine = tree.set_proof(3, "proof-0-1-2-3-4".to_string());
//         assert!(no_proofs_to_combine.is_none());
//         assert!(tree.tree[&3].is_proved());
//         assert!(tree.complete());
//     }
// }
