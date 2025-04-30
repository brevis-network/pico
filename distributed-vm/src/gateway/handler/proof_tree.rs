use std::{collections::BTreeMap, fmt, ops::Bound, sync::Arc};

// chunk index of this proof
type ProofIndex = usize;

// proof value saved in a node
// template parameter P is a proof type (as MetaProof<SC>), it's easy for testing
// proof could be returned for combine between threads (transfer from gateway thread to grpc)
type Proof<P> = Arc<P>;

// node in proof tree
#[allow(dead_code)]
enum ProofNode<P> {
    // proving in process, it includes the sub-proofs which could also be used to retry if any error
    // occurred during proving
    InProgress(Vec<Proof<P>>),
    // proof has been generated in this node, wait for the next process
    Proved(Proof<P>),
}

impl<P> fmt::Display for ProofNode<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let status = match self {
            Self::InProgress(_) => "in-progress",
            Self::Proved(_) => "proved",
        };

        write!(f, "{status}")
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

    fn proof(&self) -> Option<Proof<P>> {
        match self {
            // no generated proof if in-progress
            Self::InProgress { .. } => None,
            Self::Proved(proof) => Some(proof.clone()),
        }
    }
}

pub struct ProofTree<P> {
    tree: BTreeMap<ProofIndex, ProofNode<P>>,
}

impl<P> fmt::Display for ProofTree<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "=== Start of ProofTree ===")?;

        self.tree
            .iter()
            .try_for_each(|(i, n)| writeln!(f, "\t{i}: {n}"))?;

        writeln!(f, "=== End of ProofTree ===")
    }
}

impl<P> ProofTree<P> {
    pub fn new() -> Self {
        Self {
            tree: BTreeMap::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.tree.len()
    }

    pub fn complete(&self) -> bool {
        // TODO: fix to check if embed proof is generated
        if self.tree.len() == 1 {
            if let Some((_, ProofNode::Proved(..))) = self.tree.iter().next() {
                return true;
            }
        }

        false
    }

    pub fn init_node(&mut self, index: ProofIndex) {
        let node = ProofNode::init();

        let old = self.tree.insert(index, node);
        assert!(old.is_none(), "proof node must be initialized once in tree");

        // log for debuggin proof tree
        // tracing::info!("after init_node:\n{self}");
    }

    // return two adjacent nodes for combine proving if any
    pub fn set_proof(&mut self, index: ProofIndex, proof: P) -> Option<Vec<Arc<P>>> {
        let current_proof = Arc::new(proof);

        // try to get the previous node if proved
        let mut index_proofs = None;
        if let Some((prev_index, ProofNode::Proved(prev_proof))) =
            self.tree.range(..index).next_back()
        {
            index_proofs = Some((*prev_index, vec![prev_proof.clone(), current_proof.clone()]));
        }
        // try to get the next node if proved
        if index_proofs.is_none() {
            if let Some((next_index, ProofNode::Proved(next_proof))) = self
                .tree
                .range((Bound::Excluded(index), Bound::Unbounded))
                .next()
            {
                index_proofs = Some((*next_index, vec![current_proof.clone(), next_proof.clone()]));
            }
        }

        // save the proved node or in-progress combine node
        let (node_to_set, proofs_to_combine) = match index_proofs {
            Some((sibling_index, proofs_to_combine)) => {
                // delete the silbing node
                self.tree.remove(&sibling_index);

                // save the in-progress combine node to index
                let node = ProofNode::InProgress(proofs_to_combine.clone());

                (node, Some(proofs_to_combine))
            }
            None => {
                // save the proved node to index
                let node = ProofNode::Proved(current_proof);

                (node, None)
            }
        };
        *self.tree.get_mut(&index).unwrap() = node_to_set;

        // log for debuggin proof tree
        // tracing::info!("after set_proof:\n{self}");

        proofs_to_combine
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gateway_proof_tree() {
        let mut tree = ProofTree::<String>::new();

        // it's uncomplete if tree is empty
        assert!(!tree.complete());

        // init 3 pending nodes first for convert
        // [(0, in-progress), (1, in-progress), (2, in-progress)]
        (0..=2).for_each(|i| tree.init_node(i));
        assert_eq!(tree.tree.len(), 3);
        (0..=2).for_each(|i| {
            assert!(tree.tree[&i].is_in_progress());
        });

        // return convert proof of index-1, no combine task
        // [(0, in-progress), (1, proved), (2, in-progress)]
        let no_proofs_to_combine = tree.set_proof(1, "proof-1".to_string());
        assert!(no_proofs_to_combine.is_none());
        assert!(tree.tree[&0].is_in_progress());
        assert!(tree.tree[&1].is_proved());
        assert!(tree.tree[&2].is_in_progress());

        // return convert proof of index-2, should generate a combine task for proof-1 and proof-2
        // [(0, in-progress), (2, combine-in-progress)]
        let proofs_to_combine = tree.set_proof(2, "proof-2".to_string());
        assert_eq!(
            proofs_to_combine,
            Some(
                ["proof-1", "proof-2"]
                    .iter()
                    .map(|p| Arc::new(p.to_string()))
                    .collect()
            ),
        );
        // index-1 should be removed
        assert_eq!(tree.tree.len(), 2);
        assert!(!tree.tree.contains_key(&1));
        assert!(tree.tree[&0].is_in_progress());
        assert!(tree.tree[&2].is_in_progress());

        // init another 2 pending nodes for convert
        // [(0, in-progress), (2, combine-in-progress), (3, in-progress), (4, in-progress)]
        (3..=4).for_each(|i| tree.init_node(i));
        assert_eq!(tree.tree.len(), 4);
        (3..=4).for_each(|i| {
            assert!(tree.tree[&i].is_in_progress());
        });

        // return convert proof of index-4, no combine task
        // [(0, in-progress), (2, combine-in-progress), (3, in-progress), (4, proved)]
        let no_proofs_to_combine = tree.set_proof(4, "proof-4".to_string());
        assert!(no_proofs_to_combine.is_none());

        // return combine proof of index-1 and index-2, should no combine task
        // [(0, in-progress), (2, proved), (3, in-progress), (4, proved)]
        let no_proofs_to_combine = tree.set_proof(2, "proof-1-2".to_string());
        assert!(no_proofs_to_combine.is_none());
        assert!(tree.tree[&0].is_in_progress());
        assert!(tree.tree[&2].is_proved());
        assert!(tree.tree[&3].is_in_progress());
        assert!(tree.tree[&4].is_proved());

        // return convert proof of index-3, should generate a combine task for proof-1-2 and
        // proof-3
        // [(0, in-progress), (3, combine-in-progress), (4, proved)]
        let proofs_to_combine = tree.set_proof(3, "proof-3".to_string());
        assert_eq!(
            proofs_to_combine,
            Some(
                ["proof-1-2", "proof-3"]
                    .iter()
                    .map(|p| Arc::new(p.to_string()))
                    .collect()
            ),
        );
        assert_eq!(tree.tree.len(), 3);

        // return convert proof of index-0, should no combine task
        // [(0, proved), (3, combine-in-progress), (4, proved)]
        let no_proofs_to_combine = tree.set_proof(0, "proof-0".to_string());
        assert!(no_proofs_to_combine.is_none());

        // return combine proof of index-3, should generate a combine task for proof-0 and
        // proof-1-2-3
        // [(3, combine-in-progress), (4, proved)]
        let proofs_to_combine = tree.set_proof(3, "proof-1-2-3".to_string());
        assert_eq!(
            proofs_to_combine,
            Some(
                ["proof-0", "proof-1-2-3"]
                    .iter()
                    .map(|p| Arc::new(p.to_string()))
                    .collect()
            ),
        );
        assert_eq!(tree.tree.len(), 2);

        // return combine proof of index-3, should generate the final combine task for
        // proof-0-1-2-3 and proof-4
        // [(3, combine-in-progress)]
        let proofs_to_combine = tree.set_proof(3, "proof-0-1-2-3".to_string());
        assert_eq!(
            proofs_to_combine,
            Some(
                ["proof-0-1-2-3", "proof-4"]
                    .iter()
                    .map(|p| Arc::new(p.to_string()))
                    .collect()
            ),
        );
        assert_eq!(tree.tree.len(), 1);
        assert!(!tree.complete());

        // return the final combine proof
        // [(3, proved)]
        let no_proofs_to_combine = tree.set_proof(3, "proof-0-1-2-3-4".to_string());
        assert!(no_proofs_to_combine.is_none());
        assert!(tree.tree[&3].is_proved());
        assert!(tree.complete());
    }
}
