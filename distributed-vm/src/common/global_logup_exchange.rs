//! What a block's two machines exchange for the global LogUp, as the primary holds it between
//! its scheduler service and its pipeline.
//!
//! A chunk's convert leaf enters the hash chain over the Global table commitments of the chunks
//! before it, and a machine traces only the chunks it proves. So the secondary reports the
//! commitment of each chunk it traces, with the chunk's share of the block's real-row count,
//! and follows the commitments the primary holds, its own among them. Each machine proves the
//! group proofs over the tables it holds and their nodes; the secondary hands its nodes in, and
//! the primary reduces them with its own into the tree's prefix.
//!
//! The scheduler service is generic over the scheduler's payload, so nothing here knows a proof
//! system's types: a commitment and a node are bytes, which the pipeline encodes and decodes.
//!
//! Every message names the block its sender is on. A process may prove several blocks one after
//! another, and a message that outlives its block must not reach the next one.

use once_cell::sync::Lazy;
use std::{
    sync::{Condvar, Mutex, MutexGuard},
    time::Duration,
};

/// A chunk's Global table commitment as the secondary reported it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkTableReport {
    pub chunk_idx: usize,
    pub commit: Vec<u8>,
    /// The chunk's share of the block's real-row count.
    pub row_count: u64,
}

/// The node over a group of the secondary's chunks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupNodeReport {
    /// The group's first chunk, and how many chunks it covers.
    pub first_chunk: usize,
    pub chunks: usize,
    pub proof: Vec<u8>,
}

/// What the primary holds of the chain past the chunk a follower asked from.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChainNews {
    /// The commitments of the chunks from the one asked for on, in chunk order without a gap.
    pub commits: Vec<Vec<u8>>,
    /// The block's chunk count, once the primary's emulation is finalized.
    pub chunks: Option<usize>,
}

/// A message for a block the primary is not on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OtherBlock {
    pub asked: u64,
    pub current: u64,
}

impl std::fmt::Display for OtherBlock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "the message is for block {}, the primary is on block {}",
            self.asked, self.current
        )
    }
}

#[derive(Default)]
struct State {
    block: u64,
    /// The primary's chain: the commitments of the block's leading chunks, its own and the
    /// secondary's.
    commits: Vec<Vec<u8>>,
    chunks: Option<usize>,
    /// From the secondary, until the pipeline takes them.
    tables: Vec<ChunkTableReport>,
    nodes: Vec<GroupNodeReport>,
}

pub struct Exchange {
    state: Mutex<State>,
    /// Wakes the pipeline's waits for the secondary's reports and nodes.
    arrived: Condvar,
    /// Wakes the service's long polls: stepped whenever the chain grows or the block changes.
    published: tokio::sync::watch::Sender<u64>,
}

static EXCHANGE: Lazy<Exchange> = Lazy::new(Exchange::new);

/// The process's exchange: the one the scheduler service fills and the pipeline reads.
pub fn exchange() -> &'static Exchange {
    &EXCHANGE
}

impl Default for Exchange {
    fn default() -> Self {
        Self::new()
    }
}

impl Exchange {
    pub fn new() -> Self {
        Self {
            state: Mutex::new(State::default()),
            arrived: Condvar::new(),
            published: tokio::sync::watch::channel(0).0,
        }
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn wake_polls(&self) {
        self.published
            .send_modify(|step| *step = step.wrapping_add(1));
    }

    // === The primary's pipeline ===

    /// The primary starts `block`: whatever the previous block left is dropped.
    pub fn open(&self, block: u64) {
        *self.state() = State {
            block,
            ..State::default()
        };
        self.wake_polls();
    }

    /// The primary's chain grew by the next chunk's commitment.
    pub fn publish_commit(&self, commit: Vec<u8>) {
        self.state().commits.push(commit);
        self.wake_polls();
    }

    /// The primary's emulation is finalized at `chunks` chunks.
    pub fn publish_chunks(&self, chunks: usize) {
        self.state().chunks = Some(chunks);
        self.wake_polls();
    }

    /// The secondary's reports since the last call, waiting up to `wait` for the first.
    pub fn take_tables(&self, wait: Duration) -> Vec<ChunkTableReport> {
        let (mut state, _) = self
            .arrived
            .wait_timeout_while(self.state(), wait, |state| state.tables.is_empty())
            .unwrap_or_else(|e| e.into_inner());
        std::mem::take(&mut state.tables)
    }

    /// The secondary's nodes since the last call, waiting up to `wait` for the first.
    pub fn take_nodes(&self, wait: Duration) -> Vec<GroupNodeReport> {
        let (mut state, _) = self
            .arrived
            .wait_timeout_while(self.state(), wait, |state| state.nodes.is_empty())
            .unwrap_or_else(|e| e.into_inner());
        std::mem::take(&mut state.nodes)
    }

    // === The scheduler service, for the secondary ===

    fn on_block(&self, block: u64) -> Result<MutexGuard<'_, State>, OtherBlock> {
        let state = self.state();
        if state.block != block {
            return Err(OtherBlock {
                asked: block,
                current: state.block,
            });
        }
        Ok(state)
    }

    /// The secondary traced a chunk of `block`.
    pub fn report_table(&self, block: u64, report: ChunkTableReport) -> Result<(), OtherBlock> {
        self.on_block(block)?.tables.push(report);
        self.arrived.notify_all();
        Ok(())
    }

    /// The secondary proved the node over a group of its chunks of `block`.
    pub fn report_node(&self, block: u64, node: GroupNodeReport) -> Result<(), OtherBlock> {
        self.on_block(block)?.nodes.push(node);
        self.arrived.notify_all();
        Ok(())
    }

    /// The commitments the primary holds of `block` from chunk `from` on, waiting up to `wait`
    /// for the first, unless the block is known to end before `from`. A block the primary has
    /// not reached yet is waited for; one it has left is refused.
    pub async fn await_commits(
        &self,
        block: u64,
        from: usize,
        wait: Duration,
    ) -> Result<ChainNews, OtherBlock> {
        // Subscribed before the look at the state: a step taken in between ends the wait below
        // at once.
        let mut published = self.published.subscribe();
        let deadline = tokio::time::Instant::now() + wait;
        loop {
            let chunks = {
                let state = self.state();
                if block < state.block {
                    return Err(OtherBlock {
                        asked: block,
                        current: state.block,
                    });
                }
                let on_block = block == state.block;
                let commits = match state.commits.get(from..) {
                    Some(commits) if on_block => commits.to_vec(),
                    _ => Vec::new(),
                };
                let chunks = state.chunks.filter(|_| on_block);
                if !commits.is_empty() || chunks.is_some_and(|chunks| from >= chunks) {
                    return Ok(ChainNews { commits, chunks });
                }
                chunks
            };
            if tokio::time::timeout_at(deadline, published.changed())
                .await
                .is_err()
            {
                return Ok(ChainNews {
                    commits: Vec::new(),
                    chunks,
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    const SOON: Duration = Duration::from_millis(20);
    const LONG: Duration = Duration::from_secs(60);

    fn table(chunk_idx: usize) -> ChunkTableReport {
        ChunkTableReport {
            chunk_idx,
            commit: vec![chunk_idx as u8; 4],
            row_count: 1024 * (chunk_idx as u64 + 1),
        }
    }

    fn node(first_chunk: usize) -> GroupNodeReport {
        GroupNodeReport {
            first_chunk,
            chunks: 4,
            proof: vec![first_chunk as u8; 8],
        }
    }

    fn poll(
        exchange: &Exchange,
        block: u64,
        from: usize,
        wait: Duration,
    ) -> Result<ChainNews, OtherBlock> {
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("a test runtime")
            .block_on(exchange.await_commits(block, from, wait))
    }

    #[test]
    fn reports_and_nodes_reach_the_pipeline_once() {
        let exchange = Exchange::new();
        exchange.open(1);
        assert_eq!(exchange.report_table(1, table(5)), Ok(()));
        assert_eq!(exchange.report_table(1, table(4)), Ok(()));
        assert_eq!(exchange.report_node(1, node(4)), Ok(()));
        assert_eq!(exchange.take_tables(SOON), vec![table(5), table(4)]);
        assert_eq!(exchange.take_tables(SOON), vec![]);
        assert_eq!(exchange.take_nodes(SOON), vec![node(4)]);
        assert_eq!(exchange.take_nodes(SOON), vec![]);
    }

    #[test]
    fn a_message_for_another_block_is_refused() {
        let exchange = Exchange::new();
        exchange.open(2);
        let other = |asked| OtherBlock { asked, current: 2 };
        assert_eq!(exchange.report_table(1, table(0)), Err(other(1)));
        assert_eq!(exchange.report_table(3, table(0)), Err(other(3)));
        assert_eq!(exchange.report_node(1, node(0)), Err(other(1)));
        assert_eq!(poll(&exchange, 1, 0, LONG), Err(other(1)));
        assert_eq!(exchange.take_tables(SOON), vec![]);
        assert_eq!(exchange.take_nodes(SOON), vec![]);
    }

    #[test]
    fn a_new_block_starts_from_nothing() {
        let exchange = Exchange::new();
        exchange.open(1);
        exchange.publish_commit(vec![1]);
        exchange.publish_chunks(1);
        exchange.report_table(1, table(0)).unwrap();
        exchange.report_node(1, node(0)).unwrap();
        exchange.open(2);
        assert_eq!(exchange.take_tables(SOON), vec![]);
        assert_eq!(exchange.take_nodes(SOON), vec![]);
        assert_eq!(poll(&exchange, 2, 0, SOON), Ok(ChainNews::default()));
    }

    #[test]
    fn a_follower_gets_the_commitments_from_its_chunk_on() {
        let exchange = Exchange::new();
        exchange.open(1);
        for commit in 0..3u8 {
            exchange.publish_commit(vec![commit]);
        }
        assert_eq!(
            poll(&exchange, 1, 1, LONG),
            Ok(ChainNews {
                commits: vec![vec![1], vec![2]],
                chunks: None,
            })
        );
        // Nothing past the chain's end yet: the wait runs out, with the count if it is known.
        assert_eq!(poll(&exchange, 1, 3, SOON), Ok(ChainNews::default()));
        exchange.publish_chunks(5);
        assert_eq!(
            poll(&exchange, 1, 3, SOON),
            Ok(ChainNews {
                commits: vec![],
                chunks: Some(5),
            })
        );
    }

    #[test]
    fn a_follower_past_the_blocks_end_is_answered_at_once() {
        let exchange = Exchange::new();
        exchange.open(1);
        exchange.publish_commit(vec![0]);
        exchange.publish_chunks(1);
        assert_eq!(
            poll(&exchange, 1, 1, LONG),
            Ok(ChainNews {
                commits: vec![],
                chunks: Some(1),
            })
        );
    }

    #[test]
    fn a_waiting_follower_is_woken_by_the_next_commitment() {
        let exchange = Arc::new(Exchange::new());
        exchange.open(1);
        let follower = {
            let exchange = Arc::clone(&exchange);
            std::thread::spawn(move || poll(&exchange, 1, 0, LONG))
        };
        std::thread::sleep(SOON);
        exchange.publish_commit(vec![7]);
        assert_eq!(
            follower.join().expect("the follower's poll"),
            Ok(ChainNews {
                commits: vec![vec![7]],
                chunks: None,
            })
        );
    }

    #[test]
    fn a_follower_ahead_of_the_primary_waits_for_its_block() {
        let exchange = Arc::new(Exchange::new());
        exchange.open(1);
        exchange.publish_commit(vec![1]);
        // The primary is still on block 1: block 2 has nothing yet, block 1's chain is not it.
        assert_eq!(poll(&exchange, 2, 0, SOON), Ok(ChainNews::default()));
        let follower = {
            let exchange = Arc::clone(&exchange);
            std::thread::spawn(move || poll(&exchange, 2, 0, LONG))
        };
        std::thread::sleep(SOON);
        exchange.open(2);
        exchange.publish_commit(vec![2]);
        assert_eq!(
            follower.join().expect("the follower's poll"),
            Ok(ChainNews {
                commits: vec![vec![2]],
                chunks: None,
            })
        );
    }

    #[test]
    fn a_waiting_pipeline_is_woken_by_a_report() {
        let exchange = Arc::new(Exchange::new());
        exchange.open(1);
        let pipeline = {
            let exchange = Arc::clone(&exchange);
            std::thread::spawn(move || exchange.take_tables(LONG))
        };
        std::thread::sleep(SOON);
        exchange.report_table(1, table(3)).unwrap();
        assert_eq!(
            pipeline.join().expect("the pipeline's wait"),
            vec![table(3)]
        );
    }
}
