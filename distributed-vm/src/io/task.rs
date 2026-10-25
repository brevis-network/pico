use crate::common::{program::ProgramInput, BlockNum};
use crossbeam::channel::Sender;

use std::{
    collections::BTreeSet,
    sync::{Arc, OnceLock},
};
use tracing::error;

#[derive(Clone, Debug)]
pub enum SchedTask {
    Begin {
        block: BlockNum,
        run_id: String,
        expected: usize, // deferred_len for this block
        expected_indices: BTreeSet<u32>,
        program_input: ProgramInput,
    },
    Done {
        block: BlockNum,
    },
}

pub(crate) static SCHED_TX: OnceLock<Arc<Sender<SchedTask>>> = OnceLock::new();

#[inline]
pub fn task_begin_round(
    block: BlockNum,
    run_id: String,
    expected: usize,
    expected_indices: BTreeSet<u32>,
    program_input: ProgramInput,
) {
    if let Some(tx) = SCHED_TX.get() {
        let _ = tx.send(SchedTask::Begin {
            block,
            run_id,
            expected,
            expected_indices,
            program_input,
        });
    } else {
        error!("BlockScheduler not initialized (no SCHED_TX)");
    }
}

#[inline]
pub fn task_notify_done(block: BlockNum) {
    if let Some(tx) = SCHED_TX.get() {
        let _ = tx.send(SchedTask::Done { block });
    }
}
