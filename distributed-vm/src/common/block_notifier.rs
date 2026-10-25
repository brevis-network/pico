//! Block transition notification system
//!
//! Allows task.rs to notify scheduler.rs about block transitions in an event-driven manner.
//! This eliminates the need for polling RUN_ID in the scheduler loop.

use crossbeam::channel::{unbounded, Receiver, Sender};
use once_cell::sync::Lazy;
use tracing::info;

/// Global channel for block transition notifications
/// Sender is cloned by notifiers, receiver is used by scheduler.rs select! loop
static BLOCK_NOTIFIER: Lazy<(Sender<u64>, Receiver<u64>)> = Lazy::new(unbounded);

/// Get sender to notify about block transitions
pub fn get_block_notifier_tx() -> Sender<u64> {
    BLOCK_NOTIFIER.0.clone()
}

/// Get receiver for block transition notifications
/// Should be called once by scheduler.rs before entering main loop
pub fn get_block_notifier_rx() -> Receiver<u64> {
    BLOCK_NOTIFIER.1.clone()
}

/// Notify about block transition
/// Called by task.rs after setting RUN_ID environment variable
pub fn notify_block_transition(block: u64) {
    if let Err(e) = get_block_notifier_tx().send(block) {
        tracing::warn!(
            "Failed to send block transition notification for block {}: {}",
            block,
            e
        );
    } else {
        info!("Block transition notification sent: block {}", block);
    }
}
