//! Local Record Storage for chunk emulation records
//!
//! Both Primary and Secondary store emulation records locally.
//! Schedulers call acquire_task() to get chunk index, then load from here.
//!
//! A background cleanup thread receives proven_chunks updates and removes
//! records for chunks that have already been consumed and proven.

use parking_lot::Mutex;
use pico_vm::emulator::riscv::record::EmulationRecord;
use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, OnceLock},
};
use tracing::info;

/// Thread-safe local store for chunk emulation records
pub struct RecordStore {
    records: Mutex<HashMap<usize, EmulationRecord>>,
    /// Tracks emulation completion status per run_id
    /// Used by both Primary and Secondary to signal local emulation is done
    emulation_done: Mutex<HashMap<String, bool>>,
}

impl RecordStore {
    pub fn new() -> Self {
        Self {
            records: Mutex::new(HashMap::new()),
            emulation_done: Mutex::new(HashMap::new()),
        }
    }

    /// Insert a record for a chunk
    pub fn insert(&self, chunk_idx: usize, record: EmulationRecord) {
        info!("RecordStore: inserting chunk {}", chunk_idx);
        self.records.lock().insert(chunk_idx, record);
    }

    /// Get a record for a chunk (clones it)
    pub fn get(&self, chunk_idx: usize) -> Option<EmulationRecord> {
        self.records.lock().get(&chunk_idx).cloned()
    }

    /// Remove and return a record for a chunk
    pub fn remove(&self, chunk_idx: usize) -> Option<EmulationRecord> {
        let result = self.records.lock().remove(&chunk_idx);
        if result.is_some() {
            info!("RecordStore: removing chunk {}", chunk_idx);
        }
        result
    }

    /// Remove records for all chunk indices in the given proven set.
    /// Called by the background cleanup thread whenever proven_chunks is updated.
    pub fn cleanup_proven(&self, proven: &HashSet<usize>) {
        let mut records = self.records.lock();
        let before = records.len();
        records.retain(|k, _| !proven.contains(k));
        let cleaned = before - records.len();
        if cleaned > 0 {
            info!(
                "RecordStore: cleaned {} proven records ({} remaining)",
                cleaned,
                records.len()
            );
        }
    }

    /// Check if a chunk exists
    pub fn contains(&self, chunk_idx: usize) -> bool {
        self.records.lock().contains_key(&chunk_idx)
    }

    /// Get the number of stored records
    pub fn len(&self) -> usize {
        self.records.lock().len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.records.lock().is_empty()
    }

    /// Clear all records and emulation status for a specific run_id
    pub fn clear(&self, run_id: &str) {
        info!("RecordStore: clearing all records for run_id={}", run_id);
        self.records.lock().clear();
        self.emulation_done.lock().remove(run_id);
    }

    /// Mark emulation as done for a specific run_id
    pub fn set_emulation_done(&self, run_id: &str) {
        info!("RecordStore: marking emulation done for run_id={}", run_id);
        self.emulation_done.lock().insert(run_id.to_string(), true);
    }

    /// Check if emulation is done for a specific run_id
    pub fn is_emulation_done(&self, run_id: &str) -> bool {
        self.emulation_done
            .lock()
            .get(run_id)
            .copied()
            .unwrap_or(false)
    }
}

impl Default for RecordStore {
    fn default() -> Self {
        Self::new()
    }
}

// === Global singleton ===

static RECORD_STORE: OnceLock<Arc<RecordStore>> = OnceLock::new();

/// Get the global record store singleton.
/// Also spawns the background cleanup thread on first call.
pub fn get_record_store() -> Arc<RecordStore> {
    RECORD_STORE
        .get_or_init(|| {
            info!("RecordStore: initializing global singleton");
            spawn_cleanup_thread();
            Arc::new(RecordStore::new())
        })
        .clone()
}

// === Background cleanup thread ===

use std::sync::mpsc;

static CLEANUP_TX: OnceLock<Mutex<mpsc::Sender<CleanupMsg>>> = OnceLock::new();

enum CleanupMsg {
    /// New set of proven chunk indices to merge into the local set
    ProvenChunks(Vec<usize>),
    /// Reset the proven set (called on block transition / clear)
    Reset,
}

/// Send proven_chunks to the background cleanup thread.
/// Called by scheduler_singleton after each acquire_task.
pub fn send_proven_chunks(chunks: Vec<usize>) {
    if let Some(tx) = CLEANUP_TX.get() {
        let _ = tx.lock().send(CleanupMsg::ProvenChunks(chunks));
    }
}

/// Reset the cleanup thread's proven set (called on block transition).
pub fn reset_cleanup_state() {
    if let Some(tx) = CLEANUP_TX.get() {
        let _ = tx.lock().send(CleanupMsg::Reset);
    }
}

/// Spawn the background cleanup thread.
/// Should be called once during initialization.
/// The thread merges incoming proven_chunks into a local HashSet and
/// runs cleanup on every update.
pub fn spawn_cleanup_thread() {
    let (tx, rx) = mpsc::channel::<CleanupMsg>();
    CLEANUP_TX.get_or_init(|| Mutex::new(tx));

    std::thread::Builder::new()
        .name("record-cleanup".into())
        .spawn(move || {
            let mut proven_set = HashSet::<usize>::new();
            info!("RecordStore cleanup thread started");

            while let Ok(msg) = rx.recv() {
                match msg {
                    CleanupMsg::ProvenChunks(chunks) => {
                        // Merge new proven chunks into local set
                        let new_count = chunks.iter().filter(|c| !proven_set.contains(c)).count();
                        proven_set.extend(chunks);

                        // Only run cleanup if we actually got new proven chunks
                        if new_count > 0 {
                            get_record_store().cleanup_proven(&proven_set);
                        }
                    }
                    CleanupMsg::Reset => {
                        info!("RecordStore cleanup thread: resetting proven set");
                        proven_set.clear();
                    }
                }
            }

            info!("RecordStore cleanup thread exiting");
        })
        .expect("Failed to spawn record cleanup thread");
}
