//! Batch to chunk index mapping for two-machine distributed proof
//!
//! Records the mapping from batch_idx (CPU chunk index) to actual chunk_index range
//! during emulation. Used by GatewayHandler to detect task unit completion.
use crate::common::machine_role::{get_cpu_chunks_per_task_unit, get_machine_role};
use once_cell::sync::Lazy;
use parking_lot::RwLock;
use std::{collections::HashMap, fmt::Write};
use tracing::info;

/// Global batch to chunk mapping, populated during emulation
static BATCH_CHUNK_MAP: Lazy<RwLock<BatchChunkMapping>> =
    Lazy::new(|| RwLock::new(BatchChunkMapping::new()));

/// Mapping from batch_idx to chunk_index range
#[derive(Debug, Default)]
pub struct BatchChunkMapping {
    cpu_chunks_per_unit: usize,
    /// Map: batch_idx -> (min_chunk_index, max_chunk_index)
    batch_to_chunks: HashMap<usize, (usize, usize)>,
    /// Map: task_unit_index -> TaskUnitRange
    task_unit_ranges: HashMap<usize, TaskUnitRange>,
    /// Sub_final_proofs received from Secondary: task_unit -> (start_chunk, end_chunk)
    /// Used by Primary to determine if all Secondary proofs have been received
    received_secondary_proofs: HashMap<usize, (usize, usize)>,
    /// True when emulation is complete (after finalize_all_pending is called)
    emulation_done: bool,
    /// Cached min chunk index across all registered chunks (updated incrementally)
    cached_min_chunk: usize,
    /// Cached max chunk index across all registered chunks (updated incrementally)
    cached_max_chunk: usize,
}

#[derive(Debug, Clone, Default)]
pub struct TaskUnitRange {
    pub start_batch: usize,
    pub end_batch: usize,
    pub min_chunk: usize,
    pub max_chunk: usize,
    /// True when all chunks for this task unit have been registered during emulation
    pub emulation_finalized: bool,
    /// True when sub_final_proof has been sent to Primary (Secondary only)
    pub proof_sent: bool,
}

impl BatchChunkMapping {
    pub fn new() -> Self {
        Self {
            cpu_chunks_per_unit: get_cpu_chunks_per_task_unit(),
            batch_to_chunks: HashMap::new(),
            task_unit_ranges: HashMap::new(),
            received_secondary_proofs: HashMap::new(),
            emulation_done: false,
            cached_min_chunk: usize::MAX,
            cached_max_chunk: 0,
        }
    }

    /// Register a chunk for a given batch_idx during emulation
    pub fn register_chunk(&mut self, batch_idx: usize, chunk_index: usize) {
        let current_task_unit = batch_idx / self.cpu_chunks_per_unit;

        // Update cached min/max (O(1) instead of O(n) on get)
        self.cached_min_chunk = self.cached_min_chunk.min(chunk_index);
        self.cached_max_chunk = self.cached_max_chunk.max(chunk_index);

        // Update batch_to_chunks mapping
        let entry = self
            .batch_to_chunks
            .entry(batch_idx)
            .or_insert((chunk_index, chunk_index));
        entry.0 = entry.0.min(chunk_index);
        entry.1 = entry.1.max(chunk_index);

        // Update task unit range
        let task_entry = self
            .task_unit_ranges
            .entry(current_task_unit)
            .or_insert(TaskUnitRange {
                start_batch: batch_idx,
                end_batch: batch_idx,
                min_chunk: chunk_index,
                max_chunk: chunk_index,
                emulation_finalized: false,
                proof_sent: false,
            });
        task_entry.start_batch = task_entry.start_batch.min(batch_idx);
        task_entry.end_batch = task_entry.end_batch.max(batch_idx);
        task_entry.min_chunk = task_entry.min_chunk.min(chunk_index);
        task_entry.max_chunk = task_entry.max_chunk.max(chunk_index);
    }

    /// Internal finalize - marks task unit as having all chunks registered
    fn finalize_task_unit_internal(&mut self, task_unit: usize) {
        if let Some(entry) = self.task_unit_ranges.get_mut(&task_unit) {
            if !entry.emulation_finalized {
                entry.emulation_finalized = true;
                info!(
                    "Finalized task_unit {}: batches [{}, {}], chunks [{}, {}]",
                    task_unit, entry.start_batch, entry.end_batch, entry.min_chunk, entry.max_chunk
                );
            }
        }
    }

    /// Dump the entire state of BatchChunkMapping for debugging
    pub fn debug_dump_state(&self) {
        let mut output = String::new();
        writeln!(&mut output, "=== BatchChunkMapping State Dump ===").unwrap();
        writeln!(
            &mut output,
            "cpu_chunks_per_unit: {}",
            self.cpu_chunks_per_unit
        )
        .unwrap();

        // Sort and print batch_to_chunks
        let mut batches: Vec<_> = self.batch_to_chunks.iter().collect();
        batches.sort_by_key(|(k, _)| *k);
        writeln!(&mut output, "batch_to_chunks ({} entries):", batches.len()).unwrap();
        for (batch_idx, (min_chunk, max_chunk)) in batches {
            writeln!(
                &mut output,
                "  batch {}: chunks [{}, {}]",
                batch_idx, min_chunk, max_chunk
            )
            .unwrap();
        }

        // Sort and print task_unit_ranges
        let mut task_units: Vec<_> = self.task_unit_ranges.iter().collect();
        task_units.sort_by_key(|(k, _)| *k);
        writeln!(
            &mut output,
            "task_unit_ranges ({} entries):",
            task_units.len()
        )
        .unwrap();
        for (tu, range) in task_units {
            writeln!(
                &mut output,
                "  TU {}: batches [{}, {}], chunks [{}, {}], finalized={}, proof_sent={}",
                tu,
                range.start_batch,
                range.end_batch,
                range.min_chunk,
                range.max_chunk,
                range.emulation_finalized,
                range.proof_sent
            )
            .unwrap();
        }

        // Print count of expected Secondary task units (derived from task_unit_ranges)
        let secondary_count = self
            .task_unit_ranges
            .keys()
            .filter(|tu| !get_machine_role().should_handle_task_unit(**tu))
            .count();
        writeln!(
            &mut output,
            "expected_task_units_from_other: {}",
            secondary_count
        )
        .unwrap();

        // Sort and print received_secondary_proofs
        let mut received: Vec<_> = self.received_secondary_proofs.iter().collect();
        received.sort_by_key(|(k, _)| *k);
        writeln!(
            &mut output,
            "received_secondary_proofs ({} entries):",
            received.len()
        )
        .unwrap();
        for (tu, (start, end)) in received {
            writeln!(&mut output, "  TU {}: chunks [{}, {}]", tu, start, end).unwrap();
        }
        writeln!(&mut output, "=== End of BatchChunkMapping State Dump ===").unwrap();

        info!("{}", output);
    }

    /// Finalize when a batch is complete (all its records processed)
    /// Automatically finalizes the task unit if this is its last batch
    pub fn finalize_batch(&mut self, batch_idx: usize) {
        let task_unit = batch_idx / self.cpu_chunks_per_unit;
        let next_batch_task_unit = (batch_idx + 1) / self.cpu_chunks_per_unit;

        // Finalize if this batch is the last one in its task unit
        if next_batch_task_unit > task_unit {
            self.finalize_task_unit_internal(task_unit);
        }
    }

    /// Force-finalize all task units that have not been finalized yet.
    /// Called after emulation completes to handle the last incomplete task unit.
    /// Also marks emulation as done.
    pub fn finalize_all_pending(&mut self) {
        let task_units_to_finalize: Vec<usize> = self
            .task_unit_ranges
            .iter()
            .filter(|(_, range)| !range.emulation_finalized)
            .map(|(tu, _)| *tu)
            .collect();

        for task_unit in task_units_to_finalize {
            self.finalize_task_unit_internal(task_unit);
        }

        self.emulation_done = true;
        info!("Emulation done - all task units finalized");
    }

    /// Check if a combined proof (start_chunk, end_chunk) completes a task unit
    /// Only returns Some if emulation is finalized for that task unit
    pub fn check_task_unit_complete(&self, start_chunk: usize, end_chunk: usize) -> Option<usize> {
        for (task_unit, range) in &self.task_unit_ranges {
            // Debug log checking
            if !range.emulation_finalized {
                // Ignore non-finalized units for now, but maybe worth logging if we expect it to be ready
                continue;
            }
            if range.proof_sent {
                continue;
            }

            // It matches if range matches exactly
            if start_chunk == range.min_chunk && end_chunk == range.max_chunk {
                return Some(*task_unit);
            } else {
                // Log mismatch for potential candidates (e.g. if chunks overlap or are close)
                // This helps debug why a specific combined proof doesn't trigger completion
                info!(
                    "Check failed for TU {}: Proof [{}, {}] vs Map [{}, {}] (Batch [{}, {}])",
                    task_unit,
                    start_chunk,
                    end_chunk,
                    range.min_chunk,
                    range.max_chunk,
                    range.start_batch,
                    range.end_batch
                );
            }
        }
        None
    }

    /// Mark a task unit's proof as sent (Secondary only)
    pub fn mark_proof_sent(&mut self, task_unit: usize) {
        if let Some(entry) = self.task_unit_ranges.get_mut(&task_unit) {
            entry.proof_sent = true;
        }
    }

    /// Get count of task units that have been finalized
    pub fn finalized_task_unit_count(&self) -> usize {
        self.task_unit_ranges
            .values()
            .filter(|r| r.emulation_finalized)
            .count()
    }

    /// Get count of task units that have their proof sent
    pub fn proof_sent_count(&self) -> usize {
        self.task_unit_ranges
            .values()
            .filter(|r| r.proof_sent)
            .count()
    }

    /// Check if all task units belonging to current machine role have their proofs sent
    /// Since both Primary and Secondary maintain the full map, filter by role
    pub fn all_proofs_sent(&self) -> bool {
        let machine_role = get_machine_role();
        self.task_unit_ranges
            .iter()
            .filter(|(tu, _)| machine_role.should_handle_task_unit(**tu))
            .all(|(_, r)| r.proof_sent)
    }

    /// Get the full chunk range (min_chunk, max_chunk) for entire emulation
    /// Returns None if emulation is not done or no task units have been registered
    /// O(1) - uses cached values updated incrementally during register_chunk
    pub fn get_full_chunk_range(&self) -> Option<(usize, usize)> {
        // Emulation must be complete
        if !self.emulation_done {
            return None;
        }

        if self.task_unit_ranges.is_empty() {
            return None;
        }

        Some((self.cached_min_chunk, self.cached_max_chunk))
    }

    pub fn reset(&mut self) {
        self.batch_to_chunks.clear();
        self.task_unit_ranges.clear();
        self.received_secondary_proofs.clear();
        self.emulation_done = false;
        self.cached_min_chunk = usize::MAX;
        self.cached_max_chunk = 0;
    }

    /// Register a received proof from Secondary (Primary only)
    /// Returns true if this was a new registration
    pub fn register_secondary_proof_received(
        &mut self,
        task_unit: usize,
        start_chunk: usize,
        end_chunk: usize,
    ) -> bool {
        let is_new = !self.received_secondary_proofs.contains_key(&task_unit);
        self.received_secondary_proofs
            .insert(task_unit, (start_chunk, end_chunk));
        if is_new {
            // Derive expected count from task_unit_ranges
            let expected_count = self
                .task_unit_ranges
                .keys()
                .filter(|tu| !get_machine_role().should_handle_task_unit(**tu))
                .count();
            info!(
                "Registered Secondary proof for task_unit {}: chunks [{}, {}]. Received {}/{}",
                task_unit,
                start_chunk,
                end_chunk,
                self.received_secondary_proofs.len(),
                expected_count
            );
        }
        is_new
    }
}

// Global access functions

/// Register a chunk during emulation
/// Automatically finalizes previous task unit when crossing boundaries
pub fn register_batch_chunk(batch_idx: usize, chunk_index: usize) {
    BATCH_CHUNK_MAP
        .write()
        .register_chunk(batch_idx, chunk_index);
}

/// Dump the entire BatchChunkMapping state for debugging
pub fn dump_batch_chunk_mapping_state() {
    BATCH_CHUNK_MAP.read().debug_dump_state();
}

/// Finalize when a batch is complete (all its records processed)
/// Triggers task unit finalization if this is the last batch in the task unit
pub fn finalize_batch_chunk(batch_idx: usize) {
    BATCH_CHUNK_MAP.write().finalize_batch(batch_idx);
}

/// Force-finalize all pending task units (called after emulation completes)
pub fn finalize_all_pending_task_units() {
    BATCH_CHUNK_MAP.write().finalize_all_pending();
}

/// Check if combined proof completes a task unit
pub fn check_task_unit_complete(start_chunk: usize, end_chunk: usize) -> Option<usize> {
    BATCH_CHUNK_MAP
        .read()
        .check_task_unit_complete(start_chunk, end_chunk)
}

/// Mark task unit proof as sent
pub fn mark_task_unit_proof_sent(task_unit: usize) {
    BATCH_CHUNK_MAP.write().mark_proof_sent(task_unit);
}

/// Check if all proofs have been sent (for Secondary complete detection)
pub fn all_task_unit_proofs_sent() -> bool {
    BATCH_CHUNK_MAP.read().all_proofs_sent()
}

/// Get number of finalized task units
pub fn finalized_task_unit_count() -> usize {
    BATCH_CHUNK_MAP.read().finalized_task_unit_count()
}

/// Get number of proofs sent
pub fn proof_sent_count() -> usize {
    BATCH_CHUNK_MAP.read().proof_sent_count()
}

/// Reset the mapping (call between blocks)
pub fn reset_batch_chunk_mapping() {
    BATCH_CHUNK_MAP.write().reset();
}

/// Register a received proof from Secondary (Primary only)
pub fn register_secondary_proof_received(task_unit: usize, start_chunk: usize, end_chunk: usize) {
    BATCH_CHUNK_MAP
        .write()
        .register_secondary_proof_received(task_unit, start_chunk, end_chunk);
}

/// Get the full chunk range for all task units handled by current machine role
pub fn get_full_chunk_range() -> Option<(usize, usize)> {
    BATCH_CHUNK_MAP.read().get_full_chunk_range()
}
