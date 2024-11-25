use crate::{
    chips::chips::{
        exp_reverse_bits::ExpReverseBitsLenEvent,
        fri_fold::FriFoldEvent,
        poseidon2_wide::events::{Poseidon2CompressEvent, Poseidon2HashEvent},
        rangecheck::event::{RangeLookupEvent, RangeRecordBehavior},
        recursion_cpu::CpuEvent,
    },
    compiler::recursion::program::RecursionProgram,
    emulator::record::RecordBehavior,
    primitives::consts::MAX_NUM_PVS,
    recursion::air::Block,
};
use hashbrown::HashMap;
use p3_field::{AbstractField, PrimeField32};
use std::{array, sync::Arc};

#[derive(Default, Debug, Clone)]
pub struct RecursionRecord<F: Default> {
    pub program: Arc<RecursionProgram<F>>,
    pub cpu_events: Vec<CpuEvent<F>>,
    pub poseidon2_compress_events: Vec<Poseidon2CompressEvent<F>>,
    pub poseidon2_hash_events: Vec<Poseidon2HashEvent<F>>,
    pub fri_fold_events: Vec<FriFoldEvent<F>>,
    pub range_check_events: HashMap<RangeLookupEvent, usize>,
    pub exp_reverse_bits_len_events: Vec<ExpReverseBitsLenEvent<F>>,
    // (address, value)
    pub first_memory_record: Vec<(F, Block<F>)>,

    // (address, last_timestamp, last_value)
    pub last_memory_record: Vec<(F, F, Block<F>)>,

    /// The public values.
    pub public_values: Vec<F>,

    /// The index of the chunk.
    pub index: u32,
}

impl<F: Default> RecursionRecord<F> {
    pub fn add_range_check_events(&mut self, events: &[RangeLookupEvent]) {
        for event in events {
            *self.range_check_events.entry(*event).or_insert(0) += 1;
        }
    }
}

impl<F: PrimeField32> RecordBehavior for RecursionRecord<F> {
    fn stats(&self) -> HashMap<String, usize> {
        let mut stats = HashMap::new();
        stats.insert("cpu_events".to_string(), self.cpu_events.len());
        stats.insert(
            "poseidon2_compress_events".to_string(),
            self.poseidon2_compress_events.len(),
        );
        stats.insert(
            "poseidon2_hash_events".to_string(),
            self.poseidon2_hash_events.len(),
        );
        stats.insert("fri_fold_events".to_string(), self.fri_fold_events.len());
        stats.insert(
            "range_check_events".to_string(),
            self.range_check_events.len(),
        );
        stats.insert(
            "exp_reverse_bits_len_events".to_string(),
            self.exp_reverse_bits_len_events.len(),
        );
        stats
    }

    // NOTE: This should be unused.
    fn append(&mut self, other: &mut Self) {
        self.cpu_events.append(&mut other.cpu_events);
        self.first_memory_record
            .append(&mut other.first_memory_record);
        self.last_memory_record
            .append(&mut other.last_memory_record);

        // Merge the range check lookups.
        for (range_check_event, count) in std::mem::take(&mut other.range_check_events).into_iter()
        {
            *self
                .range_check_events
                .entry(range_check_event)
                .or_insert(0) += count;
        }
    }

    fn public_values<T: AbstractField>(&self) -> Vec<T> {
        let ret: [T; MAX_NUM_PVS] = array::from_fn(|i| {
            if i < self.public_values.len() {
                T::from_canonical_u32(self.public_values[i].as_canonical_u32())
            } else {
                T::zero()
            }
        });

        ret.to_vec()
    }

    fn name(&self) -> String {
        "RecursionRecord".to_string()
    }

    fn chunk_index(&self) -> usize {
        self.index as usize
    }
}

impl<F: Default> RangeRecordBehavior for RecursionRecord<F> {
    fn add_range_lookup_event(&mut self, event: RangeLookupEvent) {
        *self.range_check_events.entry(event).or_insert(0) += 1;
    }

    fn range_lookup_events(
        &self,
        _chunk: Option<u32>,
    ) -> Box<dyn Iterator<Item = (RangeLookupEvent, usize)> + '_> {
        Box::new(self.range_check_events.iter().map(|(k, v)| (*k, *v)))
    }
}
