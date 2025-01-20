use std::{array, sync::Arc};

use crate::{
    chips::chips::recursion_memory_v2::MemEvent,
    compiler::recursion_v2::{
        program::RecursionProgram,
        types::{
            BaseAluEvent, BatchFRIEvent, CommitPublicValuesEvent, ExpReverseBitsEvent, ExtAluEvent,
            Poseidon2Event, SelectEvent,
        },
    },
    emulator::{record::RecordBehavior, recursion::public_values::RecursionPublicValues},
    primitives::consts::MAX_NUM_PVS,
};
use hashbrown::HashMap;
use p3_field::{Field, FieldAlgebra, PrimeField32};

#[derive(Clone, Default, Debug)]
pub struct RecursionRecord<F> {
    pub program: Arc<RecursionProgram<F>>,
    /// The index of the chunk.
    pub index: u32,

    pub base_alu_events: Vec<BaseAluEvent<F>>,
    pub ext_alu_events: Vec<ExtAluEvent<F>>,
    pub mem_const_count: usize,
    pub mem_var_events: Vec<MemEvent<F>>,
    /// The public values.
    pub public_values: RecursionPublicValues<F>,

    pub select_events: Vec<SelectEvent<F>>,
    pub poseidon2_events: Vec<Poseidon2Event<F>>,
    pub exp_reverse_bits_len_events: Vec<ExpReverseBitsEvent<F>>,
    pub batch_fri_events: Vec<BatchFRIEvent<F>>,
    pub commit_pv_hash_events: Vec<CommitPublicValuesEvent<F>>,
}

impl<F: PrimeField32> RecordBehavior for RecursionRecord<F> {
    // TODO
    //type Config = EmulatorOpts;

    fn name(&self) -> String {
        "RecursionRecord".to_string()
    }

    fn stats(&self) -> hashbrown::HashMap<String, usize> {
        let mut stats = HashMap::new();
        stats.insert("base_alu_events".to_string(), self.base_alu_events.len());
        stats.insert("ext_alu_events".to_string(), self.ext_alu_events.len());
        stats.insert("mem_var_events".to_string(), self.mem_var_events.len());

        stats.insert("select_events".to_string(), self.select_events.len());
        stats.insert("poseidon2_events".to_string(), self.poseidon2_events.len());
        stats.insert(
            "exp_reverse_bits_events".to_string(),
            self.exp_reverse_bits_len_events.len(),
        );
        stats.insert("batch_fri_events".to_string(), self.batch_fri_events.len());
        stats.insert(
            "commit_pv_hash_events".to_string(),
            self.commit_pv_hash_events.len(),
        );

        stats
    }

    fn append(&mut self, other: &mut Self) {
        // Exhaustive destructuring for refactoring purposes.
        let Self {
            program: _,
            index: _,
            base_alu_events,
            ext_alu_events,
            mem_const_count,
            mem_var_events,
            public_values: _,
            poseidon2_events,
            select_events,
            exp_reverse_bits_len_events,
            batch_fri_events,
            commit_pv_hash_events,
        } = self;
        base_alu_events.append(&mut other.base_alu_events);
        ext_alu_events.append(&mut other.ext_alu_events);
        *mem_const_count += other.mem_const_count;
        mem_var_events.append(&mut other.mem_var_events);
        poseidon2_events.append(&mut other.poseidon2_events);
        select_events.append(&mut other.select_events);
        exp_reverse_bits_len_events.append(&mut other.exp_reverse_bits_len_events);
        batch_fri_events.append(&mut other.batch_fri_events);
        commit_pv_hash_events.append(&mut other.commit_pv_hash_events);
    }

    fn public_values<T: FieldAlgebra>(&self) -> Vec<T> {
        let pv_elms = self.public_values.as_array();

        let ret: [T; MAX_NUM_PVS] = array::from_fn(|i| {
            if i < pv_elms.len() {
                T::from_canonical_u32(pv_elms[i].as_canonical_u32())
            } else {
                T::ZERO
            }
        });

        ret.to_vec()
    }

    fn chunk_index(&self) -> usize {
        self.index as usize
    }
}

impl<F: Field> RecursionRecord<F> {
    #[inline]
    pub fn fixed_log2_rows(&self, chip_name: &String) -> Option<usize> {
        self.program.fixed_log2_rows(chip_name)
    }
}
