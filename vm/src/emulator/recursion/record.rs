use std::{array, sync::Arc};

use crate::{
    chips::chips::recursion_memory::MemEvent,
    compiler::recursion::{
        program::RecursionProgram,
        types::{
            AssertZeroExtEvent, BaseAluEvent, BatchFRIEvent, BinaryFoldStepEvent,
            CommitPublicValuesEvent, DigestSelectEvent, ExpBitsLenEvent, ExpReverseBitsEvent,
            ExtAluEvent, ExtDotProductEvent, FracFoldEvent, GkrSumcheckRoundEvent, HornerEvalEvent,
            LagrangeEvalD2Event, MleOpenEvent, PackBlockEvent, Poseidon2Event, SelectEvent,
            UnivariateFoldEvent, UnpackBlockEvent,
        },
    },
    emulator::{record::RecordBehavior, recursion::public_values::RecursionPublicValues},
    primitives::consts::MAX_NUM_PVS,
};
use hashbrown::HashMap;
use p3_field::{Field, PrimeCharacteristicRing, PrimeField32};

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
    pub exp_bits_len_events: Vec<ExpBitsLenEvent<F>>,
    pub batch_fri_events: Vec<BatchFRIEvent<F>>,
    pub commit_pv_hash_events: Vec<CommitPublicValuesEvent<F>>,

    // WHIR verifier chip events.
    pub assert_zero_ext_events: Vec<AssertZeroExtEvent<F>>,
    pub frac_fold_events: Vec<FracFoldEvent<F>>,
    pub univariate_fold_events: Vec<UnivariateFoldEvent<F>>,
    pub mle_open_events: Vec<MleOpenEvent<F>>,
    pub lagrange_eval_d2_events: Vec<LagrangeEvalD2Event<F>>,
    pub gkr_sumcheck_round_events: Vec<GkrSumcheckRoundEvent<F>>,
    pub ext_dot_product_events: Vec<ExtDotProductEvent<F>>,
    pub horner_eval_events: Vec<HornerEvalEvent<F>>,
    pub digest_select_events: Vec<DigestSelectEvent<F>>,
    pub binary_fold_step_events: Vec<BinaryFoldStepEvent<F>>,
    pub pack_block_events: Vec<PackBlockEvent<F>>,
    pub unpack_block_events: Vec<UnpackBlockEvent<F>>,
    pub poseidon2_packed_events: Vec<Poseidon2Event<F>>,
}

impl<F: serde::Serialize> RecursionRecord<F> {
    /// A 64-bit FNV-1a digest of everything one emulation produced.
    ///
    /// A digest, not a comparison: two records that agree here are equal with overwhelming
    /// probability, not certainly. That is the right trade for a gate run thousands of times
    /// against a ~10 MB record, but it is not proof, and "identical digest" is the strongest
    /// claim it supports.
    ///
    /// The acceptance gate for changing *how* the recursion program is interpreted: split it
    /// across two threads, batch its permutations, rewrite its memory table — the record must
    /// come out identical, because the record is the only thing that leaves `Runtime::run()` and
    /// everything downstream is derived from it. Cheaper and far sharper than proving a block:
    /// `Runtime::run()` is a pure function of `(program, witness_stream)`, so two interpretations
    /// that agree here agree everywhere, and one that does not has a bug this names immediately.
    ///
    /// Exhaustively destructured for the same reason [`RecordBehavior::append`] is: a new event
    /// vector must not be able to slip out of the check by being forgotten.
    ///
    /// `program` and `index` are excluded — they are inputs, not results.
    pub fn digest(&self) -> u64 {
        let Self {
            program: _,
            index: _,
            base_alu_events,
            ext_alu_events,
            mem_const_count,
            mem_var_events,
            public_values,
            poseidon2_events,
            select_events,
            exp_reverse_bits_len_events,
            exp_bits_len_events,
            batch_fri_events,
            commit_pv_hash_events,
            assert_zero_ext_events,
            frac_fold_events,
            univariate_fold_events,
            mle_open_events,
            lagrange_eval_d2_events,
            gkr_sumcheck_round_events,
            ext_dot_product_events,
            horner_eval_events,
            digest_select_events,
            binary_fold_step_events,
            pack_block_events,
            unpack_block_events,
            poseidon2_packed_events,
        } = self;

        // FNV-1a over each field's encoding, the same shape as `fnv1a_witness_stream` in the
        // witness driver. One reused buffer: `poseidon2_packed_events` alone is ~8 MB on a
        // combine node.
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        let mut buf: Vec<u8> = Vec::new();
        macro_rules! feed {
            ($($field:expr),+ $(,)?) => {
                $({
                    buf.clear();
                    bincode::serialize_into(&mut buf, $field).expect("record digest");
                    for b in buf.iter() {
                        h = (h ^ u64::from(*b)).wrapping_mul(0x0000_0100_0000_01b3);
                    }
                })+
            };
        }
        feed!(
            base_alu_events,
            ext_alu_events,
            mem_const_count,
            mem_var_events,
            public_values,
            poseidon2_events,
            select_events,
            exp_reverse_bits_len_events,
            exp_bits_len_events,
            batch_fri_events,
            commit_pv_hash_events,
            assert_zero_ext_events,
            frac_fold_events,
            univariate_fold_events,
            mle_open_events,
            lagrange_eval_d2_events,
            gkr_sumcheck_round_events,
            ext_dot_product_events,
            horner_eval_events,
            digest_select_events,
            binary_fold_step_events,
            pack_block_events,
            unpack_block_events,
            poseidon2_packed_events,
        );
        h
    }
}

impl<F: PrimeField32> RecordBehavior for RecursionRecord<F> {
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
        stats.insert(
            "exp_bits_len_events".to_string(),
            self.exp_bits_len_events.len(),
        );
        stats.insert("batch_fri_events".to_string(), self.batch_fri_events.len());
        stats.insert(
            "commit_pv_hash_events".to_string(),
            self.commit_pv_hash_events.len(),
        );
        stats.insert(
            "assert_zero_ext_events".to_string(),
            self.assert_zero_ext_events.len(),
        );
        stats.insert("frac_fold_events".to_string(), self.frac_fold_events.len());
        stats.insert(
            "univariate_fold_events".to_string(),
            self.univariate_fold_events.len(),
        );
        stats.insert("mle_open_events".to_string(), self.mle_open_events.len());
        stats.insert(
            "lagrange_eval_d2_events".to_string(),
            self.lagrange_eval_d2_events.len(),
        );
        stats.insert(
            "gkr_sumcheck_round_events".to_string(),
            self.gkr_sumcheck_round_events.len(),
        );
        stats.insert(
            "ext_dot_product_events".to_string(),
            self.ext_dot_product_events.len(),
        );
        stats.insert(
            "horner_eval_events".to_string(),
            self.horner_eval_events.len(),
        );
        stats.insert(
            "digest_select_events".to_string(),
            self.digest_select_events.len(),
        );
        stats.insert(
            "binary_fold_step_events".to_string(),
            self.binary_fold_step_events.len(),
        );
        stats.insert(
            "pack_block_events".to_string(),
            self.pack_block_events.len(),
        );
        stats.insert(
            "unpack_block_events".to_string(),
            self.unpack_block_events.len(),
        );
        stats.insert(
            "poseidon2_packed_events".to_string(),
            self.poseidon2_packed_events.len(),
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
            exp_bits_len_events,
            batch_fri_events,
            commit_pv_hash_events,
            assert_zero_ext_events,
            frac_fold_events,
            univariate_fold_events,
            mle_open_events,
            lagrange_eval_d2_events,
            gkr_sumcheck_round_events,
            ext_dot_product_events,
            horner_eval_events,
            digest_select_events,
            binary_fold_step_events,
            pack_block_events,
            unpack_block_events,
            poseidon2_packed_events,
        } = self;
        base_alu_events.append(&mut other.base_alu_events);
        ext_alu_events.append(&mut other.ext_alu_events);
        *mem_const_count += other.mem_const_count;
        mem_var_events.append(&mut other.mem_var_events);
        poseidon2_events.append(&mut other.poseidon2_events);
        select_events.append(&mut other.select_events);
        exp_reverse_bits_len_events.append(&mut other.exp_reverse_bits_len_events);
        exp_bits_len_events.append(&mut other.exp_bits_len_events);
        batch_fri_events.append(&mut other.batch_fri_events);
        commit_pv_hash_events.append(&mut other.commit_pv_hash_events);
        assert_zero_ext_events.append(&mut other.assert_zero_ext_events);
        frac_fold_events.append(&mut other.frac_fold_events);
        univariate_fold_events.append(&mut other.univariate_fold_events);
        mle_open_events.append(&mut other.mle_open_events);
        lagrange_eval_d2_events.append(&mut other.lagrange_eval_d2_events);
        gkr_sumcheck_round_events.append(&mut other.gkr_sumcheck_round_events);
        ext_dot_product_events.append(&mut other.ext_dot_product_events);
        horner_eval_events.append(&mut other.horner_eval_events);
        digest_select_events.append(&mut other.digest_select_events);
        binary_fold_step_events.append(&mut other.binary_fold_step_events);
        pack_block_events.append(&mut other.pack_block_events);
        unpack_block_events.append(&mut other.unpack_block_events);
        poseidon2_packed_events.append(&mut other.poseidon2_packed_events);
    }

    fn public_values<T: PrimeCharacteristicRing>(&self) -> Vec<T> {
        let pv_elms = self.public_values.as_array();

        let ret: [T; MAX_NUM_PVS] = array::from_fn(|i| {
            if i < pv_elms.len() {
                T::from_u32(pv_elms[i].as_canonical_u32())
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
    /// True when folding this record in at a different position could not change the result:
    /// every event vector empty, and no public values for [`RecordBehavior::append`] to drop.
    ///
    /// `mem_const_count` is summed and `program`/`index` are inputs, so none of the three cares
    /// where the record lands.
    ///
    /// Exhaustively destructured, like [`Self::digest`] and [`RecordBehavior::append`]: the guard
    /// this backs is only worth having if a newly added event vector cannot slip past it.
    pub fn is_position_independent(&self) -> bool {
        let Self {
            program: _,
            index: _,
            mem_const_count: _,
            base_alu_events,
            ext_alu_events,
            mem_var_events,
            public_values,
            poseidon2_events,
            select_events,
            exp_reverse_bits_len_events,
            exp_bits_len_events,
            batch_fri_events,
            commit_pv_hash_events,
            assert_zero_ext_events,
            frac_fold_events,
            univariate_fold_events,
            mle_open_events,
            lagrange_eval_d2_events,
            gkr_sumcheck_round_events,
            ext_dot_product_events,
            horner_eval_events,
            digest_select_events,
            binary_fold_step_events,
            pack_block_events,
            unpack_block_events,
            poseidon2_packed_events,
        } = self;

        base_alu_events.is_empty()
            && ext_alu_events.is_empty()
            && mem_var_events.is_empty()
            && poseidon2_events.is_empty()
            && select_events.is_empty()
            && exp_reverse_bits_len_events.is_empty()
            && exp_bits_len_events.is_empty()
            && batch_fri_events.is_empty()
            && commit_pv_hash_events.is_empty()
            && assert_zero_ext_events.is_empty()
            && frac_fold_events.is_empty()
            && univariate_fold_events.is_empty()
            && mle_open_events.is_empty()
            && lagrange_eval_d2_events.is_empty()
            && gkr_sumcheck_round_events.is_empty()
            && ext_dot_product_events.is_empty()
            && horner_eval_events.is_empty()
            && digest_select_events.is_empty()
            && binary_fold_step_events.is_empty()
            && pack_block_events.is_empty()
            && unpack_block_events.is_empty()
            && poseidon2_packed_events.is_empty()
            && public_values.as_array().iter().all(|v| *v == F::ZERO)
    }

    #[inline]
    pub fn fixed_log2_rows(&self, chip_name: &String) -> Option<usize> {
        self.program.fixed_log2_rows(chip_name)
    }
}
