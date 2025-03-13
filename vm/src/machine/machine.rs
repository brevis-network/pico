use super::{folder::DebugConstraintFolder, keys::HashableKey, lookup::LookupScope};
use crate::{
    configs::config::{StarkGenericConfig, Val},
    emulator::record::RecordBehavior,
    machine::{
        chip::{ChipBehavior, MetaChip},
        folder::{ProverConstraintFolder, VerifierConstraintFolder},
        keys::{BaseProvingKey, BaseVerifyingKey},
        proof::{BaseProof, MainTraceCommitments, MetaProof},
        prover::BaseProver,
        septic::SepticDigest,
        verifier::BaseVerifier,
        witness::ProvingWitness,
    },
};
use alloc::sync::Arc;
use anyhow::Result;
use hashbrown::HashMap;
use itertools::Itertools;
use p3_air::Air;
use p3_field::{Field, PrimeField64};
use p3_maybe_rayon::prelude::*;
use std::time::Instant;
use tracing::{debug, instrument};

/// Functions that each machine instance should implement.
pub trait MachineBehavior<SC, C, I>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<Val<SC>>,
{
    /// Get the name of the machine.
    fn name(&self) -> String;

    /// Get the basemachine
    fn base_machine(&self) -> &BaseMachine<SC, C>;

    /// Get the configuration of the machine.
    fn config(&self) -> Arc<SC> {
        self.base_machine().config()
    }

    /// Get number of public values
    fn num_public_values(&self) -> usize {
        self.base_machine().num_public_values()
    }

    /// Get the chips of the machine.
    fn chips(&self) -> Arc<[MetaChip<SC::Val, C>]> {
        self.base_machine().chips()
    }

    /// Complete the record after emulation.
    fn complement_record(&self, records: &mut [C::Record]) {
        let begin = Instant::now();
        let chips_arc = self.chips();
        let chips = chips_arc.as_ref();
        records.par_iter_mut().for_each(|record| {
            // todo optimize: parallel (the calling order of some chips needs to be satisfied)
            chips.iter().for_each(|chip| {
                if chip.is_active(record) {
                    let mut extra = C::Record::default();
                    chip.extra_record(record, &mut extra);
                    record.append(&mut extra);
                }
            });
        });
        debug!("complement record in {:?}", begin.elapsed());
    }

    /// setup prover, verifier and keys.
    fn setup_keys(&self, program: &C::Program) -> (BaseProvingKey<SC>, BaseVerifyingKey<SC>) {
        let (pk, vk) = self.base_machine().setup_keys(program);

        (pk, vk)
    }

    /// Get the prover of the machine.
    fn prove(&self, witness: &ProvingWitness<SC, C, I>) -> MetaProof<SC>
    where
        C: for<'a> Air<DebugConstraintFolder<'a, SC::Val, SC::Challenge>>
            + Air<ProverConstraintFolder<SC>>;

    /// Verify the proof.
    fn verify(&self, proof: &MetaProof<SC>, riscv_vk: &dyn HashableKey<SC::Val>) -> Result<()>
    where
        C: for<'a> Air<VerifierConstraintFolder<'a, SC>>;
}

/// A basic machine that includes elemental proving gadgets.
/// Mainly for testing purposes.
pub struct BaseMachine<SC, C>
where
    SC: StarkGenericConfig,
{
    /// Configuration of the machine
    config: Arc<SC>,

    /// Chips of the machine
    chips: Arc<[MetaChip<Val<SC>, C>]>,

    /// Base prover
    prover: BaseProver<SC, C>,

    /// Base verifier
    verifier: BaseVerifier<SC, C>,

    /// Number of public values
    num_public_values: usize,

    /// Contains global scopes.
    has_global: bool,
}

impl<SC, C> Clone for BaseMachine<SC, C>
where
    SC: StarkGenericConfig,
{
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            chips: self.chips.clone(),
            prover: self.prover.clone(),
            verifier: self.verifier.clone(),
            num_public_values: self.num_public_values,
            has_global: self.has_global,
        }
    }
}

impl<SC, C> BaseMachine<SC, C>
where
    SC: StarkGenericConfig,
{
    /// Name of BaseMachine.
    pub fn name(&self) -> String {
        "BaseMachine".to_string()
    }

    /// Get the configuration of the machine.
    pub fn config(&self) -> Arc<SC> {
        self.config.clone()
    }

    /// Get the number of public values.
    pub fn num_public_values(&self) -> usize {
        self.num_public_values
    }

    /// Check if have global chips.
    pub fn has_global(&self) -> bool {
        self.has_global
    }
}

impl<SC, C> BaseMachine<SC, C>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<Val<SC>>,
{
    /// Get the chips of the machine.
    pub fn chips(&self) -> Arc<[MetaChip<Val<SC>, C>]> {
        self.chips.clone()
    }

    /// Returns an iterator over the chips in the machine that are included in the given chunk.
    pub fn chunk_ordered_chips(
        &self,
        chip_ordering: &HashMap<String, usize>,
    ) -> impl Iterator<Item = &MetaChip<Val<SC>, C>> {
        self.chips
            .iter()
            .filter(|chip| chip_ordering.contains_key(&chip.name()))
            .sorted_by_key(|chip| chip_ordering.get(&chip.name()))
    }

    /// Create BaseMachine based on config and chip behavior.
    pub fn new(
        config: SC,
        chips: impl Into<Arc<[MetaChip<Val<SC>, C>]>>,
        num_public_values: usize,
    ) -> Self {
        let chips = chips.into();
        let has_global = chips
            .iter()
            .any(|chip| chip.lookup_scope() == LookupScope::Global);

        Self {
            config: config.into(),
            chips,
            prover: BaseProver::new(),
            verifier: BaseVerifier::new(),
            num_public_values,
            has_global,
        }
    }

    pub fn preprocessed_chip_ids(&self) -> Vec<usize> {
        self.chips()
            .iter()
            .enumerate()
            .filter(|(_, chip)| chip.preprocessed_width() > 0)
            .map(|(i, _)| i)
            .collect()
    }

    /// setup proving and verifying keys.
    #[instrument(name = "setup_keys", level = "debug", skip_all)]
    pub fn setup_keys(&self, program: &C::Program) -> (BaseProvingKey<SC>, BaseVerifyingKey<SC>) {
        let (pk, vk) = self
            .prover
            .setup_keys(&self.config(), &self.chips(), program);

        (pk, vk)
    }

    pub fn commit(&self, record: &C::Record) -> Option<MainTraceCommitments<SC>> {
        let chips_and_main_traces = self.prover.generate_main(&self.chips(), record);
        self.prover
            .commit_main(&self.config(), record, chips_and_main_traces)
    }

    /// prove a batch of records with a single pk
    pub fn prove_ensemble(
        &self,
        pk: &BaseProvingKey<SC>,
        records: &[C::Record],
    ) -> Vec<BaseProof<SC>>
    where
        C: for<'c> Air<DebugConstraintFolder<'c, SC::Val, SC::Challenge>>
            + Air<ProverConstraintFolder<SC>>,
        SC::Val: PrimeField64,
    {
        let mut challenger = self.config().challenger();
        pk.observed_by(&mut challenger);

        let proofs = records
            .iter()
            .enumerate()
            .map(|(i, record)| {
                let data = self.commit(record).unwrap();
                self.prover.prove(
                    &self.config(),
                    &self.chips(),
                    pk,
                    data,
                    &mut challenger.clone(),
                    records[i].chunk_index(),
                    self.num_public_values,
                )
            })
            .collect::<Vec<_>>();

        #[cfg(feature = "debug")]
        crate::machine::debug::debug_all_constraints(
            pk,
            &mut self.config().challenger(),
            &self.chips(),
            records,
            self.has_global,
        );
        #[cfg(feature = "debug-lookups")]
        crate::machine::debug::debug_all_lookups(pk, &self.chips(), records, None);

        proofs
    }

    /// Prove assuming that challenger has already observed pk & main commitments and pv's
    pub fn prove_plain(
        &self,
        pk: &BaseProvingKey<SC>,
        challenger: &mut SC::Challenger,
        chunk_index: usize,
        main_commitment: MainTraceCommitments<SC>,
    ) -> BaseProof<SC>
    where
        C: Air<ProverConstraintFolder<SC>>,
    {
        self.prover.prove(
            &self.config(),
            &self.chips(),
            pk,
            main_commitment,
            challenger,
            chunk_index,
            self.num_public_values,
        )
    }

    pub fn verify_riscv(&self, vk: &BaseVerifyingKey<SC>, proofs: &[BaseProof<SC>]) -> Result<()>
    where
        C: for<'a> Air<VerifierConstraintFolder<'a, SC>>,
    {
        assert!(!proofs.is_empty());

        let mut challenger = self.config().challenger();

        // observe all preprocessed and main commits and pv's
        vk.observed_by(&mut challenger);

        // verify all proofs
        for proof in proofs {
            self.verifier.verify(
                &self.config(),
                &self.chips(),
                vk,
                &mut challenger.clone(),
                proof,
                self.num_public_values,
            )?;

            if !proof.regional_cumulative_sum().is_zero() {
                panic!("verify_riscv: local lookup cumulative sum is not zero");
            }
        }

        let mut sum = proofs
            .iter()
            .map(|proof| proof.global_cumulative_sum())
            .sum();
        if self.has_global {
            sum = [sum, vk.initial_global_cumulative_sum]
                .into_iter()
                .sum::<SepticDigest<SC::Val>>();
        };
        if !sum.is_zero() {
            panic!("verify_riscv: global lookup cumulative sum is not zero");
        }

        Ok(())
    }

    /// Verify a batch of BaseProofs with a single vk
    pub fn verify_ensemble(&self, vk: &BaseVerifyingKey<SC>, proofs: &[BaseProof<SC>]) -> Result<()>
    where
        C: for<'a> Air<VerifierConstraintFolder<'a, SC>>,
    {
        assert!(!proofs.is_empty());

        let mut challenger = self.config().challenger();

        // observe all preprocessed and main commits and pv's
        vk.observed_by(&mut challenger);

        // verify all proofs
        for proof in proofs {
            self.verifier.verify(
                &self.config(),
                &self.chips(),
                vk,
                &mut challenger.clone(),
                proof,
                self.num_public_values,
            )?;

            if !proof.regional_cumulative_sum().is_zero() {
                panic!("verify_ensemble: local lookup cumulative sum is not zero");
            }
        }

        let mut sum = proofs
            .iter()
            .map(|proof| proof.global_cumulative_sum())
            .sum::<SepticDigest<SC::Val>>();
        if self.has_global {
            sum = [sum, vk.initial_global_cumulative_sum]
                .into_iter()
                .sum::<SepticDigest<SC::Val>>();
        };
        if !sum.is_zero() {
            panic!("verify_riscv: global lookup cumulative sum is not zero");
        }

        Ok(())
    }

    /// Verify assuming that challenger has already observed vk & main commitments and pv's
    pub fn verify_plain(
        &self,
        vk: &BaseVerifyingKey<SC>,
        challenger: &mut SC::Challenger,
        proof: &BaseProof<SC>,
    ) -> Result<()>
    where
        C: for<'a> Air<VerifierConstraintFolder<'a, SC>>,
    {
        self.verifier.verify(
            &self.config(),
            &self.chips(),
            vk,
            challenger,
            proof,
            self.num_public_values,
        )
    }
}
