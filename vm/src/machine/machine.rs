use super::folder::DebugConstraintFolder;
use crate::{
    configs::config::{StarkGenericConfig, Val},
    emulator::record::RecordBehavior,
    machine::{
        chip::{ChipBehavior, MetaChip},
        folder::{ProverConstraintFolder, VerifierConstraintFolder},
        keys::{BaseProvingKey, BaseVerifyingKey},
        proof::{BaseProof, MainTraceCommitments, MetaProof},
        prover::BaseProver,
        verifier::BaseVerifier,
        witness::ProvingWitness,
    },
};
use anyhow::Result;
use log::{debug, info};
use p3_air::Air;
use p3_challenger::CanObserve;
use p3_field::Field;
use std::time::Instant;

/// Functions that each machine instance should implement.
pub trait MachineBehavior<SC, C, I>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<Val<SC>>
        + for<'a> Air<ProverConstraintFolder<'a, SC>>
        + for<'a> Air<VerifierConstraintFolder<'a, SC>>,
{
    /// Get the name of the machine.
    fn name(&self) -> String;

    /// Get the basemachine
    fn base_machine(&self) -> &BaseMachine<SC, C>;

    /// Get the configuration of the machine.
    fn config<'a>(&'a self) -> &'a SC
    where
        C: 'a,
    {
        self.base_machine().config()
    }

    /// Get number of public values
    fn num_public_values(&self) -> usize {
        self.base_machine().num_public_values()
    }

    /// Get the chips of the machine.
    fn chips<'a>(&'a self) -> &'a [MetaChip<SC::Val, C>]
    where
        SC: 'a,
    {
        self.base_machine().chips()
    }

    /// Complete the record after emulation.
    fn complement_record(&self, records: &mut [C::Record]) {
        let begin = Instant::now();
        let chips = self.chips();
        records.iter_mut().for_each(|record| {
            chips.iter().for_each(|chip| {
                let mut extra = C::Record::default();
                chip.extra_record(record, &mut extra);
                record.append(&mut extra);
            });
            record.register_nonces();
        });
        debug!("complement record in {:?}", begin.elapsed());
    }

    /// setup prover, verifier and keys.
    fn setup_keys(&self, program: &C::Program) -> (BaseProvingKey<SC>, BaseVerifyingKey<SC>) {
        let begin = Instant::now();

        let (pk, vk) = self.base_machine().setup_keys(program);

        info!(
            "PERF-step=setup_keys-user_time={}",
            begin.elapsed().as_millis(),
        );

        (pk, vk)
    }

    /// Get the prover of the machine.
    fn prove(&self, pk: &BaseProvingKey<SC>, witness: &ProvingWitness<SC, C, I>) -> MetaProof<SC>
    where
        C: for<'a> Air<DebugConstraintFolder<'a, SC::Val, SC::Challenge>>;

    /// Verify the proof.
    fn verify(&self, vk: &BaseVerifyingKey<SC>, proof: &MetaProof<SC>) -> Result<()>;
}

/// A basic machine that includes elemental proving gadgets.
/// Mainly for testing purposes.
pub struct BaseMachine<SC, C>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<Val<SC>>
        + for<'a> Air<ProverConstraintFolder<'a, SC>>
        + for<'a> Air<VerifierConstraintFolder<'a, SC>>,
{
    /// Configuration of the machine
    config: SC,

    /// Chips of the machine
    chips: Vec<MetaChip<Val<SC>, C>>,

    /// Base prover
    prover: BaseProver<SC, C>,

    /// Base verifier
    verifier: BaseVerifier<SC, C>,

    /// Number of public values
    num_public_values: usize,
}

impl<SC, C> BaseMachine<SC, C>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<Val<SC>>
        + for<'a> Air<ProverConstraintFolder<'a, SC>>
        + for<'a> Air<VerifierConstraintFolder<'a, SC>>,
{
    /// Create BaseMachine based on config and chip behavior.
    pub fn new(config: SC, chips: Vec<MetaChip<Val<SC>, C>>, num_public_values: usize) -> Self {
        Self {
            config,
            chips,
            prover: BaseProver::<SC, C>::new(),
            verifier: BaseVerifier::<SC, C>::new(),
            num_public_values,
        }
    }

    /// Name of BaseMachine.
    pub fn name(&self) -> String {
        "BaseMachine".to_string()
    }

    /// Get the configuration of the machine.
    pub fn config(&self) -> &SC {
        &self.config
    }

    /// Get the chips of the machine.
    pub fn chips(&self) -> &[MetaChip<Val<SC>, C>] {
        &self.chips
    }

    /// Get the number of public values.
    pub fn num_public_values(&self) -> usize {
        self.num_public_values
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
    pub fn setup_keys(&self, program: &C::Program) -> (BaseProvingKey<SC>, BaseVerifyingKey<SC>) {
        let (pk, vk) = self.prover.setup_keys(self.config(), self.chips(), program);

        (pk, vk)
    }

    pub fn commit(&self, record: &C::Record) -> MainTraceCommitments<SC> {
        self.prover.commit_main(
            self.config(),
            record,
            self.prover.generate_main(self.chips(), record),
        )
    }

    /// prove a batch of records
    pub fn prove_ensemble(
        &self,
        pk: &BaseProvingKey<SC>,
        records: &[C::Record],
    ) -> Vec<BaseProof<SC>>
    where
        C: for<'c> Air<DebugConstraintFolder<'c, SC::Val, SC::Challenge>>,
    {
        let mut challenger = self.config().challenger();
        // observe preprocessed
        pk.observed_by(&mut challenger);

        let main_commitments = records
            .iter()
            .enumerate()
            .map(|(i, record)| {
                info!("PERF-chunk={}", i + 1);

                let commitment = self.prover.commit_main(
                    self.config(),
                    record,
                    self.prover.generate_main(self.chips(), record),
                );
                challenger.observe(commitment.commitment.clone());
                challenger.observe_slice(&commitment.public_values[..self.num_public_values]);
                commitment
            })
            .collect::<Vec<_>>();

        main_commitments
            .into_iter()
            .enumerate()
            .map(|(i, commitment)| {
                info!("PERF-chunk={}", i + 1);

                self.prover.prove(
                    self.config(),
                    self.chips(),
                    pk,
                    &mut challenger.clone(),
                    commitment,
                    records[i].chunk_index(),
                )
            })
            .collect::<Vec<_>>()
    }

    /// Prove assuming that challenger has already observed pk & main commitments and pv's
    pub fn prove_plain(
        &self,
        pk: &BaseProvingKey<SC>,
        challenger: &mut SC::Challenger,
        commitment: MainTraceCommitments<SC>,
        chunk_index: usize,
    ) -> BaseProof<SC> {
        self.prover.prove(
            self.config(),
            self.chips(),
            pk,
            challenger,
            commitment,
            chunk_index,
        )
    }

    /// Verify a batch of BaseProofs e2e
    pub fn verify_ensemble(
        &self,
        vk: &BaseVerifyingKey<SC>,
        proofs: &[BaseProof<SC>],
    ) -> Result<()> {
        assert!(!proofs.is_empty());

        let mut challenger = self.config().challenger();

        // observe all preprocessed and main commits and pv's
        vk.observed_by(&mut challenger);

        proofs.iter().for_each(|proof| {
            challenger.observe(proof.commitments.main_commit.clone());
            challenger.observe_slice(&proof.public_values[..self.num_public_values]);
        });

        // verify all proofs
        for proof in proofs {
            self.verifier.verify(
                self.config(),
                self.chips(),
                vk,
                &mut challenger.clone(),
                proof,
            )?;
        }

        let sum = proofs
            .iter()
            .map(|proof| proof.cumulative_sum())
            .sum::<SC::Challenge>();

        if !sum.is_zero() {
            panic!("verify_ensemble:lookup cumulative sum is not zero");
        }

        Ok(())
    }

    /// Verify assuming that challenger has already observed vk & main commitments and pv's
    pub fn verify_plain(
        &self,
        vk: &BaseVerifyingKey<SC>,
        challenger: &mut SC::Challenger,
        proof: &BaseProof<SC>,
    ) -> Result<()> {
        self.verifier
            .verify(self.config(), self.chips(), vk, challenger, proof)
    }
}
