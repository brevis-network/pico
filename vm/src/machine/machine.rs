use crate::{
    configs::config::StarkGenericConfig,
    emulator::record::RecordBehavior,
    machine::{
        chip::{ChipBehavior, MetaChip},
        folder::{ProverConstraintFolder, VerifierConstraintFolder},
        keys::{BaseProvingKey, BaseVerifyingKey},
        proof::{BaseProof, MainTraceCommitments, MetaProof, UnitProof},
        prover::BaseProver,
        utils::type_name_of,
        verifier::BaseVerifier,
        witness::ProvingWitness,
    },
};
use anyhow::Result;
use log::{debug, info};
use p3_air::Air;
use p3_baby_bear::{BabyBear, DiffusionMatrixBabyBear};
use p3_challenger::{CanObserve, DuplexChallenger};
use p3_commit::{Pcs, PolynomialSpace};
use p3_field::Field;
use p3_fri::FriConfig;
use p3_poseidon2::{Poseidon2, Poseidon2ExternalMatrixGeneral};
use std::time::Instant;

/// Functions that each machine instance should implement.
pub trait MachineBehavior<NSC, NC, SC, C, P, I>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<SC::Val>
        + for<'a> Air<ProverConstraintFolder<'a, SC>>
        + for<'a> Air<VerifierConstraintFolder<'a, SC>>,
{
    /// Get the name of the machine.
    fn name(&self) -> String;

    /// Get the configuration of the machine.
    fn config(&self) -> &SC;

    /// Get number of public values
    fn num_public_values(&self) -> usize;

    /// Get the chips of the machine.
    fn chips(&self) -> &[MetaChip<SC::Val, C>];

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
    fn setup_keys(&self, program: &C::Program) -> (BaseProvingKey<SC>, BaseVerifyingKey<SC>);

    /// Get the prover of the machine.
    fn prove(
        &self,
        pk: &BaseProvingKey<SC>,
        witness: &ProvingWitness<NSC, NC, SC, C, I>,
    ) -> MetaProof<SC, P>;

    /// Verify the proof.
    fn verify(&self, vk: &BaseVerifyingKey<SC>, proof: &MetaProof<SC, P>) -> Result<()>;
}

/// A basic machine that includes elemental proving gadgets.
/// Mainly for testing purposes.
pub struct BaseMachine<SC, C>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<SC::Val>
        + for<'a> Air<ProverConstraintFolder<'a, SC>>
        + for<'a> Air<VerifierConstraintFolder<'a, SC>>,
{
    prover: BaseProver<SC, C>,

    verifier: BaseVerifier<SC, C>,

    num_public_values: usize,
}

impl<SC, C> BaseMachine<SC, C>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<SC::Val>
        + for<'a> Air<ProverConstraintFolder<'a, SC>>
        + for<'a> Air<VerifierConstraintFolder<'a, SC>>,
{
    /// Create BaseMachine based on config and chip behavior.
    pub fn new(num_public_values: usize) -> Self {
        Self {
            prover: BaseProver::<SC, C>::new(),
            verifier: BaseVerifier::<SC, C>::new(),
            num_public_values,
        }
    }

    /// Name of BaseMachine with config.
    pub fn name(&self) -> String {
        "BaseMachine".to_string()
    }

    /// Get the number of public values.
    pub fn num_public_values(&self) -> usize {
        self.num_public_values
    }
    /// setup proving and verifying keys.
    pub fn setup_keys(
        &self,
        config: &SC,
        chips: &[MetaChip<SC::Val, C>],
        program: &C::Program,
    ) -> (BaseProvingKey<SC>, BaseVerifyingKey<SC>) {
        let (pk, vk) = self.prover.setup_keys(config, chips, program);

        (pk, vk)
    }

    pub fn commit(
        &self,
        config: &SC,
        chips: &[MetaChip<SC::Val, C>],
        record: &C::Record,
    ) -> MainTraceCommitments<SC> {
        self.prover
            .commit_main(config, record, self.prover.generate_main(chips, record))
    }

    /// Prove a single record.
    pub fn prove_unit(
        &self,
        config: &SC,
        chips: &[MetaChip<SC::Val, C>],
        pk: &BaseProvingKey<SC>,
        record: &C::Record,
    ) -> BaseProof<SC> {
        // observe preprocessed
        let mut challenger = config.challenger();
        pk.observed_by(&mut challenger);

        let main_commitment =
            self.prover
                .commit_main(config, record, self.prover.generate_main(chips, record));

        challenger.observe(main_commitment.commitment.clone());
        challenger.observe_slice(&main_commitment.public_values[..self.num_public_values]);

        self.prover
            .prove(config, chips, pk, &mut challenger, main_commitment)
    }

    /// prove a batch of records
    pub fn prove_ensemble(
        &self,
        config: &SC,
        chips: &[MetaChip<SC::Val, C>],
        pk: &BaseProvingKey<SC>,
        records: &[C::Record],
    ) -> Vec<BaseProof<SC>> {
        let mut challenger = config.challenger();
        // observe preprocessed
        info!("challenger observe preprocessed");
        pk.observed_by(&mut challenger);

        info!("generate commitments for {} records", records.len());
        let main_commitments = records
            .iter()
            .map(|record| {
                let commitment = self.prover.commit_main(
                    config,
                    record,
                    self.prover.generate_main(chips, record),
                );
                challenger.observe(commitment.commitment.clone());
                challenger.observe_slice(&commitment.public_values[..self.num_public_values]);
                commitment
            })
            .collect::<Vec<_>>();

        info!("iterate {} commitments and prove", main_commitments.len());
        main_commitments
            .into_iter()
            .map(|commitment| {
                self.prover
                    .prove(config, chips, pk, &mut challenger.clone(), commitment)
            })
            .collect::<Vec<_>>()
    }

    /// Prove assuming that challenger has already observed pk & main commitments and pv's
    pub fn prove_plain(
        &self,
        config: &SC,
        chips: &[MetaChip<SC::Val, C>],
        pk: &BaseProvingKey<SC>,
        challenger: &mut SC::Challenger,
        commitment: MainTraceCommitments<SC>,
    ) -> BaseProof<SC> {
        self.prover.prove(config, chips, pk, challenger, commitment)
    }

    /// Verify a single BaseProof e2e
    pub fn verify_unit(
        &self,
        config: &SC,
        chips: &[MetaChip<SC::Val, C>],
        vk: &BaseVerifyingKey<SC>,
        proof: &BaseProof<SC>,
    ) -> Result<()> {
        let mut challenger = config.challenger();

        vk.observed_by(&mut challenger);
        challenger.observe(proof.commitments.main_commit.clone());
        challenger.observe_slice(&proof.public_values[..self.num_public_values]);

        self.verifier
            .verify(config, chips, vk, &mut challenger, proof)?;

        if !proof.cumulative_sum().is_zero() {
            panic!("verify_unit: lookup cumulative sum is not zero");
        }

        Ok(())
    }

    /// Verify a batch of BaseProofs e2e
    pub fn verify_ensemble(
        &self,
        config: &SC,
        chips: &[MetaChip<SC::Val, C>],
        vk: &BaseVerifyingKey<SC>,
        proofs: &[BaseProof<SC>],
    ) -> Result<()> {
        let mut challenger = config.challenger();

        // observe all preprocessed and main commits and pv's
        vk.observed_by(&mut challenger);

        proofs.iter().for_each(|proof| {
            challenger.observe(proof.commitments.main_commit.clone());
            challenger.observe_slice(&proof.public_values[..self.num_public_values]);
        });

        // verify all proofs
        for (i, proof) in proofs.into_iter().enumerate() {
            debug!("Verifying proof {}", i);
            self.verifier
                .verify(config, chips, vk, &mut challenger.clone(), proof)?;
        }

        // compute sum of each proof.cumulative_sum() and add them up and judge if it is zero
        debug!("Verifying lookup");
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
        config: &SC,
        chips: &[MetaChip<SC::Val, C>],
        vk: &BaseVerifyingKey<SC>,
        challenger: &mut SC::Challenger,
        proof: &BaseProof<SC>,
    ) -> Result<()> {
        self.verifier.verify(config, chips, vk, challenger, proof)
    }
}
