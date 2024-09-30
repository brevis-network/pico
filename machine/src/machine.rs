use crate::{
    chip::{ChipBehavior, MetaChip},
    folder::{ProverConstraintFolder, VerifierConstraintFolder},
    keys::{BaseProvingKey, BaseVerifyingKey},
    proof::{BaseProof, MainTraceCommitments, MetaProof, UnitProof},
    prover::BaseProver,
    utils::type_name_of,
    verifier::BaseVerifier,
};
use anyhow::Result;
use log::{debug, info};
use p3_air::Air;
use p3_challenger::CanObserve;
use p3_fri::FriConfig;
use pico_compiler::program::Program;
use pico_configs::config::{StarkGenericConfig, Val};
use pico_emulator::record::RecordBehavior;
use std::time::Instant;

/// Functions that each machine instance should implement.
pub trait MachineBehavior<SC, C, P>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<Val<SC>>
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
    fn chips(&self) -> &[MetaChip<Val<SC>, C>];

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
    fn setup_keys(&self, program: &Program) -> (BaseProvingKey<SC>, BaseVerifyingKey<SC>);

    /// Get the prover of the machine.
    fn prove(&self, pk: &BaseProvingKey<SC>, records: &[C::Record]) -> MetaProof<SC, P>;

    /// Verify the proof.
    fn verify(&self, vk: &BaseVerifyingKey<SC>, proof: &MetaProof<SC, P>) -> Result<()>;
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
    pub prover: BaseProver<SC, C>,

    pub verifier: BaseVerifier<SC, C>,

    pub num_public_values: usize,
}

impl<SC, C> BaseMachine<SC, C>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<Val<SC>>
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
    fn name(&self) -> String {
        "BaseMachine".to_string()
    }

    /// setup proving and verifying keys.
    pub fn setup_keys(
        &self,
        config: &SC,
        chips: &[MetaChip<Val<SC>, C>],
        program: &Program,
    ) -> (BaseProvingKey<SC>, BaseVerifyingKey<SC>) {
        let (pk, vk) = self.prover.setup_keys(config, chips, program);

        (pk, vk)
    }

    /// Prove based on record and proving key.
    pub fn prove_unit(
        &self,
        config: &SC,
        chips: &[MetaChip<Val<SC>, C>],
        pk: &BaseProvingKey<SC>,
        record: &C::Record,
    ) -> BaseProof<SC> {
        // observe preprocessed
        let mut challenger = config.challenger();
        challenger.observe(pk.commit.clone());

        let main_commitment =
            self.prover
                .commit_main(config, record, self.prover.generate_main(chips, record));

        challenger.observe(main_commitment.commitment.clone());
        challenger.observe_slice(&main_commitment.public_values[..self.num_public_values]);

        self.prover
            .prove(config, chips, pk, &mut challenger, main_commitment)
    }

    pub fn prove_ensemble(
        &self,
        config: &SC,
        chips: &[MetaChip<Val<SC>, C>],
        pk: &BaseProvingKey<SC>,
        records: &[C::Record],
    ) -> Vec<BaseProof<SC>> {
        let mut challenger = config.challenger();
        // observe preprocessed
        info!("challenger observe preprocessed");
        challenger.observe(pk.commit.clone());

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
                    .prove(config, chips, pk, &mut challenger, commitment)
            })
            .collect::<Vec<_>>()
    }

    pub fn verify_unit(
        &self,
        config: &SC,
        chips: &[MetaChip<Val<SC>, C>],
        vk: &BaseVerifyingKey<SC>,
        proof: &BaseProof<SC>,
    ) -> Result<()> {
        let mut challenger = config.challenger();

        challenger.observe(vk.commit.clone());
        challenger.observe(proof.commitments.main_commit.clone());
        challenger.observe_slice(&proof.public_values[..self.num_public_values]);

        self.verifier
            .verify(config, chips, vk, &mut challenger, proof)?;

        Ok(())
    }

    pub fn verify_ensemble(
        &self,
        config: &SC,
        chips: &[MetaChip<Val<SC>, C>],
        vk: &BaseVerifyingKey<SC>,
        proofs: &[BaseProof<SC>],
    ) -> Result<()> {
        let mut challenger = config.challenger();

        challenger.observe(vk.commit.clone());
        proofs.iter().for_each(|proof| {
            challenger.observe(proof.commitments.main_commit.clone());
            challenger.observe_slice(&proof.public_values[..self.num_public_values]);
        });

        for proof in proofs {
            self.verifier
                .verify(config, chips, vk, &mut challenger, proof)?;
        }

        Ok(())
    }
}
