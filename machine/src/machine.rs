use crate::{
    chip::{ChipBehavior, MetaChip},
    folder::{ProverConstraintFolder, VerifierConstraintFolder},
    keys::{BaseProvingKey, BaseVerifyingKey},
    proof::{BaseProof, ElementProof, MainTraceCommitments, MetaProof},
    prover::BaseProver,
    utils::type_name_of,
    verifier::BaseVerifier,
};
use anyhow::Result;
use p3_air::Air;
use p3_challenger::CanObserve;
use p3_fri::FriConfig;
use pico_compiler::program::Program;
use pico_configs::config::{StarkGenericConfig, Val};
use pico_emulator::record::RecordBehavior;

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

    /// Get the chips of the machine.
    fn chips(&self) -> &[MetaChip<Val<SC>, C>];

    /// Complete the record after emulation.
    fn complement_record(&self, records: &mut [C::Record]) {
        let chips = self.chips();
        records.iter_mut().for_each(|record| {
            chips.iter().for_each(|chip| {
                let mut extra = C::Record::default();
                chip.extra_record(record, &mut extra);
                record.append(&mut extra);
            });
        });
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
}

impl<SC, C> BaseMachine<SC, C>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<Val<SC>>
        + for<'a> Air<ProverConstraintFolder<'a, SC>>
        + for<'a> Air<VerifierConstraintFolder<'a, SC>>,
{
    /// Create BaseMachine based on config and chip behavior.
    pub fn new() -> Self {
        Self {
            prover: BaseProver::<SC, C>::new(),
            verifier: BaseVerifier::<SC, C>::new(),
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
    pub fn prove_element(
        &self,
        config: &SC,
        chips: &[MetaChip<Val<SC>, C>],
        pk: &BaseProvingKey<SC>,
        record: &C::Record,
    ) -> BaseProof<SC> {
        // todo: generate dependencies

        // observe preprocessed
        let mut challenger = config.challenger();
        challenger.observe(pk.commit.clone());

        let main_commitment = self
            .prover
            .commit_main(config, self.prover.generate_main(chips, record));

        challenger.observe(main_commitment.commitment.clone());

        self.prove(config, chips, pk, &mut challenger, main_commitment)
    }

    pub fn prove_ensemble(
        &self,
        config: &SC,
        chips: &[MetaChip<Val<SC>, C>],
        pk: &BaseProvingKey<SC>,
        records: &[C::Record],
    ) -> Vec<BaseProof<SC>> {
        // todo: generate dependencies

        let mut challenger = config.challenger();
        // observe preprocessed
        challenger.observe(pk.commit.clone());

        let main_commitments = records
            .iter()
            .map(|record| {
                let commitment = self
                    .prover
                    .commit_main(config, self.prover.generate_main(chips, record));
                challenger.observe(commitment.commitment.clone());
                commitment
            })
            .collect::<Vec<_>>();

        main_commitments
            .into_iter()
            .map(|commitment| self.prove(config, chips, pk, &mut challenger, commitment))
            .collect::<Vec<_>>()
    }

    pub fn prove(
        &self,
        config: &SC,
        chips: &[MetaChip<Val<SC>, C>],
        pk: &BaseProvingKey<SC>,
        challenger: &mut SC::Challenger,
        main_commitments: MainTraceCommitments<SC>,
    ) -> BaseProof<SC> {
        self.prover
            .prove(config, chips, pk, challenger, main_commitments)
    }

    pub fn verify_element(
        &self,
        config: &SC,
        chips: &[MetaChip<Val<SC>, C>],
        vk: &BaseVerifyingKey<SC>,
        proof: &BaseProof<SC>,
    ) -> Result<()> {
        let mut challenger = config.challenger();

        challenger.observe(vk.commit.clone());
        challenger.observe(proof.commitments.main_commit.clone());

        self.verify(config, chips, vk, &mut challenger, proof)?;

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
        });

        for proof in proofs {
            self.verify(config, chips, vk, &mut challenger, proof)?;
        }

        Ok(())
    }
    /// Verify the proof based on verifying key.
    pub fn verify(
        &self,
        config: &SC,
        chips: &[MetaChip<Val<SC>, C>],
        vk: &BaseVerifyingKey<SC>,
        challenger: &mut SC::Challenger,
        proof: &BaseProof<SC>,
    ) -> Result<()> {
        self.verifier.verify(config, chips, vk, challenger, proof)?;

        Ok(())
    }
}
