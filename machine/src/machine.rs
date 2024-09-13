use crate::{
    chip::{ChipBehavior, MetaChip},
    folder::{ProverConstraintFolder, VerifierConstraintFolder},
    keys::{BaseProvingKey, BaseVerifyingKey},
    proof::{ElementProof, MetaProof},
    prover::BaseProver,
    verifier::BaseVerifier,
};
use anyhow::Result;
use p3_air::Air;
use pico_configs::config::{StarkGenericConfig, Val};
use pico_emulator::record::EmulationRecord;

/// Functions that each machine should implement.
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

    /// setup prover, verfier and keys.
    fn setup(&self, input: &EmulationRecord) -> (BaseProvingKey<SC>, BaseVerifyingKey<SC>);

    /// Get the prover of the machine.
    fn prove(&self, input: &EmulationRecord, pk: &BaseProvingKey<SC>) -> MetaProof<SC, P>;

    /// Verify the proof.
    fn verify(&self, proof: &MetaProof<SC, P>, vk: &BaseVerifyingKey<SC>) -> Result<()>;
}

/// A simple machine that impls MachineBehavior.
/// Mainly for testing purposes.
pub struct SimpleMachine<SC, C, P>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<Val<SC>>
        + for<'a> Air<ProverConstraintFolder<'a, SC>>
        + for<'a> Air<VerifierConstraintFolder<'a, SC>>,
{
    //pub program: PG, (ignore for now until executor integration)
    pub config: SC,

    pub chips: Vec<MetaChip<Val<SC>, C>>,

    pub prover: BaseProver<SC, C>,

    pub verifier: BaseVerifier<SC, C>,

    _phantom: std::marker::PhantomData<P>,
}

impl<SC, C> MachineBehavior<SC, C, ElementProof<SC>> for SimpleMachine<SC, C, ElementProof<SC>>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<Val<SC>>
        + for<'a> Air<ProverConstraintFolder<'a, SC>>
        + for<'a> Air<VerifierConstraintFolder<'a, SC>>,
{
    /// Name of machine with config.
    fn name(&self) -> String {
        format!("SimpleMachine with config {}", self.config.name(),)
    }

    /// Get the configuration of the machine.
    fn config(&self) -> &SC {
        &self.config
    }

    /// Get the chips of the machine.
    fn chips(&self) -> &[MetaChip<Val<SC>, C>] {
        &self.chips
    }

    /// setup proving and verifying keys.
    fn setup(&self, input: &EmulationRecord) -> (BaseProvingKey<SC>, BaseVerifyingKey<SC>) {
        let (pk, vk) = self.prover.setup_keys(&self.config, &self.chips, input);

        (pk, vk)
    }

    /// Prove based on record and proving key.
    fn prove(
        &self,
        input: &EmulationRecord,
        pk: &BaseProvingKey<SC>,
    ) -> MetaProof<SC, ElementProof<SC>> {
        let mut challenger = self.config.challenger();
        let base_proof = self
            .prover
            .prove(&self.config, &self.chips, pk, &mut challenger, input);

        MetaProof::new(self.config(), ElementProof::new(base_proof))
    }

    /// Verify the proof based on verifying key.
    fn verify(
        &self,
        proof: &MetaProof<SC, ElementProof<SC>>,
        vk: &BaseVerifyingKey<SC>,
    ) -> Result<()> {
        let mut challenger = self.config.challenger();
        self.verifier.verify(
            &self.config,
            &self.chips,
            vk,
            &mut challenger,
            &proof.proof.proof,
        )
    }
}

impl<SC, C, P> SimpleMachine<SC, C, P>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<Val<SC>>
        + for<'a> Air<ProverConstraintFolder<'a, SC>>
        + for<'a> Air<VerifierConstraintFolder<'a, SC>>,
{
    /// Create SimpleMachine based on config and chips
    pub fn new(config: SC, chips: Vec<MetaChip<Val<SC>, C>>) -> Self {
        Self {
            config,
            chips,
            prover: BaseProver::<SC, C>::new(),
            verifier: BaseVerifier::<SC, C>::new(),
            _phantom: std::marker::PhantomData,
        }
    }
}
