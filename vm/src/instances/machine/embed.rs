use crate::{
    compiler::recursion::{
        circuit::utils::assert_embed_public_values_valid, program::RecursionProgram,
    },
    configs::config::{Challenge, Com, PcsProverData, StarkGenericConfig, Val},
    emulator::{
        record::RecordBehavior,
        recursion::{emulator::RecursionRecord, public_values::RecursionPublicValues},
    },
    machine::{
        chip::{ChipBehavior, MetaChip},
        folder::{DebugConstraintFolder, ProverConstraintFolder, VerifierConstraintFolder},
        machine::{BaseMachine, MachineBehavior},
        proof::MetaProof,
        witness::ProvingWitness,
    },
};
use p3_air::Air;
use p3_field::{FieldAlgebra, PrimeField32};
use std::{any::type_name, borrow::Borrow, marker::PhantomData, time::Instant};
use tracing::{debug, info, instrument, trace};

pub struct EmbedMachine<PrevSC, SC, C, I>
where
    SC: StarkGenericConfig,
{
    base_machine: BaseMachine<SC, C>,

    phantom: std::marker::PhantomData<(PrevSC, I)>,
}

impl<PrevSC, EmbedSC, C, I> MachineBehavior<EmbedSC, C, I> for EmbedMachine<PrevSC, EmbedSC, C, I>
where
    PrevSC: StarkGenericConfig,
    EmbedSC: StarkGenericConfig<Val = PrevSC::Val>,
    Val<EmbedSC>: PrimeField32,
    Com<EmbedSC>: Send + Sync,
    PcsProverData<EmbedSC>: Send + Sync,
    C: ChipBehavior<
        Val<EmbedSC>,
        Program = RecursionProgram<Val<EmbedSC>>,
        Record = RecursionRecord<Val<EmbedSC>>,
    >,
{
    /// Get the name of the machine.
    fn name(&self) -> String {
        format!("Embed Recursion Machine <{}>", type_name::<EmbedSC>())
    }

    /// Get the base machine
    fn base_machine(&self) -> &BaseMachine<EmbedSC, C> {
        &self.base_machine
    }

    // todo: I is actually not used here
    /// Get the prover of the machine.
    #[instrument(name = "embed_prove", level = "debug", skip_all)]
    fn prove(&self, witness: &ProvingWitness<EmbedSC, C, I>) -> MetaProof<EmbedSC>
    where
        C: for<'a> Air<DebugConstraintFolder<'a, Val<EmbedSC>, Challenge<EmbedSC>>>
            + for<'a> Air<ProverConstraintFolder<'a, EmbedSC>>,
    {
        let mut records = witness.records().to_vec();
        self.complement_record(&mut records);

        info!("EMBED record stats");
        let stats = records[0].stats();
        for (key, value) in &stats {
            info!("   |- {:<28}: {}", key, value);
        }

        let proofs = self.base_machine.prove_ensemble(witness.pk(), &records);

        // construct meta proof
        let vks = vec![witness.vk.clone().unwrap()].into();

        info!("EMBED chip log degrees:");
        proofs.iter().enumerate().for_each(|(i, proof)| {
            info!("Proof {}", i);
            proof
                .main_chip_ordering
                .iter()
                .for_each(|(chip_name, idx)| {
                    info!(
                        "   |- {:<20} main: {:<8}",
                        chip_name, proof.opened_values.chips_opened_values[*idx].log_main_degree,
                    );
                });
        });

        MetaProof::new(proofs.into(), vks, None)
    }

    /// Verify the proof.
    fn verify(&self, proof: &MetaProof<EmbedSC>) -> anyhow::Result<()>
    where
        C: for<'a> Air<VerifierConstraintFolder<'a, EmbedSC>>,
    {
        let vk = proof.vks().first().unwrap();

        debug!("PERF-machine=embed");
        let begin = Instant::now();

        assert_eq!(proof.num_proofs(), 1);

        let public_values: &RecursionPublicValues<_> =
            proof.proofs[0].public_values.as_ref().borrow();
        trace!("public values: {:?}", public_values);

        // assert completion
        if public_values.flag_complete != <Val<EmbedSC>>::ONE {
            panic!("flag_complete is not 1");
        }

        // assert public value digest
        assert_embed_public_values_valid(&PrevSC::new(), public_values);

        // verify
        self.base_machine.verify_ensemble(vk, &proof.proofs())?;

        debug!("PERF-step=verify-user_time={}", begin.elapsed().as_millis());

        Ok(())
    }
}

impl<PrevSC, SC, C, I> EmbedMachine<PrevSC, SC, C, I>
where
    PrevSC: StarkGenericConfig,
    SC: StarkGenericConfig,
    C: ChipBehavior<
        Val<SC>,
        Program = RecursionProgram<Val<SC>>,
        Record = RecursionRecord<Val<SC>>,
    >,
{
    pub fn new(config: SC, chips: Vec<MetaChip<Val<SC>, C>>, num_public_values: usize) -> Self {
        Self {
            base_machine: BaseMachine::<SC, C>::new(config, chips, num_public_values),
            phantom: PhantomData,
        }
    }
}
