use super::{compress::CompressChips, MachineProver, ProverChain};
use crate::{
    compiler::recursion_v2::circuit::witness::Witnessable,
    configs::config::{Challenge, StarkGenericConfig, Val},
    instances::{
        chiptype::recursion_chiptype_v2::RecursionChipType,
        compiler_v2::recursion_circuit::{
            embed::builder::EmbedVerifierCircuit, stdin::RecursionStdin,
        },
        configs::{
            embed_config::StarkConfig as EmbedSC,
            recur_config::{FieldConfig as RecursionFC, StarkConfig as RecursionSC},
        },
        machine::embed::EmbedMachine,
    },
    machine::{
        machine::{BaseMachine, MachineBehavior},
        proof::MetaProof,
        witness::ProvingWitness,
    },
    primitives::consts::{DIGEST_SIZE, EMBED_DEGREE, EXTENSION_DEGREE, RECURSION_NUM_PVS_V2},
    recursion_v2::runtime::Runtime,
};
use alloc::sync::Arc;
use p3_field::{extension::BinomiallyExtendable, FieldAlgebra, PrimeField32};

pub type EmbedChips<SC> = RecursionChipType<Val<SC>, EMBED_DEGREE>;

pub struct EmbedProver<PrevSC, SC, I>
where
    PrevSC: StarkGenericConfig,
    Val<PrevSC>: PrimeField32 + BinomiallyExtendable<EXTENSION_DEGREE>,
    SC: StarkGenericConfig,
    Val<SC>: PrimeField32 + BinomiallyExtendable<EXTENSION_DEGREE>,
{
    machine: EmbedMachine<SC, EmbedChips<SC>, I>,
    prev_machine: BaseMachine<PrevSC, CompressChips<PrevSC>>,
}

// TODO: make RecursionCompressVerifierCircuit and Hintable traits generic over FC/SC
impl<I> ProverChain<RecursionSC, CompressChips<RecursionSC>, EmbedSC>
    for EmbedProver<RecursionSC, EmbedSC, I>
{
    fn new_with_prev(
        prev_prover: &impl MachineProver<RecursionSC, Chips = CompressChips<RecursionSC>>,
    ) -> Self {
        let machine = EmbedMachine::<_, _, I>::new(
            EmbedSC::default(),
            EmbedChips::<EmbedSC>::embed_chips(),
            RECURSION_NUM_PVS_V2,
        );
        Self {
            machine,
            prev_machine: prev_prover.machine().clone(),
        }
    }
}

impl<I> MachineProver<EmbedSC> for EmbedProver<RecursionSC, EmbedSC, I> {
    type Witness = MetaProof<RecursionSC>;
    type Chips = EmbedChips<EmbedSC>;

    fn machine(&self) -> &BaseMachine<EmbedSC, Self::Chips> {
        self.machine.base_machine()
    }

    fn prove(&self, proofs: Self::Witness) -> MetaProof<EmbedSC> {
        let vk_root = [Val::<RecursionSC>::ZERO; DIGEST_SIZE];
        let stdin = RecursionStdin::new(
            &self.prev_machine,
            proofs.vks.clone(),
            proofs.proofs.clone(),
            true,
            vk_root,
        );
        let program = EmbedVerifierCircuit::build(&self.prev_machine, &stdin);
        let (pk, vk) = self.machine.setup_keys(&program);

        let mut witness_stream = Vec::new();
        Witnessable::<RecursionFC>::write(&stdin, &mut witness_stream);

        let mut runtime = Runtime::<_, Challenge<RecursionSC>, _, _, _, _>::new(
            Arc::new(program),
            self.prev_machine.config().perm.clone(),
        );
        runtime.witness_stream = witness_stream.into();
        runtime.run().expect("error while running program");
        let witness = ProvingWitness::setup_with_keys_and_records(pk, vk, vec![runtime.record]);
        self.machine.prove(&witness)
    }

    fn verify(&self, proof: &MetaProof<EmbedSC>) -> bool {
        self.machine.verify(proof).is_ok()
    }
}
