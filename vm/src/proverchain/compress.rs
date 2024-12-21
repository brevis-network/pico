use super::{combine::CombineChips, MachineProver, ProverChain};
use crate::{
    compiler::recursion_v2::circuit::witness::Witnessable,
    configs::config::{Challenge, StarkGenericConfig, Val},
    instances::{
        chiptype::recursion_chiptype_v2::RecursionChipType,
        compiler_v2::recursion_circuit::{
            compress::builder::CompressVerifierCircuit, stdin::RecursionStdin,
        },
        configs::recur_config::{FieldConfig as RecursionFC, StarkConfig as RecursionSC},
        machine::compress::CompressMachine,
    },
    machine::{
        machine::{BaseMachine, MachineBehavior},
        proof::MetaProof,
        witness::ProvingWitness,
    },
    primitives::consts::{COMPRESS_DEGREE, DIGEST_SIZE, EXTENSION_DEGREE, RECURSION_NUM_PVS_V2},
    recursion_v2::runtime::Runtime,
};
use alloc::sync::Arc;
use p3_field::{extension::BinomiallyExtendable, FieldAlgebra, PrimeField32};

pub type CompressChips<SC> = RecursionChipType<Val<SC>, COMPRESS_DEGREE>;

pub struct CompressProver<PrevSC, SC>
where
    PrevSC: StarkGenericConfig,
    Val<PrevSC>: PrimeField32 + BinomiallyExtendable<EXTENSION_DEGREE>,
    SC: StarkGenericConfig,
    Val<SC>: PrimeField32 + BinomiallyExtendable<EXTENSION_DEGREE>,
{
    machine: CompressMachine<SC, CompressChips<SC>>,
    prev_machine: BaseMachine<PrevSC, CombineChips<PrevSC>>,
}

// TODO: make RecursionCompressVerifierCircuit and Hintable traits generic over FC/SC
impl ProverChain<RecursionSC, CombineChips<RecursionSC>, RecursionSC>
    for CompressProver<RecursionSC, RecursionSC>
{
    fn new_with_prev(
        prev_prover: &impl MachineProver<RecursionSC, Chips = CombineChips<RecursionSC>>,
    ) -> Self {
        let machine = CompressMachine::new(
            RecursionSC::compress(),
            CompressChips::<RecursionSC>::compress_chips(),
            RECURSION_NUM_PVS_V2,
        );
        Self {
            machine,
            prev_machine: prev_prover.machine().clone(),
        }
    }
}

impl MachineProver<RecursionSC> for CompressProver<RecursionSC, RecursionSC> {
    type Witness = MetaProof<RecursionSC>;
    type Chips = CompressChips<RecursionSC>;

    fn machine(&self) -> &BaseMachine<RecursionSC, Self::Chips> {
        self.machine.base_machine()
    }

    fn prove(&self, proofs: Self::Witness) -> MetaProof<RecursionSC> {
        let vk_root = [Val::<RecursionSC>::ZERO; DIGEST_SIZE];
        let stdin = RecursionStdin::new(
            self.machine.base_machine(),
            proofs.vks.clone(),
            proofs.proofs.clone(),
            true,
            vk_root,
        );
        let program = CompressVerifierCircuit::build(&self.prev_machine, &stdin);
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

    fn verify(&self, proof: &MetaProof<RecursionSC>) -> bool {
        self.machine.verify(proof).is_ok()
    }
}
