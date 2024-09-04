use p3_air::Air;
use p3_baby_bear::BabyBear;
use p3_field::Field;
use p3_uni_stark::SymbolicAirBuilder;
use std::marker::PhantomData;

use pico_chips::toy::ToyChip;
use pico_configs::{
    bb_poseidon2::BabyBearPoseidon2,
    config::{StarkGenericConfig, Val},
};

use pico_machine::{
    chip::{BaseChip, ChipBehavior},
    folder::ProverConstraintFolder,
    prover::BaseProver,
    verifier::BaseVerifier,
};

/*
pub enum ToyChipType<F, C, SC> {
    Toy(ToyChip<F>),
    NON(PhantomData<(C,SC)>)
}

impl<F, C, SC> ToyChipType<F, C, SC>
where
    F: Field,
    C: for<'a> Air<ProverConstraintFolder<'a, SC>> + ChipBehavior<Val<SC>> + Air<SymbolicAirBuilder<F>>,
    SC: StarkGenericConfig,
{
    pub fn get_prover(&self, config: SC) -> BaseProver<SC, C> {
        let chips = self.chips();
        BaseProver::new(config, chips)
    }

    pub fn get_verifier(&self, config: SC) -> BaseVerifier<SC, C> {
        let chips = self.chips();
        BaseVerifier::new(config, chips)
    }

    pub fn chips(&self) -> Vec<BaseChip<F, C>> {
        vec![
            BaseChip::new(ToyChip::default()),
        ]
    }
}
*/

fn main() {
    // Create the prover.
    println!("Creating prover");
    let config = BabyBearPoseidon2::new();
    let chips = vec![BaseChip::<BabyBear, _>::new(ToyChip::default())];
    let prover = BaseProver::new(&config, chips);

    // Setup PK and VK.
    println!("Setup PK and VK");
    let (pk, vk) = prover.setup_keys_for_main();

    println!("Generating proof");
    let mut challenger = config.challenger();
    // Generate the proof.
    let proof = prover.prove(&pk, &mut challenger);

    // Create the verifier.
    println!("Creating verifier");
    let chips = vec![BaseChip::<BabyBear, _>::new(ToyChip::default())];
    let verifier = BaseVerifier::new(&config, chips);

    // Verify the proof.
    println!("Verifying proof");
    let mut challenger = config.challenger();
    let result = verifier.verify(&vk, &mut challenger, &proof);
    println!("The proof is verified: {}", result.is_ok());
}
