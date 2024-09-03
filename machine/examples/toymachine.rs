use std::marker::PhantomData;
use p3_air::Air;
use p3_field::Field;
use p3_uni_stark::SymbolicAirBuilder;

use pico_chips::toy::{ToyChip};
use pico_configs::config::{StarkGenericConfig, Val};
use pico_configs::bb_poseidon2::BabyBearPoseidon2;

use pico_machine::chip::{BaseChip, ChipBehavior};
use pico_machine::folder::ProverConstraintFolder;
use pico_machine::prover::{BaseProver};
use pico_machine::verifier::{BaseVerifier};

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

fn main() {
    let config_p = BabyBearPoseidon2::new();
    let config_v = BabyBearPoseidon2::new();
    let chip_type = ToyChipType::Toy(ToyChip::default());
    let toy_prover = chip_type.get_prover(config_p);
    let toy_verifier = chip_type.get_verifier(config_v);

    let (pk, vk) = toy_prover.setup_keys();

    let mut challenger = config.challenger();
    let toy_proof = toy_prover.prove(&pk, &mut challenger);

    let mut challenger = config.challenger();
    let result = toy_verifier.verify(&vk, &mut challenger, &toy_proof);
}
