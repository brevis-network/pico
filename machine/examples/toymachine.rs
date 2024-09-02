// use p3_field::Field;
// use vm_configs::config_stark::{StarkGenericConfig, Val, Com, PcsProverData, Dom};
// use crate::prover::Prover;
//
// pub enum ToyChipType<F: Field> {
//     Toy(ToyChip),
// }
//
// impl<F: Field> ToyChipType<F> {
//     pub fn machine<SC, C>(config: SC) -> Prover<SC, C>
//     where SC: StarkGenericConfig<Val = F>, C: ChipBehavior<F> {
//         let chips = vec![BaseChip::new(ToyChip::new())];
//         Prover::new(config, chips)
//     }
// }
