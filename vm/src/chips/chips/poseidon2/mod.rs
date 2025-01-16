mod columns;
mod constraints;
mod traces;
pub mod utils;

use crate::{
    chips::chips::poseidon2::columns::permutation::{
        PermutationNoSbox, PermutationSBox, Poseidon2,
    },
    configs::config::Poseidon2Config,
    machine::field::{FieldBehavior, FieldType},
};
use p3_field::Field;
use std::{borrow::Borrow, marker::PhantomData, ops::Deref};

/// A chip that implements addition for the opcode Poseidon2.
#[allow(clippy::type_complexity)]
#[derive(Debug, Clone, Copy)]
pub struct Poseidon2Chip<const DEGREE: usize, Config, F> {
    pub _phantom: PhantomData<fn(F, Config) -> (F, Config)>,
}

impl<const DEGREE: usize, Config, F> Default for Poseidon2Chip<DEGREE, Config, F> {
    fn default() -> Self {
        Self {
            _phantom: PhantomData,
        }
    }
}

impl<const DEGREE: usize, Config: Poseidon2Config, F: Field> Poseidon2Chip<DEGREE, Config, F> {
    /// Transmute a row it to an immutable Poseidon2 instance.
    pub(crate) fn convert<'a, T>(
        row: impl Deref<Target = [T]>,
    ) -> Box<dyn Poseidon2<T, Config> + 'a>
    where
        // TODO: figure out why we need T: Copy + 'a
        T: Copy + 'a,
        Config: 'a,
        //PermutationSBox<T, Config>: Copy + 'a,
        //PermutationNoSbox<T, Config>: Copy + 'a,
    {
        if F::field_type() == FieldType::TypeBabyBear {
            if DEGREE == 3 {
                let convert: &PermutationSBox<T, Config> = (*row).borrow();
                Box::new(convert.clone())
            } else if DEGREE == 9 {
                let convert: &PermutationNoSbox<T, Config> = (*row).borrow();
                Box::new(convert.clone())
            } else {
                panic!("Unsupported degree");
            }
        } else if F::field_type() == FieldType::TypeKoalaBear {
            let convert: &PermutationNoSbox<T, Config> = (*row).borrow();
            Box::new(convert.clone())
        } else {
            panic!("Unsupported field type");
        }
    }
}

#[cfg(test)]
#[allow(unused_imports)]
pub(crate) mod tests {
    use super::Poseidon2Chip;
    use crate::{
        machine::chip::ChipBehavior,
        primitives::{
            consts::{BabyBearConfig, KoalaBearConfig, PERMUTATION_WIDTH},
            pico_poseidon2bb_init, pico_poseidon2kb_init,
        },
        recursion_v2::{
            runtime::RecursionRecord,
            //tests::run_recursion_test_machine,
            types::Poseidon2Event,
        },
    };
    use p3_baby_bear::BabyBear;
    use p3_field::FieldAlgebra;
    use p3_koala_bear::KoalaBear;
    use p3_matrix::dense::RowMajorMatrix;
    use p3_symmetric::Permutation;
    use rand::{prelude::StdRng, SeedableRng};
    use std::marker::PhantomData;
    use zkhash::ark_ff::UniformRand;

    #[test]
    fn generate_trace_babybear_deg_3() {
        type F = BabyBear;
        let input_0 = [F::ONE; PERMUTATION_WIDTH];
        let permuter = pico_poseidon2bb_init();
        let output_0 = permuter.permute(input_0);
        // let mut rng = rand::thread_rng();
        let mut rng = StdRng::seed_from_u64(0xDEADBEEF);

        let input_1 = [F::rand(&mut rng); PERMUTATION_WIDTH];
        let output_1 = permuter.permute(input_1);

        let chunk = RecursionRecord {
            poseidon2_events: vec![
                Poseidon2Event {
                    input: input_0,
                    output: output_0,
                },
                Poseidon2Event {
                    input: input_1,
                    output: output_1,
                },
            ],
            ..Default::default()
        };
        let chip_3 = Poseidon2Chip::<3, BabyBearConfig, F> {
            _phantom: PhantomData,
        };
        let main_trace: RowMajorMatrix<F> =
            chip_3.generate_main(&chunk, &mut RecursionRecord::default());
        println!("{:?}", main_trace.values)
    }

    #[test]
    fn generate_trace_koalabear_deg_3() {
        type F = KoalaBear;
        let input_0 = [F::ONE; PERMUTATION_WIDTH];
        let permuter = pico_poseidon2kb_init();
        let output_0 = permuter.permute(input_0);
        // let mut rng = rand::thread_rng();
        let mut rng = StdRng::seed_from_u64(0xDEADBEEF);

        let input_1 = [F::rand(&mut rng); PERMUTATION_WIDTH];
        let output_1 = permuter.permute(input_1);

        let chunk = RecursionRecord {
            poseidon2_events: vec![
                Poseidon2Event {
                    input: input_0,
                    output: output_0,
                },
                Poseidon2Event {
                    input: input_1,
                    output: output_1,
                },
            ],
            ..Default::default()
        };
        let chip_3 = Poseidon2Chip::<3, KoalaBearConfig, F> {
            _phantom: PhantomData,
        };
        let main_trace: RowMajorMatrix<F> =
            chip_3.generate_main(&chunk, &mut RecursionRecord::default());
        println!("{:?}", main_trace.values)
    }

    #[test]
    fn generate_trace_deg_9() {
        type F = BabyBear;
        let input_0 = [F::ONE; PERMUTATION_WIDTH];
        let permuter = pico_poseidon2bb_init();
        let output_0 = permuter.permute(input_0);
        // let mut rng = rand::thread_rng();
        let mut rng = StdRng::seed_from_u64(0xDEADBEEF);

        let input_1 = [F::rand(&mut rng); PERMUTATION_WIDTH];
        let output_1 = permuter.permute(input_1);

        let chunk = RecursionRecord {
            poseidon2_events: vec![
                Poseidon2Event {
                    input: input_0,
                    output: output_0,
                },
                Poseidon2Event {
                    input: input_1,
                    output: output_1,
                },
            ],
            ..Default::default()
        };
        let chip_9 = Poseidon2Chip::<9, BabyBearConfig, F> {
            _phantom: PhantomData,
        };
        let main_trace: RowMajorMatrix<F> =
            chip_9.generate_main(&chunk, &mut RecursionRecord::default());
        println!("{:?}", main_trace.values)
    }
}
