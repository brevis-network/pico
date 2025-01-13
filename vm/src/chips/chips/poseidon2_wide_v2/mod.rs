mod columns;
mod constraints;
mod traces;

use crate::chips::chips::poseidon2_wide_v2::columns::{
    permutation::Poseidon2, Poseidon2Degree3, Poseidon2Degree9,
};
use p3_field::Field;
use std::{borrow::Borrow, marker::PhantomData, ops::Deref};

/// A chip that implements addition for the opcode Poseidon2Wide.
#[derive(Default, Debug, Clone, Copy)]
pub struct Poseidon2WideChip<
    const DEGREE: usize,
    const NUM_EXTERNAL_ROUNDS: usize,
    const NUM_INTERNAL_ROUNDS: usize,
    const NUM_INTERNAL_ROUNDS_MINUS_ONE: usize,
    F,
> {
    pub _phantom: PhantomData<fn(F) -> F>,
}

impl<
        'a,
        const DEGREE: usize,
        const NUM_EXTERNAL_ROUNDS: usize,
        const NUM_INTERNAL_ROUNDS: usize,
        const NUM_INTERNAL_ROUNDS_MINUS_ONE: usize,
        F: Field,
    >
    Poseidon2WideChip<
        DEGREE,
        NUM_EXTERNAL_ROUNDS,
        NUM_INTERNAL_ROUNDS,
        NUM_INTERNAL_ROUNDS_MINUS_ONE,
        F,
    >
{
    /// Transmute a row it to an immutable Poseidon2 instance.
    pub(crate) fn convert<T>(
        row: impl Deref<Target = [T]>,
    ) -> Box<
        dyn Poseidon2<T, NUM_EXTERNAL_ROUNDS, NUM_INTERNAL_ROUNDS, NUM_INTERNAL_ROUNDS_MINUS_ONE>
            + 'a,
    >
    where
        T: Copy + 'a,
    {
        if DEGREE == 3 {
            let convert: &Poseidon2Degree3<
                T,
                NUM_EXTERNAL_ROUNDS,
                NUM_INTERNAL_ROUNDS,
                NUM_INTERNAL_ROUNDS_MINUS_ONE,
            > = (*row).borrow();
            Box::new(*convert)
        } else if DEGREE == 9 || DEGREE == 17 {
            let convert: &Poseidon2Degree9<T, NUM_EXTERNAL_ROUNDS, NUM_INTERNAL_ROUNDS_MINUS_ONE> =
                (*row).borrow();
            Box::new(*convert)
        } else {
            panic!("Unsupported degree");
        }
    }
}

#[cfg(test)]
#[allow(unused_imports)]
pub(crate) mod tests {

    use super::Poseidon2WideChip;
    use crate::{
        compiler::recursion_v2::{
            instruction::{mem, poseidon2},
            program::RecursionProgram,
        },
        machine::{chip::ChipBehavior, logger::setup_logger},
        primitives::{
            consts::{
                BABYBEAR_NUM_EXTERNAL_ROUNDS, BABYBEAR_NUM_INTERNAL_ROUNDS,
                KOALABEAR_NUM_EXTERNAL_ROUNDS, KOALABEAR_NUM_INTERNAL_ROUNDS, PERMUTATION_WIDTH,
            },
            pico_poseidon2bb_init, pico_poseidon2kb_init,
        },
        recursion_v2::{
            runtime::RecursionRecord,
            //tests::run_recursion_test_machine,
            types::{MemAccessKind, Poseidon2Event},
        },
    };
    use p3_baby_bear::BabyBear;
    use p3_field::{FieldAlgebra, PrimeField32};
    use p3_koala_bear::KoalaBear;
    use p3_matrix::dense::RowMajorMatrix;
    use p3_symmetric::Permutation;
    use rand::{prelude::StdRng, SeedableRng};
    use std::{iter::once, marker::PhantomData};
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
        let chip_3 = Poseidon2WideChip::<
            3,
            BABYBEAR_NUM_EXTERNAL_ROUNDS,
            BABYBEAR_NUM_INTERNAL_ROUNDS,
            { BABYBEAR_NUM_INTERNAL_ROUNDS - 1 },
            F,
        > {
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
        let chip_3 = Poseidon2WideChip::<
            3,
            KOALABEAR_NUM_EXTERNAL_ROUNDS,
            KOALABEAR_NUM_INTERNAL_ROUNDS,
            { KOALABEAR_NUM_INTERNAL_ROUNDS - 1 },
            F,
        > {
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
        let chip_9 = Poseidon2WideChip::<
            9,
            BABYBEAR_NUM_EXTERNAL_ROUNDS,
            BABYBEAR_NUM_INTERNAL_ROUNDS,
            { BABYBEAR_NUM_INTERNAL_ROUNDS - 1 },
            F,
        > {
            _phantom: PhantomData,
        };
        let main_trace: RowMajorMatrix<F> =
            chip_9.generate_main(&chunk, &mut RecursionRecord::default());
        println!("{:?}", main_trace.values)
    }

    /*
    #[test]
    fn test_poseidon2_wide_v2() {
        setup_logger();

        let input = [1; WIDTH];
        let output = pico_poseidon2bb_init()
            .permute(input.map(BabyBear::from_canonical_u32))
            .map(|x| BabyBear::as_canonical_u32(&x));

        let rng = &mut rand::thread_rng();
        let input_1: [BabyBear; WIDTH] = std::array::from_fn(|_| BabyBear::rand(rng));
        let output_1 = pico_poseidon2bb_init()
            .permute(input_1)
            .map(|x| BabyBear::as_canonical_u32(&x));
        let input_1 = input_1.map(|x| BabyBear::as_canonical_u32(&x));

        let instructions = (0..WIDTH)
            .map(|i| mem(MemAccessKind::Write, 1, i as u32, input[i]))
            .chain(once(poseidon2(
                [1; WIDTH],
                std::array::from_fn(|i| (i + WIDTH) as u32),
                std::array::from_fn(|i| i as u32),
            )))
            .chain((0..WIDTH).map(|i| mem(MemAccessKind::Read, 1, (i + WIDTH) as u32, output[i])))
            .chain(
                (0..WIDTH)
                    .map(|i| mem(MemAccessKind::Write, 1, (2 * WIDTH + i) as u32, input_1[i])),
            )
            .chain(once(poseidon2(
                [1; WIDTH],
                std::array::from_fn(|i| (i + 3 * WIDTH) as u32),
                std::array::from_fn(|i| (i + 2 * WIDTH) as u32),
            )))
            .chain(
                (0..WIDTH)
                    .map(|i| mem(MemAccessKind::Read, 1, (i + 3 * WIDTH) as u32, output_1[i])),
            )
            .collect::<Vec<_>>();

        let program = RecursionProgram {
            instructions,
            ..Default::default()
        };
        run_recursion_test_machine(program);
    }
    */
}
