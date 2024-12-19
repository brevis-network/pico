use std::marker::PhantomData;

pub mod columns;
pub mod constraints;
pub mod trace;
pub mod utils;

/// A chip that implements the Poseidon2 permutation in the skinny variant
/// (one external round per row and one row for all internal rounds).
pub struct Poseidon2SkinnyChip<const DEGREE: usize, F>(PhantomData<F>);

impl<const DEGREE: usize, F> Default for Poseidon2SkinnyChip<DEGREE, F> {
    fn default() -> Self {
        // We only support machines with degree 9.
        assert!(DEGREE >= 9);
        Self(PhantomData)
    }
}

#[cfg(test)]
mod tests {
    use super::{utils::WIDTH, Poseidon2SkinnyChip};
    use crate::{
        compiler::recursion_v2::{
            instruction::{mem, poseidon2},
            program::RecursionProgram,
        },
        machine::chip::ChipBehavior,
        primitives::pico_poseidon2bb_init,
        recursion_v2::{
            runtime::RecursionRecord,
            //tests::run_recursion_wrap_test_machine,
            types::{MemAccessKind, Poseidon2Event},
        },
    };
    use p3_baby_bear::BabyBear;
    use p3_field::{FieldAlgebra, PrimeField32};
    use p3_matrix::dense::RowMajorMatrix;
    use p3_symmetric::Permutation;
    use std::{array, iter::once};
    use zkhash::ark_ff::UniformRand;

    #[test]
    fn recursion_poseidon2_skinny_generate_main() {
        type F = BabyBear;
        let input_0 = [F::ONE; WIDTH];
        let permuter = pico_poseidon2bb_init();
        let output_0 = permuter.permute(input_0);
        let mut rng = rand::thread_rng();

        let input_1 = [F::rand(&mut rng); WIDTH];
        let output_1 = permuter.permute(input_1);
        let chunk = RecursionRecord::<BabyBear> {
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
        let chip_9 = Poseidon2SkinnyChip::<9, _>::default();
        let trace: RowMajorMatrix<F> =
            chip_9.generate_main(&chunk, &mut RecursionRecord::default());
        println!("Poseidon2 skinny chip: trace = {:?}", trace.values);
    }

    /*
    #[test]
    fn recursion_poseidon2_skinny_chip_prove() {
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
                array::from_fn(|i| (i + 3 * WIDTH) as u32),
                array::from_fn(|i| (i + 2 * WIDTH) as u32),
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

        run_recursion_wrap_test_machine(program);
    }
    */
}
