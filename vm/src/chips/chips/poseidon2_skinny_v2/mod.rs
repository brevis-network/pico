use crate::configs::config::Poseidon2Config;
use core::marker::PhantomData;
use typenum::Unsigned;

pub mod columns;
pub mod constraints;
pub mod trace;

/// A chip that implements the Poseidon2 permutation in the skinny variant
/// (one external round per row and one row for all internal rounds).
pub struct Poseidon2SkinnyChip<const DEGREE: usize, Config, F>(
    PhantomData<fn(F, Config) -> (F, Config)>,
);

impl<const DEGREE: usize, Config: Poseidon2Config, F> Poseidon2SkinnyChip<DEGREE, Config, F> {
    const NUM_POSEIDON2_COLS: usize = columns::num_poseidon2_cols::<Config>();
    const NUM_EXTERNAL_ROUNDS: usize = Config::ExternalRounds::USIZE;
    const NUM_INTERNAL_ROUNDS: usize = Config::InternalRounds::USIZE;
    const INTERNAL_ROUND_IDX: usize = Self::NUM_EXTERNAL_ROUNDS / 2 + 1;
    const OUTPUT_ROUND_IDX: usize = Self::NUM_EXTERNAL_ROUNDS + 2;
}

impl<const DEGREE: usize, Config, F> Default for Poseidon2SkinnyChip<DEGREE, Config, F> {
    fn default() -> Self {
        // We only support machines with degree 9.
        assert!(DEGREE >= 9);
        Self(PhantomData)
    }
}

#[cfg(test)]
#[allow(unused_imports)]
mod tests {
    use super::Poseidon2SkinnyChip;
    use crate::{
        compiler::recursion_v2::{
            instruction::{mem, poseidon2},
            program::RecursionProgram,
        },
        machine::chip::ChipBehavior,
        primitives::{
            consts::{
                BabyBearConfig, KoalaBearConfig, BABYBEAR_NUM_EXTERNAL_ROUNDS,
                BABYBEAR_NUM_INTERNAL_ROUNDS, KOALABEAR_NUM_EXTERNAL_ROUNDS,
                KOALABEAR_NUM_INTERNAL_ROUNDS, PERMUTATION_WIDTH,
            },
            pico_poseidon2bb_init, pico_poseidon2kb_init,
        },
        recursion_v2::{
            runtime::RecursionRecord,
            //tests::run_recursion_wrap_test_machine,
            types::{MemAccessKind, Poseidon2Event},
        },
    };
    use p3_baby_bear::BabyBear;
    use p3_field::{FieldAlgebra, PrimeField32};
    use p3_koala_bear::KoalaBear;
    use p3_matrix::dense::RowMajorMatrix;
    use p3_symmetric::Permutation;
    use std::{array, iter::once};
    use zkhash::ark_ff::UniformRand;

    #[test]
    fn recursion_babybear_poseidon2_skinny_generate_main() {
        type F = BabyBear;
        let input_0 = [F::ONE; PERMUTATION_WIDTH];
        let permuter = pico_poseidon2bb_init();
        let output_0 = permuter.permute(input_0);
        let mut rng = rand::thread_rng();

        let input_1 = [F::rand(&mut rng); PERMUTATION_WIDTH];
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
        let chip_9 = Poseidon2SkinnyChip::<9, BabyBearConfig, _>::default();
        let trace: RowMajorMatrix<F> =
            chip_9.generate_main(&chunk, &mut RecursionRecord::default());
        println!("Poseidon2 skinny chip: trace = {:?}", trace.values);
    }

    #[test]
    fn recursion_koalabear_poseidon2_skinny_generate_main() {
        type F = KoalaBear;
        let input_0 = [F::ONE; PERMUTATION_WIDTH];
        let permuter = pico_poseidon2kb_init();
        let output_0 = permuter.permute(input_0);
        let mut rng = rand::thread_rng();

        let input_1 = [F::rand(&mut rng); PERMUTATION_WIDTH];
        let output_1 = permuter.permute(input_1);
        let chunk = RecursionRecord::<KoalaBear> {
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
        let chip_3 = Poseidon2SkinnyChip::<9, KoalaBearConfig, _>::default();
        let trace: RowMajorMatrix<F> =
            chip_3.generate_main(&chunk, &mut RecursionRecord::default());
        println!("Poseidon2 skinny chip: trace = {:?}", trace.values);
    }

    /*
    #[test]
    fn recursion_poseidon2_skinny_chip_prove() {
        let input = [1; PERMUTATION_WIDTH];
        let output = pico_poseidon2bb_init()
            .permute(input.map(BabyBear::from_canonical_u32))
            .map(|x| BabyBear::as_canonical_u32(&x));

        let rng = &mut rand::thread_rng();
        let input_1: [BabyBear; PERMUTATION_WIDTH] = std::array::from_fn(|_| BabyBear::rand(rng));
        let output_1 = pico_poseidon2bb_init()
            .permute(input_1)
            .map(|x| BabyBear::as_canonical_u32(&x));
        let input_1 = input_1.map(|x| BabyBear::as_canonical_u32(&x));

        let instructions = (0..PERMUTATION_WIDTH)
            .map(|i| mem(MemAccessKind::Write, 1, i as u32, input[i]))
            .chain(once(poseidon2(
                [1; PERMUTATION_WIDTH],
                std::array::from_fn(|i| (i + PERMUTATION_WIDTH) as u32),
                std::array::from_fn(|i| i as u32),
            )))
            .chain((0..PERMUTATION_WIDTH).map(|i| mem(MemAccessKind::Read, 1, (i + PERMUTATION_WIDTH) as u32, output[i])))
            .chain(
                (0..PERMUTATION_WIDTH)
                    .map(|i| mem(MemAccessKind::Write, 1, (2 * PERMUTATION_WIDTH + i) as u32, input_1[i])),
            )
            .chain(once(poseidon2(
                [1; PERMUTATION_WIDTH],
                array::from_fn(|i| (i + 3 * PERMUTATION_WIDTH) as u32),
                array::from_fn(|i| (i + 2 * PERMUTATION_WIDTH) as u32),
            )))
            .chain(
                (0..PERMUTATION_WIDTH)
                    .map(|i| mem(MemAccessKind::Read, 1, (i + 3 * PERMUTATION_WIDTH) as u32, output_1[i])),
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
