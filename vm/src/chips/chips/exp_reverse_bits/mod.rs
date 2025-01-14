pub mod columns;
pub mod constraints;
pub mod traces;

use columns::*;
use std::marker::PhantomData;

#[derive(Clone, Debug, Copy, Default)]
pub struct ExpReverseBitsLenChip<F> {
    pub _phantom: PhantomData<fn(F) -> F>,
}

#[cfg(test)]
mod tests {
    use itertools::Itertools;
    use p3_util::reverse_bits_len;
    use rand::{rngs::StdRng, Rng, SeedableRng};
    use std::iter::once;

    use p3_baby_bear::BabyBear;
    use p3_field::{FieldAlgebra, PrimeField32};
    use p3_matrix::dense::RowMajorMatrix;

    use crate::{
        compiler::recursion_v2::{
            instruction::{self, Instruction},
            program::RecursionProgram,
        },
        machine::{chip::ChipBehavior, logger::setup_logger},
        recursion_v2::{
            runtime::RecursionRecord,
            //tests::run_recursion_test_machine,
            types::{ExpReverseBitsEvent, MemAccessKind},
        },
    };

    use super::*;

    #[test]
    #[allow(unused_variables)]
    fn prove_babybear_circuit_erbl() {
        setup_logger();
        type F = BabyBear;

        let mut rng = StdRng::seed_from_u64(0xDEADBEEF);
        let mut random_felt = move || -> F { F::from_canonical_u32(rng.gen_range(0..1 << 16)) };
        let mut rng = StdRng::seed_from_u64(0xDEADBEEF);
        let mut random_bit = move || rng.gen_range(0..2);
        let mut addr = 0;

        let instructions = (1..15)
            .flat_map(|i| {
                let base = random_felt();
                let exponent_bits = vec![random_bit(); i];
                let exponent = F::from_canonical_u32(
                    exponent_bits
                        .iter()
                        .enumerate()
                        .fold(0, |acc, (i, x)| acc + x * (1 << i)),
                );
                let result =
                    base.exp_u64(reverse_bits_len(exponent.as_canonical_u32() as usize, i) as u64);

                let alloc_size = i + 2;
                let exp_a = (0..i).map(|x| x + addr + 1).collect::<Vec<_>>();
                let exp_a_clone = exp_a.clone();
                let x_a = addr;
                let result_a = addr + alloc_size - 1;
                addr += alloc_size;
                let exp_bit_instructions = (0..i).map(move |j| {
                    instruction::mem_single(
                        MemAccessKind::Write,
                        1,
                        exp_a_clone[j] as u32,
                        F::from_canonical_u32(exponent_bits[j]),
                    )
                });
                once(instruction::mem_single(
                    MemAccessKind::Write,
                    1,
                    x_a as u32,
                    base,
                ))
                .chain(exp_bit_instructions)
                .chain(once(instruction::exp_reverse_bits_len(
                    1,
                    F::from_canonical_u32(x_a as u32),
                    exp_a
                        .into_iter()
                        .map(|bit| F::from_canonical_u32(bit as u32))
                        .collect_vec(),
                    F::from_canonical_u32(result_a as u32),
                )))
                .chain(once(instruction::mem_single(
                    MemAccessKind::Read,
                    1,
                    result_a as u32,
                    result,
                )))
            })
            .collect::<Vec<Instruction<F>>>();

        let program = RecursionProgram {
            instructions,
            ..Default::default()
        };

        //run_recursion_test_machine(program);
    }

    #[test]
    fn generate_erbl_circuit_main_trace() {
        type F = BabyBear;

        let chunk = RecursionRecord {
            exp_reverse_bits_len_events: vec![ExpReverseBitsEvent {
                base: F::TWO,
                exp: vec![F::ZERO, F::ONE, F::ONE],
                result: F::TWO.exp_u64(0b110),
            }],
            ..Default::default()
        };
        let chip = ExpReverseBitsLenChip::<F> {
            _phantom: PhantomData,
        };
        let main_trace: RowMajorMatrix<F> =
            chip.generate_main(&chunk, &mut RecursionRecord::default());
        println!("{:?}", main_trace.values)
    }
}
