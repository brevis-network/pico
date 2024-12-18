use std::marker::PhantomData;

mod columns;
mod constraints;
mod traces;

#[derive(Default)]
pub struct BaseAluChip<F> {
    pub _phantom: PhantomData<F>,
}

#[cfg(test)]
mod tests {
    use p3_baby_bear::BabyBear;
    use p3_field::FieldAlgebra;
    use p3_matrix::dense::RowMajorMatrix;

    use super::*;
    use crate::{
        machine::chip::ChipBehavior,
        recursion_v2::{
            runtime::{BaseAluOpcode, RecursionRecord},
            //tests::run_recursion_test_machine,
            types::{BaseAluIo, MemAccessKind},
        },
    };
    use rand::{rngs::StdRng, Rng, SeedableRng};

    use crate::compiler::recursion_v2::{
        instruction::{self, Instruction},
        program::RecursionProgram,
    };

    #[test]
    fn generate_trace() {
        type F = BabyBear;

        let chunk = RecursionRecord {
            base_alu_events: vec![BaseAluIo {
                out: F::ONE,
                in1: F::ONE,
                in2: F::ONE,
            }],
            ..Default::default()
        };
        let chip = BaseAluChip {
            _phantom: PhantomData::<F>,
        };
        let trace: RowMajorMatrix<F> = chip.generate_main(&chunk, &mut RecursionRecord::default());
        println!("{:?}", trace.values)
    }

    #[test]
    #[allow(unused_variables)]
    pub fn four_ops() {
        type F = BabyBear;

        let mut rng = StdRng::seed_from_u64(0xDEADBEEF);
        let mut random_felt = move || -> F { rng.sample(rand::distributions::Standard) };
        let mut addr = 0;

        let instructions = (0..1000)
            .flat_map(|_| {
                let quot = random_felt();
                let in2 = random_felt();
                let in1 = in2 * quot;
                let alloc_size = 6;
                let a = (0..alloc_size).map(|x| x + addr).collect::<Vec<_>>();
                addr += alloc_size;
                [
                    instruction::mem_single(MemAccessKind::Write, 4, a[0], in1),
                    instruction::mem_single(MemAccessKind::Write, 4, a[1], in2),
                    instruction::base_alu(BaseAluOpcode::AddF, 1, a[2], a[0], a[1]),
                    instruction::mem_single(MemAccessKind::Read, 1, a[2], in1 + in2),
                    instruction::base_alu(BaseAluOpcode::SubF, 1, a[3], a[0], a[1]),
                    instruction::mem_single(MemAccessKind::Read, 1, a[3], in1 - in2),
                    instruction::base_alu(BaseAluOpcode::MulF, 1, a[4], a[0], a[1]),
                    instruction::mem_single(MemAccessKind::Read, 1, a[4], in1 * in2),
                    instruction::base_alu(BaseAluOpcode::DivF, 1, a[5], a[0], a[1]),
                    instruction::mem_single(MemAccessKind::Read, 1, a[5], quot),
                ]
            })
            .collect::<Vec<Instruction<F>>>();

        let program = RecursionProgram {
            instructions,
            ..Default::default()
        };

        //run_recursion_test_machine(program);
    }
}
