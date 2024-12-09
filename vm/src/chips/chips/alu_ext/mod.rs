use std::marker::PhantomData;

mod columns;
mod constraints;
mod traces;

#[derive(Default)]
pub struct ExtAluChip<F> {
    pub _phantom: PhantomData<F>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        compiler::recursion_v2::{
            instruction::{self, Instruction},
            program::RecursionProgram,
        },
        machine::chip::ChipBehavior,
        primitives::consts_v2::EXTENSION_DEGREE,
        recursion_v2::{
            runtime::{ExtAluOpcode, RecursionRecord},
            tests::run_recursion_test_machine,
            types::{ExtAluIo, MemAccessKind},
        },
    };
    use p3_baby_bear::BabyBear;
    use p3_field::{extension::BinomialExtensionField, FieldAlgebra, FieldExtensionAlgebra};
    use p3_matrix::dense::RowMajorMatrix;
    use rand::{rngs::StdRng, Rng, SeedableRng};

    #[test]
    fn generate_trace() {
        type F = BabyBear;

        let chunk = RecursionRecord {
            ext_alu_events: vec![ExtAluIo {
                out: F::ONE.into(),
                in1: F::ONE.into(),
                in2: F::ONE.into(),
            }],
            ..Default::default()
        };
        let chip = ExtAluChip {
            _phantom: PhantomData::<F>,
        };
        let trace: RowMajorMatrix<F> = chip.generate_main(&chunk, &mut RecursionRecord::default());
        println!("{:?}", trace.values)
    }

    #[test]
    pub fn four_ops() {
        type F = BabyBear;

        let mut rng = StdRng::seed_from_u64(0xDEADBEEF);
        let mut random_extfelt = move || {
            let inner: [F; 4] = core::array::from_fn(|_| rng.sample(rand::distributions::Standard));
            BinomialExtensionField::<F, EXTENSION_DEGREE>::from_base_slice(&inner)
        };
        let mut addr = 0;

        let instructions = (0..1000)
            .flat_map(|_| {
                let quot = random_extfelt();
                let in2 = random_extfelt();
                let in1 = in2 * quot;
                let alloc_size = 6;
                let a = (0..alloc_size).map(|x| x + addr).collect::<Vec<_>>();
                addr += alloc_size;
                [
                    instruction::mem_ext(MemAccessKind::Write, 4, a[0], in1),
                    instruction::mem_ext(MemAccessKind::Write, 4, a[1], in2),
                    instruction::ext_alu(ExtAluOpcode::AddE, 1, a[2], a[0], a[1]),
                    instruction::mem_ext(MemAccessKind::Read, 1, a[2], in1 + in2),
                    instruction::ext_alu(ExtAluOpcode::SubE, 1, a[3], a[0], a[1]),
                    instruction::mem_ext(MemAccessKind::Read, 1, a[3], in1 - in2),
                    instruction::ext_alu(ExtAluOpcode::MulE, 1, a[4], a[0], a[1]),
                    instruction::mem_ext(MemAccessKind::Read, 1, a[4], in1 * in2),
                    instruction::ext_alu(ExtAluOpcode::DivE, 1, a[5], a[0], a[1]),
                    instruction::mem_ext(MemAccessKind::Read, 1, a[5], quot),
                ]
            })
            .collect::<Vec<Instruction<F>>>();

        let program = RecursionProgram {
            instructions,
            ..Default::default()
        };

        run_recursion_test_machine(program);
    }
}
