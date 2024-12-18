use std::marker::PhantomData;

pub mod columns;
pub mod constraints;
pub mod event;
pub mod traces;

#[derive(Default)]
pub struct FriFoldChip<const DEGREE: usize, F>(PhantomData<F>);

#[cfg(test)]
mod tests {
    use super::{event::FriFoldEvent, FriFoldChip};
    use crate::{
        compiler::recursion_v2::{
            instruction::{fri_fold, mem_block, mem_single, Instruction},
            program::RecursionProgram,
        },
        configs::{config::StarkGenericConfig, stark_config::bb_poseidon2::BabyBearPoseidon2},
        machine::chip::ChipBehavior,
        recursion_v2::{
            air::Block,
            runtime::RecursionRecord,
            //tests::run_recursion_test_machine,
            types::{FriFoldBaseIo, FriFoldExtSingleIo, FriFoldExtVecIo, MemAccessKind},
        },
    };
    use itertools::Itertools;
    use p3_field::{FieldAlgebra, FieldExtensionAlgebra};
    use p3_matrix::dense::RowMajorMatrix;
    use rand::{rngs::ThreadRng, thread_rng, Rng};
    use std::mem::size_of;

    type SC = BabyBearPoseidon2;
    type F = <SC as StarkGenericConfig>::Val;
    type EF = <SC as StarkGenericConfig>::Challenge;

    #[test]
    #[allow(unused_variables)]
    fn test_recursion_fri_fold_chip_proving() {
        let rng = &mut thread_rng();

        let mut addr = 0;

        let num_ext_vecs: u32 = size_of::<FriFoldExtVecIo<u8>>() as u32;
        let num_singles: u32 =
            size_of::<FriFoldBaseIo<u8>>() as u32 + size_of::<FriFoldExtSingleIo<u8>>() as u32;

        let instructions = (2..17)
            .flat_map(|i: u32| {
                let alloc_size = i * (num_ext_vecs + 2) + num_singles;

                // Allocate the memory for a FRI fold instruction. Here, i is the lengths
                // of the vectors for the vector fields of the instruction.
                let mat_opening_a = (0..i).map(|x| x + addr).collect::<Vec<_>>();
                let ps_at_z_a = (0..i).map(|x| x + i + addr).collect::<Vec<_>>();

                let alpha_pow_input_a = (0..i).map(|x: u32| x + addr + 2 * i).collect::<Vec<_>>();
                let ro_input_a = (0..i).map(|x: u32| x + addr + 3 * i).collect::<Vec<_>>();

                let alpha_pow_output_a = (0..i).map(|x: u32| x + addr + 4 * i).collect::<Vec<_>>();
                let ro_output_a = (0..i).map(|x: u32| x + addr + 5 * i).collect::<Vec<_>>();

                let x_a = addr + 6 * i;
                let z_a = addr + 6 * i + 1;
                let alpha_a = addr + 6 * i + 2;

                addr += alloc_size;

                // Generate random values for the inputs.
                let x = random_felt(rng);
                let z = random_block(rng);
                let alpha = random_block(rng);

                let alpha_pow_input = (0..i).map(|_| random_block(rng)).collect::<Vec<_>>();
                let ro_input = (0..i).map(|_| random_block(rng)).collect::<Vec<_>>();

                let ps_at_z = (0..i).map(|_| random_block(rng)).collect::<Vec<_>>();
                let mat_opening = (0..i).map(|_| random_block(rng)).collect::<Vec<_>>();

                // Compute the outputs from the inputs.
                let alpha_pow_output = (0..i)
                    .map(|i| alpha_pow_input[i as usize].ext::<EF>() * alpha.ext::<EF>())
                    .collect::<Vec<EF>>();
                let ro_output = (0..i)
                    .map(|i| {
                        let i = i as usize;
                        ro_input[i].ext::<EF>()
                            + alpha_pow_input[i].ext::<EF>()
                                * (-ps_at_z[i].ext::<EF>() + mat_opening[i].ext::<EF>())
                                / (-z.ext::<EF>() + x)
                    })
                    .collect::<Vec<EF>>();

                // Write the inputs to memory.
                let mut instructions = vec![mem_single(MemAccessKind::Write, 1, x_a, x)];

                instructions.push(mem_block(MemAccessKind::Write, 1, z_a, z));

                instructions.push(mem_block(MemAccessKind::Write, 1, alpha_a, alpha));

                (0..i).for_each(|j_32| {
                    let j = j_32 as usize;
                    instructions.push(mem_block(
                        MemAccessKind::Write,
                        1,
                        mat_opening_a[j],
                        mat_opening[j],
                    ));
                    instructions.push(mem_block(MemAccessKind::Write, 1, ps_at_z_a[j], ps_at_z[j]));

                    instructions.push(mem_block(
                        MemAccessKind::Write,
                        1,
                        alpha_pow_input_a[j],
                        alpha_pow_input[j],
                    ));
                    instructions.push(mem_block(
                        MemAccessKind::Write,
                        1,
                        ro_input_a[j],
                        ro_input[j],
                    ));
                });

                // Generate the FRI fold instruction.
                instructions.push(fri_fold(
                    z_a,
                    alpha_a,
                    x_a,
                    mat_opening_a.clone(),
                    ps_at_z_a.clone(),
                    alpha_pow_input_a.clone(),
                    ro_input_a.clone(),
                    alpha_pow_output_a.clone(),
                    ro_output_a.clone(),
                    vec![1; i as usize],
                    vec![1; i as usize],
                ));

                // Read all the outputs.
                (0..i).for_each(|j| {
                    let j = j as usize;
                    instructions.push(mem_block(
                        MemAccessKind::Read,
                        1,
                        alpha_pow_output_a[j],
                        Block::from(alpha_pow_output[j].as_base_slice()),
                    ));
                    instructions.push(mem_block(
                        MemAccessKind::Read,
                        1,
                        ro_output_a[j],
                        Block::from(ro_output[j].as_base_slice()),
                    ));
                });

                instructions
            })
            .collect::<Vec<Instruction<F>>>();

        let program = RecursionProgram {
            instructions,
            ..Default::default()
        };

        //run_recursion_test_machine(program);
    }

    #[test]
    fn test_recursion_fri_fold_chip_trace_generation() {
        let rng = &mut thread_rng();

        let shard = RecursionRecord {
            fri_fold_events: (0..17)
                .map(|_| FriFoldEvent {
                    base_single: FriFoldBaseIo {
                        x: random_felt(rng),
                    },
                    ext_single: FriFoldExtSingleIo {
                        z: random_block(rng),
                        alpha: random_block(rng),
                    },
                    ext_vec: FriFoldExtVecIo {
                        mat_opening: random_block(rng),
                        ps_at_z: random_block(rng),
                        alpha_pow_input: random_block(rng),
                        ro_input: random_block(rng),
                        alpha_pow_output: random_block(rng),
                        ro_output: random_block(rng),
                    },
                })
                .collect_vec(),
            ..Default::default()
        };
        let chip = FriFoldChip::<3, F>::default();
        let trace: RowMajorMatrix<F> = chip.generate_main(&shard, &mut RecursionRecord::default());
        println!("{:?}", trace.values);
    }

    fn random_felt(rng: &mut ThreadRng) -> F {
        F::from_canonical_u32(rng.gen_range(0..=u16::MAX as u32))
    }

    fn random_block(rng: &mut ThreadRng) -> Block<F> {
        Block::from([random_felt(rng); 4])
    }
}
