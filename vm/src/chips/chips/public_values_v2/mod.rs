use std::marker::PhantomData;

mod columns;
mod constraints;
mod traces;

pub(crate) const PUB_VALUES_LOG_HEIGHT: usize = 4;
#[derive(Default)]
pub struct PublicValuesChip<F> {
    _phantom: PhantomData<F>,
}

#[cfg(test)]
mod tests {
    use rand::{rngs::StdRng, Rng, SeedableRng};

    use crate::{
        chips::chips::public_values_v2::PublicValuesChip,
        compiler::recursion_v2::{instruction, program::RecursionProgram},
        machine::{chip::ChipBehavior, logger::setup_logger},
        primitives::consts::{DIGEST_SIZE, RECURSION_NUM_PVS},
        recursion_v2::{
            air::{RecursionPublicValues, NUM_PV_ELMS_TO_HASH},
            runtime::RecursionRecord,
            //tests::run_recursion_test_machine,
            types::{CommitPublicValuesEvent, MemAccessKind},
        },
    };
    use p3_baby_bear::BabyBear;
    use p3_field::FieldAlgebra;
    use p3_matrix::dense::RowMajorMatrix;
    use std::{array, borrow::Borrow, marker::PhantomData};

    #[test]
    #[allow(unused_variables)]
    fn prove_babybear_circuit_public_values() {
        setup_logger();
        type F = BabyBear;

        let mut rng = StdRng::seed_from_u64(0xDEADBEEF);
        let mut random_felt = move || -> F { F::from_canonical_u32(rng.gen_range(0..1 << 16)) };
        let random_pv_elements: [F; RECURSION_NUM_PVS] = array::from_fn(|_| random_felt());
        let addr = 0u32;
        let public_values_addrs: [u32; RECURSION_NUM_PVS] = array::from_fn(|i| i as u32 + addr);

        assert_eq!(
            public_values_addrs.len(),
            RECURSION_NUM_PVS,
            "public_values_addrs length mismatch"
        );
        assert_eq!(
            random_pv_elements.len(),
            RECURSION_NUM_PVS,
            "random_pv_elements length mismatch"
        );

        let mut instructions = Vec::new();
        // Allocate the memory for the public values hash.

        for i in 0..RECURSION_NUM_PVS {
            let mult = (NUM_PV_ELMS_TO_HASH..NUM_PV_ELMS_TO_HASH + DIGEST_SIZE).contains(&i);
            instructions.push(instruction::mem_block(
                MemAccessKind::Write,
                mult as u32,
                public_values_addrs[i],
                random_pv_elements[i].into(),
            ));
        }
        let public_values_addrs: &RecursionPublicValues<u32> =
            public_values_addrs.as_slice().borrow();
        instructions.push(instruction::commit_public_values(public_values_addrs));

        let program = RecursionProgram {
            instructions,
            ..Default::default()
        };

        //run_recursion_test_machine(program);
    }

    #[test]
    fn generate_public_values_circuit_trace() {
        type F = BabyBear;

        let mut rng = StdRng::seed_from_u64(0xDEADBEEF);
        let random_felts: [F; RECURSION_NUM_PVS] =
            array::from_fn(|_| F::from_canonical_u32(rng.gen_range(0..1 << 16)));
        let random_public_values: &RecursionPublicValues<F> = random_felts.as_slice().borrow();
        println!("random_public_values: {:?}", random_public_values);
        let chunk = RecursionRecord {
            commit_pv_hash_events: vec![CommitPublicValuesEvent {
                public_values: *random_public_values,
            }],
            ..Default::default()
        };
        let chip = PublicValuesChip {
            _phantom: PhantomData,
        };
        let trace: RowMajorMatrix<F> = chip.generate_main(&chunk, &mut RecursionRecord::default());
        println!("{:?}", trace.values)
    }
}
