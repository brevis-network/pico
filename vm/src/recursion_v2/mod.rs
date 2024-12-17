pub mod air;
pub mod runtime;
pub mod stark;
pub mod types;

// Degree for recursion compress machine
pub const RECURSION_COMPRESS_DEGREE: usize = 3;
// Degree for recursion combine machine
pub const RECURSION_COMBINE_DEGREE: usize = 3;
// Degree for recursion embed machine
pub const RECURSION_EMBED_DEGREE: usize = 3;
// Degree for recursion wrap (bn254) machine
pub const RECURSION_WRAP_DEGREE: usize = 9;

#[cfg(test)]
pub mod tests {
    use p3_baby_bear::BabyBear;

    use super::{runtime::Runtime, RECURSION_COMPRESS_DEGREE, RECURSION_WRAP_DEGREE};
    use crate::{
        compiler::recursion_v2::program::RecursionProgram,
        configs::{
            config::{Com, PcsProverData, StarkGenericConfig},
            stark_config::{bb_bn254_poseidon2::BbBn254Poseidon2, bb_poseidon2::BabyBearPoseidon2},
        },
        instances::{
            chiptype::recursion_chiptype_v2::RecursionChipType,
            machine::simple_machine::SimpleMachine,
        },
        machine::{chip::MetaChip, machine::MachineBehavior, witness::ProvingWitness},
        primitives::consts::{BABYBEAR_S_BOX_DEGREE, MAX_NUM_PVS_V2, PERMUTATION_WIDTH},
    };
    use std::sync::Arc;

    type SC = BabyBearPoseidon2;
    type F = <SC as StarkGenericConfig>::Val;
    type EF = <SC as StarkGenericConfig>::Challenge;

    // Only used for the test machine configuration
    type Bn254SC = BbBn254Poseidon2;

    // Test the given program with the test recursion normal (compress) machine.
    pub fn run_recursion_test_machine(program: RecursionProgram<F>) {
        run_recursion_test_machine_for_chips::<RECURSION_COMPRESS_DEGREE, SC>(
            program,
            RecursionChipType::<F, RECURSION_COMPRESS_DEGREE>::all_chips(),
        )
    }

    // Test the given program with the test recursion wrap (bn254) machine.
    pub fn run_recursion_wrap_test_machine(program: RecursionProgram<F>) {
        run_recursion_test_machine_for_chips::<RECURSION_WRAP_DEGREE, Bn254SC>(
            program,
            RecursionChipType::<F, RECURSION_WRAP_DEGREE>::wrap_chips(),
        )
    }
    // Test the given program with the test recursion machine.
    fn run_recursion_test_machine_for_chips<
        const DEGREE: usize,
        SC: Default + StarkGenericConfig<Val = BabyBear>,
    >(
        program: RecursionProgram<F>,
        chips: Vec<MetaChip<F, RecursionChipType<F, DEGREE>>>,
    ) where
        Com<SC>: Send + Sync,
        PcsProverData<SC>: Send + Sync,
    {
        // Execute the runtime and get the recursion record.
        let program = Arc::new(program);
        let record = {
            // We should always use the BabyBearPoseidon2 for permutation.
            let mut runtime = Runtime::<F, EF, _, _, PERMUTATION_WIDTH, BABYBEAR_S_BOX_DEGREE>::new(
                program.clone(),
                BabyBearPoseidon2::new().perm,
            );
            runtime.run().unwrap();
            runtime.record
        };

        // Setup the machine and get the PK and VK.
        // Set the different configuration for the degrees by SC.
        let machine = SimpleMachine::new(SC::default(), chips, MAX_NUM_PVS_V2);
        let (pk, vk) = machine.setup_keys(&program);

        // Prove with witness.
        let witness = ProvingWitness::setup_with_records(vec![record]);
        let proof = machine.prove(&pk, &witness);

        // Verify the result.
        let verified_result = machine.verify(&vk, &proof);
        assert!(verified_result.is_ok());
    }
}
