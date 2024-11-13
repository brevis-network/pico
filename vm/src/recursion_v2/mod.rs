pub mod air;
pub mod runtime;
pub mod types;

#[cfg(test)]
pub mod tests {
    use crate::{
        compiler::recursion_v2::program::RecursionProgram,
        configs::{config::StarkGenericConfig, stark_config::bb_poseidon2::BabyBearPoseidon2},
        instances::{
            chiptype::recursion_chiptype_v2::RecursionChipType,
            machine::simple_machine::SimpleMachine,
        },
        machine::{machine::MachineBehavior, witness::ProvingWitness},
        primitives::consts_v2::MAX_NUM_PVS,
        recursion_v2::runtime::Runtime,
    };
    use std::sync::Arc;

    type SC = BabyBearPoseidon2;
    type F = <SC as StarkGenericConfig>::Val;
    type EF = <SC as StarkGenericConfig>::Challenge;

    // Test the given program with the test recursion machine.
    pub fn run_recursion_test_machine(program: RecursionProgram<F>) {
        // Execute the runtime and get the recursion record.
        let program = Arc::new(program);
        let record = {
            let mut runtime = Runtime::<F, EF, _>::new(program.clone(), SC::new().perm);
            runtime.run().unwrap();
            runtime.record
        };

        // Setup the machine and get the PK and VK.
        let machine = SimpleMachine::new(
            SC::new(),
            RecursionChipType::<F, 3>::all_chips(),
            MAX_NUM_PVS,
        );
        let (pk, vk) = machine.setup_keys(&program);

        // Prove with witness.
        let witness = ProvingWitness::setup_with_records(vec![record]);
        let proof = machine.prove(&pk, &witness);

        // Verify the result.
        let verified_result = machine.verify(&vk, &proof);
        assert!(verified_result.is_ok());
    }
}
