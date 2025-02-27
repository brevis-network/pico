use std::borrow::Borrow;

use super::{columns::Poseidon2Cols, Poseidon2PermuteChip};
use crate::{
    chips::{
        chips::riscv_memory::read_write::columns::MemoryCols,
        gadgets::poseidon2::constraints::eval_poseidon2,
    },
    configs::config::Poseidon2Config,
    emulator::riscv::syscalls::SyscallCode,
    machine::{
        builder::{ChipBaseBuilder, ChipBuilder, ChipLookupBuilder, RiscVMemoryBuilder},
        field::{FieldBehavior, FieldType},
    },
    primitives::consts::PERMUTATION_WIDTH,
};
use p3_air::Air;
use p3_field::{FieldAlgebra, PrimeField32};
use p3_matrix::Matrix;
use p3_poseidon2::GenericPoseidon2LinearLayers;

impl<
        F: PrimeField32,
        LinearLayers: GenericPoseidon2LinearLayers<CB::Expr, PERMUTATION_WIDTH>,
        Config: Poseidon2Config,
        CB: ChipBuilder<F>,
    > Air<CB> for Poseidon2PermuteChip<F, LinearLayers, Config>
where
    CB::Var: Sized,
{
    fn eval(&self, builder: &mut CB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &Poseidon2Cols<CB::Var, Config> = (*local).borrow();

        // Load from memory to the state
        for (i, word) in local.input_memory.iter().enumerate() {
            builder.assert_eq(local.value_cols.inputs[i], word.value().reduce::<CB>());
        }

        let state = eval_poseidon2::<F, CB, LinearLayers, Config>(
            builder,
            &local.value_cols,
            &self.constants,
        );

        // Assert that the permuted state is being written to input_memory.
        builder.when(local.value_cols.is_real).assert_all_eq(
            state.into_iter().collect::<Vec<CB::Expr>>(),
            local
                .output_memory
                .into_iter()
                .map(|f| f.value().reduce::<CB>())
                .collect::<Vec<CB::Expr>>(),
        );

        // Read input_memory.
        builder.eval_memory_access_slice(
            local.chunk,
            local.clk.into(),
            local.input_memory_ptr,
            &local.input_memory,
            local.value_cols.is_real,
        );

        // Write output_memory.
        builder.eval_memory_access_slice(
            local.chunk,
            local.clk.into() + CB::Expr::ONE,
            local.output_memory_ptr,
            &local.output_memory,
            local.value_cols.is_real,
        );

        let syscall_code = match F::field_type() {
            FieldType::TypeBabyBear => SyscallCode::POSEIDON2_PERMUTE_BB,
            FieldType::TypeKoalaBear => SyscallCode::POSEIDON2_PERMUTE_KB,
            FieldType::TypeMersenne31 => SyscallCode::POSEIDON2_PERMUTE_M31,
            _ => unimplemented!("Unsupported field type"),
        };

        builder.looked_syscall(
            local.clk,
            CB::F::from_canonical_u32(syscall_code.syscall_id()),
            local.input_memory_ptr,
            local.output_memory_ptr,
            local.value_cols.is_real,
        );

        // Assert that is_real is a boolean.
        builder.assert_bool(local.value_cols.is_real);
    }
}
