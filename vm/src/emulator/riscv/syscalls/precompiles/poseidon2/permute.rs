use super::event::Poseidon2PermuteEvent;
use crate::{
    configs::config::Poseidon2Config,
    emulator::riscv::syscalls::{
        precompiles::PrecompileEvent, syscall_context::SyscallContext, Syscall, SyscallCode,
    },
    machine::field::{FieldBehavior, FieldType},
    primitives::{consts::PERMUTATION_WIDTH, Poseidon2Init},
};
use p3_baby_bear::BabyBear;
use p3_field::{FieldAlgebra, PrimeField32};
use p3_koala_bear::KoalaBear;
use p3_mersenne_31::Mersenne31;
use p3_symmetric::Permutation;
use std::marker::PhantomData;

#[allow(clippy::type_complexity)]
pub(crate) struct Poseidon2PermuteSyscall<F, Config>(
    pub(crate) PhantomData<fn(F, Config) -> (F, Config)>,
);

impl<F: PrimeField32, Config: Poseidon2Config> Syscall for Poseidon2PermuteSyscall<F, Config> {
    fn num_extra_cycles(&self) -> u32 {
        1
    }

    fn emulate(
        &self,
        ctx: &mut SyscallContext,
        syscall_code: SyscallCode,
        arg1: u32,
        arg2: u32,
    ) -> Option<u32> {
        if F::field_type() == FieldType::TypeBabyBear {
            assert_eq!(
                syscall_code.syscall_id(),
                SyscallCode::POSEIDON2_PERMUTE_BB.syscall_id()
            );
        }

        if F::field_type() == FieldType::TypeKoalaBear {
            assert_eq!(
                syscall_code.syscall_id(),
                SyscallCode::POSEIDON2_PERMUTE_KB.syscall_id()
            );
        }

        if F::field_type() == FieldType::TypeMersenne31 {
            assert_eq!(
                syscall_code.syscall_id(),
                SyscallCode::POSEIDON2_PERMUTE_M31.syscall_id()
            );
        }

        let clk_init = ctx.clk;
        let input_memory_ptr = arg1;
        let output_memory_ptr = arg2;

        let mut state_read_records = Vec::new();
        let mut state_write_records = Vec::new();

        let (state_records, state_values) = ctx.mr_slice(input_memory_ptr, PERMUTATION_WIDTH);
        state_read_records.extend_from_slice(&state_records);

        let state: [F; PERMUTATION_WIDTH] = state_values
            .clone()
            .into_iter()
            .map(F::from_canonical_u32)
            .collect::<Vec<F>>()
            .try_into()
            .unwrap();

        let state = match F::field_type() {
            FieldType::TypeBabyBear => {
                let perm = crate::configs::stark_config::BabyBearPoseidon2::init();
                perm.permute(state.map(|x| BabyBear::from_canonical_u32(x.as_canonical_u32())))
                    .map(|x| F::from_canonical_u32(x.as_canonical_u32()))
            }
            FieldType::TypeKoalaBear => {
                let perm = crate::configs::stark_config::KoalaBearPoseidon2::init();
                perm.permute(state.map(|x| KoalaBear::from_canonical_u32(x.as_canonical_u32())))
                    .map(|x| F::from_canonical_u32(x.as_canonical_u32()))
            }
            FieldType::TypeMersenne31 => {
                let perm = crate::configs::stark_config::M31Poseidon2::init();
                perm.permute(state.map(|x| Mersenne31::from_canonical_u32(x.as_canonical_u32())))
                    .map(|x| F::from_canonical_u32(x.as_canonical_u32()))
            }
            _ => unimplemented!("Unsupported field type"),
        };

        // Increment the clk by 1 before writing because we read from memory at start_clk.
        ctx.clk += 1;

        let write_records = ctx.mw_slice(
            output_memory_ptr,
            state
                .into_iter()
                .map(|f| f.as_canonical_u32())
                .collect::<Vec<_>>()
                .as_slice(),
        );
        state_write_records.extend_from_slice(&write_records);

        let chunk = ctx.current_chunk();
        let event = Poseidon2PermuteEvent {
            chunk,
            clk: clk_init,
            state_values,
            input_memory_ptr,
            output_memory_ptr,
            state_read_records,
            state_write_records,
            local_mem_access: ctx.postprocess(),
        };

        let syscall_event = ctx
            .rt
            .syscall_event(clk_init, syscall_code.syscall_id(), arg1, arg2);
        ctx.record_mut().add_precompile_event(
            syscall_code,
            syscall_event,
            PrecompileEvent::Poseidon2Permute(event),
        );

        None
    }
}
