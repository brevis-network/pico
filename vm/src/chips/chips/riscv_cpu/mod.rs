use std::marker::PhantomData;

pub mod branch;
pub mod chunk_clk;
pub mod columns;
pub mod constraints;
pub mod ecall;
pub mod event;
pub mod instruction;
pub mod jump;
pub mod opcode_selector;
pub mod public_values;
pub mod register;
pub mod traces;
pub mod utils;

#[derive(Default)]
pub struct CpuChip<F>(PhantomData<F>);

#[cfg(test)]
mod interaction_pins {
    use super::CpuChip;
    use crate::primitives::consts::MAX_NUM_PVS;
    use p3_air::BaseAir;
    use p3_koala_bear::KoalaBear;
    use pico_mle_core::{
        air::symbolic::get_symbolic_builder_with_public_values, keygen::types::TraceWidth,
    };

    type F = KoalaBear;

    /// Pins the Cpu chip's interaction count (17: Program, 6 register timestamp lookups, 6
    /// register memory accesses and the MemRW / Alu / CMP / Ecall dispatches; the row chain is
    /// rotation constraints, not messages, the JALR target is proven in-chip and the jump-row
    /// return address is made canonical by the Program table's `pc_carry` column) and its
    /// constraint degree. A change here is a change to the LogUp cost model: the round-0 and
    /// GKR work of every Cpu chunk scales with this count.
    #[test]
    fn cpu_interaction_count_pin() {
        let chip = CpuChip::<F>::default();
        let width = TraceWidth {
            preprocessed: None,
            cached_mains: vec![],
            common_main: BaseAir::<F>::width(&chip),
        };
        let builder = get_symbolic_builder_with_public_values::<F, _>(&chip, &width, MAX_NUM_PVS);
        let constraints = builder.constraints();
        assert_eq!(constraints.max_constraint_degree(), 3);
        assert_eq!(constraints.interactions.len(), 17);
    }
}
