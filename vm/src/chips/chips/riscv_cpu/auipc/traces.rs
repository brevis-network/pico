use super::super::CpuChip;
use crate::{
    chips::chips::{alu::event::AluEvent, riscv_cpu::event::CpuEvent},
    compiler::riscv::opcode::Opcode,
};
use hashbrown::HashMap;
use p3_field::Field;

impl<F: Field> CpuChip<F> {
    /// Populate columns related to AUIPC.
    pub(crate) fn populate_auipc(
        &self,
        event: &CpuEvent,
        alu_events: &mut HashMap<Opcode, Vec<AluEvent>>,
    ) {
        // `auipc x0, imm` discards its result, and the AIR does not dispatch an ALU
        // lookup for it (`auipc/constraints.rs`, gated on `1 - op_a_0`). Emitting the event
        // anyway would leave the Add chip supplying an unmatched row.
        if matches!(event.instruction.opcode, Opcode::AUIPC) && event.instruction.op_a != 0 {
            // Create ALU event with full 64-bit values
            let add_event = AluEvent {
                clk: event.clk,
                opcode: Opcode::ADD,
                a: event.a,
                b: event.pc,
                c: event.b,
                ..Default::default()
            };

            alu_events
                .entry(Opcode::ADD)
                .and_modify(|op_new_events| op_new_events.push(add_event))
                .or_insert(vec![add_event]);
        }
    }
}
