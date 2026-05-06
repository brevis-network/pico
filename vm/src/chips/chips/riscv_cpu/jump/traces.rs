use super::super::CpuChip;
use crate::{
    chips::chips::{alu::event::AluEvent, riscv_cpu::event::CpuEvent},
    compiler::riscv::opcode::Opcode,
};
use hashbrown::HashMap;
use p3_field::Field;

impl<F: Field> CpuChip<F> {
    /// Populate columns related to jumping.
    pub(crate) fn populate_jump(
        &self,
        event: &CpuEvent,
        alu_events: &mut HashMap<Opcode, Vec<AluEvent>>,
    ) {
        if event.instruction.is_jump_instruction() {
            match event.instruction.opcode {
                Opcode::JAL => {
                    let next_pc = event.pc.wrapping_add(event.b);

                    let add_event = AluEvent {
                        clk: event.clk,
                        opcode: Opcode::ADD,
                        a: next_pc,
                        b: event.pc,
                        c: event.b,
                        ..Default::default()
                    };

                    alu_events
                        .entry(Opcode::ADD)
                        .and_modify(|op_new_events| op_new_events.push(add_event))
                        .or_insert(vec![add_event]);
                }
                Opcode::JALR => {
                    let next_pc = event.b.wrapping_add(event.c);

                    let add_event = AluEvent {
                        clk: event.clk,
                        opcode: Opcode::ADD,
                        a: next_pc,
                        b: event.b,
                        c: event.c,
                        ..Default::default()
                    };

                    alu_events
                        .entry(Opcode::ADD)
                        .and_modify(|op_new_events| op_new_events.push(add_event))
                        .or_insert(vec![add_event]);
                }
                _ => unreachable!(),
            }
        }
    }
}
