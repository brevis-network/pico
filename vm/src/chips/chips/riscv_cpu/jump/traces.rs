use super::super::{columns::CpuCols, CpuChip};
use crate::{
    chips::{
        chips::{alu::event::AluEvent, riscv_cpu::event::CpuEvent},
        utils::create_alu_lookups,
    },
    compiler::{riscv::opcode::Opcode, word::Word},
};
use hashbrown::HashMap;
use p3_field::Field;

impl<F: Field> CpuChip<F> {
    /// Populate columns related to jumping.
    pub(crate) fn populate_jump(
        &self,
        cols: &mut CpuCols<F>,
        event: &CpuEvent,
        alu_events: &mut HashMap<Opcode, Vec<AluEvent>>,
    ) {
        if event.instruction.is_jump_instruction() {
            let jump_columns = cols.opcode_specific.jump_mut();

            match event.instruction.opcode {
                Opcode::JAL => {
                    let next_pc = event.pc.wrapping_add(event.b);
                    jump_columns.op_a_range_checker.populate(event.a);
                    jump_columns.pc = Word::from(event.pc);
                    jump_columns.pc_range_checker.populate(event.pc);
                    jump_columns.next_pc = Word::from(next_pc);
                    jump_columns.next_pc_range_checker.populate(next_pc);

                    let add_event = AluEvent {
                        lookup_id: event.jump_jal_lookup_id,
                        chunk: event.chunk,
                        clk: event.clk,
                        opcode: Opcode::ADD,
                        a: next_pc,
                        b: event.pc,
                        c: event.b,
                        sub_lookups: create_alu_lookups(),
                    };

                    alu_events
                        .entry(Opcode::ADD)
                        .and_modify(|op_new_events| op_new_events.push(add_event))
                        .or_insert(vec![add_event]);
                }
                Opcode::JALR => {
                    let next_pc = event.b.wrapping_add(event.c);
                    jump_columns.op_a_range_checker.populate(event.a);
                    jump_columns.next_pc = Word::from(next_pc);
                    jump_columns.next_pc_range_checker.populate(next_pc);

                    let add_event = AluEvent {
                        lookup_id: event.jump_jalr_lookup_id,
                        chunk: event.chunk,
                        clk: event.clk,
                        opcode: Opcode::ADD,
                        a: next_pc,
                        b: event.b,
                        c: event.c,
                        sub_lookups: create_alu_lookups(),
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
