use super::super::{columns::CpuCols, CpuChip};
use crate::{
    chips::chips::{
        alu::event::AluEvent, byte::event::ByteRecordBehavior, riscv_cpu::event::CpuEvent,
    },
    compiler::riscv::opcode::Opcode,
};
use hashbrown::HashMap;
use p3_field::Field;

impl<F: Field> CpuChip<F> {
    /// Populate columns related to jumping.
    pub(crate) fn populate_jump(
        &self,
        cols: &mut CpuCols<F>,
        event: &CpuEvent,
        blu_events: &mut impl ByteRecordBehavior,
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
                    // sum = rs1 + imm (unmasked); next_pc = sum & !1 (= event.next_pc).
                    let sum = event.b.wrapping_add(event.c);
                    let jalr_lsb = (sum & 1) as u32;
                    // next_pc[0] is the low 16-bit limb of event.next_pc; it is always even.
                    let next_pc_low = event.next_pc as u16;

                    cols.opcode_specific.jump_mut().jalr_lsb = F::from_canonical_u32(jalr_lsb);
                    // next_pc[0] / 2 feeds the u16 range check that proves next_pc[0] is even.
                    blu_events.add_u16_range_check(next_pc_low >> 1);

                    // The ALU event proves sum = b + c (i.e. next_pc + jalr_lsb = rs1 + imm).
                    let add_event = AluEvent {
                        clk: event.clk,
                        opcode: Opcode::ADD,
                        a: sum,
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
