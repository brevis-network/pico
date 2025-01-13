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
    /// Populates columns related to branching.
    pub(crate) fn populate_branch(
        &self,
        cols: &mut CpuCols<F>,
        event: &CpuEvent,
        alu_events: &mut HashMap<Opcode, Vec<AluEvent>>,
    ) {
        if event.instruction.is_branch_instruction() {
            let branch_columns = cols.opcode_specific.branch_mut();

            let a_eq_b = event.a == event.b;

            let use_signed_comparison =
                matches!(event.instruction.opcode, Opcode::BLT | Opcode::BGE);

            let a_lt_b = if use_signed_comparison {
                (event.a as i32) < (event.b as i32)
            } else {
                event.a < event.b
            };
            let a_gt_b = if use_signed_comparison {
                (event.a as i32) > (event.b as i32)
            } else {
                event.a > event.b
            };

            let alu_op_code = if use_signed_comparison {
                Opcode::SLT
            } else {
                Opcode::SLTU
            };

            // Add the ALU events for the comparisons
            let lt_comp_event = AluEvent {
                lookup_id: event.branch_lt_lookup_id,
                chunk: event.chunk,
                clk: event.clk,
                opcode: alu_op_code,
                a: a_lt_b as u32,
                b: event.a,
                c: event.b,
                sub_lookups: create_alu_lookups(),
            };

            alu_events
                .entry(alu_op_code)
                .and_modify(|op_new_events| op_new_events.push(lt_comp_event))
                .or_insert(vec![lt_comp_event]);

            let gt_comp_event = AluEvent {
                lookup_id: event.branch_gt_lookup_id,
                chunk: event.chunk,
                clk: event.clk,
                opcode: alu_op_code,
                a: a_gt_b as u32,
                b: event.b,
                c: event.a,
                sub_lookups: create_alu_lookups(),
            };

            alu_events
                .entry(alu_op_code)
                .and_modify(|op_new_events| op_new_events.push(gt_comp_event))
                .or_insert(vec![gt_comp_event]);

            branch_columns.a_eq_b = F::from_bool(a_eq_b);
            branch_columns.a_lt_b = F::from_bool(a_lt_b);
            branch_columns.a_gt_b = F::from_bool(a_gt_b);

            let branching = match event.instruction.opcode {
                Opcode::BEQ => a_eq_b,
                Opcode::BNE => !a_eq_b,
                Opcode::BLT | Opcode::BLTU => a_lt_b,
                Opcode::BGE | Opcode::BGEU => a_eq_b || a_gt_b,
                _ => unreachable!(),
            };

            let next_pc = event.pc.wrapping_add(event.c);
            branch_columns.pc = Word::from(event.pc);
            branch_columns.next_pc = Word::from(next_pc);
            branch_columns.pc_range_checker.populate(event.pc);
            branch_columns.next_pc_range_checker.populate(next_pc);

            if branching {
                cols.branching = F::ONE;

                let add_event = AluEvent {
                    lookup_id: event.branch_add_lookup_id,
                    chunk: event.chunk,
                    clk: event.clk,
                    opcode: Opcode::ADD,
                    a: next_pc,
                    b: event.pc,
                    c: event.c,
                    sub_lookups: create_alu_lookups(),
                };

                alu_events
                    .entry(Opcode::ADD)
                    .and_modify(|op_new_events| op_new_events.push(add_event))
                    .or_insert(vec![add_event]);
            } else {
                cols.not_branching = F::ONE;
            }
        }
    }
}
