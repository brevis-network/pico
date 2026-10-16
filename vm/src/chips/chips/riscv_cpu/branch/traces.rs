use super::super::{columns::CpuCols, CpuChip};
use crate::{
    chips::chips::{alu::event::AluEvent, riscv_cpu::event::CpuEvent},
    compiler::riscv::opcode::Opcode,
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
            let use_signed_comparison =
                matches!(event.instruction.opcode, Opcode::BLT | Opcode::BGE);

            let a_lt_b = if use_signed_comparison {
                (event.a as i64) < (event.b as i64)
            } else {
                event.a < event.b
            };
            let a_gt_b = if use_signed_comparison {
                (event.a as i64) > (event.b as i64)
            } else {
                event.a > event.b
            };

            let alu_op_code = if use_signed_comparison {
                Opcode::SLT
            } else {
                Opcode::SLTU
            };

            // One merged comparison event: the Lt row pins both bits (`a[0] = a_lt_b`,
            // `a[1] = a_gt_b`), so `a` packs them as limbs 0 and 1. Must stay in step with
            // `count_cpu_event` (one lt slot per branch) and the two GPU mirrors.
            let cmp_event = AluEvent {
                clk: event.clk,
                opcode: alu_op_code,
                a: (a_lt_b as u64) | ((a_gt_b as u64) << 16),
                b: event.a,
                c: event.b,
                is_cmp: true,
                ..Default::default()
            };

            alu_events
                .entry(alu_op_code)
                .and_modify(|op_new_events| op_new_events.push(cmp_event))
                .or_insert(vec![cmp_event]);

            // `a_eq_b` is derived in the constraints (1 - a_lt_b - a_gt_b); no column.
            cols.a_lt_b = F::from_bool(a_lt_b);
            cols.a_gt_b = F::from_bool(a_gt_b);

            // Nothing else to write: the taken predicate is an expression of these two bits and
            // the opcode selectors (`CpuChip::branch_taken_expr`), not a column, and a taken
            // branch emits no ADD event -- the AIR proves `next_pc = pc + c` with one field
            // equation over the sign-extended offset instead of dispatching to the Add chip.
        }
    }
}
