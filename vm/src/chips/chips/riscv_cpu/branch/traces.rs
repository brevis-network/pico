use super::super::{columns::CpuCols, CpuChip};
use crate::{
    chips::chips::{alu::event::AluEvent, riscv_cpu::event::CpuEvent},
    compiler::riscv::opcode::Opcode,
    emulator::riscv::event_types::{RvClk, RvValue},
};
use p3_field::Field;

impl<F: Field> CpuChip<F> {
    /// Populates columns related to branching.
    pub(crate) fn populate_branch(&self, cols: &mut CpuCols<F>, event: &CpuEvent) {
        if event.instruction.is_branch_instruction() {
            let (a_lt_b, a_gt_b) = compare(event.instruction.opcode, event.a, event.b);

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

/// The less-than row proving the comparison of the branch `opcode` at `clk`, whose raw operands
/// are `a` and `b`.
pub(crate) fn branch_compare(opcode: Opcode, clk: RvClk, a: RvValue, b: RvValue) -> AluEvent {
    let (a_lt_b, a_gt_b) = compare(opcode, a, b);
    // One merged comparison event: the Lt row pins both bits (`a[0] = a_lt_b`,
    // `a[1] = a_gt_b`), so `a` packs them as limbs 0 and 1. Must stay in step with
    // `count_cpu_event` (one lt slot per branch) and the two GPU mirrors.
    AluEvent {
        clk,
        opcode: if is_signed(opcode) {
            Opcode::SLT
        } else {
            Opcode::SLTU
        },
        a: (a_lt_b as u64) | ((a_gt_b as u64) << 16),
        b: a,
        c: b,
        is_cmp: true,
        ..Default::default()
    }
}

fn is_signed(opcode: Opcode) -> bool {
    matches!(opcode, Opcode::BLT | Opcode::BGE)
}

/// `(a < b, a > b)`, signed for the signed branches.
fn compare(opcode: Opcode, a: RvValue, b: RvValue) -> (bool, bool) {
    if is_signed(opcode) {
        ((a as i64) < (b as i64), (a as i64) > (b as i64))
    } else {
        (a < b, a > b)
    }
}
