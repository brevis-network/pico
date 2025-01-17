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
    /// Populate columns related to AUIPC.
    pub(crate) fn populate_auipc(
        &self,
        cols: &mut CpuCols<F>,
        event: &CpuEvent,
        alu_events: &mut HashMap<Opcode, Vec<AluEvent>>,
    ) {
        if matches!(event.instruction.opcode, Opcode::AUIPC) {
            let auipc_columns = cols.opcode_specific.auipc_mut();

            auipc_columns.pc = Word::from(event.pc);
            auipc_columns.pc_range_checker.populate(event.pc);

            let add_event = AluEvent {
                lookup_id: event.auipc_lookup_id,
                clk: event.clk,
                opcode: Opcode::ADD,
                a: event.a,
                b: event.pc,
                c: event.b,
                sub_lookups: create_alu_lookups(),
            };

            alu_events
                .entry(Opcode::ADD)
                .and_modify(|op_new_events| op_new_events.push(add_event))
                .or_insert(vec![add_event]);
        }
    }
}
