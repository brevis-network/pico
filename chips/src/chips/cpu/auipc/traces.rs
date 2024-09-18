use crate::chips::cpu::{columns::CpuCols, CpuChip};
use hashbrown::HashMap;
use p3_field::Field;
use pico_compiler::opcode::Opcode;
use pico_emulator::riscv::events::{create_alu_lookups, AluEvent, CpuEvent};
use pico_machine::word::Word;

impl<F: Field> CpuChip<F> {
    /// Populate columns related to AUIPC.
    pub(crate) fn populate_auipc(
        &self,
        cols: &mut CpuCols<F>,
        event: &CpuEvent,
        alu_events: &mut HashMap<Opcode, Vec<AluEvent>>,
        nonce_lookup: &HashMap<u128, u32>,
    ) {
        if matches!(event.instruction.opcode, Opcode::AUIPC) {
            let auipc_columns = cols.opcode_specific.auipc_mut();

            auipc_columns.pc = Word::from(event.pc);
            auipc_columns.pc_range_checker.populate(event.pc);

            let add_event = AluEvent {
                lookup_id: event.auipc_lookup_id,
                shard: event.shard,
                channel: event.channel,
                clk: event.clk,
                opcode: Opcode::ADD,
                a: event.a,
                b: event.pc,
                c: event.b,
                sub_lookups: create_alu_lookups(),
            };
            auipc_columns.auipc_nonce = F::from_canonical_u32(
                nonce_lookup
                    .get(&event.auipc_lookup_id)
                    .copied()
                    .unwrap_or_default(),
            );

            alu_events
                .entry(Opcode::ADD)
                .and_modify(|op_new_events| op_new_events.push(add_event))
                .or_insert(vec![add_event]);
        }
    }
}
