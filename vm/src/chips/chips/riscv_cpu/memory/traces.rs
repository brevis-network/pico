use super::super::{columns::CpuCols, CpuChip};
use crate::{
    compiler::{
        riscv::{
            opcode::{ByteOpcode, Opcode},
            register::Register::X0,
        },
        word::WORD_SIZE,
    },
    emulator::riscv::events::{
        create_alu_lookups, AluEvent, ByteLookupEvent, ByteRecordBehavior, CpuEvent,
    },
};
use hashbrown::HashMap;
use p3_field::Field;
use std::array;

impl<F: Field> CpuChip<F> {
    /// Populates columns related to memory.
    pub(crate) fn populate_memory(
        &self,
        cols: &mut CpuCols<F>,
        event: &CpuEvent,
        new_alu_events: &mut HashMap<Opcode, Vec<AluEvent>>,
        blu_events: &mut impl ByteRecordBehavior,
        nonce_lookup: &HashMap<u128, u32>,
    ) {
        if !matches!(
            event.instruction.opcode,
            Opcode::LB
                | Opcode::LH
                | Opcode::LW
                | Opcode::LBU
                | Opcode::LHU
                | Opcode::SB
                | Opcode::SH
                | Opcode::SW
        ) {
            return;
        }

        // Populate addr_word and addr_aligned columns.
        let memory_columns = cols.opcode_specific.memory_mut();
        let memory_addr = event.b.wrapping_add(event.c);
        let aligned_addr = memory_addr - memory_addr % WORD_SIZE as u32;
        memory_columns.addr_word = memory_addr.into();
        memory_columns.addr_word_range_checker.populate(memory_addr);
        memory_columns.addr_aligned = F::from_canonical_u32(aligned_addr);

        // Populate the aa_least_sig_byte_decomp columns.
        assert!(aligned_addr % 4 == 0);
        let aligned_addr_ls_byte = (aligned_addr & 0x000000FF) as u8;
        let bits: [bool; 8] = array::from_fn(|i| aligned_addr_ls_byte & (1 << i) != 0);
        memory_columns.aa_least_sig_byte_decomp = array::from_fn(|i| F::from_bool(bits[i + 2]));

        // Add event to ALU check to check that addr == b + c
        let add_event = AluEvent {
            lookup_id: event.memory_add_lookup_id,
            chunk: event.chunk,
            channel: event.channel,
            clk: event.clk,
            opcode: Opcode::ADD,
            a: memory_addr,
            b: event.b,
            c: event.c,
            sub_lookups: create_alu_lookups(),
        };
        new_alu_events
            .entry(Opcode::ADD)
            .and_modify(|op_new_events| op_new_events.push(add_event))
            .or_insert(vec![add_event]);
        memory_columns.addr_word_nonce = F::from_canonical_u32(
            nonce_lookup
                .get(&event.memory_add_lookup_id)
                .copied()
                .unwrap_or_default(),
        );

        // Populate memory offsets.
        let addr_offset = (memory_addr % WORD_SIZE as u32) as u8;
        memory_columns.addr_offset = F::from_canonical_u8(addr_offset);
        memory_columns.offset_is_one = F::from_bool(addr_offset == 1);
        memory_columns.offset_is_two = F::from_bool(addr_offset == 2);
        memory_columns.offset_is_three = F::from_bool(addr_offset == 3);

        // If it is a load instruction, set the unsigned_mem_val column.
        let mem_value = event.memory_record.unwrap().value();
        if matches!(
            event.instruction.opcode,
            Opcode::LB | Opcode::LBU | Opcode::LH | Opcode::LHU | Opcode::LW
        ) {
            match event.instruction.opcode {
                Opcode::LB | Opcode::LBU => {
                    cols.unsigned_mem_val =
                        (mem_value.to_le_bytes()[addr_offset as usize] as u32).into();
                }
                Opcode::LH | Opcode::LHU => {
                    let value = match (addr_offset >> 1) % 2 {
                        0 => mem_value & 0x0000FFFF,
                        1 => (mem_value & 0xFFFF0000) >> 16,
                        _ => unreachable!(),
                    };
                    cols.unsigned_mem_val = value.into();
                }
                Opcode::LW => {
                    cols.unsigned_mem_val = mem_value.into();
                }
                _ => unreachable!(),
            }

            // For the signed load instructions, we need to check if the loaded value is negative.
            if matches!(event.instruction.opcode, Opcode::LB | Opcode::LH) {
                let most_sig_mem_value_byte: u8;
                let sign_value: u32;
                if matches!(event.instruction.opcode, Opcode::LB) {
                    sign_value = 256;
                    most_sig_mem_value_byte = cols.unsigned_mem_val.to_u32().to_le_bytes()[0];
                } else {
                    // LHU case
                    sign_value = 65536;
                    most_sig_mem_value_byte = cols.unsigned_mem_val.to_u32().to_le_bytes()[1];
                };

                for i in (0..8).rev() {
                    memory_columns.most_sig_byte_decomp[i] =
                        F::from_canonical_u8(most_sig_mem_value_byte >> i & 0x01);
                }
                if memory_columns.most_sig_byte_decomp[7] == F::one() {
                    cols.mem_value_is_neg_not_x0 =
                        F::from_bool(event.instruction.op_a != (X0 as u32));
                    let sub_event = AluEvent {
                        lookup_id: event.memory_sub_lookup_id,
                        channel: event.channel,
                        chunk: event.chunk,
                        clk: event.clk,
                        opcode: Opcode::SUB,
                        a: event.a,
                        b: cols.unsigned_mem_val.to_u32(),
                        c: sign_value,
                        sub_lookups: create_alu_lookups(),
                    };
                    cols.unsigned_mem_val_nonce = F::from_canonical_u32(
                        nonce_lookup
                            .get(&event.memory_sub_lookup_id)
                            .copied()
                            .unwrap_or_default(),
                    );

                    new_alu_events
                        .entry(Opcode::SUB)
                        .and_modify(|op_new_events| op_new_events.push(sub_event))
                        .or_insert(vec![sub_event]);
                }
            }

            // Set the `mem_value_is_pos_not_x0` composite flag.
            cols.mem_value_is_pos_not_x0 = F::from_bool(
                ((matches!(event.instruction.opcode, Opcode::LB | Opcode::LH)
                    && (memory_columns.most_sig_byte_decomp[7] == F::zero()))
                    || matches!(
                        event.instruction.opcode,
                        Opcode::LBU | Opcode::LHU | Opcode::LW
                    ))
                    && event.instruction.op_a != (X0 as u32),
            );
        }

        // Add event to byte lookup for byte range checking each byte in the memory addr
        let addr_bytes = memory_addr.to_le_bytes();
        for byte_pair in addr_bytes.chunks_exact(2) {
            blu_events.add_byte_lookup_event(ByteLookupEvent {
                chunk: event.chunk,
                channel: event.channel,
                opcode: ByteOpcode::U8Range,
                a1: 0,
                a2: 0,
                b: byte_pair[0],
                c: byte_pair[1],
            });
        }
    }
}
