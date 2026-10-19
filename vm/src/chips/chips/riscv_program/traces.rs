use super::{
    columns::{
        ProgramMultiplicityCols, ProgramPreprocessedCols, NUM_PROGRAM_MULT_COLS,
        NUM_PROGRAM_PREPROCESSED_COLS,
    },
    ProgramChip,
};
use crate::{
    compiler::{addr::Pc, riscv::program::Program},
    emulator::riscv::record::EmulationRecord,
    iter::{IndexedPicoIterator, IntoPicoRefIterator, PicoIterator},
    machine::{
        chip::ChipBehavior,
        utils::{pad_to_power_of_two, pad_to_power_of_two_repeating_first_row},
    },
};
use hashbrown::HashMap;
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use std::borrow::BorrowMut;

/// Row 0 is the filler for the padding rows and for every trap (UNIMP / EBREAK) instruction, so
/// it must not be a trap itself: a trap row in the table would be claimable as a no-op once there
/// is no `is_unimpl` selector to reject it. A transpiled program starts at `_start`, so this never
/// fires in production; a program whose first word does not decode (the disassembler emits UNIMP
/// for those) fails here, at keygen.
fn assert_instruction_zero_is_not_a_trap(program: &Program) {
    let first = program
        .instructions
        .first()
        .expect("the Program chip needs at least one instruction");
    assert!(
        !first.opcode.is_trap(),
        "instruction 0 ({:?}) is a trap; the preprocessed table uses row 0 as the filler for trap rows and padding",
        first.opcode
    );
}

impl<F: PrimeField32> ChipBehavior<F> for ProgramChip<F> {
    type Record = EmulationRecord;
    type Program = Program;

    fn name(&self) -> String {
        "Program".to_string()
    }

    fn preprocessed_width(&self) -> usize {
        NUM_PROGRAM_PREPROCESSED_COLS
    }

    fn generate_preprocessed(&self, program: &Program) -> Option<RowMajorMatrix<F>> {
        debug_assert!(!program.instructions.is_empty(), "empty program");
        assert_instruction_zero_is_not_a_trap(program);
        // `jalr_lsb` is pinned by membership because every table pc has the same residue mod 4
        // (`riscv_cpu/jump/constraints.rs`); that needs a 4-aligned base.
        assert!(
            program.pc_base.is_multiple_of(4),
            "pc_base {:#x} is not 4-aligned",
            program.pc_base
        );

        let rows = program
            .instructions
            .iter()
            .enumerate()
            .map(|(i, instruction)| {
                let pc = program.pc_base + (i as u64 * 4);
                let mut row = [F::ZERO; NUM_PROGRAM_PREPROCESSED_COLS];
                let cols: &mut ProgramPreprocessedCols<F> = row.as_mut_slice().borrow_mut();
                // Two limbs: `Pc::try_from` rejects a pc at or above 2^32, and
                // `InstructionCols::populate` rejects an operand whose bits 32..64 are not a
                // sign fill. Both hold for every transpiled program (guest addresses stay below
                // `0x7800_0000`); a program that violates either fails here, at keygen.
                //
                // A Cpu-chip argument leans on this bound and it is asserted here so the premise
                // is checked where the table is built, not only by the ELF loader: a jump row's
                // return address `pc + 4` has a canonical limb 1 because `pc[1] <= 0x77FF` and a
                // canonical limb 0 because the `pc_carry` column below is the carry out of
                // `pc[0] + 4` (`register/constraints.rs`).
                assert!(
                    pc < 0x7800_0000,
                    "program pc {pc:#x} outside the guest address space"
                );
                // A trap instruction (UNIMP / EBREAK) gets row 0's content instead of its own,
                // exactly as the padding rows do: the emulator never executes a trap, so no Cpu
                // row ever needs this pc, and leaving the pc out of the table is what makes a Cpu
                // row that claims it unprovable (there is no `is_unimpl` selector to reject it
                // with). The CUDA kernel applies the same rule (`program.hpp`).
                let (row_pc, source) = if instruction.opcode.is_trap() {
                    (program.pc_base, &program.instructions[0])
                } else {
                    (pc, instruction)
                };
                cols.pc = Pc::try_from(row_pc).unwrap();
                // The carry out of limb 0 in `row_pc + 4`, as a function of the row's own pc
                // (a trap row therefore carries row 0's). The Cpu chip writes the same
                // `[pc[0] >= 0xFFFC]` on every real row and the Program message carries it; the
                // CUDA kernel writes the same value (`program.hpp`).
                cols.pc_carry = F::from_bool((row_pc & 0xFFFF) >= 0xFFFC);
                cols.instruction.populate(*source);
                cols.selectors.populate(*source);

                row
            })
            .collect::<Vec<_>>();

        // Convert the trace to a row major matrix.
        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_PROGRAM_PREPROCESSED_COLS,
        );

        let log_size = program.fixed_log2_rows(&self.name());
        // Pad by repeating instruction 0, not with zeros. A zero row is a valid entry in this
        // table -- it reads as "pc = 0 holds an instruction with no opcode selected and
        // op_a_0 = 0" -- and the multiplicity column is prover-supplied and ungated, so a CPU
        // row could claim to execute it. Repeating a real instruction leaves nothing to claim.
        // Trap rows are filled the same way (see the loop above), which is why instruction 0
        // must not itself be a trap.
        pad_to_power_of_two_repeating_first_row::<NUM_PROGRAM_PREPROCESSED_COLS, F>(
            &mut trace.values,
            log_size,
        );

        Some(trace)
    }

    fn generate_main(&self, input: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {
        // Collect instruction counts in parallel using a thread-safe HashMap
        let instruction_counts: HashMap<u64, usize> = input
            .cpu_events
            .pico_iter()
            .pico_fold(HashMap::new, |mut acc, event| {
                let pc = event.pc;
                *acc.entry(pc).or_insert(0) += 1;
                acc
            })
            .pico_reduce(HashMap::new, |mut a, b| {
                b.into_iter().for_each(|(pc, count)| {
                    *a.entry(pc).or_insert(0) += count;
                });
                a
            });

        // Generate rows in parallel
        let rows: Vec<[F; NUM_PROGRAM_MULT_COLS]> = input
            .program
            .instructions
            .pico_iter()
            .enumerate()
            .map(|(i, _)| {
                let pc = input.program.pc_base + (i as u64 * 4);
                let mut row = [F::ZERO; NUM_PROGRAM_MULT_COLS];
                let cols: &mut ProgramMultiplicityCols<F> = row.as_mut_slice().borrow_mut();
                cols.multiplicity = F::from_usize(*instruction_counts.get(&pc).unwrap_or(&0));
                row
            })
            .collect();

        // Convert the trace to a row major matrix
        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_PROGRAM_MULT_COLS,
        );

        // Pad the trace to a power of two
        let log_rows = input.shape_chip_size(&self.name());
        pad_to_power_of_two::<NUM_PROGRAM_MULT_COLS, F>(&mut trace.values, log_rows);

        trace
    }

    fn is_active(&self, _record: &Self::Record) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::{
        super::columns::{ProgramPreprocessedCols, NUM_PROGRAM_PREPROCESSED_COLS},
        ProgramChip,
    };
    use crate::{
        compiler::riscv::{instruction::Instruction, opcode::Opcode, program::Program},
        machine::chip::ChipBehavior,
    };
    use p3_field::PrimeCharacteristicRing;
    use p3_koala_bear::KoalaBear;
    use std::borrow::Borrow;

    type F = KoalaBear;

    /// A hand-built program with a trap at index 1 and 3: `[ADD, UNIMP, ADD, EBREAK]`.
    fn program_with_traps() -> Program {
        let pc_base: u64 = 0x1000_0000;
        let instructions = vec![
            Instruction::new(Opcode::ADD, 1, 2, 3, false, false),
            Instruction::new(Opcode::UNIMP, 0, 0, 0, true, true),
            Instruction::new(Opcode::ADD, 4, 5, 6, false, false),
            Instruction::new(Opcode::EBREAK, 0, 0, 0, false, false),
        ];
        Program::new(instructions, pc_base, pc_base)
    }

    /// The preprocessed table writes row 0 in place of every trap instruction, whole row included
    /// (pc, instruction and selectors), and leaves the other rows alone.
    #[test]
    fn preprocessed_table_writes_row_zero_for_trap_instructions() {
        let chip = ProgramChip::<F>::default();
        let program = program_with_traps();
        let trace = chip.generate_preprocessed(&program).unwrap();
        let w = NUM_PROGRAM_PREPROCESSED_COLS;
        assert_eq!(trace.values.len() % w, 0);
        let rows = trace.values.len() / w;
        assert!(rows >= 4, "{rows} rows for 4 instructions");
        let row = |i: usize| &trace.values[i * w..(i + 1) * w];

        assert_eq!(row(1), row(0), "the UNIMP row must be a copy of row 0");
        assert_eq!(row(3), row(0), "the EBREAK row must be a copy of row 0");
        assert_ne!(row(2), row(0));
        // Padding rows repeat row 0 as well (the trap rows and the padding share one filler).
        for i in 4..rows {
            assert_eq!(row(i), row(0), "padding row {i} must be a copy of row 0");
        }

        let cols2: &ProgramPreprocessedCols<F> = row(2).borrow();
        let pc2 = program.pc_base + 8;
        assert_eq!(
            cols2.pc.0,
            [
                F::from_u16((pc2 & 0xFFFF) as u16),
                F::from_u16(((pc2 >> 16) & 0xFFFF) as u16)
            ]
        );
        assert_eq!(cols2.instruction.opcode, Opcode::ADD.as_field::<F>());
        assert_eq!(cols2.instruction.op_a, F::from_u8(4));
        assert_eq!(cols2.selectors.imm_b, F::ZERO);
        assert_eq!(cols2.selectors.is_ecall, F::ZERO);

        assert!(Opcode::UNIMP.is_trap() && Opcode::EBREAK.is_trap());
        assert!(!Opcode::ADD.is_trap() && !Opcode::ECALL.is_trap() && !Opcode::JAL.is_trap());
    }

    #[test]
    #[should_panic(expected = "instruction 0 (UNIMP) is a trap")]
    fn preprocessed_table_rejects_a_trap_at_instruction_zero() {
        let chip = ProgramChip::<F>::default();
        let pc_base: u64 = 0x1000_0000;
        let program = Program::new(
            vec![
                Instruction::new(Opcode::UNIMP, 0, 0, 0, true, true),
                Instruction::new(Opcode::ADD, 1, 2, 3, false, false),
            ],
            pc_base,
            pc_base,
        );
        let _ = chip.generate_preprocessed(&program);
    }
}
