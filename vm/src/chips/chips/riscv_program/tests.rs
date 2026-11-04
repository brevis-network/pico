use crate::{
    chips::chips::riscv_program::{
        columns::{ProgramPreprocessedCols, NUM_PROGRAM_PREPROCESSED_COLS},
        ProgramChip,
    },
    compiler::riscv::{instruction::Instruction, opcode::Opcode, program::Program},
    machine::chip::ChipBehavior,
};
#[cfg(feature = "cuda")]
use crate::{chips::tests::init_test_stream, machine::chip::GpuChipBehavior};
use p3_field::PrimeCharacteristicRing;
use p3_koala_bear::KoalaBear;
#[cfg(feature = "cuda")]
use p3_matrix::dense::RowMajorMatrix;
use std::borrow::Borrow;

type F = KoalaBear;

#[cfg(feature = "cuda")]
/// 2^16 ADDs. A pc has two u16 limbs (`Pc::try_from` rejects 2^32 and above), so the base sits
/// inside the guest range like a real program's.
fn fixture_program() -> Program {
    let pc_base: u64 = 0x1000_0000;
    let instructions: Vec<Instruction> = (0..1 << 16)
        .map(|_| Instruction::new(Opcode::ADD, 0, 0, 0, false, false))
        .collect();
    Program::new(instructions, pc_base, pc_base)
}

#[cfg(feature = "cuda")]
fn gpu_generate_preprocessed(chip: &ProgramChip<F>, program: &Program) -> RowMajorMatrix<F> {
    let stream = init_test_stream();
    let trace = chip.gpu_generate_preprocessed(0, program).unwrap();
    trace.to_host(stream)
}

#[cfg(feature = "cuda")]
#[test]
fn test_riscv_program_gpu_generate_preprocessed() {
    let chip = ProgramChip::<F>::default();
    let program = fixture_program();

    let cpu_trace = chip.generate_preprocessed(&program).unwrap();
    let gpu_trace = gpu_generate_preprocessed(&chip, &program);

    assert_eq!(cpu_trace.values.len(), gpu_trace.values.len());
    assert_eq!(cpu_trace, gpu_trace);

    let non_zero_count = cpu_trace.values.iter().filter(|&&v| v != F::ZERO).count();
    assert!(
        non_zero_count > 0,
        "preprocessed trace is all zeros — both CPU and GPU may be broken"
    );

    let num_rows = cpu_trace.values.len() / chip.preprocessed_width();
    println!(
        "riscv_program: preprocessed trace size: {} cols × {} rows, non-zero: {}/{}",
        chip.preprocessed_width(),
        num_rows,
        non_zero_count,
        cpu_trace.values.len(),
    );
}

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

#[cfg(feature = "cuda")]
/// The CUDA kernel applies the trap rule by opcode value; the two tables must agree cell by cell
/// or the app preprocessed commitments differ.
#[test]
fn test_riscv_program_gpu_generate_preprocessed_with_traps() {
    let chip = ProgramChip::<F>::default();
    let program = program_with_traps();
    let cpu_trace = chip.generate_preprocessed(&program).unwrap();
    let gpu_trace = gpu_generate_preprocessed(&chip, &program);
    assert_eq!(cpu_trace.values.len(), gpu_trace.values.len());
    assert_eq!(cpu_trace, gpu_trace);
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
