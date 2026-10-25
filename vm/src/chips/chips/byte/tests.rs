use crate::{
    chips::{
        chips::byte::{columns::NUM_BYTE_PREPROCESSED_COLS, ByteChip},
        tests::init_test_stream,
    },
    compiler::riscv::program::Program,
    machine::chip::ChipBehavior,
};
use p3_field::PrimeCharacteristicRing;
use p3_koala_bear::KoalaBear;
use p3_matrix::dense::RowMajorMatrix;

type F = KoalaBear;

fn dummy_program() -> Program {
    Program::new(vec![], 0, 0)
}

fn cpu_generate_preprocessed(chip: &ByteChip<F>, program: &Program) -> RowMajorMatrix<F> {
    chip.generate_preprocessed(program).unwrap()
}

fn gpu_generate_preprocessed(chip: &ByteChip<F>, program: &Program) -> RowMajorMatrix<F> {
    let stream = init_test_stream();
    let trace = chip.gpu_generate_preprocessed(0, program).unwrap();
    trace.to_host(stream)
}

#[test]
fn test_byte_gpu_generate_preprocessed() {
    let program = dummy_program();
    let chip = ByteChip::<F>::default();

    let cpu_trace = cpu_generate_preprocessed(&chip, &program);
    let gpu_trace = gpu_generate_preprocessed(&chip, &program);

    assert_eq!(cpu_trace.values.len(), gpu_trace.values.len());
    assert_eq!(cpu_trace, gpu_trace);

    let non_zero_count = cpu_trace.values.iter().filter(|&&v| v != F::ZERO).count();
    assert!(
        non_zero_count > 0,
        "preprocessed trace is all zeros — both CPU and GPU may be broken"
    );

    println!(
        "byte: preprocessed trace size: {} cols × {} rows, non-zero: {}/{}",
        NUM_BYTE_PREPROCESSED_COLS,
        cpu_trace.values.len() / NUM_BYTE_PREPROCESSED_COLS,
        non_zero_count,
        cpu_trace.values.len(),
    );
}
