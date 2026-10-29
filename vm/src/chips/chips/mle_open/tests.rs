use super::MleOpenChip;
use crate::{
    compiler::recursion::{
        instruction::Instruction,
        ir::Block,
        program::RecursionProgram,
        types::{Address, MleOpenEvent, MleOpenInstr},
    },
    emulator::recursion::emulator::RecursionRecord,
    machine::chip::ChipBehavior,
};
use p3_field::PrimeCharacteristicRing;
use p3_koala_bear::KoalaBear;
use p3_matrix::Matrix;

type F = KoalaBear;

#[test]
fn test_mle_open_trace_dimensions() {
    let chip = MleOpenChip::<F>::default();

    let event = MleOpenEvent {
        col_ref: (1u32 << 16) | 3, // air_id=1, col_id=3
        opening_value: Block([F::from_u32(42), F::ZERO, F::ZERO, F::ZERO]),
    };

    let mut record = RecursionRecord::<F>::default();
    record.mle_open_events.push(event);

    let mut output = RecursionRecord::<F>::default();
    let trace = chip.generate_main(&record, &mut output);

    assert!(trace.height() >= 16);
    assert_eq!(trace.width(), super::columns::NUM_MLE_OPEN_COLS);
    // opening_value[0] = 42 in the first row
    assert_eq!(trace.row_slice(0).unwrap()[0], F::from_u32(42));
}

#[test]
fn test_mle_open_preprocessed_dimensions() {
    let chip = MleOpenChip::<F>::default();

    let instr = MleOpenInstr {
        col_ref: (5u32 << 16) | 7,
        opening_value_addr: Address(F::from_u32(100)),
    };

    let program = RecursionProgram {
        instructions: vec![Instruction::MleOpen(instr)],
        ..Default::default()
    };

    let preprocessed = chip.generate_preprocessed(&program).unwrap();
    assert!(preprocessed.height() >= 16);
    assert_eq!(
        preprocessed.width(),
        super::columns::NUM_MLE_OPEN_PREPROCESSED_COLS
    );
    let row = preprocessed.row_slice(0).unwrap();
    assert_eq!(row[0], F::ONE); // is_real
    assert_eq!(row[1], F::from_u32((5u32 << 16) | 7)); // col_ref
}

/// GPU trace-gen must be element-wise identical to the CPU path, including padding rows.
/// The recursion layer is KoalaBear-only, so these run over KoalaBear (the GPU path allocates
/// `DevicePoolAllocation::<KoalaBear>`). Requires a CUDA device — run on the GPU host.
#[cfg(feature = "cuda")]
mod gpu {
    use crate::{
        chips::{chips::mle_open::MleOpenChip, tests::init_test_stream},
        compiler::recursion::{
            instruction::Instruction,
            ir::Block,
            program::RecursionProgram,
            types::{Address, MleOpenEvent, MleOpenInstr},
        },
        emulator::recursion::emulator::RecursionRecord,
        machine::chip::{ChipBehavior, GpuChipBehavior},
    };
    use p3_field::PrimeCharacteristicRing;
    use p3_koala_bear::KoalaBear;

    type F = KoalaBear;

    fn sample_events(n: u32) -> Vec<MleOpenEvent<F>> {
        (0..n)
            .map(|i| MleOpenEvent {
                col_ref: (i << 16) | (i + 1),
                opening_value: Block([
                    F::from_u32(i),
                    F::from_u32(i.wrapping_add(1)),
                    F::from_u32(i.wrapping_add(2)),
                    F::from_u32(i.wrapping_add(3)),
                ]),
            })
            .collect()
    }

    fn sample_program(n: u32) -> RecursionProgram<F> {
        RecursionProgram {
            instructions: (0..n)
                .map(|i| {
                    Instruction::MleOpen(MleOpenInstr {
                        col_ref: (i << 16) | (i + 1),
                        opening_value_addr: Address(F::from_u32(i)),
                    })
                })
                .collect(),
            ..Default::default()
        }
    }

    /// CPU `generate_main` vs GPU `gpu_generate_main` — full matrix incl. padding.
    fn assert_main_parity(n: u32) {
        let stream = init_test_stream();
        let chip = MleOpenChip::<F>::default();
        let mut record = RecursionRecord::<F>::default();
        record.mle_open_events = sample_events(n);

        let cpu = chip.generate_main(&record, &mut RecursionRecord::default());
        let gpu = chip
            .gpu_generate_main(0, &record, &mut RecursionRecord::default())
            .to_host(stream);

        assert_eq!(cpu.values, gpu.values, "main parity failed for {n} events");
    }

    /// CPU `generate_preprocessed` vs GPU `gpu_generate_preprocessed` — full matrix incl. padding.
    fn assert_preprocessed_parity(n: u32) {
        let stream = init_test_stream();
        let chip = MleOpenChip::<F>::default();
        let program = sample_program(n);

        let cpu = chip.generate_preprocessed(&program).unwrap();
        let gpu = chip
            .gpu_generate_preprocessed(0, &program)
            .unwrap()
            .to_host(stream);

        assert_eq!(
            cpu.values, gpu.values,
            "preprocessed parity failed for {n} instrs"
        );
    }

    // Row-count cases (CPU `pad_to_power_of_two`: floor real rows to 16, then next_power_of_two):
    //   0 -> 16 (all padding), 5 -> 16 (under floor), 40 -> 64 (non-power-of-two), 64 -> 64 (exact).

    #[test]
    fn test_mle_open_gpu_main_empty_matches_cpu() {
        assert_main_parity(0);
    }

    #[test]
    fn test_mle_open_gpu_main_sub16_matches_cpu() {
        assert_main_parity(5);
    }

    #[test]
    fn test_mle_open_gpu_main_matches_cpu() {
        assert_main_parity(40);
    }

    #[test]
    fn test_mle_open_gpu_main_pow2_matches_cpu() {
        assert_main_parity(64);
    }

    #[test]
    fn test_mle_open_gpu_preprocessed_empty_matches_cpu() {
        assert_preprocessed_parity(0);
    }

    #[test]
    fn test_mle_open_gpu_preprocessed_sub16_matches_cpu() {
        assert_preprocessed_parity(5);
    }

    #[test]
    fn test_mle_open_gpu_preprocessed_matches_cpu() {
        assert_preprocessed_parity(40);
    }

    #[test]
    fn test_mle_open_gpu_preprocessed_pow2_matches_cpu() {
        assert_preprocessed_parity(64);
    }
}
