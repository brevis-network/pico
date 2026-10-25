use super::FracFoldChip;
use crate::{
    compiler::recursion::{
        instruction::Instruction,
        ir::Block,
        types::{Address, FracFoldEvent, FracFoldInstr},
    },
    emulator::recursion::emulator::RecursionRecord,
    machine::chip::ChipBehavior,
};
use p3_field::PrimeCharacteristicRing;
use p3_koala_bear::KoalaBear;
use p3_matrix::Matrix;

type F = KoalaBear;

fn make_block(v0: u32) -> Block<F> {
    Block([F::from_u32(v0), F::ZERO, F::ZERO, F::ZERO])
}

#[test]
fn test_frac_fold_trace_dimensions() {
    let chip = FracFoldChip::<F>::default();

    // (p1,q1) ⊕ (p2,q2): p1=1, q1=1, p2=2, q2=3
    // out_p = 1*3 + 2*1 = 5,  out_q = 1*3 = 3
    let event = FracFoldEvent {
        p1: make_block(1),
        q1: make_block(1),
        p2: make_block(2),
        q2: make_block(3),
        out_p: make_block(5),
        out_q: make_block(3),
    };

    let mut record = RecursionRecord::<F>::default();
    record.frac_fold_events.push(event);

    let mut output = RecursionRecord::<F>::default();
    let trace = chip.generate_main(&record, &mut output);

    // pad_to_power_of_two enforces minimum 16 rows
    assert!(trace.height() >= 16);
    assert_eq!(trace.width(), super::columns::NUM_FRAC_FOLD_COLS);
}

#[test]
fn test_frac_fold_preprocessed_dimensions() {
    use crate::compiler::recursion::program::RecursionProgram;

    let chip = FracFoldChip::<F>::default();

    let instr = FracFoldInstr {
        in_p1_addr: Address(F::from_u32(10)),
        in_q1_addr: Address(F::from_u32(11)),
        in_p2_addr: Address(F::from_u32(12)),
        in_q2_addr: Address(F::from_u32(13)),
        out_p_addr: Address(F::from_u32(14)),
        out_q_addr: Address(F::from_u32(15)),
        mult: F::ONE,
    };

    let program = RecursionProgram {
        instructions: vec![Instruction::FracFold(instr)],
        ..Default::default()
    };

    let preprocessed = chip.generate_preprocessed(&program).unwrap();
    assert!(preprocessed.height() >= 16);
    assert_eq!(
        preprocessed.width(),
        super::columns::NUM_FRAC_FOLD_PREPROCESSED_COLS
    );
    // is_real should be 1 for the first (instruction) row
    assert_eq!(preprocessed.row_slice(0).unwrap()[0], F::ONE);
}

#[test]
fn test_frac_fold_trace_values() {
    let chip = FracFoldChip::<F>::default();

    let p1 = make_block(3);
    let q1 = make_block(7);
    let p2 = make_block(5);
    let q2 = make_block(2);
    // out_p = p1*q2 + p2*q1 = 3*2 + 5*7 = 6 + 35 = 41  (base field elements, degree-0 EF mul)
    // out_q = q1*q2 = 7*2 = 14
    let out_p = make_block(41);
    let out_q = make_block(14);

    let event = FracFoldEvent {
        p1,
        q1,
        p2,
        q2,
        out_p,
        out_q,
    };

    let mut record = RecursionRecord::<F>::default();
    record.frac_fold_events.push(event);

    let mut output = RecursionRecord::<F>::default();
    let trace = chip.generate_main(&record, &mut output);

    let row = trace.row_slice(0).unwrap();
    // Columns: [p1(4), q1(4), p2(4), q2(4), out_p(4), out_q(4)]
    assert_eq!(row[0], F::from_u32(3)); // p1[0]
    assert_eq!(row[4], F::from_u32(7)); // q1[0]
    assert_eq!(row[8], F::from_u32(5)); // p2[0]
    assert_eq!(row[12], F::from_u32(2)); // q2[0]
    assert_eq!(row[16], F::from_u32(41)); // out_p[0]
    assert_eq!(row[20], F::from_u32(14)); // out_q[0]
}

/// GPU trace-gen must be element-wise identical to the CPU path, including padding rows.
/// The recursion layer is KoalaBear-only, so these run over KoalaBear (the GPU path allocates
/// `DevicePoolAllocation::<KoalaBear>`). Requires a CUDA device — run on the GPU host.
mod gpu {
    use crate::{
        chips::{chips::frac_fold::FracFoldChip, tests::init_test_stream},
        compiler::recursion::{
            instruction::Instruction,
            ir::Block,
            program::RecursionProgram,
            types::{Address, FracFoldEvent, FracFoldInstr},
        },
        emulator::recursion::emulator::RecursionRecord,
        machine::chip::ChipBehavior,
    };
    use p3_field::PrimeCharacteristicRing;
    use p3_koala_bear::KoalaBear;

    type F = KoalaBear;

    fn block(base: u32) -> Block<F> {
        Block([
            F::from_u32(base),
            F::from_u32(base.wrapping_add(1)),
            F::from_u32(base.wrapping_add(2)),
            F::from_u32(base.wrapping_add(3)),
        ])
    }

    fn sample_events(n: u32) -> Vec<FracFoldEvent<F>> {
        (0..n)
            .map(|i| {
                let b = i.wrapping_mul(10);
                FracFoldEvent {
                    p1: block(b),
                    q1: block(b.wrapping_add(100)),
                    p2: block(b.wrapping_add(200)),
                    q2: block(b.wrapping_add(300)),
                    out_p: block(b.wrapping_add(400)),
                    out_q: block(b.wrapping_add(500)),
                }
            })
            .collect()
    }

    fn sample_program(n: u32) -> RecursionProgram<F> {
        RecursionProgram {
            instructions: (0..n)
                .map(|i| {
                    let a = i.wrapping_mul(6);
                    Instruction::FracFold(FracFoldInstr {
                        in_p1_addr: Address(F::from_u32(a)),
                        in_q1_addr: Address(F::from_u32(a.wrapping_add(1))),
                        in_p2_addr: Address(F::from_u32(a.wrapping_add(2))),
                        in_q2_addr: Address(F::from_u32(a.wrapping_add(3))),
                        out_p_addr: Address(F::from_u32(a.wrapping_add(4))),
                        out_q_addr: Address(F::from_u32(a.wrapping_add(5))),
                        mult: F::ONE,
                    })
                })
                .collect(),
            ..Default::default()
        }
    }

    /// CPU `generate_main` vs GPU `gpu_generate_main` — full matrix incl. padding.
    fn assert_main_parity(n: u32) {
        let stream = init_test_stream();
        let chip = FracFoldChip::<F>::default();
        let mut record = RecursionRecord::<F>::default();
        record.frac_fold_events = sample_events(n);

        let cpu = chip.generate_main(&record, &mut RecursionRecord::default());
        let gpu = chip
            .gpu_generate_main(0, &record, &mut RecursionRecord::default(), None)
            .to_host(stream);

        assert_eq!(cpu.values, gpu.values, "main parity failed for {n} events");
    }

    /// CPU `generate_preprocessed` vs GPU `gpu_generate_preprocessed` — full matrix incl. padding.
    fn assert_preprocessed_parity(n: u32) {
        let stream = init_test_stream();
        let chip = FracFoldChip::<F>::default();
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
    fn test_frac_fold_gpu_main_empty_matches_cpu() {
        assert_main_parity(0);
    }

    #[test]
    fn test_frac_fold_gpu_main_sub16_matches_cpu() {
        assert_main_parity(5);
    }

    #[test]
    fn test_frac_fold_gpu_main_matches_cpu() {
        assert_main_parity(40);
    }

    #[test]
    fn test_frac_fold_gpu_main_pow2_matches_cpu() {
        assert_main_parity(64);
    }

    #[test]
    fn test_frac_fold_gpu_preprocessed_empty_matches_cpu() {
        assert_preprocessed_parity(0);
    }

    #[test]
    fn test_frac_fold_gpu_preprocessed_sub16_matches_cpu() {
        assert_preprocessed_parity(5);
    }

    #[test]
    fn test_frac_fold_gpu_preprocessed_matches_cpu() {
        assert_preprocessed_parity(40);
    }

    #[test]
    fn test_frac_fold_gpu_preprocessed_pow2_matches_cpu() {
        assert_preprocessed_parity(64);
    }
}
