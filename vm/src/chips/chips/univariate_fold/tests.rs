use super::{UnivariateFoldChip, MAX_COEFFS};
use crate::{
    compiler::recursion::{
        instruction::Instruction,
        ir::Block,
        program::RecursionProgram,
        types::{Address, UnivariateFoldEvent, UnivariateFoldInstr},
    },
    emulator::recursion::emulator::RecursionRecord,
    machine::chip::ChipBehavior,
    primitives::consts::EXTENSION_DEGREE,
};
use p3_field::{
    extension::QuinticTrinomialExtensionField, BasedVectorSpace, PrimeCharacteristicRing,
};
use p3_koala_bear::KoalaBear;
use p3_matrix::Matrix;

type F = KoalaBear;
type EF = QuinticTrinomialExtensionField<KoalaBear>;

fn b(v: u32) -> Block<F> {
    Block::from(F::from_u32(v))
}

#[test]
fn test_univariate_fold_trace_dimensions() {
    let chip = UnivariateFoldChip::<F>::default();

    // Stacking domain-sum constraint: (coeffs[0] + coeffs[omega_order]) * omega_order == claimed_sum.
    // omega_order = (MAX_COEFFS+1)/2 = 16.  Only 3 non-zero coefficients (rest zero-padded):
    //   coeffs[0] = 1, coeffs[16] = 0 → domain_sum = (1+0)*16 = 16.
    // poly(r) = poly(2) = 1 + 2*2 + 3*4 = 17.
    let event = UnivariateFoldEvent {
        coeffs: vec![b(1), b(2), b(3)],
        claimed_sum: b(16),
        r: b(2),
        next_sum: b(17),
    };

    let mut record = RecursionRecord::<F>::default();
    record.univariate_fold_events.push(event);

    let mut output = RecursionRecord::<F>::default();
    let trace = chip.generate_main(&record, &mut output);

    assert!(trace.height() >= 16);
    assert_eq!(trace.width(), super::columns::NUM_UNIVARIATE_FOLD_COLS);
}

#[test]
fn test_univariate_fold_preprocessed_dimensions() {
    let chip = UnivariateFoldChip::<F>::default();

    let mut coeffs_addrs = [Address(F::ZERO); MAX_COEFFS];
    for (i, addr) in coeffs_addrs.iter_mut().enumerate() {
        *addr = Address(F::from_u32(20 + i as u32));
    }

    let instr = UnivariateFoldInstr {
        coeffs_addrs: coeffs_addrs[..3].to_vec(),
        claimed_sum_addr: Address(F::from_u32(35)),
        r_addr: Address(F::from_u32(36)),
        next_sum_addr: Address(F::from_u32(37)),
        mult: F::ONE,
    };

    let program = RecursionProgram {
        instructions: vec![Instruction::UnivariateFold(Box::new(instr))],
        ..Default::default()
    };

    let preprocessed = chip.generate_preprocessed(&program).unwrap();
    assert!(preprocessed.height() >= 16);
    assert_eq!(
        preprocessed.width(),
        super::columns::NUM_UNIVARIATE_FOLD_PREPROCESSED_COLS
    );
    assert_eq!(preprocessed.row_slice(0).unwrap()[0], F::ONE); // is_real
}

#[test]
fn test_univariate_fold_eval_columns() {
    let chip = UnivariateFoldChip::<F>::default();

    // eval_at_0 = coeffs[0] = 1; eval_at_1 = coeffs[omega_order=16] = 0 (zero-padded).
    let event = UnivariateFoldEvent {
        coeffs: vec![b(1), b(2), b(3)],
        claimed_sum: b(16), // (1 + 0) * 16 = 16
        r: b(2),
        next_sum: b(17),
    };

    let mut record = RecursionRecord::<F>::default();
    record.univariate_fold_events.push(event);

    let mut output = RecursionRecord::<F>::default();
    let trace = chip.generate_main(&record, &mut output);
    let row = trace.row_slice(0).unwrap();

    // eval_at_0 offset: after MAX_COEFFS + 3 blocks of EXTENSION_DEGREE lanes.
    let eval_at_0_offset = (MAX_COEFFS + 3) * EXTENSION_DEGREE;
    let eval_at_1_offset = eval_at_0_offset + EXTENSION_DEGREE;
    assert_eq!(row[eval_at_0_offset], F::from_u32(1)); // eval_at_0 = coeffs[0] = 1
    assert_eq!(row[eval_at_1_offset], F::from_u32(0)); // eval_at_1 = coeffs[16] = 0 (zero-padded)
}

/// An extension element with every one of its `EXTENSION_DEGREE` coefficients non-zero and
/// distinct, so a tracegen that only handled the first four would disagree with `EF`.
fn ef(seed: u32) -> EF {
    EF::from_basis_coefficients_fn(|i| F::from_u32(seed + 7 * i as u32 + 1))
}

fn blk(e: EF) -> Block<F> {
    Block::from(e.as_basis_coefficients_slice())
}

fn ef_at(row: &[F], at: usize) -> EF {
    EF::from_basis_coefficients_slice(&row[at..at + EXTENSION_DEGREE]).unwrap()
}

#[test]
fn test_univariate_fold_horner_all_lanes() {
    let chip = UnivariateFoldChip::<F>::default();

    // p(X) = c0 + c1 X + c2 X^2 with every coefficient a full extension element.
    let (c0, c1, c2) = (ef(1), ef(2), ef(3));
    let r = ef(5);
    let next_sum = c2 * r * r + c1 * r + c0;
    // Domain sum (p(0) + p(1)) * omega_order with p(1) = coeffs[omega_order] = 0 (padding).
    let claimed_sum = c0 * EF::from(F::from_u32(MAX_COEFFS.div_ceil(2) as u32));

    let mut record = RecursionRecord::<F>::default();
    record.univariate_fold_events.push(UnivariateFoldEvent {
        coeffs: vec![blk(c0), blk(c1), blk(c2)],
        claimed_sum: blk(claimed_sum),
        r: blk(r),
        next_sum: blk(next_sum),
    });

    let mut output = RecursionRecord::<F>::default();
    let trace = chip.generate_main(&record, &mut output);
    // Layout: [coeffs(MAX_COEFFS * E), claimed_sum, r, next_sum, eval_at_0, eval_at_1 (E each),
    // acc((MAX_COEFFS - 1) * E)]; acc[i] = acc[i-1] * r + coeffs[MAX_COEFFS-1-i], acc[0] = 0 here.
    const E: usize = EXTENSION_DEGREE;
    let acc_at = |i: usize| (MAX_COEFFS + 5 + i) * E;
    let row = trace.row_slice(0).unwrap();
    assert_eq!(ef_at(&row[..], (MAX_COEFFS + 1) * E), r);
    assert_eq!(ef_at(&row[..], acc_at(MAX_COEFFS - 4)), EF::ZERO); // coeffs[3] slot: padding
    assert_eq!(ef_at(&row[..], acc_at(MAX_COEFFS - 3)), c2); // + coeffs[2]
    assert_eq!(ef_at(&row[..], acc_at(MAX_COEFFS - 2)), c2 * r + c1); // + coeffs[1]
                                                                      // next_sum = acc[MAX_COEFFS - 2] * r + coeffs[0] is enforced by the AIR, not a column.
    assert_eq!(ef_at(&row[..], (MAX_COEFFS + 2) * E), next_sum);
}

/// GPU trace-gen must be element-wise identical to the CPU path, including the derived Horner
/// accumulator / eval columns and padding rows. The recursion layer is KoalaBear-only, so these
/// run over KoalaBear. Requires a CUDA device — run on the GPU host.
#[cfg(feature = "cuda")]
mod gpu {
    use crate::{
        chips::{
            chips::univariate_fold::{UnivariateFoldChip, MAX_COEFFS},
            tests::init_test_stream,
        },
        compiler::recursion::{
            instruction::Instruction,
            ir::Block,
            program::RecursionProgram,
            types::{Address, UnivariateFoldEvent, UnivariateFoldInstr},
        },
        emulator::recursion::emulator::RecursionRecord,
        machine::chip::{ChipBehavior, GpuChipBehavior},
    };
    use p3_field::PrimeCharacteristicRing;
    use p3_koala_bear::KoalaBear;

    type F = KoalaBear;

    /// A full extension-field block, every lane non-zero, so the kernel's trinomial reduction terms
    /// are exercised.
    fn block4(base: u32) -> Block<F> {
        Block([
            F::from_u32(base.wrapping_add(1)),
            F::from_u32(base.wrapping_mul(3).wrapping_add(2)),
            F::from_u32(base.wrapping_mul(7).wrapping_add(5)),
            F::from_u32(base.wrapping_mul(13).wrapping_add(11)),
            F::from_u32(base.wrapping_mul(17).wrapping_add(13)),
        ])
    }

    fn sample_events(n: u32) -> Vec<UnivariateFoldEvent<F>> {
        (0..n)
            .map(|i| {
                // Full MAX_COEFFS coefficients so the Horner recurrence runs its full length.
                let coeffs: Vec<Block<F>> = (0..MAX_COEFFS as u32)
                    .map(|k| block4(i.wrapping_mul(31).wrapping_add(k)))
                    .collect();
                UnivariateFoldEvent {
                    coeffs,
                    claimed_sum: block4(i.wrapping_add(1000)),
                    r: block4(i.wrapping_mul(5).wrapping_add(3)),
                    next_sum: block4(i.wrapping_add(2000)),
                }
            })
            .collect()
    }

    fn sample_program(n: u32) -> RecursionProgram<F> {
        RecursionProgram {
            instructions: (0..n)
                .map(|i| {
                    // Vary the active coefficient count to exercise num_coeffs + padding.
                    let len = (i % (MAX_COEFFS as u32)) + 1;
                    let coeffs_addrs = (0..len)
                        .map(|k| Address(F::from_u32(i.wrapping_mul(64).wrapping_add(k))))
                        .collect::<Vec<_>>();
                    Instruction::UnivariateFold(Box::new(UnivariateFoldInstr {
                        coeffs_addrs,
                        claimed_sum_addr: Address(F::from_u32(i.wrapping_add(5000))),
                        r_addr: Address(F::from_u32(i.wrapping_add(6000))),
                        next_sum_addr: Address(F::from_u32(i.wrapping_add(7000))),
                        mult: F::ONE,
                    }))
                })
                .collect(),
            ..Default::default()
        }
    }

    /// CPU `generate_main` vs GPU `gpu_generate_main` — full matrix incl. derived cols and padding.
    fn assert_main_parity(n: u32) {
        let stream = init_test_stream();
        let chip = UnivariateFoldChip::<F>::default();
        let mut record = RecursionRecord::<F>::default();
        record.univariate_fold_events = sample_events(n);

        let cpu = chip.generate_main(&record, &mut RecursionRecord::default());
        let gpu = chip
            .gpu_generate_main(0, &record, &mut RecursionRecord::default())
            .to_host(stream);

        assert_eq!(cpu.values, gpu.values, "main parity failed for {n} events");
    }

    /// CPU `generate_preprocessed` vs GPU `gpu_generate_preprocessed` — full matrix incl. padding.
    fn assert_preprocessed_parity(n: u32) {
        let stream = init_test_stream();
        let chip = UnivariateFoldChip::<F>::default();
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
    fn test_univariate_fold_gpu_main_empty_matches_cpu() {
        assert_main_parity(0);
    }

    #[test]
    fn test_univariate_fold_gpu_main_sub16_matches_cpu() {
        assert_main_parity(5);
    }

    #[test]
    fn test_univariate_fold_gpu_main_matches_cpu() {
        assert_main_parity(40);
    }

    #[test]
    fn test_univariate_fold_gpu_main_pow2_matches_cpu() {
        assert_main_parity(64);
    }

    /// Short (< MAX_COEFFS) coefficient vectors — exercises the flatten zero-pad branch and the
    /// `eval_at_1` index (16) landing in the zero-padded region.
    #[test]
    fn test_univariate_fold_gpu_main_short_coeffs_matches_cpu() {
        let stream = init_test_stream();
        let chip = UnivariateFoldChip::<F>::default();
        let mut record = RecursionRecord::<F>::default();
        record.univariate_fold_events = [1u32, 3, 16, 17, 30]
            .iter()
            .map(|&len| UnivariateFoldEvent {
                coeffs: (0..len).map(|k| block4(k.wrapping_add(1))).collect(),
                claimed_sum: block4(77),
                r: block4(13),
                next_sum: block4(99),
            })
            .collect();

        let cpu = chip.generate_main(&record, &mut RecursionRecord::default());
        let gpu = chip
            .gpu_generate_main(0, &record, &mut RecursionRecord::default())
            .to_host(stream);

        assert_eq!(
            cpu.values, gpu.values,
            "main parity failed for short-coeff events"
        );
    }

    #[test]
    fn test_univariate_fold_gpu_preprocessed_empty_matches_cpu() {
        assert_preprocessed_parity(0);
    }

    #[test]
    fn test_univariate_fold_gpu_preprocessed_sub16_matches_cpu() {
        assert_preprocessed_parity(5);
    }

    #[test]
    fn test_univariate_fold_gpu_preprocessed_matches_cpu() {
        assert_preprocessed_parity(40);
    }

    #[test]
    fn test_univariate_fold_gpu_preprocessed_pow2_matches_cpu() {
        assert_preprocessed_parity(64);
    }
}
