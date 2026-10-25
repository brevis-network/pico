use super::{
    columns::{
        ExpBitsLenCols, ExpBitsLenPreprocessedCols, NUM_BITS_MAX_PLUS_ONE, NUM_EXP_BITS_LEN_COLS,
        NUM_EXP_BITS_LEN_PREPROCESSED_COLS,
    },
    ExpBitsLenChip,
};
use crate::{
    compiler::recursion::{
        instruction::Instruction,
        program::RecursionProgram,
        types::{Address, ExpBitsLenEvent, ExpBitsLenInstr},
    },
    emulator::recursion::emulator::RecursionRecord,
    machine::chip::ChipBehavior,
};
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_koala_bear::KoalaBear;
use p3_matrix::Matrix;
use std::borrow::Borrow;

type F = KoalaBear;

/// Reference implementation of the chip's semantic equation, mirroring the host `sample_bits`:
/// `result = base^(canonical(bit_src) & ((1 << num_bits) - 1))`.
fn expected_result(base: F, bit_src: F, num_bits: usize) -> F {
    let v = bit_src.as_canonical_u32();
    let mask = if num_bits >= 32 {
        u32::MAX
    } else {
        (1u32 << num_bits) - 1
    };
    base.exp_u64((v & mask) as u64)
}

fn run_case(base_u: u32, bit_src_u: u32, num_bits: usize) {
    let base = F::from_u32(base_u);
    let bit_src = F::from_u32(bit_src_u);

    let chip = ExpBitsLenChip::<F>::default();
    let mut record = RecursionRecord::<F>::default();
    record.exp_bits_len_events.push(ExpBitsLenEvent {
        base,
        bit_src,
        num_bits: num_bits as u32,
    });

    let mut output = RecursionRecord::<F>::default();
    let trace = chip.generate_main(&record, &mut output);

    assert_eq!(trace.width(), NUM_EXP_BITS_LEN_COLS);
    assert!(trace.height() >= NUM_BITS_MAX_PLUS_ONE);

    // Row 0 (is_first) carries the anchored inputs and the final result.
    let row0 = trace.row_slice(0).unwrap();
    let first: &ExpBitsLenCols<F> = (*row0).borrow();
    assert_eq!(first.bit_idx, F::ZERO);
    assert_eq!(first.base, base);
    assert_eq!(first.bit_src, bit_src);
    assert_eq!(
        first.result,
        expected_result(base, bit_src, num_bits),
        "result mismatch for base={base_u}, bit_src={bit_src_u}, num_bits={num_bits}",
    );

    // Each decomposition row j (0..=30) exports the j-th canonical bit.
    let canonical = bit_src.as_canonical_u32();
    for j in 0..NUM_BITS_MAX_PLUS_ONE - 1 {
        let row = trace.row_slice(j).unwrap();
        let cols: &ExpBitsLenCols<F> = (*row).borrow();
        let want = (canonical >> j) & 1;
        assert_eq!(
            cols.bit_src_mod_2,
            F::from_u32(want),
            "bit {j} mismatch for bit_src={bit_src_u}",
        );
    }

    // Terminal row (row 31) anchors.
    let last = trace.row_slice(NUM_BITS_MAX_PLUS_ONE - 1).unwrap();
    let term: &ExpBitsLenCols<F> = (*last).borrow();
    assert_eq!(term.bit_idx, F::from_usize(NUM_BITS_MAX_PLUS_ONE - 1));
    assert_eq!(term.bit_src, F::ZERO);
    assert_eq!(term.num_bits, F::ZERO);
    assert_eq!(term.result, F::ONE);
    assert_eq!(term.result_multiplier, F::ONE);
    // Canonicality terminal check must hold: high_bits_all_one * (1 - low_bits_are_zero) == 0.
    let hi = term.high_bits_all_one;
    let lo = term.low_bits_are_zero;
    assert_eq!(hi * (F::ONE - lo), F::ZERO);
}

#[test]
fn test_exp_bits_len_result_matches_spec() {
    // Small values.
    run_case(3, 0b1011, 4); // 3^(11)
    run_case(5, 0b1101, 2); // only low 2 bits => 5^1
    run_case(7, 12345, 10);
    // num_bits == 0 => result must be 1 regardless of bit_src.
    run_case(9, 987654, 0);
    // A value >= 2^24 to exercise the KoalaBear high-region canonicity path.
    run_case(2, (1u32 << 24) + 12345, 31);
    run_case(11, (1u32 << 30) + 7, 31);
    // Full-width decomposition of a large canonical element.
    run_case(6, KoalaBear::ORDER_U32 - 1, 31);
}

#[test]
fn test_exp_bits_len_preprocessed_dimensions() {
    let chip = ExpBitsLenChip::<F>::default();

    let mk = |v: u32| Address(F::from_u32(v));
    // 31 bit-output addresses (one per decomposition row).
    let bit_outs: Vec<(Address<F>, F)> = (0..NUM_BITS_MAX_PLUS_ONE - 1)
        .map(|i| (mk(100 + i as u32), F::ONE))
        .collect();

    let instr = ExpBitsLenInstr {
        base: F::from_u32(3),
        num_bits: 8,
        bit_src_in_addr: mk(5),
        result_out_addr: mk(6),
        result_mult: F::from_u32(2),
        bit_outs_addrs_mults: bit_outs,
    };

    let program = RecursionProgram {
        instructions: vec![Instruction::ExpBitsLen(Box::new(instr))],
        ..Default::default()
    };

    let preprocessed = chip.generate_preprocessed(&program).unwrap();
    assert_eq!(preprocessed.width(), NUM_EXP_BITS_LEN_PREPROCESSED_COLS);
    assert!(preprocessed.height() >= NUM_BITS_MAX_PLUS_ONE);

    // Row 0 = is_first; row 31 = is_last.
    let row0 = preprocessed.row_slice(0).unwrap();
    let p0: &ExpBitsLenPreprocessedCols<F> = (*row0).borrow();
    assert_eq!(p0.is_first, F::ONE);
    assert_eq!(p0.is_last, F::ZERO);
    assert_eq!(p0.is_real, F::ONE);
    assert_eq!(p0.bit_src_in.addr.0, F::from_u32(5));
    assert_eq!(p0.bit_src_in.mult, F::NEG_ONE); // read on first row
    assert_eq!(p0.result_out.addr.0, F::from_u32(6));
    assert_eq!(p0.result_out.mult, F::from_u32(2)); // write count on first row
    assert_eq!(p0.base_const, F::from_u32(3));
    assert_eq!(p0.num_bits_const, F::from_u32(8));

    let row31 = preprocessed.row_slice(NUM_BITS_MAX_PLUS_ONE - 1).unwrap();
    let p31: &ExpBitsLenPreprocessedCols<F> = (*row31).borrow();
    assert_eq!(p31.is_first, F::ZERO);
    assert_eq!(p31.is_last, F::ONE);
    assert_eq!(p31.is_real, F::ONE);
    assert_eq!(p31.bit_src_in.mult, F::ZERO); // no read off the first row
    assert_eq!(p31.result_out.mult, F::ZERO); // no write off the first row
    assert_eq!(p31.bit_out.mult, F::ZERO); // terminal row exports no bit
}

/// GPU trace-gen must be element-wise identical to the CPU path over the full 32-row blocks, the
/// non-zero padding rows (result = result_multiplier = 1), and — critically — the closed-form
/// canonicality flags recomputed per-row on the device. The boundary set exercises the low/high
/// region split at bit 24, `num_bits` extremes, and all-zero / all-one bit patterns. Needs a CUDA
/// device (chip is KoalaBear-only).
mod gpu {
    use super::F;
    use crate::{
        chips::{chips::exp_bits_len::ExpBitsLenChip, tests::init_test_stream, trace::TraceData},
        compiler::recursion::{
            instruction::Instruction,
            program::RecursionProgram,
            types::{Address, ExpBitsLenEvent, ExpBitsLenInstr},
        },
        emulator::recursion::emulator::RecursionRecord,
        machine::chip::ChipBehavior,
    };
    use p3_field::PrimeCharacteristicRing;

    // (bit_src canonical u32, num_bits). All bit_src < p = 2^31 - 2^24 + 1 (0x7F000001), num_bits < 32.
    // Covers: zero, single bit, low-24 all-one, the bit-24 boundary, high-bits-all-one (p-1), etc.
    const BOUNDARY: &[(u32, u32)] = &[
        (0, 0),
        (0, 31),
        (1, 1),
        (0x00FF_FFFF, 24),
        (0x00FF_FFFF, 25),
        (0x0100_0000, 25),
        (0x7F00_0000, 31),
        (0x0000_FFFF, 16),
        (0x4000_0001, 31),
        (0x0055_5555, 20),
    ];

    fn ev(base_u: u32, bit_src_u: u32, num_bits: u32) -> ExpBitsLenEvent<F> {
        ExpBitsLenEvent {
            base: F::from_u32(base_u),
            bit_src: F::from_u32(bit_src_u),
            num_bits,
        }
    }

    fn cycled_events(n: usize) -> Vec<ExpBitsLenEvent<F>> {
        (0..n)
            .map(|i| {
                let (src, nb) = BOUNDARY[i % BOUNDARY.len()];
                ev(2 + (i as u32 % 5), src, nb)
            })
            .collect()
    }

    fn assert_main_parity(events: Vec<ExpBitsLenEvent<F>>) {
        let stream = init_test_stream();
        let chip = ExpBitsLenChip::<F>::default();
        let mut record = RecursionRecord::<F>::default();
        record.exp_bits_len_events = events;
        let cpu = chip.generate_main(&record, &mut RecursionRecord::default());
        let gpu: TraceData<'_, F> =
            chip.gpu_generate_main(0, &record, &mut RecursionRecord::default(), None);
        let gpu = gpu.to_host(stream);
        assert_eq!(cpu.values, gpu.values, "main parity failed");
    }

    /// Build a program whose instructions have exactly the given per-instruction bit-output counts.
    fn program_with_bit_out_counts(counts: &[usize]) -> RecursionProgram<F> {
        let mk = |v: u32| Address(F::from_u32(v));
        let instructions = counts
            .iter()
            .enumerate()
            .map(|(k, &cnt)| {
                let base = (k as u32 + 1) * 1000;
                let (_, nb) = BOUNDARY[k % BOUNDARY.len()];
                Instruction::ExpBitsLen(Box::new(ExpBitsLenInstr {
                    base: F::from_u32(2 + k as u32),
                    num_bits: nb,
                    bit_src_in_addr: mk(base),
                    result_out_addr: mk(base + 1),
                    result_mult: F::from_u32(k as u32 + 1),
                    bit_outs_addrs_mults: (0..cnt as u32)
                        .map(|i| (mk(base + 100 + i), F::from_u32(i + 1)))
                        .collect(),
                }))
            })
            .collect();
        RecursionProgram {
            instructions,
            ..Default::default()
        }
    }

    fn assert_preprocessed_parity(program: RecursionProgram<F>) {
        let stream = init_test_stream();
        let chip = ExpBitsLenChip::<F>::default();
        let cpu = chip.generate_preprocessed(&program).unwrap();
        let gpu = chip
            .gpu_generate_preprocessed(0, &program)
            .unwrap()
            .to_host(stream);
        assert_eq!(cpu.values, gpu.values, "preprocessed parity failed");
    }

    #[test]
    fn test_exp_bits_len_gpu_main_empty_matches_cpu() {
        assert_main_parity(vec![]);
    }
    #[test]
    fn test_exp_bits_len_gpu_main_single_matches_cpu() {
        assert_main_parity(vec![ev(7, 0x0155_5555, 23)]);
    }
    #[test]
    fn test_exp_bits_len_gpu_main_boundary_matches_cpu() {
        // One event per boundary pattern, so every flag boundary is exercised.
        let events = BOUNDARY.iter().map(|&(s, nb)| ev(3, s, nb)).collect();
        assert_main_parity(events);
    }
    #[test]
    fn test_exp_bits_len_gpu_main_multi_matches_cpu() {
        assert_main_parity(cycled_events(10));
    }
    #[test]
    fn test_exp_bits_len_gpu_preprocessed_empty_matches_cpu() {
        assert_preprocessed_parity(program_with_bit_out_counts(&[]));
    }
    #[test]
    fn test_exp_bits_len_gpu_preprocessed_single_matches_cpu() {
        assert_preprocessed_parity(program_with_bit_out_counts(&[31]));
    }
    #[test]
    fn test_exp_bits_len_gpu_preprocessed_varied_matches_cpu() {
        // Varied bit-output counts, including 0 and the full 31, across several instructions.
        assert_preprocessed_parity(program_with_bit_out_counts(&[0, 5, 31, 12]));
    }
}
