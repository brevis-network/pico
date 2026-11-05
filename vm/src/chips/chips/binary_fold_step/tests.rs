use super::{traces::fold_out, BinaryFoldStepChip};
use crate::{
    compiler::recursion::{
        instruction::Instruction,
        ir::Block,
        program::RecursionProgram,
        types::{Address, BinaryFoldStepEvent, BinaryFoldStepInstr},
    },
    emulator::recursion::emulator::RecursionRecord,
    machine::chip::ChipBehavior,
    primitives::consts::EXTENSION_DEGREE,
};
use p3_field::{
    extension::QuinticTrinomialExtensionField, BasedVectorSpace, Field, PrimeCharacteristicRing,
};
use p3_koala_bear::KoalaBear;
use p3_matrix::Matrix;

type F = KoalaBear;
type EF = QuinticTrinomialExtensionField<KoalaBear>;

fn b(v: u32) -> Block<F> {
    Block::from(F::from_u32(v))
}

#[test]
fn test_binary_fold_step_trace_values() {
    let chip = BinaryFoldStepChip::<F>::default();

    let tw = F::from_u32(3);
    let xi = F::from_u32(5);
    let inv_tw = tw.inverse();
    let xi_inv = xi.inverse();
    let alpha = F::from_u32(11);
    let v_lo = F::from_u32(100);
    let v_hi = F::from_u32(60);
    // out = v_lo + (alpha - tw*xi) * (v_lo - v_hi) * (inv_tw * xi_inv / 2)
    let out = v_lo + (alpha - tw * xi) * (v_lo - v_hi) * (inv_tw * xi_inv * F::TWO.inverse());

    let event = BinaryFoldStepEvent {
        tw,
        xi,
        inv_tw,
        xi_inv,
        alpha: b(11),
        v_lo: b(100),
        v_hi: b(60),
        out: Block::from(out),
    };

    let mut record = RecursionRecord::<F>::default();
    record.binary_fold_step_events.push(event);

    let mut output = RecursionRecord::<F>::default();
    let trace = chip.generate_main(&record, &mut output);
    assert!(trace.height() >= 16);
    assert_eq!(trace.width(), super::columns::NUM_BINARY_FOLD_STEP_COLS);
    // Layout: [tw, xi, inv_tw, xi_inv, alpha(E), v_lo(E), v_hi(E), amt(E), tih, out(E)], E = EXTENSION_DEGREE
    const E: usize = EXTENSION_DEGREE;
    let row = trace.row_slice(0).unwrap();
    assert_eq!(row[0], tw);
    assert_eq!(row[4], alpha); // alpha[0]
    assert_eq!(row[4 + 3 * E], alpha - tw * xi); // amt[0]
    assert_eq!(row[4 + 4 * E], inv_tw * xi_inv * F::TWO.inverse()); // tih
    assert_eq!(row[5 + 4 * E], out); // out[0]
}

#[test]
fn test_binary_fold_step_preprocessed_dimensions() {
    let chip = BinaryFoldStepChip::<F>::default();

    let mk_addr = |v: u32| Address(F::from_u32(v));
    let instr = BinaryFoldStepInstr {
        tw_addr: mk_addr(1),
        xi_addr: mk_addr(2),
        inv_tw_addr: mk_addr(3),
        xi_inv_addr: mk_addr(4),
        alpha_addr: mk_addr(5),
        v_lo_addr: mk_addr(6),
        v_hi_addr: mk_addr(7),
        out_addr: mk_addr(8),
        mult: F::ONE,
    };

    let program = RecursionProgram {
        instructions: vec![Instruction::BinaryFoldStep(Box::new(instr))],
        ..Default::default()
    };

    let preprocessed = chip.generate_preprocessed(&program).unwrap();
    assert!(preprocessed.height() >= 16);
    assert_eq!(
        preprocessed.width(),
        super::columns::NUM_BINARY_FOLD_STEP_PREPROCESSED_COLS
    );
    assert_eq!(preprocessed.row_slice(0).unwrap()[0], F::ONE); // is_real
    assert_eq!(preprocessed.row_slice(1).unwrap()[0], F::ZERO); // padding
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
fn test_binary_fold_step_trace_values_all_lanes() {
    let chip = BinaryFoldStepChip::<F>::default();

    let tw = F::from_u32(3);
    let xi = F::from_u32(5);
    let inv_tw = tw.inverse();
    let xi_inv = xi.inverse();
    let alpha = ef(11);
    let v_lo = ef(100);
    let v_hi = ef(60);
    let tih = inv_tw * xi_inv * F::TWO.inverse();
    let amt = alpha - EF::from(tw * xi);
    let out = v_lo + amt * (v_lo - v_hi) * EF::from(tih);

    let mut record = RecursionRecord::<F>::default();
    record.binary_fold_step_events.push(BinaryFoldStepEvent {
        tw,
        xi,
        inv_tw,
        xi_inv,
        alpha: blk(alpha),
        v_lo: blk(v_lo),
        v_hi: blk(v_hi),
        out: blk(out),
    });

    // The tracegen's all-lane recomputation of `out` (its debug-build check) against the
    // extension-field arithmetic, in every profile.
    assert_eq!(
        fold_out(blk(v_lo).0, blk(v_hi).0, blk(amt).0, tih),
        blk(out).0
    );

    let mut output = RecursionRecord::<F>::default();
    let trace = chip.generate_main(&record, &mut output);
    const E: usize = EXTENSION_DEGREE;
    let row = trace.row_slice(0).unwrap();
    assert_eq!(ef_at(&row[..], 4), alpha);
    assert_eq!(ef_at(&row[..], 4 + 3 * E), amt); // derived by the tracegen
    assert_eq!(row[4 + 4 * E], tih); // derived by the tracegen
    assert_eq!(ef_at(&row[..], 5 + 4 * E), out);
}

/// GPU trace-gen must be element-wise identical to the CPU path (device-computed amt/tih, verbatim
/// out) including padding. Events carry full-Block alpha/v_lo/v_hi with a correctly folded `out`
/// (the CPU generate_main debug-asserts it). KoalaBear-only; needs a CUDA device.
#[cfg(feature = "cuda")]
mod gpu {
    use crate::{
        chips::{chips::binary_fold_step::BinaryFoldStepChip, tests::init_test_stream},
        compiler::recursion::{
            instruction::Instruction,
            ir::Block,
            program::RecursionProgram,
            types::{Address, BinaryFoldStepEvent, BinaryFoldStepInstr},
        },
        emulator::recursion::emulator::RecursionRecord,
        machine::chip::{ChipBehavior, GpuChipBehavior},
        primitives::consts::EXTENSION_DEGREE,
    };
    use p3_field::{extension::trinomial_quintic_mul, Field, PrimeCharacteristicRing};
    use p3_koala_bear::KoalaBear;

    type F = KoalaBear;

    fn ef_mul(a: [F; EXTENSION_DEGREE], b: [F; EXTENSION_DEGREE]) -> [F; EXTENSION_DEGREE] {
        let mut r = [F::ZERO; EXTENSION_DEGREE];
        trinomial_quintic_mul(&a, &b, &mut r);
        r
    }

    /// Build an event whose `out` is the correct binary-fold result (so the CPU debug_assert holds).
    fn make_event(i: u32) -> BinaryFoldStepEvent<F> {
        let b = i.wrapping_mul(100) + 1;
        let tw = F::from_u32(b + 3);
        let xi = F::from_u32(b + 5);
        let inv_tw = tw.inverse();
        let xi_inv = xi.inverse();
        let alpha: [F; EXTENSION_DEGREE] = std::array::from_fn(|k| F::from_u32(b + 10 + k as u32));
        let v_lo: [F; EXTENSION_DEGREE] = std::array::from_fn(|k| F::from_u32(b + 20 + k as u32));
        let v_hi: [F; EXTENSION_DEGREE] = std::array::from_fn(|k| F::from_u32(b + 30 + k as u32));

        let mut amt = alpha;
        amt[0] -= tw * xi;
        let diff: [F; EXTENSION_DEGREE] = std::array::from_fn(|k| v_lo[k] - v_hi[k]);
        let t = ef_mul(amt, diff);
        let tih = inv_tw * xi_inv * F::TWO.inverse();
        let out: [F; EXTENSION_DEGREE] = std::array::from_fn(|k| v_lo[k] + t[k] * tih);

        BinaryFoldStepEvent {
            tw,
            xi,
            inv_tw,
            xi_inv,
            alpha: Block(alpha),
            v_lo: Block(v_lo),
            v_hi: Block(v_hi),
            out: Block(out),
        }
    }

    fn sample_events(n: u32) -> Vec<BinaryFoldStepEvent<F>> {
        (0..n).map(make_event).collect()
    }

    fn sample_program(n: u32) -> RecursionProgram<F> {
        let mk = |v: u32| Address(F::from_u32(v));
        RecursionProgram {
            instructions: (0..n)
                .map(|i| {
                    let b = i.wrapping_mul(10);
                    Instruction::BinaryFoldStep(Box::new(BinaryFoldStepInstr {
                        tw_addr: mk(b),
                        xi_addr: mk(b + 1),
                        inv_tw_addr: mk(b + 2),
                        xi_inv_addr: mk(b + 3),
                        alpha_addr: mk(b + 4),
                        v_lo_addr: mk(b + 5),
                        v_hi_addr: mk(b + 6),
                        out_addr: mk(b + 7),
                        mult: F::ONE,
                    }))
                })
                .collect(),
            ..Default::default()
        }
    }

    fn assert_main_parity(n: u32) {
        let stream = init_test_stream();
        let chip = BinaryFoldStepChip::<F>::default();
        let mut record = RecursionRecord::<F>::default();
        record.binary_fold_step_events = sample_events(n);
        let cpu = chip.generate_main(&record, &mut RecursionRecord::default());
        let gpu = chip
            .gpu_generate_main(0, &record, &mut RecursionRecord::default())
            .to_host(stream);
        assert_eq!(cpu.values, gpu.values, "main parity failed for {n} events");
    }

    fn assert_preprocessed_parity(n: u32) {
        let stream = init_test_stream();
        let chip = BinaryFoldStepChip::<F>::default();
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

    #[test]
    fn test_binary_fold_step_gpu_main_empty_matches_cpu() {
        assert_main_parity(0);
    }
    #[test]
    fn test_binary_fold_step_gpu_main_sub16_matches_cpu() {
        assert_main_parity(5);
    }
    #[test]
    fn test_binary_fold_step_gpu_main_matches_cpu() {
        assert_main_parity(40);
    }
    #[test]
    fn test_binary_fold_step_gpu_main_pow2_matches_cpu() {
        assert_main_parity(64);
    }
    #[test]
    fn test_binary_fold_step_gpu_preprocessed_empty_matches_cpu() {
        assert_preprocessed_parity(0);
    }
    #[test]
    fn test_binary_fold_step_gpu_preprocessed_sub16_matches_cpu() {
        assert_preprocessed_parity(5);
    }
    #[test]
    fn test_binary_fold_step_gpu_preprocessed_matches_cpu() {
        assert_preprocessed_parity(40);
    }
    #[test]
    fn test_binary_fold_step_gpu_preprocessed_pow2_matches_cpu() {
        assert_preprocessed_parity(64);
    }
}
