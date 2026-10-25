use super::ExtDotProductChip;
use crate::{
    compiler::recursion::{
        instruction::Instruction,
        ir::Block,
        program::RecursionProgram,
        types::{Address, ExtDotProductEvent, ExtDotProductInstr},
    },
    emulator::recursion::emulator::RecursionRecord,
    machine::chip::ChipBehavior,
    primitives::consts::{EXT_DOT_PRODUCT_DATAPAR, EXT_DOT_PRODUCT_GROUPS},
};
use p3_field::PrimeCharacteristicRing;
use p3_koala_bear::KoalaBear;
use p3_matrix::Matrix;

type F = KoalaBear;
const D: usize = EXT_DOT_PRODUCT_DATAPAR;
const G: usize = EXT_DOT_PRODUCT_GROUPS;

fn b(v: u32) -> Block<F> {
    Block([F::from_u32(v), F::ZERO, F::ZERO, F::ZERO])
}

#[test]
fn test_ext_dot_product_trace_row_acc() {
    let chip = ExtDotProductChip::<F>::default();

    // One row: G packed value blocks (lanes all 2) and D mus = 1..D
    // -> acc = 2 * (1+..+D).
    let mus: [Block<F>; D] = std::array::from_fn(|j| b(j as u32 + 1));
    let vals: [Block<F>; G] = std::array::from_fn(|_| Block([F::from_u32(2); 4]));
    let sum = 2 * (D * (D + 1) / 2) as u32;

    let mut record = RecursionRecord::<F>::default();
    record.ext_dot_product_events.push(ExtDotProductEvent {
        mus,
        vals,
        acc: b(sum),
    });

    let mut output = RecursionRecord::<F>::default();
    let trace = chip.generate_main(&record, &mut output);
    assert!(trace.height() >= 16);
    assert_eq!(trace.width(), super::columns::NUM_EXT_DOT_PRODUCT_COLS);
    // Column layout: [mus[D] (4 lanes each), vals[G] (4 lanes each), acc]
    let row = trace.row_slice(0).unwrap();
    assert_eq!(row[0], F::from_u32(1)); // mus[0] lane 0
    assert_eq!(row[4 * D], F::from_u32(2)); // vals[0] lane 0
    assert_eq!(row[4 * D + 1], F::from_u32(2)); // vals[0] lane 1 (packed!)
    assert_eq!(row[4 * D + 4 * G], F::from_u32(sum)); // acc
}

#[test]
fn test_ext_dot_product_preprocessed_segmentation() {
    let chip = ExtDotProductChip::<F>::default();

    let mk_addr = |v: u32| Address(F::from_u32(v));
    // Two rows (2*G packed groups = 2*D elements) in one instruction, then a
    // single-row instruction.
    let instr1 = ExtDotProductInstr {
        mu_addrs: (0..2 * D as u32).map(|i| mk_addr(100 + i)).collect(),
        val_addrs: (0..2 * G as u32).map(|i| mk_addr(200 + i)).collect(),
        acc_addr: mk_addr(50),
        mult: F::TWO,
    };
    let instr2 = ExtDotProductInstr {
        mu_addrs: (0..D as u32).map(|i| mk_addr(300 + i)).collect(),
        val_addrs: (0..G as u32).map(|i| mk_addr(400 + i)).collect(),
        acc_addr: mk_addr(51),
        mult: F::ONE,
    };

    let program = RecursionProgram {
        instructions: vec![
            Instruction::ExtDotProduct(Box::new(instr1)),
            Instruction::ExtDotProduct(Box::new(instr2)),
        ],
        ..Default::default()
    };

    let preprocessed = chip.generate_preprocessed(&program).unwrap();
    assert_eq!(
        preprocessed.width(),
        super::columns::NUM_EXT_DOT_PRODUCT_PREPROCESSED_COLS
    );
    // Column layout: [is_real, is_end, mu_addrs[D], val_addrs[G], acc_addr, mult]
    let expect = [
        (F::ONE, F::ZERO, F::ZERO),
        (F::ONE, F::ONE, F::TWO),
        (F::ONE, F::ONE, F::ONE),
        (F::ZERO, F::ZERO, F::ZERO), // padding
    ];
    let mult_col = 2 + D + G + 1;
    for (i, &(is_real, is_end, mult)) in expect.iter().enumerate() {
        let row = preprocessed.row_slice(i).unwrap();
        assert_eq!(row[0], is_real, "row {i} is_real");
        assert_eq!(row[1], is_end, "row {i} is_end");
        assert_eq!(row[mult_col], mult, "row {i} mult");
    }
}

/// GPU trace-gen must be element-wise identical to the CPU path. The main event maps 1:1 to a row;
/// each preprocessed instruction expands to a data-dependent number of rows (host-side), so this
/// exercises multi-instruction concatenation and multi-row segments. KoalaBear-only; needs a CUDA
/// device.
mod gpu {
    use crate::{
        chips::{chips::ext_dot_product::ExtDotProductChip, tests::init_test_stream},
        compiler::recursion::{
            instruction::Instruction,
            ir::Block,
            program::RecursionProgram,
            types::{Address, ExtDotProductEvent, ExtDotProductInstr},
        },
        emulator::recursion::emulator::RecursionRecord,
        machine::chip::ChipBehavior,
        primitives::consts::{EXT_DOT_PRODUCT_DATAPAR, EXT_DOT_PRODUCT_GROUPS},
    };
    use p3_field::PrimeCharacteristicRing;
    use p3_koala_bear::KoalaBear;

    type F = KoalaBear;
    const D: usize = EXT_DOT_PRODUCT_DATAPAR;
    const G: usize = EXT_DOT_PRODUCT_GROUPS;

    fn blk(base: u32) -> Block<F> {
        Block(std::array::from_fn(|k| F::from_u32(base + k as u32)))
    }

    fn sample_events(n: u32) -> Vec<ExtDotProductEvent<F>> {
        (0..n)
            .map(|i| {
                let base = i.wrapping_mul(1000);
                ExtDotProductEvent {
                    mus: std::array::from_fn(|j| blk(base + 4 * j as u32)),
                    vals: std::array::from_fn(|g| blk(base + 100 + 4 * g as u32)),
                    acc: blk(base + 900),
                }
            })
            .collect()
    }

    /// Build a program whose instructions have exactly the given per-instruction row counts.
    fn program_with_row_counts(counts: &[usize]) -> RecursionProgram<F> {
        let mk = |v: u32| Address(F::from_u32(v));
        let instructions = counts
            .iter()
            .enumerate()
            .map(|(k, &n_rows)| {
                let base = (k as u32 + 1) * 10_000;
                // mu_addrs.len() = n_rows * D, val_addrs.len() = n_rows * G.
                Instruction::ExtDotProduct(Box::new(ExtDotProductInstr {
                    mu_addrs: (0..(n_rows * D) as u32).map(|i| mk(base + i)).collect(),
                    val_addrs: (0..(n_rows * G) as u32)
                        .map(|i| mk(base + 5000 + i))
                        .collect(),
                    acc_addr: mk(base + 9000),
                    mult: F::from_u32(k as u32 + 1),
                }))
            })
            .collect();
        RecursionProgram {
            instructions,
            ..Default::default()
        }
    }

    fn assert_main_parity(n: u32) {
        let stream = init_test_stream();
        let chip = ExtDotProductChip::<F>::default();
        let mut record = RecursionRecord::<F>::default();
        record.ext_dot_product_events = sample_events(n);
        let cpu = chip.generate_main(&record, &mut RecursionRecord::default());
        let gpu = chip
            .gpu_generate_main(0, &record, &mut RecursionRecord::default(), None)
            .to_host(stream);
        assert_eq!(cpu.values, gpu.values, "main parity failed for {n} events");
    }

    fn assert_preprocessed_parity(counts: &[usize]) {
        let stream = init_test_stream();
        let chip = ExtDotProductChip::<F>::default();
        let program = program_with_row_counts(counts);
        let cpu = chip.generate_preprocessed(&program).unwrap();
        let gpu = chip
            .gpu_generate_preprocessed(0, &program)
            .unwrap()
            .to_host(stream);
        assert_eq!(
            cpu.values, gpu.values,
            "preprocessed parity failed for row counts {counts:?}"
        );
    }

    #[test]
    fn test_ext_dot_product_gpu_main_empty_matches_cpu() {
        assert_main_parity(0);
    }
    #[test]
    fn test_ext_dot_product_gpu_main_small_matches_cpu() {
        assert_main_parity(5);
    }
    #[test]
    fn test_ext_dot_product_gpu_main_matches_cpu() {
        assert_main_parity(40);
    }
    #[test]
    fn test_ext_dot_product_gpu_main_multirow_matches_cpu() {
        assert_main_parity(130);
    }
    #[test]
    fn test_ext_dot_product_gpu_preprocessed_empty_matches_cpu() {
        assert_preprocessed_parity(&[]);
    }
    #[test]
    fn test_ext_dot_product_gpu_preprocessed_single_matches_cpu() {
        assert_preprocessed_parity(&[1]);
    }
    #[test]
    fn test_ext_dot_product_gpu_preprocessed_multi_matches_cpu() {
        // Multiple instructions, each a multi-row segment; total 6 rows -> padded to 16.
        assert_preprocessed_parity(&[2, 1, 3]);
    }
    #[test]
    fn test_ext_dot_product_gpu_preprocessed_multirow_matches_cpu() {
        // Total 35 rows -> padded to 64; exercises segment boundaries past the 16-row floor.
        assert_preprocessed_parity(&[10, 20, 5]);
    }
}
