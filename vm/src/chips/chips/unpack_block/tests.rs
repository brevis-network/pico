use super::UnpackBlockChip;
use crate::{
    compiler::recursion::{
        instruction::Instruction,
        ir::Block,
        program::RecursionProgram,
        types::{Address, UnpackBlockEvent, UnpackBlockInstr},
    },
    emulator::recursion::emulator::RecursionRecord,
    machine::chip::ChipBehavior,
};
use p3_field::PrimeCharacteristicRing;
use p3_koala_bear::KoalaBear;
use p3_matrix::Matrix;

type F = KoalaBear;

#[test]
fn test_unpack_block_trace_values() {
    let chip = UnpackBlockChip::<F>::default();

    let val = Block(std::array::from_fn(|i| F::from_u32(100 + i as u32)));

    let mut record = RecursionRecord::<F>::default();
    record.unpack_block_events.push(UnpackBlockEvent { val });

    let mut output = RecursionRecord::<F>::default();
    let trace = chip.generate_main(&record, &mut output);
    assert!(trace.height() >= 16);
    assert_eq!(trace.width(), super::columns::NUM_UNPACK_BLOCK_COLS);
    let row = trace.row_slice(0).unwrap();
    // Layout: [val[4]]
    for i in 0..4 {
        assert_eq!(row[i], val.0[i]);
    }
    // Padding row is all zeros.
    assert_eq!(trace.row_slice(1).unwrap()[0], F::ZERO);
}

#[test]
fn test_unpack_block_preprocessed_dimensions() {
    let chip = UnpackBlockChip::<F>::default();

    let mk_addr = |v: u32| Address(F::from_u32(v));
    let instr = UnpackBlockInstr {
        in_addr: mk_addr(5),
        out_addrs: std::array::from_fn(|i| mk_addr(10 + i as u32)),
        mults: [F::TWO; 4],
    };

    let program = RecursionProgram {
        instructions: vec![Instruction::UnpackBlock(Box::new(instr))],
        ..Default::default()
    };

    let preprocessed = chip.generate_preprocessed(&program).unwrap();
    assert!(preprocessed.height() >= 16);
    assert_eq!(
        preprocessed.width(),
        super::columns::NUM_UNPACK_BLOCK_PREPROCESSED_COLS
    );
    // Layout: [is_real, in_addr, out[4] (addr, mult pairs)]
    let row = preprocessed.row_slice(0).unwrap();
    assert_eq!(row[0], F::ONE); // is_real
    assert_eq!(row[1], F::from_u32(5)); // in_addr
    assert_eq!(row[2], F::from_u32(10)); // out[0].addr
    assert_eq!(row[3], F::TWO); // out[0].mult
    assert_eq!(preprocessed.row_slice(1).unwrap()[0], F::ZERO); // padding
}

/// GPU trace-gen must be element-wise identical to the CPU path, including padding rows.
/// KoalaBear-only (the GPU path allocates `DevicePoolAllocation::<KoalaBear>`); needs a CUDA device.
#[cfg(feature = "cuda")]
mod gpu {
    use crate::{
        chips::{chips::unpack_block::UnpackBlockChip, tests::init_test_stream},
        compiler::recursion::{
            instruction::Instruction,
            ir::Block,
            program::RecursionProgram,
            types::{Address, UnpackBlockEvent, UnpackBlockInstr},
        },
        emulator::recursion::emulator::RecursionRecord,
        machine::chip::{ChipBehavior, GpuChipBehavior},
    };
    use p3_field::PrimeCharacteristicRing;
    use p3_koala_bear::KoalaBear;

    type F = KoalaBear;

    fn sample_events(n: u32) -> Vec<UnpackBlockEvent<F>> {
        (0..n)
            .map(|i| UnpackBlockEvent {
                val: Block([
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
                    let a = i.wrapping_mul(8);
                    Instruction::UnpackBlock(Box::new(UnpackBlockInstr {
                        in_addr: Address(F::from_u32(a)),
                        out_addrs: std::array::from_fn(|k| {
                            Address(F::from_u32(a.wrapping_add(1 + k as u32)))
                        }),
                        mults: std::array::from_fn(|k| F::from_u32(k as u32)),
                    }))
                })
                .collect(),
            ..Default::default()
        }
    }

    fn assert_main_parity(n: u32) {
        let stream = init_test_stream();
        let chip = UnpackBlockChip::<F>::default();
        let mut record = RecursionRecord::<F>::default();
        record.unpack_block_events = sample_events(n);
        let cpu = chip.generate_main(&record, &mut RecursionRecord::default());
        let gpu = chip
            .gpu_generate_main(0, &record, &mut RecursionRecord::default())
            .to_host(stream);
        assert_eq!(cpu.values, gpu.values, "main parity failed for {n} events");
    }

    fn assert_preprocessed_parity(n: u32) {
        let stream = init_test_stream();
        let chip = UnpackBlockChip::<F>::default();
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
    fn test_unpack_block_gpu_main_empty_matches_cpu() {
        assert_main_parity(0);
    }
    #[test]
    fn test_unpack_block_gpu_main_sub16_matches_cpu() {
        assert_main_parity(5);
    }
    #[test]
    fn test_unpack_block_gpu_main_matches_cpu() {
        assert_main_parity(40);
    }
    #[test]
    fn test_unpack_block_gpu_main_pow2_matches_cpu() {
        assert_main_parity(64);
    }
    #[test]
    fn test_unpack_block_gpu_preprocessed_empty_matches_cpu() {
        assert_preprocessed_parity(0);
    }
    #[test]
    fn test_unpack_block_gpu_preprocessed_sub16_matches_cpu() {
        assert_preprocessed_parity(5);
    }
    #[test]
    fn test_unpack_block_gpu_preprocessed_matches_cpu() {
        assert_preprocessed_parity(40);
    }
    #[test]
    fn test_unpack_block_gpu_preprocessed_pow2_matches_cpu() {
        assert_preprocessed_parity(64);
    }
}
