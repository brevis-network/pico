use super::FieldSpecificPoseidon2PackedChip;
use crate::{
    compiler::recursion::{
        instruction::Instruction,
        program::RecursionProgram,
        types::{Address, Poseidon2PackedInstr},
    },
    machine::chip::ChipBehavior,
};
use p3_field::PrimeCharacteristicRing;
use p3_koala_bear::KoalaBear;
use p3_matrix::Matrix;

type F = KoalaBear;

#[test]
fn test_poseidon2_packed_preprocessed_dimensions() {
    let chip = FieldSpecificPoseidon2PackedChip::<F>::default();

    let mk_addr = |v: u32| Address(F::from_u32(v));
    let instr = Poseidon2PackedInstr {
        input_addrs: std::array::from_fn(|i| mk_addr(10 + i as u32)),
        output_addrs: std::array::from_fn(|i| mk_addr(20 + i as u32)),
        mults: [F::TWO; 4],
    };

    let program = RecursionProgram {
        instructions: vec![Instruction::Poseidon2Packed(Box::new(instr))],
        ..Default::default()
    };

    let preprocessed = chip.generate_preprocessed(&program).unwrap();
    assert!(preprocessed.height() >= 16);
    assert_eq!(
        preprocessed.width(),
        super::columns::NUM_POSEIDON2_PACKED_PREPROCESSED_COLS
    );
    // Layout: [is_real, input[4], output[4] (addr, mult pairs)]
    let row = preprocessed.row_slice(0).unwrap();
    assert_eq!(row[0], F::ONE); // is_real
    assert_eq!(row[1], F::from_u32(10)); // input[0]
    assert_eq!(row[5], F::from_u32(20)); // output[0].addr
    assert_eq!(row[6], F::TWO); // output[0].mult
    assert_eq!(preprocessed.row_slice(1).unwrap()[0], F::ZERO); // padding
}

/// GPU trace-gen must be element-wise identical to the CPU path. The main columns are the shared
/// Poseidon2ValueCols (the permutation trace reuses the recursion poseidon2 kernel); events carry a
/// correct permutation output (the CPU populate_perm asserts it). KoalaBear-only; needs a CUDA
/// device.
mod gpu {
    use crate::{
        chips::{
            chips::poseidon2_packed::FieldSpecificPoseidon2PackedChip, tests::init_test_stream,
        },
        compiler::recursion::{
            instruction::Instruction,
            program::RecursionProgram,
            types::{Address, Poseidon2Event, Poseidon2PackedInstr},
        },
        emulator::recursion::emulator::RecursionRecord,
        machine::{chip::ChipBehavior, field::FieldSpecificPoseidon2Config},
        primitives::consts::PERMUTATION_WIDTH,
    };
    use p3_field::PrimeCharacteristicRing;
    use p3_koala_bear::KoalaBear;
    use p3_symmetric::Permutation;

    type F = KoalaBear;

    fn sample_events(n: u32) -> Vec<Poseidon2Event<F>> {
        let perm = KoalaBear::permutation();
        (0..n)
            .map(|i| {
                let input: [F; PERMUTATION_WIDTH] =
                    std::array::from_fn(|k| F::from_u32(i.wrapping_mul(37) + k as u32));
                let output = perm.permute(input);
                Poseidon2Event { input, output }
            })
            .collect()
    }

    fn sample_program(n: u32) -> RecursionProgram<F> {
        let mk = |v: u32| Address(F::from_u32(v));
        RecursionProgram {
            instructions: (0..n)
                .map(|i| {
                    let b = i.wrapping_mul(10);
                    Instruction::Poseidon2Packed(Box::new(Poseidon2PackedInstr {
                        input_addrs: std::array::from_fn(|k| mk(b + k as u32)),
                        output_addrs: std::array::from_fn(|k| mk(b + 4 + k as u32)),
                        mults: std::array::from_fn(|k| F::from_u32(k as u32 + 1)),
                    }))
                })
                .collect(),
            ..Default::default()
        }
    }

    fn assert_main_parity(n: u32) {
        let stream = init_test_stream();
        let chip = FieldSpecificPoseidon2PackedChip::<F>::default();
        let mut record = RecursionRecord::<F>::default();
        record.poseidon2_packed_events = sample_events(n);
        let cpu = chip.generate_main(&record, &mut RecursionRecord::default());
        let gpu = chip
            .gpu_generate_main(0, &record, &mut RecursionRecord::default(), None)
            .to_host(stream);
        assert_eq!(cpu.values, gpu.values, "main parity failed for {n} events");
    }

    fn assert_preprocessed_parity(n: u32) {
        let stream = init_test_stream();
        let chip = FieldSpecificPoseidon2PackedChip::<F>::default();
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

    // No empty-events main case: the reused recursion poseidon2 kernel fills padding rows from the
    // dummy row only relative to a non-empty event set (a convert proof always has >= 1 permutation).
    // The sub16 case below already exercises the real + dummy-padding row mix.
    #[test]
    fn test_poseidon2_packed_gpu_main_sub16_matches_cpu() {
        assert_main_parity(5);
    }
    #[test]
    fn test_poseidon2_packed_gpu_main_matches_cpu() {
        assert_main_parity(40);
    }
    #[test]
    fn test_poseidon2_packed_gpu_main_pow2_matches_cpu() {
        assert_main_parity(64);
    }
    #[test]
    fn test_poseidon2_packed_gpu_preprocessed_empty_matches_cpu() {
        assert_preprocessed_parity(0);
    }
    #[test]
    fn test_poseidon2_packed_gpu_preprocessed_sub16_matches_cpu() {
        assert_preprocessed_parity(5);
    }
    #[test]
    fn test_poseidon2_packed_gpu_preprocessed_matches_cpu() {
        assert_preprocessed_parity(40);
    }
    #[test]
    fn test_poseidon2_packed_gpu_preprocessed_pow2_matches_cpu() {
        assert_preprocessed_parity(64);
    }
}
