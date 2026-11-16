//! Every precompile chip refuses to write the program's code, and only that.
//!
//! Each case runs one ECALL in the emulator on operands the syscall accepts, so the record holds
//! one event and the chip's trace one real row. That row is evaluated, through
//! [`DebugConstraintFolder`], with the program's code moved: onto the first and the last bytes the
//! event writes and around all of them, which has to fail the AIR, and right below and right above
//! those bytes, and onto bytes the event only reads, which has to satisfy it. The emulator refuses
//! the same writes (part 1b): any dword the precompile writes that meets the code.
//!
//! What they do not cover: the folder ignores lookups, so the code range's lookup of the Program
//! table and its two u16 checks are the end-to-end proof's job. A write into the code fails here on
//! the distance's equations, which two u16 limbs cannot satisfy for a negative distance.

use crate::{
    chips::{
        gadgets::{
            curves::{
                edwards::ed25519::{Ed25519, Ed25519Parameters},
                weierstrass::{
                    bls381::Bls381BaseField, bn254::Bn254BaseField, Bls12381, Bn254, Secp256k1,
                    Secp256r1,
                },
                AffinePoint, EllipticCurve,
            },
            field::secp256k1::Secp256k1BaseField,
        },
        precompiles::{
            edwards::{EdAddAssignChip, EdDecompressChip},
            fptower::{fp::FpOpChip, fp2_addsub::Fp2AddSubChip, fp2_mul::Fp2MulChip},
            keccak256::KeccakControlChip,
            poseidon2::FieldSpecificPrecompilePoseidon2Chip,
            sha256::{compress::ShaCompressControlChip, extend::ShaExtendControlChip},
            uint256::Uint256MulChip,
            weierstrass::{
                weierstrass_add::WeierstrassAddAssignChip,
                weierstrass_decompress::WeierstrassDecompressChip,
                weierstrass_double::WeierstrassDoubleAssignChip,
            },
        },
        tests::test_rv64_emulate,
    },
    compiler::riscv::{instruction::Instruction, opcode::Opcode, program::Program},
    configs::stark_config::KoalaBearPoseidon2,
    emulator::{
        riscv::{record::EmulationRecord, syscalls::SyscallCode},
        stdin::EmulatorStdin,
    },
    machine::{chip::ChipBehavior, debug_folder::DebugConstraintFolder, septic::SepticDigest},
};
use core::ops::Range;
use num::BigUint;
use p3_air::{Air, RowWindow};
use p3_field::{extension::QuinticTrinomialExtensionField, PrimeCharacteristicRing};
use p3_koala_bear::KoalaBear;
use p3_matrix::Matrix;
use std::{collections::BTreeMap, sync::Arc};

type F = KoalaBear;
type EF = QuinticTrinomialExtensionField<KoalaBear>;

/// Where the operands go: dword-aligned, clear of each other, and far above the test program,
/// whose code is its few instructions from 0.
const A: u64 = 0x10_0000;
const B: u64 = 0x10_1000;

fn li(rd: u8, imm: u64) -> Instruction {
    Instruction::new(Opcode::ADD, rd, 0, imm, true, true)
}

/// One ECALL of `code` on `arg1` and `arg2`, then a halt.
fn one_syscall(code: SyscallCode, arg1: u64, arg2: u64) -> Vec<Instruction> {
    vec![
        li(10, arg1),
        li(11, arg2),
        li(5, u64::from(code as u32)),
        Instruction::new(Opcode::ECALL, 5, 10, 11, false, false),
        li(10, 0),
        li(5, u64::from(SyscallCode::HALT as u32)),
        Instruction::new(Opcode::ECALL, 5, 10, 11, false, false),
    ]
}

/// `dwords` laid down from `at`.
fn put(image: &mut BTreeMap<u64, u64>, at: u64, dwords: &[u64]) {
    for (i, &dword) in dwords.iter().enumerate() {
        image.insert(at + 8 * i as u64, dword);
    }
}

/// `value` as `bytes / 8` little-endian dwords.
fn dwords_of(value: &BigUint, bytes: usize) -> Vec<u64> {
    let mut le = value.to_bytes_le();
    le.resize(bytes, 0);
    le.as_chunks::<8>()
        .0
        .iter()
        .map(|c| u64::from_le_bytes(*c))
        .collect()
}

/// A point as the guest holds it: x's dwords, then y's.
fn point_dwords<E: EllipticCurve>(p: &AffinePoint<E>) -> Vec<u64> {
    p.to_words_le()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u64::from(c[0]) | (u64::from(c[1]) << 32))
        .collect()
}

/// A program whose code is exactly `code`, a whole number of instructions.
fn program_over(code: Range<u64>) -> Arc<Program> {
    let n = ((code.end - code.start) / 4) as usize;
    Arc::new(Program::new(vec![li(0, 0); n], code.start, code.start))
}

/// The constraints the AIR reports violated on `row`.
fn failures<C>(chip: &C, row: &[F]) -> Vec<String>
where
    C: for<'a> Air<DebugConstraintFolder<'a, F, EF>>,
{
    let dummy = [F::ZERO];
    let mut folder = DebugConstraintFolder::<F, EF> {
        preprocessed: RowWindow::from_two_rows(&dummy, &dummy),
        main: RowWindow::from_two_rows(row, row),
        global_cumulative_sum: SepticDigest::<F>::zero(),
        is_first_row: F::ZERO,
        is_last_row: F::ZERO,
        is_transition: F::ONE,
        public_values: &[],
        failures: Vec::new(),
        scopes: Vec::new(),
        constraint_count: 0,
    };
    chip.eval(&mut folder);
    folder
        .failures
        .iter()
        .map(|(scopes, failure)| format!("{scopes:?} {failure:?}"))
        .collect()
}

/// One precompile call: its ECALL, the memory it starts from, the bytes it writes, and bytes it
/// only reads.
struct Case {
    name: &'static str,
    syscall: SyscallCode,
    arg1: u64,
    arg2: u64,
    image: BTreeMap<u64, u64>,
    written: Range<u64>,
    read_only: Range<u64>,
}

/// The record of the chunk `case`'s ECALL ran in.
fn record_of(case: &Case) -> EmulationRecord {
    let program = Program {
        instructions: one_syscall(case.syscall, case.arg1, case.arg2).into(),
        pc_start: 0,
        pc_base: 0,
        memory_image: Arc::new(case.image.clone()),
        preprocessed_shape: None,
        profiled_functions: Default::default(),
    };
    let stdin = EmulatorStdin::new_builder::<KoalaBearPoseidon2>().finalize();
    test_rv64_emulate(Arc::new(program), stdin)
        .into_iter()
        .find(|record| !record.precompile_events.is_empty())
        .unwrap_or_else(|| panic!("{}: the ECALL raised no precompile event", case.name))
}

/// Runs `case` and holds `chip`'s row for its event to the code range rules.
fn check<C>(chip: C, case: Case)
where
    C: ChipBehavior<F, Record = EmulationRecord, Program = Program>
        + for<'a> Air<DebugConstraintFolder<'a, F, EF>>,
{
    let name = case.name;
    let record = record_of(&case);
    assert_eq!(
        record.precompile_events.all_events().count(),
        1,
        "{name}: one event"
    );

    let row_with = |code: Range<u64>| {
        let mut record = record.clone();
        record.program = program_over(code);
        let trace = chip.generate_main(&record, &mut EmulationRecord::default());
        trace.values[..trace.width()].to_vec()
    };
    let (start, end) = (case.written.start, case.written.end);

    // Where the emulator ran it, and where nothing is written.
    let passing = [
        record.program.code(),
        start - 8..start,
        end..end + 8,
        case.read_only.clone(),
    ];
    for code in passing {
        let failures = failures(&chip, &row_with(code.clone()));
        assert!(
            failures.is_empty(),
            "{name}, code at {code:x?}: {failures:?}"
        );
    }
    // On the first written byte, on the last, and around the whole write.
    let failing = [start..start + 4, end - 4..end, start - 64..end + 64];
    for code in failing {
        assert!(
            !failures(&chip, &row_with(code.clone())).is_empty(),
            "{name}, code at {code:x?}: the write into it satisfies the AIR"
        );
    }
}

fn sha_extend_case() -> Case {
    let mut image = BTreeMap::new();
    put(
        &mut image,
        A,
        &(1..=16).map(|i| i * 0x0101_0101).collect::<Vec<_>>(),
    );
    Case {
        name: "SHA_EXTEND",
        syscall: SyscallCode::SHA_EXTEND,
        arg1: A,
        arg2: 0,
        image,
        // `w[16..64]`; `w[0..16]` is only read.
        written: A + 128..A + 512,
        read_only: A..A + 128,
    }
}

#[test]
fn sha_extend_refuses_to_write_the_code() {
    check(ShaExtendControlChip::<F>::default(), sha_extend_case());
}

fn sha_compress_case() -> Case {
    let mut image = BTreeMap::new();
    put(
        &mut image,
        A,
        &(1..=64).map(|i| i * 0x0301_0201).collect::<Vec<_>>(),
    );
    put(
        &mut image,
        B,
        &(1..=8).map(|i| i * 0x1111_1111).collect::<Vec<_>>(),
    );
    Case {
        name: "SHA_COMPRESS",
        syscall: SyscallCode::SHA_COMPRESS,
        arg1: A,
        arg2: B,
        image,
        written: B..B + 64,
        read_only: A..A + 512,
    }
}

#[test]
fn sha_compress_refuses_to_write_the_code() {
    check(ShaCompressControlChip::<F>::default(), sha_compress_case());
}

fn keccak_case() -> Case {
    let mut image = BTreeMap::new();
    put(
        &mut image,
        A,
        &(1..=25)
            .map(|i| i * 0x0123_4567_89ab_cdef)
            .collect::<Vec<_>>(),
    );
    Case {
        name: "KECCAK_PERMUTE",
        syscall: SyscallCode::KECCAK_PERMUTE,
        arg1: A,
        arg2: 0,
        image,
        written: A..A + 200,
        // The state is read and written in place: nothing is only read.
        read_only: A + 200..A + 208,
    }
}

#[test]
fn keccak_refuses_to_write_the_code() {
    check(KeccakControlChip::<F>::default(), keccak_case());
}

fn uint256_case() -> Case {
    let mut image = BTreeMap::new();
    put(&mut image, A, &dwords_of(&BigUint::from(12_345u32), 32));
    put(&mut image, B, &dwords_of(&BigUint::from(678u32), 32));
    put(
        &mut image,
        B + 32,
        &dwords_of(&BigUint::from(1_000_003u32), 32),
    );
    Case {
        name: "UINT256_MUL",
        syscall: SyscallCode::UINT256_MUL,
        arg1: A,
        arg2: B,
        image,
        written: A..A + 32,
        read_only: B..B + 64,
    }
}

#[test]
fn uint256_refuses_to_write_the_code() {
    check(Uint256MulChip::<F>::default(), uint256_case());
}

fn poseidon2_case() -> Case {
    let mut image = BTreeMap::new();
    put(
        &mut image,
        A,
        &(0..8u64)
            .map(|i| (2 * i + 1) | ((2 * i + 2) << 32))
            .collect::<Vec<_>>(),
    );
    put(&mut image, B, &[0; 8]);
    Case {
        name: "POSEIDON2_PERMUTE",
        syscall: SyscallCode::POSEIDON2_PERMUTE,
        arg1: A,
        arg2: B,
        image,
        written: B..B + 64,
        read_only: A..A + 64,
    }
}

#[test]
fn poseidon2_refuses_to_write_the_code() {
    check(
        FieldSpecificPrecompilePoseidon2Chip::<F>::default(),
        poseidon2_case(),
    );
}

fn edwards_add_case() -> Case {
    let g = Ed25519::ec_generator();
    let mut image = BTreeMap::new();
    put(&mut image, A, &point_dwords(&g));
    put(&mut image, B, &point_dwords(&g));
    Case {
        name: "ED_ADD",
        syscall: SyscallCode::ED_ADD,
        arg1: A,
        arg2: B,
        image,
        written: A..A + 64,
        read_only: B..B + 64,
    }
}

#[test]
fn edwards_add_refuses_to_write_the_code() {
    check(EdAddAssignChip::<F, Ed25519>::default(), edwards_add_case());
}

fn edwards_decompress_case() -> Case {
    let g = Ed25519::ec_generator();
    let sign = g.x.bit(0);
    let mut image = BTreeMap::new();
    put(&mut image, A, &[0; 4]);
    put(&mut image, A + 32, &dwords_of(&g.y, 32));
    Case {
        name: "ED_DECOMPRESS",
        syscall: SyscallCode::ED_DECOMPRESS,
        arg1: A,
        arg2: u64::from(sign),
        image,
        // `x` goes to the slice's first half; `y`, the second, is only read.
        written: A..A + 32,
        read_only: A + 32..A + 64,
    }
}

#[test]
fn edwards_decompress_refuses_to_write_the_code() {
    check(
        EdDecompressChip::<F, Ed25519Parameters>::default(),
        edwards_decompress_case(),
    );
}

/// `g += 2g` and `g = 2g` on curve `E`, `g` its generator.
fn weierstrass<E: EllipticCurve>(add: SyscallCode, double: SyscallCode) -> [Case; 2] {
    let g = E::ec_generator();
    let g2 = E::ec_double(&g);
    let point = (point_dwords(&g).len() * 8) as u64;
    let mut add_image = BTreeMap::new();
    put(&mut add_image, A, &point_dwords(&g));
    put(&mut add_image, B, &point_dwords(&g2));
    let mut double_image = BTreeMap::new();
    put(&mut double_image, A, &point_dwords(&g));
    [
        Case {
            name: "weierstrass add",
            syscall: add,
            arg1: A,
            arg2: B,
            image: add_image,
            written: A..A + point,
            read_only: B..B + point,
        },
        Case {
            name: "weierstrass double",
            syscall: double,
            arg1: A,
            arg2: 0,
            image: double_image,
            written: A..A + point,
            read_only: A + point..A + point + 8,
        },
    ]
}

/// `g += 2g` and `g = 2g` in BLS12-381 G2, `g` its generator.
fn g2_cases() -> [Case; 2] {
    use crate::chips::precompiles::bls12381_g2::{
        g2_double, point_to_dwords, tests::generator, G2_POINT_BYTES,
    };
    let point = u64::from(G2_POINT_BYTES);
    let g = generator();
    let g2 = g2_double(&g).unwrap();
    let mut add_image = BTreeMap::new();
    put(&mut add_image, A, &point_to_dwords(&g));
    put(&mut add_image, B, &point_to_dwords(&g2));
    let mut double_image = BTreeMap::new();
    put(&mut double_image, A, &point_to_dwords(&g));
    [
        Case {
            name: "G2 add",
            syscall: SyscallCode::BLS12381_G2_ADD,
            arg1: A,
            arg2: B,
            image: add_image,
            written: A..A + point,
            read_only: B..B + point,
        },
        Case {
            name: "G2 double",
            syscall: SyscallCode::BLS12381_G2_DOUBLE,
            arg1: A,
            arg2: 0,
            image: double_image,
            written: A..A + point,
            read_only: A + point..A + point + 8,
        },
    ]
}

#[test]
fn g2_chips_refuse_to_write_the_code() {
    use crate::chips::precompiles::bls12381_g2::{
        add::Bls12381G2AddChip, double::Bls12381G2DoubleChip,
    };
    let [add, double] = g2_cases();
    check(Bls12381G2AddChip::<F>::default(), add);
    check(Bls12381G2DoubleChip::<F>::default(), double);
}

/// The decompression of `E`'s generator, whose coordinates take `bytes`: `y` goes to the slice's
/// first half, and `x`, the second, is only read.
fn decompress<E: EllipticCurve>(syscall: SyscallCode, bytes: usize) -> Case {
    let g = E::ec_generator();
    let mut image = BTreeMap::new();
    put(&mut image, A, &vec![0; bytes / 8]);
    put(&mut image, A + bytes as u64, &dwords_of(&g.x, bytes));
    Case {
        name: "weierstrass decompress",
        syscall,
        arg1: A,
        arg2: u64::from(g.y.bit(0)),
        image,
        written: A..A + bytes as u64,
        read_only: A + bytes as u64..A + 2 * bytes as u64,
    }
}

#[test]
fn weierstrass_chips_refuse_to_write_the_code() {
    let [add, double] =
        weierstrass::<Secp256k1>(SyscallCode::SECP256K1_ADD, SyscallCode::SECP256K1_DOUBLE);
    check(WeierstrassAddAssignChip::<F, Secp256k1>::default(), add);
    check(
        WeierstrassDoubleAssignChip::<F, Secp256k1>::default(),
        double,
    );
    let [add, double] =
        weierstrass::<Secp256r1>(SyscallCode::SECP256R1_ADD, SyscallCode::SECP256R1_DOUBLE);
    check(WeierstrassAddAssignChip::<F, Secp256r1>::default(), add);
    check(
        WeierstrassDoubleAssignChip::<F, Secp256r1>::default(),
        double,
    );
    let [add, double] = weierstrass::<Bn254>(SyscallCode::BN254_ADD, SyscallCode::BN254_DOUBLE);
    check(WeierstrassAddAssignChip::<F, Bn254>::default(), add);
    check(WeierstrassDoubleAssignChip::<F, Bn254>::default(), double);
    let [add, double] =
        weierstrass::<Bls12381>(SyscallCode::BLS12381_ADD, SyscallCode::BLS12381_DOUBLE);
    check(WeierstrassAddAssignChip::<F, Bls12381>::default(), add);
    check(
        WeierstrassDoubleAssignChip::<F, Bls12381>::default(),
        double,
    );

    check(
        WeierstrassDecompressChip::<F, Secp256k1>::default(),
        decompress::<Secp256k1>(SyscallCode::SECP256K1_DECOMPRESS, 32),
    );
    check(
        WeierstrassDecompressChip::<F, Secp256r1>::default(),
        decompress::<Secp256r1>(SyscallCode::SECP256R1_DECOMPRESS, 32),
    );
    check(
        WeierstrassDecompressChip::<F, Bls12381>::default(),
        decompress::<Bls12381>(SyscallCode::BLS12381_DECOMPRESS, 48),
    );
}

/// `x op= y` on field elements of `bytes`, and on pairs of them.
fn field_case(name: &'static str, syscall: SyscallCode, bytes: u64) -> Case {
    let mut image = BTreeMap::new();
    let x: Vec<u64> = (1..=bytes / 8).collect();
    let y: Vec<u64> = (1..=bytes / 8).map(|i| 3 * i).collect();
    put(&mut image, A, &x);
    put(&mut image, B, &y);
    Case {
        name,
        syscall,
        arg1: A,
        arg2: B,
        image,
        written: A..A + bytes,
        read_only: B..B + bytes,
    }
}

#[test]
fn field_chips_refuse_to_write_the_code() {
    check(
        FpOpChip::<F, Bn254BaseField>::default(),
        field_case("BN254_FP_ADD", SyscallCode::BN254_FP_ADD, 32),
    );
    check(
        FpOpChip::<F, Bls381BaseField>::default(),
        field_case("BLS12381_FP_ADD", SyscallCode::BLS12381_FP_ADD, 48),
    );
    check(
        FpOpChip::<F, Secp256k1BaseField>::default(),
        field_case("SECP256K1_FP_ADD", SyscallCode::SECP256K1_FP_ADD, 32),
    );
    check(
        Fp2AddSubChip::<F, Bn254BaseField>::default(),
        field_case("BN254_FP2_ADD", SyscallCode::BN254_FP2_ADD, 64),
    );
    check(
        Fp2AddSubChip::<F, Bls381BaseField>::default(),
        field_case("BLS12381_FP2_ADD", SyscallCode::BLS12381_FP2_ADD, 96),
    );
    check(
        Fp2MulChip::<F, Bn254BaseField>::default(),
        field_case("BN254_FP2_MUL", SyscallCode::BN254_FP2_MUL, 64),
    );
    check(
        Fp2MulChip::<F, Bls381BaseField>::default(),
        field_case("BLS12381_FP2_MUL", SyscallCode::BLS12381_FP2_MUL, 96),
    );
}

// ---- The device's code range ----
//
// A precompile whose trace the device generates fills its code range in a pass of its own, after
// the chip's kernel (`code_range::fill_on_device`). Its trace and byte lookups have to be the
// host's: each case's event, in a deferred record, with the code where the emulator had it, below
// the data, so the check takes the side above the code, and with the code above the write, the
// side below it.
#[cfg(feature = "cuda")]
mod device {
    use super::*;
    use crate::{
        chips::{
            chips::byte::{columns::NUM_BYTE_MULT_COLS, ByteChip},
            tests::init_test_stream,
            trace::TraceData,
        },
        instances::preparer::{
            gpu_allocate_byte_trace, gpu_finalize_byte_trace, precompute_event_size,
            PreallocatedGpuMemory, PreparedGpuEvents,
        },
        machine::chip::GpuChipBehavior,
    };

    /// `case`'s one event as a deferred record, the program's code at `code`, or the emulated
    /// program's when `None`.
    fn deferred_record(case: &Case, code: Option<Range<u64>>) -> EmulationRecord {
        let program = Program {
            instructions: one_syscall(case.syscall, case.arg1, case.arg2).into(),
            pc_start: 0,
            pc_base: 0,
            memory_image: Arc::new(case.image.clone()),
            preprocessed_shape: None,
            profiled_functions: Default::default(),
        };
        let stdin = EmulatorStdin::new_builder::<KoalaBearPoseidon2>().finalize();
        let emulated = test_rv64_emulate(Arc::new(program), stdin)
            .into_iter()
            .find(|record| !record.precompile_events.is_empty())
            .unwrap_or_else(|| panic!("{}: the ECALL raised no precompile event", case.name));
        let program = code.map_or_else(|| emulated.program.clone(), program_over);
        let mut record = EmulationRecord::new(program);
        // A deferred record, as `EmulationRecord::defer` makes one: it carries no history.
        record.is_cpu_chunk = false;
        record.precompile_events = emulated.precompile_events.clone();
        record
    }

    /// `chip`'s device trace and byte lookups for `case`'s event against the host's, with the code
    /// below the data and above the write.
    fn device_parity<C>(chip: C, case: Case)
    where
        C: GpuChipBehavior<F, Record = EmulationRecord, Program = Program>,
    {
        let above = case.written.end + 0x100..case.written.end + 0x200;
        for code in [None, Some(above)] {
            let record = deferred_record(&case, code.clone());
            let name = format!("{}, code at {code:x?}", case.name);

            let mut complete = record.clone();
            chip.extra_record(&record, &mut complete);
            let host = chip.generate_main(&complete, &mut EmulationRecord::default());
            let host_bytes =
                ByteChip::<F>::default().generate_main(&complete, &mut EmulationRecord::default());

            let stream = init_test_stream();
            let prepared = PreparedGpuEvents::new(&record, precompute_event_size::<F>(&record));
            let mut memory = PreallocatedGpuMemory {
                d_byte_trace: gpu_allocate_byte_trace(stream, 0).unwrap(),
                ..Default::default()
            };
            let device = chip
                .gpu_generate_extra_record_and_main(0, &record, &prepared, &mut memory)
                .to_host(stream);
            stream.synchronize().unwrap();
            assert_eq!(host.width, device.width, "{name}: {} width", chip.name());
            assert!(
                host.values == device.values,
                "{name}: {}'s device trace is not the host's",
                chip.name()
            );

            gpu_finalize_byte_trace(stream, &mut memory).unwrap();
            stream.synchronize().unwrap();
            let device_bytes =
                TraceData::<F>::Gpu(NUM_BYTE_MULT_COLS, memory.d_byte_trace.take().unwrap())
                    .to_host(stream);
            stream.synchronize().unwrap();
            assert!(
                host_bytes.values == device_bytes.values,
                "{name}: {}'s device byte lookups are not the host's",
                chip.name()
            );
        }
    }

    /// Every precompile the device generates: the controllers of SHA-256 and Keccak, uint256, and the
    /// field and curve chips. Poseidon2 and the Ed25519 pair are generated on the host.
    #[test]
    fn device_code_ranges_are_the_hosts() {
        device_parity(ShaExtendControlChip::<F>::default(), sha_extend_case());
        device_parity(ShaCompressControlChip::<F>::default(), sha_compress_case());
        device_parity(KeccakControlChip::<F>::default(), keccak_case());
        device_parity(Uint256MulChip::<F>::default(), uint256_case());

        let [add, double] =
            weierstrass::<Secp256k1>(SyscallCode::SECP256K1_ADD, SyscallCode::SECP256K1_DOUBLE);
        device_parity(WeierstrassAddAssignChip::<F, Secp256k1>::default(), add);
        device_parity(
            WeierstrassDoubleAssignChip::<F, Secp256k1>::default(),
            double,
        );
        let [add, double] =
            weierstrass::<Secp256r1>(SyscallCode::SECP256R1_ADD, SyscallCode::SECP256R1_DOUBLE);
        device_parity(WeierstrassAddAssignChip::<F, Secp256r1>::default(), add);
        device_parity(
            WeierstrassDoubleAssignChip::<F, Secp256r1>::default(),
            double,
        );
        let [add, double] = weierstrass::<Bn254>(SyscallCode::BN254_ADD, SyscallCode::BN254_DOUBLE);
        device_parity(WeierstrassAddAssignChip::<F, Bn254>::default(), add);
        device_parity(WeierstrassDoubleAssignChip::<F, Bn254>::default(), double);
        let [add, double] =
            weierstrass::<Bls12381>(SyscallCode::BLS12381_ADD, SyscallCode::BLS12381_DOUBLE);
        device_parity(WeierstrassAddAssignChip::<F, Bls12381>::default(), add);
        device_parity(
            WeierstrassDoubleAssignChip::<F, Bls12381>::default(),
            double,
        );
        device_parity(
            WeierstrassDecompressChip::<F, Secp256k1>::default(),
            decompress::<Secp256k1>(SyscallCode::SECP256K1_DECOMPRESS, 32),
        );
        device_parity(
            WeierstrassDecompressChip::<F, Secp256r1>::default(),
            decompress::<Secp256r1>(SyscallCode::SECP256R1_DECOMPRESS, 32),
        );
        device_parity(
            WeierstrassDecompressChip::<F, Bls12381>::default(),
            decompress::<Bls12381>(SyscallCode::BLS12381_DECOMPRESS, 48),
        );

        device_parity(
            FpOpChip::<F, Bn254BaseField>::default(),
            field_case("BN254_FP_ADD", SyscallCode::BN254_FP_ADD, 32),
        );
        device_parity(
            FpOpChip::<F, Bls381BaseField>::default(),
            field_case("BLS12381_FP_ADD", SyscallCode::BLS12381_FP_ADD, 48),
        );
        device_parity(
            FpOpChip::<F, Secp256k1BaseField>::default(),
            field_case("SECP256K1_FP_ADD", SyscallCode::SECP256K1_FP_ADD, 32),
        );
        device_parity(
            Fp2AddSubChip::<F, Bn254BaseField>::default(),
            field_case("BN254_FP2_ADD", SyscallCode::BN254_FP2_ADD, 64),
        );
        device_parity(
            Fp2AddSubChip::<F, Bls381BaseField>::default(),
            field_case("BLS12381_FP2_ADD", SyscallCode::BLS12381_FP2_ADD, 96),
        );
        device_parity(
            Fp2MulChip::<F, Bn254BaseField>::default(),
            field_case("BN254_FP2_MUL", SyscallCode::BN254_FP2_MUL, 64),
        );
        device_parity(
            Fp2MulChip::<F, Bls381BaseField>::default(),
            field_case("BLS12381_FP2_MUL", SyscallCode::BLS12381_FP2_MUL, 96),
        );
    }
}

/// The G2 chips' arithmetic: every row of an honest trace, padding included, satisfies the AIR,
/// and a wrong result coordinate does not.
#[test]
fn g2_chips_constrain_the_result() {
    use crate::chips::precompiles::bls12381_g2::{
        add::{Bls12381G2AddChip, G2AddCols},
        double::{Bls12381G2DoubleChip, G2DoubleCols},
    };
    use core::borrow::BorrowMut;

    let [add, double] = g2_cases();
    let chip = Bls12381G2AddChip::<F>::default();
    let trace = chip.generate_main(&record_of(&add), &mut EmulationRecord::default());
    for row in trace.values.chunks(trace.width()) {
        assert_eq!(failures(&chip, row), Vec::<String>::new());
    }
    let mut row = trace.values[..trace.width()].to_vec();
    let cols: &mut G2AddCols<F> = row.as_mut_slice().borrow_mut();
    cols.result.y3_1.result[0] += F::ONE;
    assert!(!failures(&chip, &row).is_empty(), "G2 add: a wrong y3.c1");

    let chip = Bls12381G2DoubleChip::<F>::default();
    let trace = chip.generate_main(&record_of(&double), &mut EmulationRecord::default());
    for row in trace.values.chunks(trace.width()) {
        assert_eq!(failures(&chip, row), Vec::<String>::new());
    }
    let mut row = trace.values[..trace.width()].to_vec();
    let cols: &mut G2DoubleCols<F> = row.as_mut_slice().borrow_mut();
    cols.result.x3_0.result[3] += F::ONE;
    assert!(
        !failures(&chip, &row).is_empty(),
        "G2 double: a wrong x3.c0"
    );
}
