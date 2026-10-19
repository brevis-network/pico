//! The uint256 mulmod chip on operands at or above the modulus.
//!
//! `syscall_uint256_mulmod` asks for no particular representative of `x` and `y`, the emulator
//! computes `(x * y) mod m` for any 256-bit pair, and the AIR (`x * y == result + carry * m`, the
//! result checked below `m`) accepts every pair whose carry fits in its 32 bytes. These tests hold
//! the trace to that same domain. Each row comes out of a real emulation of the ECALL, the chip's
//! own `generate_main` turns the record into a trace, and [`DebugConstraintFolder`] evaluates the
//! AIR on the row.
//!
//! What they do not cover: the folder is an `EmptyLookupBuilder`, so the memory and byte buses are
//! ignored. Bus balance is the end-to-end proof's job.

use super::{columns::Uint256MulCols, Uint256MulChip};
use crate::{
    chips::tests::test_rv64_emulate,
    compiler::riscv::{instruction::Instruction, opcode::Opcode, program::Program},
    configs::stark_config::KoalaBearPoseidon2,
    emulator::{
        riscv::{
            record::EmulationRecord,
            syscalls::{precompiles::PrecompileEvent, SyscallCode},
        },
        stdin::EmulatorStdin,
    },
    machine::{chip::ChipBehavior, debug_folder::DebugConstraintFolder, septic::SepticDigest},
};
use num::BigUint;
use p3_air::{Air, RowWindow};
use p3_field::{extension::BinomialExtensionField, PrimeCharacteristicRing};
use p3_koala_bear::KoalaBear;
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use std::{borrow::BorrowMut, collections::BTreeMap, sync::Arc};

type F = KoalaBear;
type EF = BinomialExtensionField<KoalaBear, 4>;

/// `x`, then `y` followed by the modulus, dword-aligned and clear of each other.
const X_PTR: u64 = 0x10_0000;
const Y_PTR: u64 = 0x10_0040;

/// BN254's scalar modulus: the one mainnet's MODEXP calls reach this chip with.
fn bn254_r() -> BigUint {
    BigUint::parse_bytes(
        b"30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001",
        16,
    )
    .unwrap()
}

fn max_u256() -> BigUint {
    (BigUint::from(1u8) << 256u32) - 1u8
}

/// A 256-bit value as the four little-endian dwords the guest holds it in.
fn dwords(v: &BigUint) -> Vec<u64> {
    let mut bytes = v.to_bytes_le();
    bytes.resize(32, 0);
    bytes
        .as_chunks::<8>()
        .0
        .iter()
        .map(|c| u64::from_le_bytes(*c))
        .collect()
}

/// `rd = imm`, the shape the emulator's ECALL path reads its operands from.
fn li(rd: u8, imm: u64) -> Instruction {
    Instruction::new(Opcode::ADD, rd, 0, imm, true, true)
}

/// Emulate `x = x * y mod m` through the ECALL and return every record it produced.
fn mulmod_records(x: &BigUint, y: &BigUint, m: &BigUint) -> Vec<EmulationRecord> {
    let mut image = BTreeMap::new();
    for (i, w) in dwords(x).into_iter().enumerate() {
        image.insert(X_PTR + 8 * i as u64, w);
    }
    for (i, w) in dwords(y).into_iter().chain(dwords(m)).enumerate() {
        image.insert(Y_PTR + 8 * i as u64, w);
    }
    let instructions = vec![
        li(10, X_PTR),
        li(11, Y_PTR),
        li(5, u64::from(SyscallCode::UINT256_MUL as u32)),
        Instruction::new(Opcode::ECALL, 5, 10, 11, false, false),
        li(10, 0),
        li(5, u64::from(SyscallCode::HALT as u32)),
        Instruction::new(Opcode::ECALL, 5, 10, 11, false, false),
    ];
    let program = Program {
        instructions: instructions.into(),
        pc_start: 0,
        pc_base: 0,
        memory_image: Arc::new(image),
        preprocessed_shape: None,
    };
    let stdin = EmulatorStdin::<Program, Vec<u8>>::new_builder::<KoalaBearPoseidon2>().finalize();
    test_rv64_emulate(Arc::new(program), stdin)
}

/// The record carrying the mulmod event, and the value the emulator wrote back to `x`.
fn mulmod_record(x: &BigUint, y: &BigUint, m: &BigUint) -> (EmulationRecord, BigUint) {
    let record = mulmod_records(x, y, m)
        .into_iter()
        .find(|r| !r.get_precompile_events(SyscallCode::UINT256_MUL).is_empty())
        .expect("the ECALL produced no UINT256_MUL event");
    let written = match &record.get_precompile_events(SyscallCode::UINT256_MUL)[0].1 {
        PrecompileEvent::Uint256Mul(event) => BigUint::from_bytes_le(
            &event
                .x_memory_records
                .iter()
                .flat_map(|r| r.value.to_le_bytes())
                .collect::<Vec<u8>>(),
        ),
        _ => unreachable!(),
    };
    (record, written)
}

/// The chip's trace for the one event, as a flat row.
fn row_of(record: &EmulationRecord) -> Vec<F> {
    let trace: RowMajorMatrix<F> =
        Uint256MulChip::<F>::default().generate_main(record, &mut EmulationRecord::default());
    let width = trace.width();
    trace.values[..width].to_vec()
}

/// The constraints the AIR reports violated on `row`.
fn failures(row: &[F]) -> Vec<String> {
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
    Uint256MulChip::<F>::default().eval(&mut folder);
    folder
        .failures
        .iter()
        .map(|(scopes, failure)| format!("{scopes:?} {failure:?}"))
        .collect()
}

/// Each case writes back `x * y mod m`, and its row satisfies the AIR.
#[test]
fn operands_at_or_above_the_modulus_are_proved() {
    let r = bn254_r();
    let one = BigUint::from(1u8);
    let cases = [
        // MODEXP's reduction of an unreduced base: the base times one. The carry is 5.
        (max_u256(), one.clone(), r.clone()),
        (r.clone(), one, r.clone()),
        // A multiply step with the unreduced base as `y`. The carry is just under 2^256.
        (&r - 1u8, max_u256(), r.clone()),
        // Both operands reduced, as before.
        (&r - 1u8, &r - 2u8, r.clone()),
    ];
    for (x, y, m) in cases {
        let (record, written) = mulmod_record(&x, &y, &m);
        assert_eq!(written, (&x * &y) % &m, "x = {x:x}, y = {y:x}");
        let failures = failures(&row_of(&record));
        assert!(failures.is_empty(), "x = {x:x}, y = {y:x}: {failures:?}");
    }
}

/// The check above is not vacuous: the same row with one result byte changed fails.
#[test]
fn a_wrong_result_fails_the_air() {
    let (record, _) = mulmod_record(&max_u256(), &BigUint::from(1u8), &bn254_r());
    let mut row = row_of(&record);
    let cols: &mut Uint256MulCols<F> = row.as_mut_slice().borrow_mut();
    cols.output.result.0[0] += F::ONE;
    assert!(!failures(&row).is_empty());
}

/// `(2^256 - 1)^2 / r` is about 2^258, past the 32-byte carry: refused as a domain error rather
/// than as a limb-count panic further down.
#[test]
#[should_panic(expected = "must fit in the 256-bit carry")]
fn a_carry_past_32_bytes_is_refused() {
    let (record, _) = mulmod_record(&max_u256(), &max_u256(), &bn254_r());
    row_of(&record);
}
