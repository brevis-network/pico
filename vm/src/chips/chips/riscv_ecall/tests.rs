//! A HALT whose operand is not a canonical field element is rejected by the Ecall chip.
//!
//! The exit code reaches the public values as `op_b_value.reduce()`, a field element. An operand
//! `v >= p` would reduce to `v mod p`, so `p` or `2p` could claim exit code 0 for a run that halted
//! with another. The chip forbids it: on real HALT rows `range_check_operand` gates
//! `FieldWordRangeChecker` on `operand_to_check`, which the row binds to `op_b_value`.
//!
//! Each case starts from the trace of a program that really halts, so no other row or column is
//! malformed, and then rewrites only the HALT row's operand: `op_b_value`, `operand_to_check`, the
//! range checker's comparison bit, and the public `exit_code`, set to `v mod p` so the binding
//! holds and only the range check can object. Every row is evaluated through
//! [`DebugConstraintFolder`] with its real successor.
//!
//! The folder ignores lookups, and the range check has one: `ms_limb - TOP + bit * 2^16` must be a
//! u16. So each operand is tried with **both** comparison bits, and the chip's own u16 range
//! lookups on the HALT row — read from its symbolic constraints and evaluated on the row, not
//! recomputed here — must carry some value outside `[0, 2^16)`, which no row of the u16 table can
//! serve, whenever the AIR accepts the witness. So neither bit gets a non-canonical operand past
//! both checks. The valid controls pass both.
//!
//! A last test breaks the row's own ties instead — gate off, another word range checked, another
//! exit code published — so the gate and both bindings are exercised, not only the range checker.

use super::{columns::EcallChipCols, EcallChip};
use crate::{
    chips::tests::test_rv64_emulate,
    compiler::{
        riscv::{
            instruction::Instruction,
            opcode::{ByteOpcode, Opcode},
            program::Program,
        },
        word::Word,
    },
    configs::stark_config::KoalaBearPoseidon2,
    emulator::{
        riscv::{public_values::PublicValues, record::EmulationRecord, syscalls::SyscallCode},
        stdin::EmulatorStdin,
    },
    machine::{
        chip::ChipBehavior, debug_folder::DebugConstraintFolder, lookup::LookupType,
        septic::SepticDigest,
    },
    primitives::consts::MAX_NUM_PVS,
};
use core::borrow::{Borrow, BorrowMut};
use p3_air::{Air, BaseAir, RowWindow};
use p3_field::{extension::QuinticTrinomialExtensionField, PrimeCharacteristicRing, PrimeField64};
use p3_koala_bear::KoalaBear;
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use pico_mle_core::{
    air::symbolic::{
        get_symbolic_builder_with_public_values, symbolic_expression::SymbolicExpression,
        symbolic_variable::Entry,
    },
    keygen::types::TraceWidth,
};
use std::sync::Arc;

type F = KoalaBear;
type EF = QuinticTrinomialExtensionField<KoalaBear>;

/// The KoalaBear modulus.
const P: u64 = KoalaBear::ORDER_U64;
/// `(P - 1) >> 16`: the most significant u16 limb of a 32-bit value at most `P - 1`; only the
/// honest comparison bit is derived from it here.
const TOP: u64 = 0x7F00;

/// `a0 = 0`, `t0 = HALT`, `ECALL`: the trace every case rewrites.
fn halting_record() -> EmulationRecord {
    let li = |rd: u8, imm: u64| Instruction::new(Opcode::ADD, rd, 0, imm, true, true);
    let program = Program::new(
        vec![
            li(10, 0),
            li(5, u64::from(SyscallCode::HALT as u32)),
            Instruction::new(Opcode::ECALL, 5, 10, 11, false, false),
        ],
        0x1000,
        0x1000,
    );
    let stdin = EmulatorStdin::new_builder::<KoalaBearPoseidon2>().finalize();
    test_rv64_emulate(Arc::new(program), stdin)
        .into_iter()
        .find(|record| !record.cpu_steps().is_empty())
        .expect("the halting chunk")
}

/// The constraints `trace` violates, every row against its real successor.
fn failures(trace: &RowMajorMatrix<F>, public_values: &[F]) -> Vec<String> {
    let chip = EcallChip::<F>::default();
    let (width, height) = (trace.width(), trace.height());
    let dummy = [F::ZERO];
    let mut found = Vec::new();
    for row in 0..height {
        let local = &trace.values[row * width..(row + 1) * width];
        let next_row = (row + 1) % height;
        let next = &trace.values[next_row * width..(next_row + 1) * width];
        let mut folder = DebugConstraintFolder::<F, EF> {
            preprocessed: RowWindow::from_two_rows(&dummy, &dummy),
            main: RowWindow::from_two_rows(local, next),
            global_cumulative_sum: SepticDigest::<F>::zero(),
            is_first_row: F::from_bool(row == 0),
            is_last_row: F::from_bool(row == height - 1),
            is_transition: F::from_bool(row != height - 1),
            public_values,
            failures: Vec::new(),
            scopes: Vec::new(),
            constraint_count: 0,
        };
        chip.eval(&mut folder);
        found.extend(
            folder
                .failures
                .iter()
                .map(|(scopes, failure)| format!("row {row}: {scopes:?} {failure:?}")),
        );
    }
    found
}

/// `expr` on a row, with `next` its successor and `public_values` the chunk's.
fn evaluate(expr: &SymbolicExpression<F>, local: &[F], next: &[F], public_values: &[F]) -> F {
    let eval = |e: &SymbolicExpression<F>| evaluate(e, local, next, public_values);
    match expr {
        SymbolicExpression::Variable(v) => match v.entry {
            Entry::Main { offset: 0, .. } => local[v.index],
            Entry::Main { .. } => next[v.index],
            Entry::Public => public_values[v.index],
            Entry::Preprocessed { .. } => F::ZERO,
        },
        SymbolicExpression::Constant(c) => *c,
        SymbolicExpression::IsFirstRow
        | SymbolicExpression::IsLastRow
        | SymbolicExpression::IsTransition => F::ZERO,
        SymbolicExpression::Add { x, y, .. } => eval(x) + eval(y),
        SymbolicExpression::Sub { x, y, .. } => eval(x) - eval(y),
        SymbolicExpression::Neg { x, .. } => -eval(x),
        SymbolicExpression::Mul { x, y, .. } => eval(x) * eval(y),
    }
}

/// The values the chip's u16 range lookups carry on `row`, for those whose count is not zero
/// there: what the byte table would have to hold for the row to prove.
fn u16_lookups(trace: &RowMajorMatrix<F>, row: usize, public_values: &[F]) -> Vec<u64> {
    let chip = EcallChip::<F>::default();
    let width = TraceWidth {
        preprocessed: None,
        cached_mains: vec![],
        common_main: BaseAir::<F>::width(&chip),
    };
    let constraints =
        get_symbolic_builder_with_public_values(&chip, &width, MAX_NUM_PVS).constraints();
    let w = trace.width();
    let local = &trace.values[row * w..(row + 1) * w];
    let next_row = (row + 1) % trace.height();
    let next = &trace.values[next_row * w..(next_row + 1) * w];
    let u16_range = F::from_u8(ByteOpcode::U16Range as u8);
    constraints
        .interactions
        .iter()
        .filter(|i| matches!(i.kind, LookupType::Byte))
        .filter(|i| evaluate(&i.message[0], local, next, public_values) == u16_range)
        .filter(|i| evaluate(&i.count, local, next, public_values) != F::ZERO)
        .map(|i| evaluate(&i.message[1], local, next, public_values).as_canonical_u64())
        .collect()
}

/// What one rewritten trace says: the AIR's failures, and the values the HALT row's u16 range
/// lookups carry.
struct Outcome {
    failures: Vec<String>,
    u16_lookups: Vec<u64>,
}

impl Outcome {
    /// Every lookup a value the u16 table holds.
    fn lookups_served(&self) -> bool {
        self.u16_lookups.iter().all(|&v| v < 1 << 16)
    }
}

/// What the HALT row is rewritten to hold.
#[derive(Clone, Copy)]
struct HaltRow {
    /// `op_b_value`, the word the exit code is read from.
    op_b: u64,
    /// `operand_to_check`, the word the range checker sees.
    checked: u64,
    /// `range_check_operand`, the range checker's gate.
    gate: bool,
    /// The range checker's comparison bit.
    bit: bool,
    /// The public `exit_code`.
    exit_code: u64,
}

impl HaltRow {
    /// `operand` everywhere, gate on, exit code `operand mod P`: only the range check can object.
    fn new(operand: u64, bit: bool) -> Self {
        Self {
            op_b: operand,
            checked: operand,
            gate: true,
            bit,
            exit_code: operand % P,
        }
    }

    /// Whether the row gets past both the AIR and the u16 lookup.
    fn provable(self) -> bool {
        let outcome = rewrite_halt(self);
        outcome.failures.is_empty() && outcome.lookups_served()
    }
}

/// The halting trace with its HALT row's operand set to `operand` and the comparison bit to
/// `bit`, and the public `exit_code` set to `operand mod P`.
fn halt_with(operand: u64, bit: bool) -> Outcome {
    rewrite_halt(HaltRow::new(operand, bit))
}

/// The halting trace with its HALT row and the public `exit_code` rewritten to `halt`.
fn rewrite_halt(halt: HaltRow) -> Outcome {
    let record = halting_record();
    let mut trace =
        EcallChip::<F>::default().generate_main(&record, &mut EmulationRecord::default());
    let width = trace.width();
    let halt_row = (0..trace.height())
        .find(|&row| {
            let cols: &EcallChipCols<F> = trace.values[row * width..(row + 1) * width].borrow();
            cols.range_check_operand == F::ONE && cols.is_halt == F::ONE
        })
        .expect("the HALT row");
    {
        let cols: &mut EcallChipCols<F> =
            trace.values[halt_row * width..(halt_row + 1) * width].borrow_mut();
        cols.op_b_value = Word::<F>::from(halt.op_b);
        cols.ecall.operand_to_check = Word::<F>::from(halt.checked);
        cols.range_check_operand = F::from_bool(halt.gate);
        cols.ecall.operand_range_check_cols.ms_limb_lt_top = F::from_bool(halt.bit);
        cols.ecall.operand_range_check_cols.low_limb_not_max_inv = F::ZERO;
    }

    let mut public_values = record.public_values.to_vec::<F>();
    {
        let pvs: &mut PublicValues<Word<F>, F> = public_values.as_mut_slice().borrow_mut();
        pvs.exit_code = F::from_u64(halt.exit_code);
    }

    Outcome {
        failures: failures(&trace, &public_values),
        u16_lookups: u16_lookups(&trace, halt_row, &public_values),
    }
}

/// Whether some witness bit gets `operand` past both the AIR and the u16 lookup.
fn accepted(operand: u64) -> bool {
    [false, true]
        .into_iter()
        .any(|bit| HaltRow::new(operand, bit).provable())
}

/// The unmodified trace passes, so nothing else in it accounts for a rejection below.
#[test]
fn the_halting_trace_satisfies_the_ecall_constraints() {
    let record = halting_record();
    let trace = EcallChip::<F>::default().generate_main(&record, &mut EmulationRecord::default());
    let failures = failures(&trace, &record.public_values.to_vec::<F>());
    assert!(failures.is_empty(), "{failures:#?}");
}

/// Canonical operands, 0 and the largest, are accepted with the bit the prover would write.
#[test]
fn a_canonical_operand_is_accepted() {
    for operand in [0, 1, P - 1] {
        assert!(accepted(operand), "{operand:#x} must be provable");
    }
    // And the range check's lookup is on the HALT row to be checked at all.
    assert!(!halt_with(0, true).u16_lookups.is_empty());
}

/// `p` and `2p` reduce to exit code 0 and `2^32` to `2^32 mod p`; none is provable, whichever
/// comparison bit the prover writes.
#[test]
fn a_non_canonical_operand_is_rejected_for_every_witness() {
    for operand in [P, 2 * P, 1 << 32] {
        for bit in [false, true] {
            let outcome = halt_with(operand, bit);
            assert!(
                !outcome.failures.is_empty() || !outcome.lookups_served(),
                "{operand:#x} with bit {bit}: no AIR failure, and the u16 lookups {:?} would be \
                 served",
                outcome.u16_lookups
            );
        }
        assert!(!accepted(operand), "{operand:#x} must not be provable");
    }
}

/// The AIR alone, not only the lookup, rejects each non-canonical operand under the bit an honest
/// trace generator writes for it, and the failure is in the range check.
#[test]
fn the_honest_witness_for_a_non_canonical_operand_fails_the_air() {
    for operand in [P, 2 * P, 1 << 32] {
        let honest_bit = ((operand >> 16) & 0xFFFF) < TOP;
        let outcome = halt_with(operand, honest_bit);
        assert!(
            !outcome.failures.is_empty(),
            "{operand:#x}: the honest witness passes the AIR"
        );
    }
}

/// The HALT row cannot step around its range check: turning the gate off, checking a canonical
/// word other than `op_b_value`, or publishing an exit code other than the operand's is rejected
/// under both comparison bits.
#[test]
fn a_halt_row_cannot_unhook_its_range_check_or_exit_code() {
    for bit in [false, true] {
        let gate_off = HaltRow {
            gate: false,
            ..HaltRow::new(P, bit)
        };
        assert!(!gate_off.provable(), "bit {bit}: HALT with its gate off");

        let other_word_checked = HaltRow {
            checked: 0,
            ..HaltRow::new(P, bit)
        };
        assert!(
            !other_word_checked.provable(),
            "bit {bit}: 0 range checked while the exit code is read from p"
        );

        let other_exit_code = HaltRow {
            exit_code: 1,
            ..HaltRow::new(0, bit)
        };
        assert!(
            !other_exit_code.provable(),
            "bit {bit}: operand 0 published as exit code 1"
        );
    }
}
