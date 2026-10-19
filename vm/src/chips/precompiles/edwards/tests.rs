//! What the two Ed25519 precompile chips are, at the level a unit test can see.
//!
//! # Scope
//!
//! Every row here comes out of a real emulation: a synthetic `Program` issues the ECALL, the
//! emulator dispatches it, and the chip's own `generate_main` turns the resulting record into a
//! trace. So a green test covers the whole chain the two chips were shelved for — syscall
//! registration, the ECALL path, the emulator's dword bookkeeping, and the AIR's reading of it —
//! rather than the AIR alone against a hand-built event.
//!
//! What it does *not* cover: [`DebugConstraintFolder`] is an `EmptyLookupBuilder`, so the memory
//! bus, the byte bus and the syscall bus are all ignored. Bus balance is the end-to-end test's
//! job.
//!
//! # On the canonicality checks
//!
//! `x3_range`, `y3_range` and `neg_x_range` exist because the gadget that produces each written
//! value pins it only up to the identity it satisfies, and the representative plus `p` satisfies
//! the same one. Demonstrating that directly would mean building a row that carries a
//! non-canonical result *with a consistent witness* — re-deriving `FieldOpCols`'s carry
//! decomposition by hand, since `populate` only ever emits canonical results. What is tested
//! here instead is that each checker is bound to the column it is meant to guard, which is the
//! failure mode this port could realistically have introduced (a checker wired to the wrong
//! operand); the algebraic claim itself is inherited from the gadget the Weierstrass chips use.
//!
//! Note what such a test has to do to mean anything. `FieldLtCols`'s witness is not the value:
//! it is the index of the most significant byte where the value drops below the modulus, plus
//! that byte pair. Two values differing only in a low byte therefore share a witness exactly, so
//! re-witnessing against a near neighbour changes nothing and the row still passes. See
//! [`decoy`].

use super::{EdAddAssignChip, EdAddAssignCols, EdDecompressChip, EdDecompressCols};
use crate::{
    chips::{
        chips::{byte::event::ByteRecordBehavior, events::ByteLookupEvent},
        gadgets::{
            curves::{
                edwards::{
                    ed25519::{Ed25519, Ed25519BaseField, Ed25519Parameters},
                    EdwardsParameters,
                },
                AffinePoint,
            },
            utils::field_params::FieldParameters,
        },
        tests::test_rv64_emulate,
    },
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
type AddChip = EdAddAssignChip<F, Ed25519>;
type DecompressChip = EdDecompressChip<F, Ed25519Parameters>;

/// Two 64-byte curve points and one 64-byte decompression slice, all dword-aligned and clear of
/// each other.
const P_PTR: u64 = 0x10_0000;
const Q_PTR: u64 = 0x10_0040;
const SLICE_PTR: u64 = 0x10_0100;

/// A byte-lookup sink. The folder ignores lookups, so these are collected and dropped; the
/// gadget's `populate` still needs somewhere to put them.
#[derive(Default)]
struct Blu(#[allow(dead_code)] Vec<ByteLookupEvent>);
impl ByteRecordBehavior for Blu {
    fn add_byte_lookup_event(&mut self, e: ByteLookupEvent) {
        self.0.push(e);
    }
}

/// `rd = imm` -- `ADD rd, x0, imm`, the shape the emulator's ECALL path reads its operands from
/// (`x5` the syscall id, `x10`/`x11` the two arguments).
fn li(rd: u8, imm: u64) -> Instruction {
    Instruction::new(Opcode::ADD, rd, 0, imm, true, true)
}

fn generator() -> AffinePoint<Ed25519> {
    let (x, y) = Ed25519Parameters::generator();
    AffinePoint::new(x, y)
}

/// A point as the eight little-endian dwords the guest holds it in: x first, then y.
fn point_dwords(p: &AffinePoint<Ed25519>) -> Vec<u64> {
    p.to_words_le()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u64::from(c[0]) | (u64::from(c[1]) << 32))
        .collect()
}

/// A field element as four little-endian dwords.
fn field_dwords(x: &BigUint) -> Vec<u64> {
    let mut bytes = x.to_bytes_le();
    bytes.resize(32, 0);
    bytes
        .as_chunks::<8>()
        .0
        .iter()
        .map(|c| u64::from_le_bytes(*c))
        .collect()
}

/// Emulate `program` and return every record it produced.
fn emulate(
    instructions: Vec<Instruction>,
    memory_image: BTreeMap<u64, u64>,
) -> Vec<EmulationRecord> {
    let program = Program {
        instructions: instructions.into(),
        pc_start: 0,
        pc_base: 0,
        memory_image: Arc::new(memory_image),
        preprocessed_shape: None,
    };
    let stdin = EmulatorStdin::<Program, Vec<u8>>::new_builder::<KoalaBearPoseidon2>().finalize();
    test_rv64_emulate(Arc::new(program), stdin)
}

/// One ECALL followed by a halt.
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

/// Run `ed_add(p, q)` in the emulator.
fn add_records(p: &AffinePoint<Ed25519>, q: &AffinePoint<Ed25519>) -> Vec<EmulationRecord> {
    let mut image = BTreeMap::new();
    for (i, w) in point_dwords(p).into_iter().enumerate() {
        image.insert(P_PTR + 8 * i as u64, w);
    }
    for (i, w) in point_dwords(q).into_iter().enumerate() {
        image.insert(Q_PTR + 8 * i as u64, w);
    }
    emulate(one_syscall(SyscallCode::ED_ADD, P_PTR, Q_PTR), image)
}

/// Run `ed_decompress(slice, sign)` in the emulator. `y` goes in the second half of the slice,
/// with its sign bit already stripped -- that is what the SDK's `syscall_ed_decompress` does
/// before it traps.
fn decompress_records(y: &BigUint, sign: bool) -> Vec<EmulationRecord> {
    let mut image = BTreeMap::new();
    for i in 0..4 {
        image.insert(SLICE_PTR + 8 * i, 0);
    }
    for (i, w) in field_dwords(y).into_iter().enumerate() {
        image.insert(SLICE_PTR + 32 + 8 * i as u64, w);
    }
    emulate(
        one_syscall(SyscallCode::ED_DECOMPRESS, SLICE_PTR, u64::from(sign)),
        image,
    )
}

/// The record that carries the precompile events for `code`.
fn record_with(records: Vec<EmulationRecord>, code: SyscallCode) -> EmulationRecord {
    records
        .into_iter()
        .find(|r| !r.get_precompile_events(code).is_empty())
        .unwrap_or_else(|| {
            panic!(
                "the ECALL produced no {code:?} event -- the syscall is not registered, or \
                    the ECALL path did not dispatch it"
            )
        })
}

/// The chip's trace for a single event, as a flat row.
fn row_of<C: ChipBehavior<F, Record = EmulationRecord>>(
    chip: &C,
    record: &EmulationRecord,
) -> Vec<F> {
    let trace: RowMajorMatrix<F> = chip.generate_main(record, &mut EmulationRecord::default());
    let width = trace.width();
    trace.values[..width].to_vec()
}

/// How many algebraic constraints `chip`'s AIR reports violated on `row`.
fn failures<C>(chip: &C, row: &[F]) -> usize
where
    C: for<'a> Air<DebugConstraintFolder<'a, F, EF>>,
{
    failure_report(chip, row).len()
}

/// The violated constraints, as the folder describes them. Used in assertion messages so a
/// failure says which constraint went wrong rather than only how many did.
fn failure_report<C>(chip: &C, row: &[F]) -> Vec<String>
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

fn honest_add_row() -> Vec<F> {
    let g = generator();
    let two_g = g.clone() + g.clone();
    let record = record_with(add_records(&g, &two_g), SyscallCode::ED_ADD);
    row_of(&AddChip::new(), &record)
}

fn honest_decompress_row(sign: bool) -> Vec<F> {
    let record = record_with(
        decompress_records(&generator().y, sign),
        SyscallCode::ED_DECOMPRESS,
    );
    row_of(&DecompressChip::new(), &record)
}

/// The decoy every range-checker wiring test re-witnesses against.
///
/// It has to be a value whose witness actually *differs*, and `FieldLtCols`'s witness is not the
/// value: it is the index of the most significant byte where the value falls below the modulus,
/// plus that byte pair. Two values that differ only low down share a witness exactly. `p - 1`
/// falls below the modulus at byte 0 (`0xEC` against `0xED`) and agrees with it everywhere
/// above, so its witness is the one no ordinary coordinate has. Each test asserts the flags
/// moved, so a decoy that happened to share a witness would fail loudly rather than pass
/// vacuously.
fn decoy() -> BigUint {
    Ed25519BaseField::modulus() - BigUint::from(1u32)
}

/// The little-endian dwords `w` encode, as an integer.
fn dwords_value(w: &[u64]) -> BigUint {
    BigUint::from_bytes_le(&w.iter().flat_map(|d| d.to_le_bytes()).collect::<Vec<u8>>())
}

/// `-x^2 + y^2 == 1 + d*x^2*y^2`, the Ed25519 curve equation.
fn on_curve(x: &BigUint, y: &BigUint) -> bool {
    let m = Ed25519BaseField::modulus();
    let (xx, yy) = ((x * x) % &m, (y * y) % &m);
    let lhs = (&yy + &m - &xx) % &m;
    let rhs = (BigUint::from(1u32) + Ed25519Parameters::d_biguint() * &xx % &m * &yy) % &m;
    lhs == rhs
}

// ───────────────────────── the emulator computes the right thing ─────────────────────────

/// Decompression returns the point the compressed form names, not merely *a* self-consistent
/// one.
///
/// This is the only check here that is not circular: `Ed25519Parameters::generator()` is a
/// hard-coded pair, and `decompress` recovers `x` from `y` alone. `ed25519_sqrt` returns the
/// even root and the basepoint's `x` is even, so `sign = 0` must reproduce it exactly and
/// `sign = 1` its negation.
#[test]
fn the_decompress_syscall_recovers_the_basepoint() {
    let g = generator();
    for sign in [false, true] {
        let record = record_with(decompress_records(&g.y, sign), SyscallCode::ED_DECOMPRESS);
        let events = record.get_precompile_events(SyscallCode::ED_DECOMPRESS);
        let PrecompileEvent::EdDecompress(event) = &events[0].1 else {
            panic!("the event recorded under ED_DECOMPRESS is not a decompression");
        };
        let expected = if sign {
            (Ed25519BaseField::modulus() - &g.x) % Ed25519BaseField::modulus()
        } else {
            g.x.clone()
        };
        assert_eq!(
            dwords_value(&event.decompressed_x_words),
            expected,
            "decompressing the basepoint with sign = {sign} produced the wrong x"
        );
    }
}

/// The adder writes a point that is actually on the curve.
///
/// Comparing against a second implementation of the addition would only re-run the same
/// `AffinePoint::add` the syscall used. The curve equation is an independent statement about
/// the result, and it is what a coordinate mix-up in the dword packing would break.
#[test]
fn the_add_syscall_writes_a_curve_point() {
    let g = generator();
    let two_g = g.clone() + g.clone();
    let record = record_with(add_records(&g, &two_g), SyscallCode::ED_ADD);
    let events = record.get_precompile_events(SyscallCode::ED_ADD);
    let PrecompileEvent::EdAdd(event) = &events[0].1 else {
        panic!("the event recorded under ED_ADD is not an addition");
    };
    let written: Vec<u64> = event.p_memory_records.iter().map(|r| r.value).collect();
    let half = written.len() / 2;
    let (x, y) = (
        dwords_value(&written[..half]),
        dwords_value(&written[half..]),
    );
    assert!(
        on_curve(&x, &y),
        "G + 2G was written back as ({x}, {y}), which is not on the curve"
    );
    // And it is the point the host computes, read back through the same dword packing the chip
    // reads -- so a packing error shows up here rather than only in a proof.
    let expected = g + two_g;
    assert_eq!(
        (x, y),
        (expected.x, expected.y),
        "G + 2G is the wrong point"
    );
}

// ───────────────────────── positive controls ─────────────────────────

/// `G + 2G` goes through the emulator and satisfies the adder's every constraint.
///
/// This is the whole port in one assertion: the address gadgets, the u16→u8 decomposition of
/// both operands, the eight field gadgets, the two range checks and the write-back binding all
/// have to agree with what the emulator actually wrote.
#[test]
fn an_honest_addition_satisfies_every_constraint() {
    assert_eq!(
        failures(&AddChip::new(), &honest_add_row()),
        0,
        "an honest ed25519 addition row violates a constraint"
    );
}

/// Doubling shares a pointer between the two operands, which is why the write is ordered at
/// `clk + 1`. Worth its own row: `p_ptr == q_ptr` is the case that ordering exists for.
#[test]
fn an_honest_doubling_satisfies_every_constraint() {
    let g = generator();
    let mut image = BTreeMap::new();
    for (i, w) in point_dwords(&g).into_iter().enumerate() {
        image.insert(P_PTR + 8 * i as u64, w);
    }
    let records = emulate(one_syscall(SyscallCode::ED_ADD, P_PTR, P_PTR), image);
    let record = record_with(records, SyscallCode::ED_ADD);
    assert_eq!(
        failures(&AddChip::new(), &row_of(&AddChip::new(), &record)),
        0,
        "an honest ed25519 doubling row violates a constraint"
    );
}

/// Both sign branches of the decompressor. `sign = 1` is the one that writes `neg_x`, which is
/// the value `neg_x_range` guards.
#[test]
fn an_honest_decompression_satisfies_every_constraint() {
    for sign in [false, true] {
        assert_eq!(
            failures(&DecompressChip::new(), &honest_decompress_row(sign)),
            0,
            "an honest ed25519 decompression row (sign = {sign}) violates a constraint"
        );
    }
}

/// Padding rows have to satisfy the AIR too.
///
/// A chip's trace is padded to a power of two (and, under a shape, to the shape's height), and
/// every padded row is folded like any other. Nothing in an emulation makes those rows appear,
/// so a padding row that violates a constraint is invisible until a real proof is attempted --
/// which is exactly how this was found. Generating from an empty record produces a trace of
/// nothing but padding.
#[test]
fn padding_rows_satisfy_every_constraint() {
    let empty = EmulationRecord::default();

    let add_trace: RowMajorMatrix<F> =
        AddChip::new().generate_main(&empty, &mut EmulationRecord::default());
    let width = add_trace.width();
    for (i, row) in add_trace.values.chunks_exact(width).enumerate() {
        assert_eq!(
            failures(&AddChip::new(), row),
            0,
            "EdAddAssign padding row {i}: {:?}",
            failure_report(&AddChip::new(), row)
        );
    }

    let dec_trace: RowMajorMatrix<F> =
        DecompressChip::new().generate_main(&empty, &mut EmulationRecord::default());
    let width = dec_trace.width();
    for (i, row) in dec_trace.values.chunks_exact(width).enumerate() {
        assert_eq!(
            failures(&DecompressChip::new(), row),
            0,
            "EdDecompress padding row {i}: {:?}",
            failure_report(&DecompressChip::new(), row)
        );
    }
}

// ───────────────────────── the range checkers are wired to the right columns ────────────────

#[test]
fn the_adder_range_checkers_are_bound_to_the_written_coordinates() {
    for x3 in [true, false] {
        let which = if x3 { "x3" } else { "y3" };
        let mut row = honest_add_row();
        let cols: &mut EdAddAssignCols<F> = row.as_mut_slice().borrow_mut();
        let mut blu = Blu::default();
        let before = if x3 {
            cols.x3_range.byte_flags
        } else {
            cols.y3_range.byte_flags
        };
        if x3 {
            cols.x3_range
                .populate(&mut blu, &decoy(), &Ed25519BaseField::modulus());
        } else {
            cols.y3_range
                .populate(&mut blu, &decoy(), &Ed25519BaseField::modulus());
        }
        let after = if x3 {
            cols.x3_range.byte_flags
        } else {
            cols.y3_range.byte_flags
        };
        assert_ne!(
            before.0.as_slice(),
            after.0.as_slice(),
            "{which}_range's witness did not move, so this test proves nothing"
        );
        assert_ne!(
            failures(&AddChip::new(), &row),
            0,
            "{which}_range accepted a witness for a different value; it is not bound to \
             {which}_ins.result"
        );
    }
}

#[test]
fn the_decompressor_range_checkers_are_bound_to_their_operands() {
    // `neg_x_range` guards the value written when `sign = 1`.
    let mut row = honest_decompress_row(true);
    let cols: &mut EdDecompressCols<F> = row.as_mut_slice().borrow_mut();
    let mut blu = Blu::default();
    let before = cols.neg_x_range.byte_flags;
    cols.neg_x_range
        .populate(&mut blu, &decoy(), &Ed25519BaseField::modulus());
    assert_ne!(
        before.0.as_slice(),
        cols.neg_x_range.byte_flags.0.as_slice(),
        "neg_x_range's witness did not move, so this test proves nothing"
    );
    assert_ne!(
        failures(&DecompressChip::new(), &row),
        0,
        "neg_x_range accepted a witness for a different value; it is not bound to neg_x.result"
    );

    // `y_range` guards the input read out of guest memory.
    let mut row = honest_decompress_row(false);
    let cols: &mut EdDecompressCols<F> = row.as_mut_slice().borrow_mut();
    let mut blu = Blu::default();
    let before = cols.y_range.byte_flags;
    cols.y_range
        .populate(&mut blu, &decoy(), &Ed25519BaseField::modulus());
    assert_ne!(
        before.0.as_slice(),
        cols.y_range.byte_flags.0.as_slice(),
        "y_range's witness did not move, so this test proves nothing"
    );
    assert_ne!(
        failures(&DecompressChip::new(), &row),
        0,
        "y_range accepted a witness for a different value; it is not bound to the y limbs"
    );
}

// ───────────────────────── the emulator rejects what the AIR cannot prove ───────────────────

/// A coordinate at or above `p` has no provable trace: the field gadgets' witness bounds assume
/// operands below the modulus. The syscall is the side that knows why, so it is the side that
/// fails.
#[test]
#[should_panic(expected = "not a canonical field element")]
fn a_non_canonical_input_coordinate_is_rejected_by_the_syscall() {
    let g = generator();
    let bad = AffinePoint::<Ed25519>::new(Ed25519BaseField::modulus(), g.y.clone());
    let _ = add_records(&bad, &g);
}

/// Same for the decompressor's `y`. A guest reaching this through a patched curve25519 crate
/// never gets here — the `FD_EDDECOMPRESS` hook reports a non-canonical `y` as not
/// decompressable and the crate takes the software path — but a direct ecall can.
#[test]
#[should_panic(expected = "not a canonical field element")]
fn a_non_canonical_y_is_rejected_by_the_syscall() {
    let _ = decompress_records(&Ed25519BaseField::modulus(), false);
}

// ───────────────────────── the decompression hint protocol ─────────────────────────

mod hook {
    use crate::{
        chips::gadgets::{
            curves::edwards::{
                ed25519::{ed25519_sqrt, Ed25519BaseField, Ed25519Parameters},
                EdwardsParameters,
            },
            utils::field_params::FieldParameters,
        },
        emulator::riscv::hook::ed_decompress::hint_ed_decompress,
    };
    use num::{BigUint, One, Zero};

    /// The hook's input: 32 bytes of compressed point, then the guest's `v = d*y^2 + 1`.
    fn buf(y: &BigUint) -> Vec<u8> {
        let modulus = Ed25519BaseField::modulus();
        let yy = (y * y) % &modulus;
        let v = (yy * Ed25519Parameters::d_biguint() + BigUint::one()) % &modulus;
        let mut out = y.to_bytes_le();
        out.resize(32, 0);
        let mut v_bytes = v.to_bytes_le();
        v_bytes.resize(32, 0);
        out.extend_from_slice(&v_bytes);
        out
    }

    fn call(y: &BigUint) -> Vec<Vec<u8>> {
        hint_ed_decompress(&buf(y))
    }

    /// The FD is wired to the hook this module tests.
    #[test]
    fn the_fd_is_wired_to_this_hook() {
        use crate::emulator::riscv::hook::{default_hook_map, FD_EDDECOMPRESS};
        assert!(
            default_hook_map().contains_key(&FD_EDDECOMPRESS),
            "FD_EDDECOMPRESS is not registered"
        );
    }

    /// A point on the curve is reported as decompressable, and nothing else is returned.
    #[test]
    fn a_curve_point_is_reported_decompressable() {
        let (_, y) = Ed25519Parameters::generator();
        assert_eq!(call(&y), vec![vec![1]]);
    }

    /// `y >= p` is reported as not decompressable with no witnesses, because the chip's
    /// `y_range` could not be satisfied for it whatever the rest of the row said.
    #[test]
    fn a_non_canonical_y_is_reported_not_decompressable() {
        assert_eq!(call(&Ed25519BaseField::modulus()), vec![vec![0]]);
        assert_eq!(
            call(&(Ed25519BaseField::modulus() + BigUint::one())),
            vec![vec![0]]
        );
    }

    /// The older protocol wrote 32 bytes. Taking those as `y || v` would silently hint on a
    /// truncated `v`, so the length is checked rather than assumed.
    #[test]
    #[should_panic(expected = "64 bytes")]
    fn a_32_byte_write_is_rejected() {
        let _ = hint_ed_decompress(&[0u8; 32]);
    }

    /// For a `y` that is not on the curve, the hook returns the two witnesses the guest
    /// constrains: `v_inv` and a root of `NQR * u/v`. Check them the way the guest does.
    #[test]
    fn a_non_curve_point_comes_with_checkable_witnesses() {
        let modulus = Ed25519BaseField::modulus();
        // Walk up from 2 until a y lands off the curve.
        let mut y = BigUint::from(2u32);
        let out = loop {
            let out = call(&y);
            if out[0] == vec![0] {
                break out;
            }
            y += BigUint::one();
            assert!(y < modulus, "no off-curve y found below the modulus");
        };
        assert_eq!(out.len(), 3, "an off-curve y must come with two witnesses");
        assert_eq!(out[1].len(), 32);
        assert_eq!(out[2].len(), 32);

        let yy = (&y * &y) % &modulus;
        let v = (&yy * Ed25519Parameters::d_biguint() + BigUint::one()) % &modulus;
        let u = (&yy + &modulus - BigUint::one()) % &modulus;
        let v_inv = BigUint::from_bytes_le(&out[1]);
        let root = BigUint::from_bytes_le(&out[2]);

        assert_eq!(
            &v * &v_inv % &modulus,
            BigUint::one(),
            "v_inv is not v's inverse"
        );
        assert!(!root.is_zero(), "0 is a quadratic residue");
        let u_div_v = (&u * &v_inv) % &modulus;
        assert_eq!(
            (&root * &root) % &modulus,
            (&u_div_v * BigUint::from(2u32)) % &modulus,
            "the hinted root does not satisfy the non-residue check"
        );
        assert!(
            ed25519_sqrt(&u_div_v).is_none(),
            "the hook claimed a decompressable point is not one"
        );
    }
}
