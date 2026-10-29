//! The canonicality half of the poseidon2 precompile's memory binding.
//!
//! # Scope
//!
//! [`DebugConstraintFolder`] is an `EmptyLookupBuilder`, so what runs here is the chip's
//! algebraic surface alone -- the memory bus, the byte bus and the syscall bus are all ignored.
//! That is the right scope for these constraints and the wrong one for anything else about this
//! chip. The gap they close is algebraic: `state[j] == lo + hi * 2^16` is an equality between
//! *field elements*, so it pins the 32-bit word in guest memory only up to a multiple of `p`.
//! Bus balance and emulator/AIR agreement are the end-to-end test's job, not this module's.
//!
//! # What the events here are, and are not
//!
//! The events are built by hand rather than driven through [`SyscallContext`], so they are only
//! as faithful as [`honest_event`]'s mirror of the emulator's dword bookkeeping
//! (`syscalls/precompiles/poseidon2/permute.rs`). That mirror is not asserted anywhere -- but it
//! is *checked*, because an event shaped wrongly cannot satisfy the input binding, the output
//! binding or the address gadgets, and [`an_honest_permutation_satisfies_every_constraint`]
//! would go red. A green positive test is therefore also evidence that the construction below
//! matches what the AIR expects of the emulator.
//!
//! [`SyscallContext`]: crate::emulator::riscv::syscalls::syscall_context::SyscallContext

use super::{columns::Poseidon2Cols, FieldSpecificPrecompilePoseidon2Chip, STATE_NUM_DWORDS};
use crate::{
    chips::chips::{
        byte::event::ByteRecordBehavior,
        events::ByteLookupEvent,
        riscv_memory::event::{MemoryReadRecord, MemoryWriteRecord},
    },
    compiler::word::Word,
    emulator::riscv::{
        record::EmulationRecord,
        syscalls::{
            precompiles::{poseidon2::event::Poseidon2PermuteEvent, PrecompileEvent},
            SyscallCode, SyscallEvent,
        },
    },
    machine::{
        chip::ChipBehavior, debug_folder::DebugConstraintFolder,
        field::FieldSpecificPoseidon2Config, septic::SepticDigest,
    },
    primitives::consts::{KoalaBearConfig, PERMUTATION_WIDTH},
};
use p3_air::{Air, RowWindow};
use p3_field::{extension::BinomialExtensionField, PrimeCharacteristicRing, PrimeField32};
use p3_koala_bear::KoalaBear;
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use p3_symmetric::Permutation;
use std::borrow::BorrowMut;

type F = KoalaBear;
type EF = BinomialExtensionField<KoalaBear, 4>;
type Config = KoalaBearConfig;
type Chip = FieldSpecificPrecompilePoseidon2Chip<F>;

/// `p` for the field under test. Every forgery below is `honest + P`, which is the smallest
/// non-canonical representative of the same field element and is always below `2^32`: the
/// honest word is under `p`, and `2p < 2^32`.
const P: u32 = <F as PrimeField32>::ORDER_U32;

const INPUT_PTR: u64 = 0x2_0000;
const OUTPUT_PTR: u64 = 0x2_0100;
const CHUNK: u32 = 1;
const READ_CLK: u32 = 8;

/// A byte-lookup sink. The folder ignores lookups, so these are collected and dropped; the
/// gadget's `populate` still needs somewhere to put them.
#[derive(Default)]
struct Blu(#[allow(dead_code)] Vec<ByteLookupEvent>);
impl ByteRecordBehavior for Blu {
    fn add_byte_lookup_event(&mut self, e: ByteLookupEvent) {
        self.0.push(e);
    }
}

fn dword(lo: u32, hi: u32) -> u64 {
    u64::from(lo) | (u64::from(hi) << 32)
}

/// Sixteen distinct canonical inputs, including the two edges the range check turns on:
/// `0` (smallest) and `p - 1` (largest accepted).
fn inputs() -> [u32; PERMUTATION_WIDTH] {
    let mut s = [0u32; PERMUTATION_WIDTH];
    s[0] = 0;
    s[1] = P - 1;
    for (j, slot) in s.iter_mut().enumerate().skip(2) {
        *slot = (j as u32) * 0x0101_0101 % P;
    }
    s
}

/// An event shaped the way `permute.rs` shapes one, for an 8-byte-aligned call.
///
/// Both record vectors are indexed by *state word* while the emulator only touched memory once
/// per *dword*, so each holds two entries per access:
///
/// * reads -- `read_word_records_via_dwords` pushes the same `MemoryReadRecord` into slots `2k`
///   and `2k + 1`, so both carry the whole dword and the trace generator reads slot `2k`.
/// * writes -- `write_word_records_via_dwords` splits one dword write into two synthetic
///   half-word records sharing its timestamps: slot `2k` carries the dword's original
///   `prev_value` and the value after the low half was inserted, slot `2k + 1` carries that as
///   its `prev_value` and the fully updated dword as its `value`.
fn honest_event() -> Poseidon2PermuteEvent {
    let state_values = inputs();
    let permuted = F::permutation().permute(state_values.map(F::from_u32));
    let out: [u32; PERMUTATION_WIDTH] = permuted.map(|f| f.as_canonical_u32());

    let mut state_read_records = Vec::with_capacity(PERMUTATION_WIDTH);
    let mut state_write_records = Vec::with_capacity(PERMUTATION_WIDTH);

    for k in 0..STATE_NUM_DWORDS {
        let read = MemoryReadRecord {
            value: dword(state_values[2 * k], state_values[2 * k + 1]),
            chunk: CHUNK,
            timestamp: READ_CLK,
            prev_chunk: CHUNK,
            prev_timestamp: READ_CLK - 4,
        };
        state_read_records.push(read);
        state_read_records.push(read);

        // The buffer the guest is writing into held something before the call; `0` is as good a
        // previous value as any, and using it keeps `prev_value` distinct from `value`.
        let original = 0u64;
        let after_lo = dword(out[2 * k], 0);
        let finished = dword(out[2 * k], out[2 * k + 1]);
        let common = MemoryWriteRecord {
            value: after_lo,
            prev_value: original,
            chunk: CHUNK,
            timestamp: READ_CLK + 1,
            prev_chunk: CHUNK,
            prev_timestamp: READ_CLK,
        };
        state_write_records.push(common);
        state_write_records.push(MemoryWriteRecord {
            value: finished,
            prev_value: after_lo,
            ..common
        });
    }

    Poseidon2PermuteEvent {
        chunk: CHUNK,
        clk: u64::from(READ_CLK),
        state_values: state_values.to_vec(),
        input_memory_ptr: INPUT_PTR,
        output_memory_ptr: OUTPUT_PTR,
        state_read_records,
        state_write_records,
        local_mem_access: vec![],
    }
}

/// The chip's trace for a single honest permutation, as a flat row.
fn honest_row() -> Vec<F> {
    let mut record = EmulationRecord::default();
    record.add_precompile_event(
        SyscallCode::POSEIDON2_PERMUTE,
        SyscallEvent {
            chunk: CHUNK,
            clk: u64::from(READ_CLK),
            syscall_id: SyscallCode::POSEIDON2_PERMUTE.syscall_id(),
            arg1: INPUT_PTR,
            arg2: OUTPUT_PTR,
        },
        PrecompileEvent::Poseidon2Permute(honest_event()),
    );

    let trace: RowMajorMatrix<F> =
        Chip::default().generate_main(&record, &mut EmulationRecord::default());
    let width = trace.width();
    trace.values[..width].to_vec()
}

/// How many algebraic constraints the chip's AIR reports violated on `row`.
fn failures(row: &[F]) -> usize {
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
    Chip::default().eval(&mut folder);
    folder.failures.len()
}

/// Read the 32-bit value limbs `base` and `base + 1` of `word` encode.
fn half(word: &Word<F>, base: usize) -> u32 {
    word[base].as_canonical_u32() | (word[base + 1].as_canonical_u32() << 16)
}

/// Overwrite limbs `base` and `base + 1` of `word` with `value`.
fn set_half(word: &mut Word<F>, base: usize, value: u32) {
    word[base] = F::from_u32(value & 0xFFFF);
    word[base + 1] = F::from_u32(value >> 16);
}

/// Replace state word `j` of one side with `honest + P` and re-witness its range checker the way
/// an honest prover would for the value actually present, so the forgery is rejected by the
/// comparison itself rather than by a stale witness.
///
/// Returns the tampered row.
fn shift_word_by_p(j: usize, output: bool) -> Vec<F> {
    let mut row = honest_row();
    let cols: &mut Poseidon2Cols<F, Config> = row.as_mut_slice().borrow_mut();
    let (dw, base) = (j / 2, (j % 2) * 2);
    let mut blu = Blu::default();

    if output {
        let word = &mut cols.output_memory[dw].access.value;
        let forged = half(word, base) + P;
        set_half(word, base, forged);
        cols.output_range_checkers[j].populate(&mut blu, u64::from(forged));
    } else {
        let word = &mut cols.input_memory[dw].access.value;
        let forged = half(word, base) + P;
        set_half(word, base, forged);
        cols.input_range_checkers[j].populate(&mut blu, u64::from(forged));
    }

    row
}

/// The positive control. It also stands in for the faithfulness of [`honest_event`]: a row built
/// from a mis-shaped event could not satisfy the bindings or the address gadgets.
#[test]
fn an_honest_permutation_satisfies_every_constraint() {
    assert_eq!(
        failures(&honest_row()),
        0,
        "an honest poseidon2 row violates a constraint"
    );
}

/// The soundness gap this module exists for.
///
/// `state[j] + P` is congruent to `state[j]`, so the output binding
/// `state[j] == lo + hi * 2^16` still holds for it -- meaning that before
/// `output_range_checkers` there was nothing stopping a prover from writing it into guest
/// memory. Every one of the sixteen written words has to be covered, so every one is checked.
#[test]
fn a_written_word_shifted_by_p_is_rejected() {
    for j in 0..PERMUTATION_WIDTH {
        assert_ne!(
            failures(&shift_word_by_p(j, true)),
            0,
            "output word {j} was accepted as `state[{j}] + p`; the written value is not unique"
        );
    }
}

/// The input side of the same argument.
///
/// Not a soundness gap on its own -- the emulator would have reduced such a word and permuted
/// the same field element -- but it is what makes "the word in guest memory" and "the element
/// this chip permuted" the same object. The syscall rejects these words up front; this keeps
/// the two sides from drifting apart if that assertion is ever relaxed.
#[test]
fn an_input_word_shifted_by_p_is_rejected() {
    for j in 0..PERMUTATION_WIDTH {
        assert_ne!(
            failures(&shift_word_by_p(j, false)),
            0,
            "input word {j} was accepted as `state[{j}] + p`"
        );
    }
}

/// The largest accepted value and the smallest rejected one sit next to each other, so a
/// comparison that is off by one would show up here and nowhere else in this file.
///
/// `inputs()` puts `p - 1` in slot 1 and the permutation output is whatever it is, so this
/// drives the boundary through the input checker, where the value is ours to choose.
#[test]
fn the_boundary_between_p_minus_one_and_p_is_exact() {
    assert_eq!(
        failures(&honest_row()),
        0,
        "`p - 1` (input word 1) must be accepted"
    );

    let mut row = honest_row();
    let cols: &mut Poseidon2Cols<F, Config> = row.as_mut_slice().borrow_mut();
    let mut blu = Blu::default();
    // Input word 1 lives in dword 0, limbs 2-3. Raise it from `p - 1` to exactly `p`.
    set_half(&mut cols.input_memory[0].access.value, 2, P);
    cols.input_range_checkers[1].populate(&mut blu, u64::from(P));
    assert_ne!(failures(&row), 0, "`p` itself must be rejected");
}

/// The syscall is reachable from a running program.
///
/// Everything above this point tests the AIR against an event built by hand. That leaves the
/// half this chip was shelved for untested: whether a guest can actually *reach* the
/// permutation. `default_syscall_map` has to register it, the ECALL path has to find it, and the
/// emulator has to emit a `Poseidon2Permute` event -- three things that a chip-level test cannot
/// see and that the compiler does not check either, since an unregistered syscall is a missing
/// map entry rather than a missing symbol.
///
/// A synthetic program is used rather than the guest ELF `perf/bench_data/rv64/poseidon2-elf`,
/// which the MLE e2e proves (`--elf poseidon2`): seven hand-assembled instructions (four to issue
/// the permute ECALL, three to halt) keep this test independent of a prebuilt binary and aimed at
/// exactly the syscall-map, ECALL and event path. `riscv_constraint_dump` builds a `Program` the
/// same way.
#[cfg(test)]
mod syscall_reachability_tests {
    use crate::{
        chips::tests::test_rv64_emulate,
        compiler::riscv::{instruction::Instruction, opcode::Opcode, program::Program},
        configs::stark_config::KoalaBearPoseidon2,
        emulator::{riscv::syscalls::SyscallCode, stdin::EmulatorStdin},
        primitives::consts::PERMUTATION_WIDTH,
    };
    use p3_field::{PrimeCharacteristicRing, PrimeField32};
    use p3_koala_bear::KoalaBear;
    use p3_symmetric::Permutation;
    use std::{collections::BTreeMap, sync::Arc};

    use crate::machine::field::FieldSpecificPoseidon2Config;

    type F = KoalaBear;

    const INPUT_PTR: u64 = 0x10_0000;
    const OUTPUT_PTR: u64 = 0x10_0100;

    /// `x5 = imm` -- `ADD rd, x0, imm`, the shape the emulator's ECALL path reads its operands
    /// from (`x5` the syscall id, `x10`/`x11` the two arguments).
    fn li(rd: u8, imm: u64) -> Instruction {
        Instruction::new(Opcode::ADD, rd, 0, imm, true, true)
    }

    /// Sixteen canonical inputs, two per dword in the packed layout the chip reads.
    fn state_words() -> [u32; PERMUTATION_WIDTH] {
        std::array::from_fn(|j| ((j as u32) * 0x0101_0101) % F::ORDER_U32)
    }

    #[test]
    fn a_guest_ecall_reaches_the_permutation() {
        let words = state_words();
        let mut memory_image = BTreeMap::new();
        for k in 0..PERMUTATION_WIDTH / 2 {
            let dword = u64::from(words[2 * k]) | (u64::from(words[2 * k + 1]) << 32);
            memory_image.insert(INPUT_PTR + 8 * k as u64, dword);
            memory_image.insert(OUTPUT_PTR + 8 * k as u64, 0);
        }

        let program = Program {
            instructions: vec![
                li(10, INPUT_PTR),
                li(11, OUTPUT_PTR),
                li(5, u64::from(SyscallCode::POSEIDON2_PERMUTE as u32)),
                Instruction::new(Opcode::ECALL, 5, 10, 11, false, false),
                li(10, 0),
                li(5, u64::from(SyscallCode::HALT as u32)),
                Instruction::new(Opcode::ECALL, 5, 10, 11, false, false),
            ]
            .into(),
            pc_start: 0,
            pc_base: 0,
            memory_image: Arc::new(memory_image),
            preprocessed_shape: None,
        };

        let stdin =
            EmulatorStdin::<Program, Vec<u8>>::new_builder::<KoalaBearPoseidon2>().finalize();
        let records = test_rv64_emulate(Arc::new(program), stdin);

        let events: Vec<_> = records
            .iter()
            .flat_map(|r| r.get_precompile_events(SyscallCode::POSEIDON2_PERMUTE))
            .collect();
        assert_eq!(
            events.len(),
            1,
            "the ECALL produced no poseidon2 event -- the syscall is not registered, or the \
             ECALL path did not dispatch it"
        );

        // And it computed the permutation, not something else.
        let expected = F::permutation().permute(words.map(F::from_u32));
        let (_, event) = events[0];
        let crate::emulator::riscv::syscalls::precompiles::PrecompileEvent::Poseidon2Permute(e) =
            event
        else {
            panic!("the event recorded under POSEIDON2_PERMUTE is not a poseidon2 event");
        };
        assert_eq!(
            e.state_values,
            words.to_vec(),
            "the syscall read a different input than the guest wrote"
        );
        assert_eq!(
            e.state_write_records.last().unwrap().value & 0xFFFF_FFFF,
            u64::from(expected[PERMUTATION_WIDTH - 2].as_canonical_u32()),
            "the written state does not match the reference permutation"
        );
    }
}
