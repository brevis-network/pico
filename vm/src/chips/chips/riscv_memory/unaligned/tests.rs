//! The chip's AIR against the emulator's semantics, one row at a time.
//!
//! Each case builds the records the emulator makes for a load or store (`util::dword_bytes`,
//! `straddling_bytes` and `splice_dword` are what it computes with), the chip turns them into a
//! row, and [`DebugConstraintFolder`] evaluates the AIR on it. A row that satisfies every
//! constraint says the circuit reads and writes the bytes the emulator does.
//!
//! What they do not cover: the folder ignores lookups, so the byte and range checks and the memory
//! and dispatch buses are the end-to-end proof's job.

use super::{
    columns::{MemoryUnalignedCols, NUM_MEMORY_UNALIGNED_COLS},
    MemoryUnalignedChip,
};
use crate::{
    chips::{
        chips::{
            riscv_cpu::event::CpuEvent,
            riscv_memory::event::{MemoryReadRecord, MemoryRecordEnum, MemoryWriteRecord},
        },
        ffi::FfiOption,
        tests::test_rv64_emulate_with_opts,
    },
    compiler::riscv::{instruction::Instruction, opcode::Opcode, program::Program},
    configs::stark_config::KoalaBearPoseidon2,
    emulator::{
        opts::EmulatorOpts,
        riscv::{
            emulator::{
                guard::access_width,
                util::{dword_bytes, splice_dword, straddling_bytes},
            },
            record::EmulationRecord,
            syscalls::SyscallCode,
        },
        stdin::EmulatorStdin,
    },
    machine::{chip::ChipBehavior, debug_folder::DebugConstraintFolder, septic::SepticDigest},
};
use p3_air::{Air, RowWindow};
use p3_field::{extension::QuinticTrinomialExtensionField, PrimeCharacteristicRing};
use p3_koala_bear::KoalaBear;
use std::{
    borrow::{Borrow, BorrowMut},
    collections::BTreeMap,
    sync::Arc,
};

type F = KoalaBear;
type EF = QuinticTrinomialExtensionField<KoalaBear>;

const CHUNK: u32 = 1;
const CLK: u64 = 400;
/// rs1's value, a dword address: the access lands at `BASE + offset`.
const BASE: u64 = 0x2_0000;
/// The program's code, above the data the synthetic accesses use.
const CODE: core::ops::Range<u64> = 0x20_0800..0x20_1000;

const LOADS: [Opcode; 7] = [
    Opcode::LB,
    Opcode::LBU,
    Opcode::LH,
    Opcode::LHU,
    Opcode::LW,
    Opcode::LWU,
    Opcode::LD,
];
const STORES: [Opcode; 4] = [Opcode::SB, Opcode::SH, Opcode::SW, Opcode::SD];

/// Two dwords and a register value each: plain bytes, every sign bit set, and all ones.
const VALUES: [(u64, u64, u64); 4] = [
    (
        0x8877_6655_4433_2211,
        0xffee_ddcc_bbaa_9988,
        0x0123_4567_89ab_cdef,
    ),
    (
        0x8081_8283_8485_8687,
        0xf0f1_f2f3_f4f5_f6f7,
        0xfedc_ba98_7654_3210,
    ),
    (
        0x0102_0304_0506_0708,
        0x0000_0000_0000_0000,
        0x8000_0000_8000_8080,
    ),
    (u64::MAX, u64::MAX, u64::MAX),
];

/// A load's value in rd: the bytes it reads, sign- or zero-extended.
fn load_value(opcode: Opcode, bytes: u64) -> u64 {
    match opcode {
        Opcode::LB => bytes as u8 as i8 as i64 as u64,
        Opcode::LH => bytes as u16 as i16 as i64 as u64,
        Opcode::LW => bytes as u32 as i32 as i64 as u64,
        _ => bytes,
    }
}

fn read(value: u64, timestamp: u64) -> MemoryRecordEnum {
    MemoryRecordEnum::Read(MemoryReadRecord {
        value,
        chunk: CHUNK,
        timestamp: timestamp as u32,
        prev_chunk: CHUNK,
        prev_timestamp: timestamp as u32 - 100,
    })
}

fn write(prev_value: u64, value: u64, timestamp: u64) -> MemoryRecordEnum {
    MemoryRecordEnum::Write(MemoryWriteRecord {
        value,
        chunk: CHUNK,
        timestamp: timestamp as u32,
        prev_value,
        prev_chunk: CHUNK,
        prev_timestamp: timestamp as u32 - 100,
    })
}

/// A load or store at `base + offset` with rd (or rs2) x5 and rs1 x6, over the dword `first` and
/// the one after it, `second`; `value` is rs2's for a store. Returns its event and the access to
/// the second dword, as the emulator records them.
fn access(
    opcode: Opcode,
    base: u64,
    offset: u64,
    (first, second, value): (u64, u64, u64),
) -> (CpuEvent, Option<MemoryRecordEnum>) {
    let width = access_width(opcode);
    let crosses = offset + width > 8;
    let store = STORES.contains(&opcode);
    let (a, a_record, memory_record, next) = if store {
        let low = if crosses { 8 - offset } else { width };
        let next = crosses.then(|| {
            let high = splice_dword(second, 0, width - low, value >> (8 * low));
            write(second, high, CLK + 1)
        });
        let written = write(first, splice_dword(first, offset, low, value), CLK);
        (value, read(value, CLK + 3), written, next)
    } else {
        let bytes = if crosses {
            straddling_bytes(first, second, offset, width)
        } else {
            dword_bytes(first, offset, width)
        };
        let loaded = load_value(opcode, bytes);
        let next = crosses.then(|| read(second, CLK + 1));
        (loaded, write(0, loaded, CLK + 3), read(first, CLK), next)
    };
    let event = CpuEvent {
        chunk: CHUNK,
        clk: CLK,
        pc: 0x20_0800,
        next_pc: 0x20_0804,
        instruction: Instruction::new(opcode, 5, 6, offset, false, true),
        a,
        a_record: FfiOption::Some(a_record),
        b: base,
        b_record: FfiOption::Some(read(base, CLK + 2)),
        c: offset,
        c_record: FfiOption::None,
        memory: FfiOption::Some(first),
        memory_record: FfiOption::Some(memory_record),
        exit_code: 0,
    };
    (event, next)
}

fn row_of((event, next): &(CpuEvent, Option<MemoryRecordEnum>)) -> Vec<F> {
    let mut row = vec![F::ZERO; NUM_MEMORY_UNALIGNED_COLS];
    let cols: &mut MemoryUnalignedCols<F> = row.as_mut_slice().borrow_mut();
    MemoryUnalignedChip::<F>::default().event_to_row(event, *next, &CODE, cols, &mut Vec::new());
    row
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
    MemoryUnalignedChip::<F>::default().eval(&mut folder);
    folder
        .failures
        .iter()
        .map(|(scopes, failure)| format!("{scopes:?} {failure:?}"))
        .collect()
}

fn cols(row: &mut [F]) -> &mut MemoryUnalignedCols<F> {
    row.borrow_mut()
}

/// Every load and store, at every offset in its dword, on every value pattern: within the dword
/// and across into the next, and aligned too, since an aligned access may come to this chip.
#[test]
fn every_width_at_every_offset_satisfies_the_air() {
    for opcode in LOADS.into_iter().chain(STORES) {
        for offset in 0..8 {
            for values in VALUES {
                let failures = failures(&row_of(&access(opcode, BASE, offset, values)));
                assert!(
                    failures.is_empty(),
                    "{opcode:?} at offset {offset}, {values:x?}: {failures:?}"
                );
            }
        }
    }
}

/// The next dword's address carries into limb 1 when the access starts in the last dword of a
/// 64 KiB block.
#[test]
fn an_access_into_the_next_64_kib_satisfies_the_air() {
    let base = 0x2_fff8;
    for opcode in [Opcode::LD, Opcode::SD, Opcode::LW, Opcode::SH] {
        let mut row = row_of(&access(opcode, base, 7, VALUES[1]));
        assert_eq!(cols(&mut row).next_carry, F::ONE, "{opcode:?}");
        let failures = failures(&row);
        assert!(failures.is_empty(), "{opcode:?}: {failures:?}");
    }
}

/// An x0 destination is not constrained to the loaded value: the Cpu chip pins it to zero.
#[test]
fn a_load_into_x0_satisfies_the_air() {
    let (mut event, next) = access(Opcode::LD, BASE, 3, VALUES[0]);
    event.instruction.op_a = 0;
    event.a = 0;
    event.a_record = FfiOption::Some(write(0, 0, CLK + 3));
    let failures = failures(&row_of(&(event, next)));
    assert!(failures.is_empty(), "{failures:?}");
}

/// The checks above are not vacuous: each of these rows breaks one fact, and fails the AIR.
#[test]
fn a_row_that_lies_fails_the_air() {
    type Tamper = fn(&mut MemoryUnalignedCols<F>);
    let cases: [(&str, Opcode, u64, Tamper); 9] = [
        ("a loaded byte", Opcode::LD, 3, |c| {
            c.instruction.op_a_value.0[1] += F::ONE
        }),
        ("the offset", Opcode::LW, 5, |c| {
            c.offset[5] = F::ZERO;
            c.offset[6] = F::ONE;
        }),
        ("the crossing", Opcode::LD, 3, |c| c.cross = F::ZERO),
        ("a byte written to the next dword", Opcode::SD, 3, |c| {
            c.second.access.value.0[0] += F::ONE
        }),
        ("a byte written to the first dword", Opcode::SW, 6, |c| {
            c.first.access.value.0[3] += F::ONE
        }),
        ("a byte a store leaves", Opcode::SH, 1, |c| {
            c.first.access.value.0[3] += F::ONE
        }),
        ("the sign", Opcode::LH, 7, |c| c.msb = F::ONE - c.msb),
        ("the next dword's carry", Opcode::LD, 1, |c| {
            c.next_carry = F::ONE;
            c.next_carry_inv = F::ZERO;
        }),
        ("a load changing memory", Opcode::LWU, 6, |c| {
            c.second.access.value.0[0] += F::ONE
        }),
    ];
    for (fact, opcode, offset, tamper) in cases {
        let mut row = row_of(&access(opcode, BASE, offset, VALUES[1]));
        assert!(failures(&row).is_empty(), "{fact}: the honest row fails");
        tamper(cols(&mut row));
        assert!(
            !failures(&row).is_empty(),
            "{fact}: {opcode:?} at offset {offset} passes with it changed"
        );
    }
}

/// A row that does not cross has no second access, and its second dword's columns stay zero.
#[test]
fn a_row_within_its_dword_leaves_the_second_access_empty() {
    let mut row = row_of(&access(Opcode::LW, BASE, 3, VALUES[0]));
    let c = cols(&mut row);
    assert_eq!(c.cross, F::ZERO);
    assert!(c.second.prev_value.0.iter().all(|v| *v == F::ZERO));
    assert!(c.second.access.value.0.iter().all(|v| *v == F::ZERO));
}

/// Real records: a program makes every load and store at every offset, each on a fresh pair of
/// dwords, and the emulator runs it with its trace recorded. The misaligned ones, and only they,
/// are in the history's unaligned table, and every row the chip makes of them satisfies the AIR.
#[test]
fn the_emulators_misaligned_accesses_satisfy_the_air() {
    const DATA: u64 = 0x2_0000;
    let li = |rd: u8, imm: u64| Instruction::new(Opcode::ADD, rd, 0, imm, true, true);
    let image: BTreeMap<u64, u64> = (0..2 * 88u64)
        .map(|i| {
            (
                DATA + 8 * i,
                0x8091_a2b3_c4d5_e6f7_u64.rotate_left(8 * i as u32) ^ i,
            )
        })
        .collect();
    let mut instructions = vec![li(7, 0xfedc_ba98_7654_3210)];
    let (mut accesses, mut misaligned) = (0u64, 0);
    for opcode in LOADS.into_iter().chain(STORES) {
        for offset in 0..8 {
            instructions.push(li(6, DATA + 16 * accesses));
            let op_a = if STORES.contains(&opcode) { 7 } else { 5 };
            instructions.push(Instruction::new(opcode, op_a, 6, offset, false, true));
            accesses += 1;
            misaligned += usize::from(offset % access_width(opcode) != 0);
        }
    }
    instructions.extend([
        li(5, SyscallCode::HALT as u64),
        li(10, 0),
        Instruction::new(Opcode::ECALL, 5, 10, 11, false, false),
    ]);
    let program = Program {
        instructions: instructions.into(),
        pc_start: 0,
        pc_base: 0,
        memory_image: Arc::new(image),
        preprocessed_shape: None,
    };
    let stdin = EmulatorStdin::<Program, Vec<u8>>::new_builder::<KoalaBearPoseidon2>().finalize();
    let opts = EmulatorOpts::default();
    let records = test_rv64_emulate_with_opts(Arc::new(program), stdin, opts);

    let chip = MemoryUnalignedChip::<F>::default();
    let (mut unaligned, mut aligned, mut rows) = (0, 0, 0);
    for record in &records {
        if let Some(history) = &record.history {
            unaligned += history.unaligned.len();
            aligned += history.chip_steps.memory.len();
        }
        let trace = chip.generate_main(record, &mut EmulationRecord::default());
        for row in trace.values.chunks(NUM_MEMORY_UNALIGNED_COLS) {
            let cols: &MemoryUnalignedCols<F> = row.borrow();
            if cols.offset.iter().all(|flag| *flag == F::ZERO) {
                continue;
            }
            rows += 1;
            let failures = failures(row);
            assert!(
                failures.is_empty(),
                "row {rows} ({:?}): {failures:?}",
                cols.instruction
            );
        }
    }
    assert_eq!(
        misaligned, 44,
        "the misaligned offsets of the eleven accesses"
    );
    assert_eq!(unaligned, misaligned, "the history's unaligned steps");
    assert_eq!(
        aligned,
        accesses as usize - misaligned,
        "the memory chip's steps"
    );
    assert_eq!(rows, misaligned, "the chip's rows");
}

/// A store that meets the program's code fails the AIR, by any of its bytes; one that ends where
/// the code starts, or starts where it ends, satisfies it.
#[test]
fn a_store_into_the_code_fails_the_air() {
    let at = |opcode, addr: u64| access(opcode, addr & !7, addr % 8, VALUES[0]);
    let off_the_code = [
        (Opcode::SD, CODE.start - 8),
        (Opcode::SW, CODE.start - 7),
        (Opcode::SB, CODE.end),
        (Opcode::SD, CODE.end + 3),
    ];
    for (opcode, addr) in off_the_code {
        let failures = failures(&row_of(&at(opcode, addr)));
        assert!(
            failures.is_empty(),
            "{opcode:?} at 0x{addr:x}: {failures:?}"
        );
    }
    let into_the_code = [
        (Opcode::SD, CODE.start - 4),
        (Opcode::SB, CODE.start),
        (Opcode::SH, CODE.end - 1),
        (Opcode::SW, CODE.start + 0x101),
    ];
    for (opcode, addr) in into_the_code {
        assert!(
            !failures(&row_of(&at(opcode, addr))).is_empty(),
            "{opcode:?} at 0x{addr:x} satisfies the AIR"
        );
    }
}
