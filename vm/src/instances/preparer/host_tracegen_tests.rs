//! The GPU prover's host-tracegen path: the poseidon2 precompile and the two Ed25519 chips build
//! their traces on the host and add their byte lookups to the device byte table
//! ([`gpu_add_host_byte_lookups`]).
//!
//! Two things can go wrong there without any constraint noticing until a proof fails: a lookup
//! counted on a different row or column than the [`ByteChip`] reads it from, and a chip's lookups
//! counted twice or not at all. Both are checked against the host reference, the byte chip's own
//! `generate_main` over the lookups the chip's `extra_record` raises.

use super::{
    add_byte_lookups_to_raw_table, gpu_add_host_byte_lookups, gpu_allocate_byte_trace,
    gpu_finalize_byte_trace, precompute_event_size, PreallocatedGpuMemory, PreparedGpuEvents,
};
use crate::{
    chips::{
        chips::byte::{
            columns::NUM_BYTE_MULT_COLS, event::ByteLookupEvent, traces::NUM_ROWS, ByteChip,
        },
        gadgets::curves::edwards::ed25519::{Ed25519, Ed25519Parameters},
        precompiles::{
            edwards::{EdAddAssignChip, EdDecompressChip},
            poseidon2::FieldSpecificPrecompilePoseidon2Chip,
        },
        tests::{init_test_stream, test_rv64_emulate},
        trace::TraceData,
    },
    compiler::riscv::{
        compiler::{Compiler, SourceType},
        opcode::ByteOpcode,
        program::Program,
    },
    configs::stark_config::KoalaBearPoseidon2,
    emulator::{
        riscv::{record::EmulationRecord, syscalls::SyscallCode},
        stdin::EmulatorStdin,
    },
    instances::compiler::shapes::riscv_shape::RiscvPadShape,
    machine::chip::ChipBehavior,
};
use cudart::stream::CudaStream;
use hashbrown::HashMap;
use p3_field::PrimeCharacteristicRing;
use p3_koala_bear::KoalaBear;
use p3_matrix::dense::RowMajorMatrix;
use rand::{rngs::StdRng, RngExt, SeedableRng};
use std::{path::PathBuf, sync::Arc};

type F = KoalaBear;

/// A fresh device byte table, zeroed the way the orchestrator allocates it.
fn device_byte_table(stream: &CudaStream) -> PreallocatedGpuMemory<'_> {
    let memory = PreallocatedGpuMemory {
        d_byte_trace: gpu_allocate_byte_trace(stream, 0).unwrap(),
        ..Default::default()
    };
    stream.synchronize().unwrap();
    memory
}

/// Finalize the device table and bring it back.
fn finalized(stream: &CudaStream, mut memory: PreallocatedGpuMemory<'_>) -> RowMajorMatrix<F> {
    gpu_finalize_byte_trace(stream, &mut memory).unwrap();
    let table = memory.d_byte_trace.take().unwrap();
    let host = TraceData::<F>::Gpu(NUM_BYTE_MULT_COLS, table).to_host(stream);
    stream.synchronize().unwrap();
    host
}

/// The byte chip's trace over `lookups`: what the device table has to equal once finalized.
fn reference_table(lookups: &HashMap<ByteLookupEvent, usize>) -> RowMajorMatrix<F> {
    let mut record = EmulationRecord::default();
    record.byte_lookups = lookups.clone();
    ByteChip::<F>::default().generate_main(&record, &mut EmulationRecord::default())
}

/// Lookups over every opcode, `BitRange` at every width, with random multiplicities. `a1` varies
/// too, so distinct map entries land in the same slot and have to add up.
fn random_lookups(rng: &mut StdRng, n: usize) -> HashMap<ByteLookupEvent, usize> {
    let mut lookups = HashMap::new();
    for _ in 0..n {
        let opcode = ByteOpcode::all()[rng.random_range(0..ByteOpcode::all().len())];
        let (a2, b, c) = if opcode == ByteOpcode::BitRange {
            let bits: u8 = rng.random_range(0..=16);
            let value: u32 = rng.random_range(0..(1u32 << bits));
            (bits, (value >> 8) as u8, value as u8)
        } else {
            (0, rng.random(), rng.random())
        };
        let lookup = ByteLookupEvent::new(opcode, rng.random_range(0..4), a2, b, c);
        *lookups.entry(lookup).or_insert(0) += rng.random_range(1..1000);
    }
    lookups
}

fn merged(
    a: &HashMap<ByteLookupEvent, usize>,
    b: &HashMap<ByteLookupEvent, usize>,
) -> HashMap<ByteLookupEvent, usize> {
    let mut out = a.clone();
    for (lookup, mult) in b {
        *out.entry(*lookup).or_insert(0) += mult;
    }
    out
}

/// The host-side count agrees with the byte chip slot for slot, before any device is involved.
#[test]
fn host_counts_land_where_the_byte_chip_reads_them() {
    let mut rng = StdRng::seed_from_u64(0x0b17e);
    let lookups = random_lookups(&mut rng, 4000);

    let mut table = vec![0u32; NUM_ROWS * NUM_BYTE_MULT_COLS];
    add_byte_lookups_to_raw_table(&mut table, lookups.clone());
    let counted: Vec<F> = table.into_iter().map(F::from_u32).collect();

    assert_eq!(counted, reference_table(&lookups).values);
}

/// A row outside the table is a mapping bug, not a lookup to drop.
#[test]
#[should_panic(expected = "outside the")]
fn a_lookup_past_the_table_is_refused() {
    // 15 bits, and a value that does not fit them: row `2^16 + 2^16 + 2^15`.
    let lookup = ByteLookupEvent::new(ByteOpcode::BitRange, 0, 15, 0xFF, 0xFF);
    let mut table = vec![0u32; NUM_ROWS * NUM_BYTE_MULT_COLS];
    add_byte_lookups_to_raw_table(&mut table, [(lookup, 1)]);
}

/// Through the device: two batches added on top of each other and on top of counts already in
/// the table, then finalized, equal the byte chip's trace over all of them. The second batch
/// comes the way the poseidon2 precompile hands its lookups over, one `(lookup, 1)` per lookup
/// made, repeats and all.
#[test]
fn host_lookups_added_to_the_device_table_match_the_byte_chip() {
    let stream = init_test_stream();
    let mut rng = StdRng::seed_from_u64(0x60d);
    let first = random_lookups(&mut rng, 3000);
    let second = random_lookups(&mut rng, 3000);
    let second_one_by_one = second
        .iter()
        .flat_map(|(&lookup, &mult)| std::iter::repeat_n((lookup, 1), mult));

    let mut memory = device_byte_table(stream);
    gpu_add_host_byte_lookups(first.clone(), &mut memory).unwrap();
    gpu_add_host_byte_lookups(second_one_by_one, &mut memory).unwrap();
    gpu_add_host_byte_lookups(std::iter::empty(), &mut memory).unwrap();

    assert_eq!(
        finalized(stream, memory),
        reference_table(&merged(&first, &second))
    );
}

fn bench_elf(name: &str) -> Arc<Program> {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push(format!("../perf/bench_data/rv64/{name}-elf"));
    let elf = std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    Compiler::new(SourceType::RISCV, &elf).unwrap().compile()
}

/// The first of `records` with `code` events. A precompile's events sit in tail records of their
/// own kind, so each kind is looked up separately.
fn record_with(records: &[EmulationRecord], code: SyscallCode) -> EmulationRecord {
    records
        .iter()
        .find(|r| !r.get_precompile_events(code).is_empty())
        .unwrap_or_else(|| panic!("no record carries {code:?} events"))
        .clone()
}

/// `perf/bench_data/rv64/poseidon2-elf`, hashing twice.
fn poseidon2_records() -> Vec<EmulationRecord> {
    let mut stdin = EmulatorStdin::<Program, Vec<u8>>::new_builder::<KoalaBearPoseidon2>();
    stdin.write(&2u32);
    test_rv64_emulate(bench_elf("poseidon2"), stdin.finalize())
}

/// `perf/bench_data/rv64/ed25519-elf` with the input `--elf ed25519` gives it
/// (`examples/common/parse_args.rs`): the basepoint and its negation, then two scalars.
fn ed25519_records() -> Vec<EmulationRecord> {
    let mut stdin = EmulatorStdin::<Program, Vec<u8>>::new_builder::<KoalaBearPoseidon2>();
    let mut basepoint = [0x66u8; 32];
    basepoint[0] = 0x58;
    stdin.write(&basepoint);
    let mut neg_basepoint = basepoint;
    neg_basepoint[31] |= 0x80;
    stdin.write(&neg_basepoint);
    let mut scalar = [0u8; 32];
    scalar[..4].copy_from_slice(&3u32.to_le_bytes());
    stdin.write(&scalar);
    scalar[4] = 1;
    stdin.write(&scalar);
    test_rv64_emulate(bench_elf("ed25519"), stdin.finalize())
}

/// Run `chip`'s GPU tracegen on `record`, padded past its events by a shape so the padding rows
/// are covered too, and check it against the host: the trace is `generate_main`'s, and the byte
/// table holds exactly the chip's `extra_record` lookups -- once.
fn check_host_tracegen<C>(chip: &C, mut record: EmulationRecord, code: SyscallCode)
where
    C: ChipBehavior<F, Record = EmulationRecord>,
{
    let events = record.get_precompile_events(code).len();
    assert!(
        chip.is_active_for_extra_record(&PreparedGpuEvents::new(
            &record,
            precompute_event_size::<F>(&record)
        )),
        "{} is not active for a shapeless record with {events} events",
        chip.name()
    );

    let log_rows = (events.next_power_of_two().trailing_zeros() as usize + 1).max(4);
    let mut shape = RiscvPadShape::default();
    shape.inner.insert(chip.name(), log_rows);
    record.shape = Some(shape);

    let prepared = PreparedGpuEvents::new(&record, precompute_event_size::<F>(&record));
    assert!(
        chip.is_active_for_extra_record(&prepared),
        "{} is not active for a record whose shape lists it",
        chip.name()
    );

    let mut extra = EmulationRecord::default();
    chip.extra_record(&record, &mut extra);
    assert!(
        !extra.byte_lookups.is_empty(),
        "{}: no byte lookups to check",
        chip.name()
    );

    let stream = init_test_stream();
    let mut memory = device_byte_table(stream);
    let trace = chip.gpu_generate_extra_record_and_main(0, &record, &prepared, &mut memory);
    let TraceData::Cpu(trace) = trace else {
        panic!("{}: expected a host trace", chip.name());
    };
    let expected = chip.generate_main(&record, &mut EmulationRecord::default());
    assert_eq!(trace.values.len(), expected.values.len());
    assert_eq!(
        trace,
        expected,
        "{}: trace differs from generate_main",
        chip.name()
    );
    assert_eq!(trace.values.len() / trace.width, 1 << log_rows);

    assert_eq!(
        finalized(stream, memory),
        reference_table(&extra.byte_lookups),
        "{}: device byte table differs from the extra_record lookups",
        chip.name()
    );
    println!(
        "{}: {events} events, {} rows, {} distinct byte lookups",
        chip.name(),
        1 << log_rows,
        extra.byte_lookups.len()
    );
}

/// The Ed25519 overrides take their lookups from `generate_main`'s output record instead of a
/// second `extra_record` pass; that is only right while the two raise the same lookups.
fn assert_generate_main_raises_the_extra_record_lookups<C>(chip: &C, record: &EmulationRecord)
where
    C: ChipBehavior<F, Record = EmulationRecord>,
{
    let (mut generated, mut extra) = (EmulationRecord::default(), EmulationRecord::default());
    chip.generate_main(record, &mut generated);
    chip.extra_record(record, &mut extra);
    assert_eq!(
        generated.byte_lookups,
        extra.byte_lookups,
        "{}: generate_main and extra_record raise different byte lookups",
        chip.name()
    );
}

#[test]
fn the_poseidon2_precompile_host_tracegen_matches_the_host() {
    let code = SyscallCode::POSEIDON2_PERMUTE;
    check_host_tracegen(
        &FieldSpecificPrecompilePoseidon2Chip::<F>::default(),
        record_with(&poseidon2_records(), code),
        code,
    );
}

#[test]
fn the_ed25519_host_tracegen_matches_the_host() {
    let records = ed25519_records();

    let add = EdAddAssignChip::<F, Ed25519>::default();
    let record = record_with(&records, SyscallCode::ED_ADD);
    assert_generate_main_raises_the_extra_record_lookups(&add, &record);
    check_host_tracegen(&add, record, SyscallCode::ED_ADD);

    let decompress = EdDecompressChip::<F, Ed25519Parameters>::default();
    let record = record_with(&records, SyscallCode::ED_DECOMPRESS);
    assert_generate_main_raises_the_extra_record_lookups(&decompress, &record);
    check_host_tracegen(&decompress, record, SyscallCode::ED_DECOMPRESS);
}
