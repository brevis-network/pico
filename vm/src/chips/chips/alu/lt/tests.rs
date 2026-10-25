//! GPU / CPU trace parity for the Lt chip, including the merged branch-comparison rows
//! (`is_cmp = 1`, `a = lt | gt << 16`) that the Cpu chip emits since the two SLT/SLTU branch
//! lookups were folded into one.

use crate::{
    chips::{
        chips::{
            alu::{
                event::AluEvent,
                lt::{
                    columns::{LtValueCols, NUM_LT_COLS, NUM_LT_VALUE_COLS},
                    LtChip,
                },
            },
            byte::{columns::NUM_BYTE_MULT_COLS, ByteChip},
        },
        gadgets::{lt_signed::LtSignedGadget, lt_word_u16::LtWordU16Gadget},
        tests::init_test_stream,
        trace::TraceData,
    },
    compiler::riscv::opcode::Opcode,
    emulator::riscv::{
        alu_event_pool::{init_alu_event_buffer_pool, is_alu_pool_initialized},
        record::EmulationRecord,
    },
    instances::{
        compiler::shapes::riscv_shape::RiscvPadShape,
        preparer::{
            gpu_allocate_and_copy_lt_events, gpu_allocate_byte_trace, gpu_finalize_byte_trace,
            precompute_event_size, verify_lt_events, PreallocatedGpuMemory, PreparedGpuEvents,
        },
    },
    machine::chip::ChipBehavior,
};
use cudart::memory::CudaHostAllocFlags;
use p3_field::PrimeCharacteristicRing;
use p3_koala_bear::KoalaBear;
use p3_matrix::dense::RowMajorMatrix;
use rand::{rng, RngExt};

type F = KoalaBear;

/// One merged branch comparison as the Cpu chip emits it (`populate_branch`).
fn cmp_event(clk: u64, signed: bool, b: u64, c: u64) -> AluEvent {
    let (lt, gt) = if signed {
        ((b as i64) < (c as i64), (b as i64) > (c as i64))
    } else {
        (b < c, b > c)
    };
    AluEvent {
        clk,
        opcode: if signed { Opcode::SLT } else { Opcode::SLTU },
        a: (lt as u64) | ((gt as u64) << 16),
        b,
        c,
        is_cmp: true,
        ..Default::default()
    }
}

/// A plain SLT/SLTU result row as the emulator emits it.
fn slt_event(clk: u64, signed: bool, b: u64, c: u64, is_imm: bool) -> AluEvent {
    let a = if signed {
        ((b as i64) < (c as i64)) as u64
    } else {
        (b < c) as u64
    };
    AluEvent::new(
        clk,
        if signed { Opcode::SLT } else { Opcode::SLTU },
        a,
        b,
        c,
        is_imm,
    )
}

/// Deterministic corner cases first (every (sign, order) class, both row kinds), then a random
/// mix; returns the record and the indices of the merged rows for the column checks.
fn generate_gpu_test_record(event_count: u64) -> (EmulationRecord, Vec<usize>) {
    if !is_alu_pool_initialized() {
        init_alu_event_buffer_pool(50, CudaHostAllocFlags::DEFAULT);
    }
    let neg1 = u64::MAX; // -1 as i64
    let neg2 = u64::MAX - 1; // -2 as i64
    let corner: [(bool, u64, u64); 12] = [
        // unsigned: b < c, b > c, b = c, both zero
        (false, 3, 7),
        (false, 7, 3),
        (false, 5, 5),
        (false, 0, 0),
        // signed: b < 0 < c, c < 0 < b, b = c < 0, b < c < 0, equal at the sign boundary
        (true, neg1, 7),
        (true, 7, neg1),
        (true, neg1, neg1),
        (true, neg2, neg1),
        (true, 1 << 63, 1 << 63),
        // unsigned view of the same negatives: -1 is the largest u64
        (false, neg1, 7),
        (false, 7, neg1),
        (true, i64::MIN as u64, i64::MAX as u64),
    ];

    let mut events = Vec::with_capacity(event_count as usize);
    let mut cmp_rows = Vec::new();
    let mut clk = 0u64;
    for &(signed, b, c) in &corner {
        cmp_rows.push(events.len());
        events.push(cmp_event(clk, signed, b, c));
        events.push(slt_event(clk + 1, signed, b, c, false));
        clk += 2;
    }

    let rng = &mut rng();
    while (events.len() as u64) < event_count {
        let signed = rng.random_bool(0.5);
        // Small magnitudes keep the equal case reachable.
        let (b, c): (u64, u64) = if rng.random_bool(0.3) {
            let x = rng.random_range(0..4u64);
            let y = rng.random_range(0..4u64);
            ((x as i64 - 2) as u64, (y as i64 - 2) as u64)
        } else {
            (rng.random(), rng.random())
        };
        if rng.random_bool(0.4) {
            cmp_rows.push(events.len());
            events.push(cmp_event(clk, signed, b, c));
        } else {
            events.push(slt_event(clk, signed, b, c, rng.random_bool(0.2)));
        }
        clk += 1;
    }

    let mut record = EmulationRecord::default();
    record.lt_events.extend_from_alu_slice(&events).unwrap();
    (record, cmp_rows)
}

fn cpu_generate_main(chip: &LtChip<F>, input: &EmulationRecord) -> RowMajorMatrix<F> {
    chip.generate_main(input, &mut EmulationRecord::default())
}

fn gpu_generate_extra_record_and_main(
    chip: &LtChip<F>,
    input: &EmulationRecord,
    prepared_gpu_events: &PreparedGpuEvents,
    preallocated_gpu_memory: &mut PreallocatedGpuMemory,
) -> RowMajorMatrix<F> {
    let stream = init_test_stream();
    let trace = chip.gpu_generate_extra_record_and_main(
        0,
        input,
        prepared_gpu_events,
        preallocated_gpu_memory,
    );
    trace.to_host(stream)
}

#[test]
fn test_lt_gpu_generate_extra_record_and_main() {
    let (original_record, cmp_rows) = generate_gpu_test_record(1 << 16);
    let n_events = original_record.lt_events.len();

    let chip = LtChip::<F>::default();

    let mut complete_record = original_record.clone();
    chip.extra_record(&original_record, &mut complete_record);
    let counted_record = original_record.clone();
    let event_counter = precompute_event_size::<F>(&counted_record);
    event_counter.assert_event_counts_match(&complete_record);
    assert_eq!(event_counter.num_lt_events, n_events);

    // 2^16 events into 2^17 rows: half the trace is padding, which must stay all-zero (the
    // ungated `a[1]` / `is_cmp` constraints rely on that).
    let log_height = 17;
    complete_record.shape = Some(RiscvPadShape::default());
    complete_record
        .shape
        .as_mut()
        .unwrap()
        .inner
        .insert(chip.name(), log_height);
    let mut counted_record = counted_record;
    counted_record.shape = Some(RiscvPadShape::default());
    counted_record
        .shape
        .as_mut()
        .unwrap()
        .inner
        .insert(chip.name(), log_height);

    let cpu_trace = cpu_generate_main(&chip, &complete_record);
    let byte_chip = ByteChip::<F>::default();
    let cpu_byte_trace = byte_chip.generate_main(&complete_record, &mut EmulationRecord::default());

    let stream = init_test_stream();
    let prepared_gpu_events = PreparedGpuEvents::new(&counted_record, event_counter.clone());
    let mut preallocated_gpu_memory = PreallocatedGpuMemory {
        d_lt_events: gpu_allocate_and_copy_lt_events(
            stream,
            0,
            &counted_record,
            &prepared_gpu_events,
        )
        .unwrap(),
        d_byte_trace: gpu_allocate_byte_trace(stream, 0).unwrap(),
        ..Default::default()
    };

    let gpu_trace = gpu_generate_extra_record_and_main(
        &chip,
        &counted_record,
        &prepared_gpu_events,
        &mut preallocated_gpu_memory,
    );

    // The CUDA `LtValueColsU64` mirrors the Rust layout field by field; a missing `is_cmp` there
    // shifts the last column and fails this equality.
    assert_eq!(NUM_LT_COLS, NUM_LT_VALUE_COLS);
    assert_eq!(cpu_trace.values.len(), (1usize << log_height) * NUM_LT_COLS);
    assert_eq!(cpu_trace, gpu_trace);

    // Merged rows: `is_cmp = 1`, `a[0] = [b < c]`, `a[1] = [b > c]`, at most one set; plain
    // rows: `is_cmp = 0`, `a[1] = 0`. Column indices from the `#[repr(C)]` layout.
    let col_a = std::mem::offset_of!(LtValueCols<u8>, a);
    let col_is_cmp = std::mem::offset_of!(LtValueCols<u8>, is_cmp);
    // The gadget columns the new constraint is written over. `cols.a` is a verbatim limb copy of
    // the event, so checking a[1] against the event alone would be near-tautological: what must
    // hold is `a[1] == is_cmp * (sum(u16_flags) - bit)`, i.e. the trace satisfies the constraint.
    let col_flags = std::mem::offset_of!(LtValueCols<u8>, lt_signed)
        + std::mem::offset_of!(LtSignedGadget<u8>, result)
        + std::mem::offset_of!(LtWordU16Gadget<u8>, u16_flags);
    let col_bit = std::mem::offset_of!(LtValueCols<u8>, lt_signed)
        + std::mem::offset_of!(LtSignedGadget<u8>, result)
        + std::mem::offset_of!(LtWordU16Gadget<u8>, bit);
    assert_eq!(col_is_cmp, NUM_LT_VALUE_COLS - 1);
    let events = complete_record.lt_events.as_slice();
    let mut seen_lt = 0;
    let mut seen_gt = 0;
    let mut seen_eq = 0;
    for (row, ev) in events.iter().enumerate() {
        let cell = |col: usize| cpu_trace.values[row * NUM_LT_COLS + col];
        let a0 = cell(col_a);
        let a1 = cell(col_a + 1);
        assert_eq!(cell(col_is_cmp), F::from_bool(ev.is_cmp), "row {row}");
        assert_eq!(cell(col_a + 2), F::ZERO, "row {row}");
        assert_eq!(cell(col_a + 3), F::ZERO, "row {row}");
        // The new constraint itself, evaluated on the generated row.
        let sum_flags: F = (0..4).map(|i| cell(col_flags + i)).sum();
        let bit = cell(col_bit);
        assert_eq!(
            a1,
            cell(col_is_cmp) * (sum_flags - bit),
            "row {row}: a[1] != is_cmp * (sum_flags - bit)"
        );
        // Every fixture row is real (`is_slt + is_slt_u == 1`), so the gated binding applies.
        assert_eq!(a0, bit, "row {row}: a[0] != gadget bit");
        if ev.is_cmp {
            let signed = ev.opcode == Opcode::SLT;
            let (lt, gt) = if signed {
                ((ev.b as i64) < (ev.c as i64), (ev.b as i64) > (ev.c as i64))
            } else {
                (ev.b < ev.c, ev.b > ev.c)
            };
            assert_eq!(a0, F::from_bool(lt), "row {row}: {ev:?}");
            assert_eq!(a1, F::from_bool(gt), "row {row}: {ev:?}");
            assert_eq!(a0 * a1, F::ZERO, "row {row}");
            assert_eq!(
                F::ONE - a0 - a1,
                F::from_bool(ev.b == ev.c),
                "row {row}: trichotomy"
            );
            seen_lt += lt as usize;
            seen_gt += gt as usize;
            seen_eq += (ev.b == ev.c) as usize;
        } else {
            assert_eq!(a1, F::ZERO, "row {row}");
        }
    }
    assert_eq!(
        cmp_rows.len(),
        events.iter().filter(|e| e.is_cmp).count(),
        "fixture bookkeeping"
    );
    assert!(
        seen_lt > 0 && seen_gt > 0 && seen_eq > 0,
        "fixture must cover all three outcomes"
    );
    // Padding rows are all-zero.
    for v in &cpu_trace.values[n_events * NUM_LT_COLS..] {
        assert_eq!(*v, F::ZERO);
    }

    // The GPU event buffer is a byte copy of the record here (no GPU emitter in this fixture);
    // this checks the flag byte survives the H2D copy and the 48-byte layout agrees.
    assert!(verify_lt_events(
        &preallocated_gpu_memory.d_lt_events,
        event_counter.num_lt_events,
        &complete_record,
        stream,
    ));

    gpu_finalize_byte_trace(stream, &mut preallocated_gpu_memory).unwrap();
    stream.synchronize().unwrap();
    let d_byte_trace = preallocated_gpu_memory.d_byte_trace.take().unwrap();
    let host_gpu_byte_trace = TraceData::<F>::Gpu(NUM_BYTE_MULT_COLS, d_byte_trace).to_host(stream);
    assert_eq!(host_gpu_byte_trace.values, cpu_byte_trace.values);
}
