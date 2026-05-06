//! Equivalence test for `emulate_snapshot_pipeline` across interpreter and AOT
//! snapshot-main modes. Asserts identical `(total_cycles, pv_stream, reports.len())`
//! on the RV64 fibonacci benchmark.

use std::sync::Arc;

use aot::register_with_vm;
use p3_koala_bear::KoalaBear;
use pico_vm::{
    compiler::riscv::{
        compiler::{Compiler, SourceType},
        program::Program,
    },
    emulator::{
        opts::{EmulatorOpts, SnapshotMainMode},
        stdin::EmulatorStdin,
    },
    instances::{
        chiptype::riscv_chiptype::RiscvChipType,
        configs::riscv_kb_config::StarkConfig as RiscvKBSC,
    },
    machine::{report::EmulationReport, witness::ProvingWitness},
    proverchain::emulate_snapshot_pipeline,
};

const INPUT_VALUE: u32 = 10_000_000u32;

type Chips = RiscvChipType<KoalaBear>;

fn make_witness(
    program: Arc<Program>,
    stdin: EmulatorStdin<Program, Vec<u8>>,
    opts: EmulatorOpts,
) -> ProvingWitness<RiscvKBSC, Chips, Vec<u8>> {
    ProvingWitness {
        program: Some(program),
        pk: None,
        vk: None,
        proof: None,
        vk_root: None,
        stdin: Some(stdin),
        flag_empty_stdin: false,
        config: None,
        opts: Some(opts),
        records: vec![],
    }
}

fn run_mode(
    program: Arc<Program>,
    opts: EmulatorOpts,
) -> (u64, Vec<u8>, Vec<EmulationReport>) {
    let mut stdin_builder = EmulatorStdin::<Program, Vec<u8>>::new_builder::<RiscvKBSC>();
    stdin_builder.write(&INPUT_VALUE);
    let (stdin, _) = stdin_builder.finalize::<Program>();

    let witness = make_witness(program, stdin, opts);

    let (pipeline_reports, total_cycles, pv_stream) =
        emulate_snapshot_pipeline(&witness, move |_rec, _done| {})
            .expect("emulate_snapshot_pipeline failed");

    (total_cycles, pv_stream, pipeline_reports)
}

#[test]
fn snapshot_pipeline_interp_vs_aot_equivalent() {
    let elf_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../perf/bench_data/rv64/fib-elf"
    );

    let Ok(elf_bytes) = std::fs::read(elf_path) else {
        println!("skipping: ELF not found at {elf_path}");
        return;
    };

    let program: Arc<Program> = Compiler::new(SourceType::RISCV, &elf_bytes)
        .expect("failed to parse RISC-V ELF")
        .compile();

    register_with_vm();

    let opts_interp = EmulatorOpts::test_opts().with_snapshot_main(SnapshotMainMode::Interpreter);
    let opts_aot = EmulatorOpts::test_opts().with_snapshot_main(SnapshotMainMode::Aot);

    let (cycles_i, pv_i, reports_i) = run_mode(program.clone(), opts_interp);
    let (cycles_a, pv_a, reports_a) = run_mode(program, opts_aot);

    assert_eq!(cycles_i, cycles_a, "total_cycles mismatch");
    assert_eq!(pv_i, pv_a, "pv_stream mismatch");
    assert_eq!(
        reports_i.len(),
        reports_a.len(),
        "reports.len() mismatch: interp={} aot={}",
        reports_i.len(),
        reports_a.len()
    );
    for (i, (ri, ra)) in reports_i.iter().zip(reports_a.iter()).enumerate() {
        assert_eq!(
            ri.start_chunk, ra.start_chunk,
            "reports[{i}].start_chunk mismatch: interp={} aot={}",
            ri.start_chunk, ra.start_chunk
        );
        assert_eq!(
            ri.current_cycle, ra.current_cycle,
            "reports[{i}].current_cycle mismatch: interp={} aot={}",
            ri.current_cycle, ra.current_cycle
        );
        assert_eq!(
            ri.done, ra.done,
            "reports[{i}].done mismatch: interp={} aot={}",
            ri.done, ra.done
        );
    }
}
