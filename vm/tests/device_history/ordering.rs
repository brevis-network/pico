//! The ordering edges the CPU chip's history trace rests on, each held by a case of two arms in
//! child processes: its producer delayed with the edge kept, then with the edge dropped. Kept, ten
//! rounds alternating two chunks must each give the host's CPU and program traces with the fill's
//! error word clear; dropped, every round must give a wrong trace or a set error word. The slot
//! fence's case compares the fill read back from the device with the history it was uploaded from
//! instead, the slot handed to the other chunk's history as soon as the upload is enqueued.
//!
//! The chips run on streams of this test's own, the chunk's history uploaded there, with no host
//! wait between the upload and the chips but their wrappers' own, as the orchestrator runs them
//! and without its other chips around them. The chunks are fib runs of several slices, cut finer
//! than production's so that both copy streams and both slice streams carry slices; the history
//! region is poisoned before every fill, so a kernel that reads a copy before it lands reads
//! poison, not an earlier fill of the same chunk.
//!
//! Nothing but the edge under test may order the consumer after the delayed producer. The
//! histories are uploaded from pinned arena slots, as in production: a copy out of pageable memory
//! may hold the host until its stream reaches it, which orders it before every reader the host
//! makes afterwards. And every kernel is loaded before a case is armed, by a round run with no
//! case and by eager module loading in the child: a kernel's first launch may synchronise the
//! whole context, which waits out any spin. The child also opens the most hardware work queues
//! the driver allows, so that a consumer's stream is unlikely to share one with a delayed
//! producer's and wait behind it.

use std::{num::NonZeroUsize, process::Command};

use cudart::stream::{CudaStream, CudaStreamCreateFlags};
use p3_matrix::dense::RowMajorMatrix;
use pico_vm::{
    chips::chips::{
        riscv_cpu::{
            traces::ordering_edge::{self, delay, Edge},
            CpuChip,
        },
        riscv_program::ProgramChip,
    },
    cuda_adaptor::{get_global_mem_pool, get_global_stream_pool},
    emulator::riscv::{
        history::ExecutionHistory,
        history_arena::{HistoryArena, HistoryCapacity, SpillPolicy},
        history_fill::DerivedRows,
        record::EmulationRecord,
    },
    instances::preparer::{
        gpu_allocate_byte_trace, precompute_event_size, DeviceHistory, DeviceProgram,
        PreallocatedGpuMemory, PreparedGpuEvents,
    },
    machine::chip::{ChipBehavior, GpuChipBehavior},
    mle::machine::{
        riscv::{init_mle_gpu_pool, Kb, MLE_GPU_DEVICE},
        trace_oracle,
    },
};

use super::{record_parity, trace_source::history_run};

/// The arm a child process of this binary runs, by name.
const ARM: &str = "PICO_HISTORY_CPU_MEMORY_LT_ARM";

/// The arm this process runs, when it is a child of a test below.
fn arm() -> Option<String> {
    std::env::var(ARM).ok().filter(|arm| !arm.is_empty())
}

/// Runs `test` with `arm` named in a child process of this binary, its environment also
/// holding `vars`; its output is this one's.
fn in_child_with(test: &str, arm: &str, vars: &[(&str, &str)]) {
    let exe = std::env::current_exe().expect("the test binary's path");
    let out = Command::new(exe)
        .args(["--exact", test, "--nocapture", "--test-threads=1"])
        .env(ARM, arm)
        .envs(vars.iter().copied())
        .output()
        .expect("re-run this test binary");
    let stdout = String::from_utf8_lossy(&out.stdout);
    print!("{stdout}");
    eprint!("{}", String::from_utf8_lossy(&out.stderr));
    assert!(out.status.success(), "{test}: the {arm} arm failed");
    // A filter that matches no test exits 0, so a rename would pass every arm unrun.
    assert!(
        stdout.contains("test result: ok. 1 passed"),
        "{test}: the {arm} arm ran no test"
    );
}

/// The CPU slices the cases' fills are cut into.
const SLICE_STEPS: u32 = 1 << 15;
/// fib's loop runs this many times in each of the two chunks: some 6 slices each.
const FIB: [u32; 2] = [30_000, 24_000];
const ROUNDS: usize = 10;

/// The one CPU chunk of fib on `n`, with every step in it.
fn fib_chunk(n: u32) -> EmulationRecord {
    let mut chunks = Vec::new();
    history_run(
        record_parity::FIB_ELF,
        &record_parity::fib_input(n),
        record_parity::WHOLE,
        |record| {
            if record.is_cpu_chunk {
                chunks.push(record);
            }
        },
    );
    assert_eq!(chunks.len(), 1, "fib on {n}: one CPU chunk");
    let chunk = chunks.pop().expect("one");
    let steps = chunk
        .history
        .as_ref()
        .map_or(0, |history| history.steps.len());
    assert!(
        steps > 2 * SLICE_STEPS as usize,
        "fib on {n}: {steps} steps, too few for slices on both streams"
    );
    chunk
}

/// The chunk's CPU and program traces from its history, generated as the module comment says
/// in `edge`'s case. `Err` names the fill's error word.
fn generate(
    edge: Edge,
    record: &EmulationRecord,
    pinned: &ExecutionHistory,
    prepared: &PreparedGpuEvents,
) -> Result<(RowMajorMatrix<Kb>, RowMajorMatrix<Kb>), String> {
    let device_id = MLE_GPU_DEVICE;
    let stream = || CudaStream::create_with_flags(CudaStreamCreateFlags::NON_BLOCKING).unwrap();
    let (owner, copies, bytes) = (stream(), [stream(), stream()], stream());
    let mem_pool = &get_global_mem_pool(device_id).0;
    let main = &get_global_stream_pool(device_id).0;

    // The byte table is ready before any chip, as the orchestrator has it.
    let d_byte_trace = gpu_allocate_byte_trace(&bytes, device_id).expect("the byte table");
    bytes.synchronize().unwrap();

    let view = record
        .history_view()
        .expect("a CPU chunk's record carries its history");
    let program = DeviceProgram::of(device_id, view.program, &owner).expect("the program");
    // The odd slices' copies alone are held back, so each even slice's kernel runs before its
    // neighbour's copy lands and reads the boundary step from its own slice's copy.
    delay(Edge::SliceCopy, &copies[1]);
    for copy in &copies {
        delay(Edge::SliceCopyJoin, copy);
    }
    let fill = DeviceHistory::upload(
        pinned,
        DerivedRows::of(view.history, view.program),
        program,
        mem_pool,
        &owner,
        [&copies[0], &copies[1]],
        SLICE_STEPS,
    )
    .expect("the upload");
    let mut memory = PreallocatedGpuMemory {
        d_history: Some(fill),
        d_byte_trace,
        ..Default::default()
    };

    // Each wrapper waits on the host for its own streams before it returns. The CPU chip's
    // slice streams wait on every slice's copy, so run first it lands every step before the
    // program chip, the one reader of the whole fill and so the one the join orders, reads
    // any. The program chip's stream waits on the completion event, which with the join kept
    // follows every copy and the descriptor, so run first it leaves the CPU chip's edges
    // nothing to race. Hence the program chip first in the join's case alone.
    let (cpu, program) = (CpuChip::<Kb>::default(), ProgramChip::<Kb>::default());
    let (cpu_trace, program_trace) = if edge == Edge::SliceCopyJoin {
        let program_trace =
            program.gpu_generate_extra_record_and_main(device_id, record, prepared, &mut memory);
        let cpu_trace =
            cpu.gpu_generate_extra_record_and_main(device_id, record, prepared, &mut memory);
        (cpu_trace, program_trace)
    } else {
        let cpu_trace =
            cpu.gpu_generate_extra_record_and_main(device_id, record, prepared, &mut memory);
        let program_trace =
            program.gpu_generate_extra_record_and_main(device_id, record, prepared, &mut memory);
        (cpu_trace, program_trace)
    };
    // A dropped edge's late kernels have all run before anything is read back or freed.
    let code = unsafe { cudart_sys::cudaDeviceSynchronize() };
    assert_eq!(
        code,
        cudart_sys::CudaError::Success,
        "synchronising the card"
    );
    let traces = (cpu_trace.to_host(main), program_trace.to_host(main));
    memory
        .d_history
        .take()
        .expect("the fill")
        .finish()
        .map_err(|e| e.to_string())?;
    Ok(traces)
}

fn run_case(edge: Edge, dropped: bool) {
    trace_oracle::poison::arm();
    init_mle_gpu_pool(MLE_GPU_DEVICE);

    let chunks = FIB.map(fib_chunk);
    let arena = HistoryArena::pin(
        NonZeroUsize::new(FIB.len()).expect("two chunks"),
        record_parity::WHOLE,
        HistoryCapacity::CENSUS,
        SpillPolicy::Refuse,
    )
    .expect("an arena");
    let pinned = chunks.each_ref().map(|chunk| {
        arena
            .fill(
                chunk
                    .history
                    .as_ref()
                    .expect("a CPU chunk's record carries its history"),
            )
            .expect("room in a census slot")
    });
    let expected = chunks.each_ref().map(|chunk| {
        (
            CpuChip::<Kb>::default().generate_main(chunk, &mut EmulationRecord::default()),
            ProgramChip::<Kb>::default().generate_main(chunk, &mut EmulationRecord::default()),
        )
    });
    let prepared = chunks
        .each_ref()
        .map(|chunk| PreparedGpuEvents::new(chunk, precompute_event_size::<Kb>(chunk)));

    let verdict = |index: usize| {
        let (want_cpu, want_program) = &expected[index];
        match generate(edge, &chunks[index], &pinned[index], &prepared[index]) {
            Err(error) => Err(error),
            Ok((cpu, _)) if cpu != *want_cpu => Err("the CPU trace differs".to_owned()),
            Ok((_, program)) if program != *want_program => {
                Err("the program trace differs".to_owned())
            }
            Ok(_) => Ok(()),
        }
    };

    for (index, n) in FIB.iter().enumerate() {
        if let Err(why) = verdict(index) {
            panic!("fib on {n}, no case armed: {why}");
        }
    }
    ordering_edge::arm(edge, dropped);

    for round in 0..ROUNDS {
        for (index, n) in FIB.iter().enumerate() {
            let at = format!("{edge:?} round {round}, fib on {n}");
            match (dropped, verdict(index)) {
                (false, Err(why)) => panic!("{at}, the edge kept: {why}"),
                (true, Ok(())) => {
                    panic!("{at}, the edge dropped: the traces came out right, the race unseen")
                }
                (true, Err(why)) => println!("{at}, the edge dropped, caught: {why}"),
                (false, Ok(())) => {}
            }
        }
    }
    println!(
        "{edge:?}, the edge {}: {ROUNDS} rounds as expected",
        if dropped { "dropped" } else { "kept" }
    );
}

/// The slot fence's case: each chunk's history filled into the arena's one slot, its upload
/// enqueued with the copy streams held back, the history dropped at once and the slot filled
/// with the other chunk's, then the fill read back. Kept, the drop waits for the copies, so
/// every round reads back the dropped history's own rows; dropped, the slot is overwritten
/// under the copies and the read-back differs.
fn run_slot_case(edge: Edge, dropped: bool) {
    trace_oracle::poison::arm();
    init_mle_gpu_pool(MLE_GPU_DEVICE);
    let device_id = MLE_GPU_DEVICE;

    let chunks = FIB.map(fib_chunk);
    let history = |index: usize| {
        chunks[index]
            .history_view()
            .expect("a CPU chunk's record carries its history")
    };
    let arena = HistoryArena::pin(
        NonZeroUsize::MIN,
        record_parity::WHOLE,
        HistoryCapacity::CENSUS,
        SpillPolicy::Refuse,
    )
    .expect("an arena");
    let stream = || CudaStream::create_with_flags(CudaStreamCreateFlags::NON_BLOCKING).unwrap();
    let (owner, copies) = (stream(), [stream(), stream()]);
    let mem_pool = &get_global_mem_pool(device_id).0;

    let verdict = |index: usize| -> Result<(), String> {
        let view = history(index);
        let filled = arena.fill(view.history).expect("room in a census slot");
        let program = DeviceProgram::of(device_id, view.program, &owner).expect("the program");
        for copy in &copies {
            delay(Edge::SlotFence, copy);
        }
        let mut fill = DeviceHistory::upload(
            &filled,
            DerivedRows::of(view.history, view.program),
            program,
            mem_pool,
            &owner,
            [&copies[0], &copies[1]],
            SLICE_STEPS,
        )
        .expect("the upload");
        drop(filled);
        let other = arena
            .fill(history(1 - index).history)
            .expect("the slot back, and room in it");
        let decoded = fill.read_back().map_err(|e| e.to_string())?;
        let differ = decoded.differences(view.history, fill.descriptor());
        drop(other);
        fill.finish().map_err(|e| e.to_string())?;
        if differ.is_empty() {
            Ok(())
        } else {
            Err(format!("{differ:?} read back otherwise than uploaded"))
        }
    };

    for (index, n) in FIB.iter().enumerate() {
        if let Err(why) = verdict(index) {
            panic!("fib on {n}, no case armed: {why}");
        }
    }
    ordering_edge::arm(edge, dropped);

    for round in 0..ROUNDS {
        for (index, n) in FIB.iter().enumerate() {
            let at = format!("{edge:?} round {round}, fib on {n}");
            match (dropped, verdict(index)) {
                (false, Err(why)) => panic!("{at}, the edge kept: {why}"),
                (true, Ok(())) => {
                    panic!("{at}, the edge dropped: the fill read back right, the race unseen")
                }
                (true, Err(why)) => println!("{at}, the edge dropped, caught: {why}"),
                (false, Ok(())) => {}
            }
        }
    }
    println!(
        "{edge:?}, the edge {}: {ROUNDS} rounds as expected",
        if dropped { "dropped" } else { "kept" }
    );
}

fn case(test: &str, edge: Edge) {
    let run = if edge == Edge::SlotFence {
        run_slot_case
    } else {
        run_case
    };
    match arm().as_deref() {
        Some("kept") => run(edge, false),
        Some("dropped") => run(edge, true),
        Some(other) => panic!("{test}: no arm {other}"),
        None => {
            for arm in ["kept", "dropped"] {
                in_child_with(
                    &format!("ordering::{test}"),
                    arm,
                    &[
                        ("CUDA_MODULE_LOADING", "EAGER"),
                        ("CUDA_DEVICE_MAX_CONNECTIONS", "32"),
                    ],
                );
            }
        }
    }
}

#[test]
fn slice_copy_before_its_kernel() {
    case("slice_copy_before_its_kernel", Edge::SliceCopy);
}

#[test]
fn zero_fill_before_the_kernels() {
    case("zero_fill_before_the_kernels", Edge::ZeroFill);
}

#[test]
fn kernels_before_the_sink_write() {
    case("kernels_before_the_sink_write", Edge::SinkWrite);
}

#[test]
fn descriptor_before_the_kernels() {
    case("descriptor_before_the_kernels", Edge::Descriptor);
}

#[test]
fn slice_copies_before_the_completion_word() {
    case(
        "slice_copies_before_the_completion_word",
        Edge::SliceCopyJoin,
    );
}

#[test]
fn slot_held_until_its_copies_run() {
    case("slot_held_until_its_copies_run", Edge::SlotFence);
}
