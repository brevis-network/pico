//! `register`, the checked way into the VM's AOT slot, and what the pipeline reads from it. The
//! slot is process-wide and is never emptied, so each case runs alone in a child process: this test
//! binary, re-run for that one test.

use std::{
    num::NonZeroUsize,
    process::Command,
    sync::{Arc, Barrier},
    thread,
};

use pico_aot_runtime::{register, AotEmulatorCore, AotError, AotProgram};
use pico_vm::{
    compiler::riscv::program::Program,
    emulator::{
        aot::{
            create_aot_emulator, is_aot_factory_registered, is_aot_replay_factory_registered,
            register_aot_factory, register_aot_replay_factory, AotReplayEmulator,
            AotSnapshotEmulator,
        },
        opts::{EmulatorOpts, ReplayWorkers, SnapshotMainMode},
        riscv::{
            public_values::RecordFinalPvsState, riscv_emulator::EmulationError,
            state::RiscvEmulationState,
        },
        stdin::EmulatorStdin,
    },
    mle::machine::riscv::{emulate_with_pipeline, EmulateError},
    proverchain::riscv::check_pipeline,
};

const CHILD: &str = "PICO_AOT_REGISTRY_CHILD";

/// Runs `case` in a process of its own: the parent re-runs this binary for `test` alone and
/// requires it to pass and to print that `case` returned. A name that matches no test still exits
/// 0, so the printed line is what shows the case ran at all.
fn in_own_process(test: &str, case: impl FnOnce()) {
    let finished = format!("[registry] {test} finished");
    if std::env::var_os(CHILD).is_some() {
        case();
        println!("{finished}");
        return;
    }
    let out = Command::new(std::env::current_exe().expect("test binary"))
        .args(["--exact", test, "--nocapture"])
        .env(CHILD, "1")
        .output()
        .expect("re-run this test binary");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "child `{test}` failed:\n{stdout}\n{stderr}"
    );
    assert!(
        stdout.contains(&finished),
        "child `{test}` ran no case:\n{stdout}\n{stderr}"
    );
}

fn halt(emu: &mut AotEmulatorCore) -> Result<(), String> {
    emu.pc = 0;
    Ok(())
}

fn halt_too(emu: &mut AotEmulatorCore) -> Result<(), String> {
    emu.pc = 0;
    Ok(())
}

fn foreign_factory(
    _program: Arc<Program>,
    _input_stream: Vec<Vec<u8>>,
    _opts: EmulatorOpts,
    _final_pvs_state: Arc<RecordFinalPvsState>,
) -> Box<dyn AotSnapshotEmulator> {
    unreachable!("the test never asks for an emulator")
}

fn foreign_replay_factory(
    _program: Arc<Program>,
    _state: RiscvEmulationState,
    _target_global_clk: u64,
    _final_segment: bool,
) -> Box<dyn AotReplayEmulator> {
    unreachable!("the test never asks for a replay worker")
}

/// A pipeline run on the AOT snapshot thread with `replay_workers`, every field stated, since
/// `EmulatorOpts::default` reads the environment.
fn aot_opts(replay_workers: ReplayWorkers) -> EmulatorOpts {
    EmulatorOpts {
        chunk_size: 1 << 12,
        chunk_batch_size: 1,
        max_cycles: Some(1 << 20),
        cycle_tracker: false,
        cost_estimator: false,
        snapshot_main: SnapshotMainMode::Aot,
        replay_workers,
    }
}

/// A refused registration leaves nothing for the pipeline to build an AOT snapshot thread from:
/// the run is refused before any thread starts.
fn assert_no_aot_snapshot_thread() {
    assert!(
        !is_aot_factory_registered(),
        "a refused registration must leave the snapshot factory unset"
    );
    let opts = aot_opts(ReplayWorkers::Interpreter);
    assert!(create_aot_emulator(
        Arc::new(Program::default()),
        Vec::new(),
        opts,
        Arc::new(RecordFinalPvsState::default()),
    )
    .is_none());
    let refused = emulate_with_pipeline(
        Arc::new(Program::default()),
        &EmulatorStdin::default(),
        opts,
        NonZeroUsize::MIN,
    )
    .map(|_| ());
    assert!(
        matches!(refused, Err(EmulateError::AotUnavailable)),
        "{refused:?}"
    );
}

/// A replay factory installed around `register` holds a slot of unknown program, whether or not
/// the program would install one.
#[test]
fn a_foreign_replay_factory_is_refused_without_installing_a_snapshot_factory() {
    static GENERATED: AotProgram =
        AotProgram::stamped([6; 32], AotProgram::CODEGEN_STAMP, halt).with_recorder(halt_too);
    static PLAIN: AotProgram = AotProgram::stamped([12; 32], AotProgram::CODEGEN_STAMP, halt);

    in_own_process(
        "a_foreign_replay_factory_is_refused_without_installing_a_snapshot_factory",
        || {
            assert!(!is_aot_factory_registered());
            assert!(!is_aot_replay_factory_registered());
            assert!(register_aot_replay_factory(foreign_replay_factory));

            assert_eq!(register(&GENERATED), Err(AotError::ForeignFactory));
            assert_no_aot_snapshot_thread();
            assert_eq!(
                register(&GENERATED),
                Err(AotError::ForeignFactory),
                "a refusal records nothing that a retry could match"
            );
            assert_eq!(register(&PLAIN), Err(AotError::ForeignFactory));
            assert_no_aot_snapshot_thread();
        },
    );
}

/// A replay factory installed from another thread while `register` runs: either `register` takes
/// both slots and the foreign install is refused, or the foreign one lands first and `register` is
/// refused with no snapshot factory of its own left behind. One race per process, so it runs in
/// several; it meets only the interleavings the scheduler gives it.
#[test]
fn a_replay_factory_installed_while_register_runs_leaves_it_whole_or_refused() {
    const TEST: &str = "a_replay_factory_installed_while_register_runs_leaves_it_whole_or_refused";
    static GENERATED: AotProgram =
        AotProgram::stamped([14; 32], AotProgram::CODEGEN_STAMP, halt).with_recorder(halt_too);

    fn race() {
        let start = Barrier::new(2);
        let (registered, foreign) = thread::scope(|s| {
            let registered = s.spawn(|| {
                start.wait();
                register(&GENERATED)
            });
            let foreign = s.spawn(|| {
                start.wait();
                register_aot_replay_factory(foreign_replay_factory)
            });
            (registered.join().unwrap(), foreign.join().unwrap())
        });
        match registered {
            Ok(()) => {
                assert!(!foreign, "the foreign install found both slots filled");
                assert!(is_aot_replay_factory_registered());
                assert!(create_aot_emulator(
                    Arc::new(Program::new(Vec::new(), 0x1000, 0x1000)),
                    Vec::new(),
                    aot_opts(ReplayWorkers::Aot),
                    Arc::new(RecordFinalPvsState::default()),
                )
                .is_some());
                assert_eq!(register(&GENERATED), Ok(()));
            }
            Err(AotError::ForeignFactory) => {
                assert!(foreign, "a refusal names a factory that holds a slot");
                assert_no_aot_snapshot_thread();
                assert_eq!(register(&GENERATED), Err(AotError::ForeignFactory));
            }
            Err(other) => panic!("register: {other}"),
        }
    }

    let rounds = if std::env::var_os(CHILD).is_some() {
        1
    } else {
        16
    };
    for _ in 0..rounds {
        in_own_process(TEST, race);
    }
}

/// The bootstrap stub is refused, and the refusal installs nothing: a real program registers after
/// it.
#[test]
fn the_stub_is_refused_and_installs_nothing() {
    static GENERATED: AotProgram = AotProgram::stamped([3; 32], AotProgram::CODEGEN_STAMP, halt);

    in_own_process("the_stub_is_refused_and_installs_nothing", || {
        assert!(AotProgram::STUB.is_stub());
        assert!(!GENERATED.is_stub());

        assert_eq!(register(&AotProgram::STUB), Err(AotError::Stub));
        assert!(!is_aot_factory_registered());

        assert_eq!(register(&GENERATED), Ok(()));
    });
}

/// Code generated against another runtime contract is refused, by a message naming both stamps, and
/// the refusal installs nothing. A crate generated before the stamp existed builds its program with
/// `AotProgram::new`, which carries none.
#[test]
fn code_generated_against_another_codegen_stamp_is_refused() {
    const EXPECTED: u32 = AotProgram::CODEGEN_STAMP;
    #[allow(deprecated)]
    static UNSTAMPED: AotProgram = AotProgram::new([5; 32], halt);
    static OTHER: AotProgram = AotProgram::stamped([5; 32], EXPECTED + 1, halt);
    static CURRENT: AotProgram = AotProgram::stamped([5; 32], EXPECTED, halt);

    in_own_process(
        "code_generated_against_another_codegen_stamp_is_refused",
        || {
            let unstamped = register(&UNSTAMPED).expect_err("an unstamped program is refused");
            assert_eq!(
                unstamped,
                AotError::CodegenStamp {
                    found: 0,
                    expected: EXPECTED
                }
            );
            assert!(
                unstamped.to_string().contains("no codegen stamp")
                    && unstamped.to_string().contains(&format!("stamp {EXPECTED}")),
                "{unstamped}"
            );

            let other = register(&OTHER).expect_err("another stamp is refused");
            assert_eq!(
                other,
                AotError::CodegenStamp {
                    found: EXPECTED + 1,
                    expected: EXPECTED
                }
            );
            assert!(
                other
                    .to_string()
                    .contains(&format!("codegen stamp {}", EXPECTED + 1)),
                "{other}"
            );
            assert!(!is_aot_factory_registered());

            assert_eq!(register(&CURRENT), Ok(()));
        },
    );
}

/// `register` keys a program by its ELF digest: the same digest registers again, and a different
/// one is refused.
#[test]
fn the_same_program_registers_again_and_a_different_one_is_refused() {
    static FIRST: AotProgram = AotProgram::stamped([1; 32], AotProgram::CODEGEN_STAMP, halt);
    // The same ELF behind another static and another entry point: the digest decides, not the
    // pointer.
    static FIRST_AGAIN: AotProgram =
        AotProgram::stamped([1; 32], AotProgram::CODEGEN_STAMP, halt_too);
    static SECOND: AotProgram = AotProgram::stamped([2; 32], AotProgram::CODEGEN_STAMP, halt);

    in_own_process(
        "the_same_program_registers_again_and_a_different_one_is_refused",
        || {
            assert_eq!(register(&FIRST), Ok(()));
            assert!(is_aot_factory_registered());

            assert_eq!(register(&FIRST), Ok(()));
            assert_eq!(register(&FIRST_AGAIN), Ok(()));

            assert_eq!(
                register(&SECOND),
                Err(AotError::Conflict {
                    registered: [1; 32],
                    requested: [2; 32],
                })
            );
            assert_eq!(
                register(&FIRST),
                Ok(()),
                "a refusal leaves the first program in place"
            );
            assert!(
                !register_aot_factory(foreign_factory),
                "a direct install finds the slot `register` filled"
            );
        },
    );
}

/// A factory installed through the VM directly, around `register`, makes `register` refuse: the
/// process's AOT slot then holds a program of unknown ELF.
#[test]
fn a_factory_installed_around_register_is_refused() {
    static GENERATED: AotProgram = AotProgram::stamped([4; 32], AotProgram::CODEGEN_STAMP, halt);

    in_own_process("a_factory_installed_around_register_is_refused", || {
        assert!(
            register_aot_factory(foreign_factory),
            "the first install wins"
        );

        assert_eq!(register(&GENERATED), Err(AotError::ForeignFactory));
        assert_eq!(
            register(&GENERATED),
            Err(AotError::ForeignFactory),
            "a refusal records nothing that a retry could match"
        );
    });
}

/// No replay worker runs a program's ordinary entry point in place of a missing recording one.
#[test]
fn a_program_without_a_recording_entry_point_installs_no_replay_workers() {
    static PLAIN: AotProgram = AotProgram::stamped([7; 32], AotProgram::CODEGEN_STAMP, halt);

    in_own_process(
        "a_program_without_a_recording_entry_point_installs_no_replay_workers",
        || {
            assert!(PLAIN.record_entry().is_none());
            assert_eq!(register(&PLAIN), Ok(()));
            assert!(is_aot_factory_registered());
            assert!(!is_aot_replay_factory_registered());
        },
    );
}

/// AOT replay workers are refused for want of a program before `register`, and for want of a
/// recording entry point after it, each refusal naming its own reason.
#[test]
fn aot_workers_for_a_program_without_a_recording_entry_point_are_refused_for_that() {
    static PLAIN: AotProgram = AotProgram::stamped([13; 32], AotProgram::CODEGEN_STAMP, halt);

    in_own_process(
        "aot_workers_for_a_program_without_a_recording_entry_point_are_refused_for_that",
        || {
            let opts = aot_opts(ReplayWorkers::Aot);
            let checked = check_pipeline(NonZeroUsize::MIN, &opts);
            let Err(EmulationError::UnsupportedReplayWorkers(unregistered)) = &checked else {
                panic!("AOT workers with no program registered: {checked:?}");
            };
            assert!(
                unregistered.contains("no AOT program is registered"),
                "{unregistered}"
            );

            assert_eq!(register(&PLAIN), Ok(()));
            // Refused before any thread starts, so the program never runs.
            let refused = emulate_with_pipeline(
                Arc::new(Program::default()),
                &EmulatorStdin::default(),
                opts,
                NonZeroUsize::MIN,
            )
            .map(|_| ());
            let Err(EmulateError::Emulation(EmulationError::UnsupportedReplayWorkers(reason))) =
                &refused
            else {
                panic!("AOT workers for a program without a recording entry point: {refused:?}");
            };
            assert!(
                reason.contains("no recording entry point") && reason.contains("regenerate"),
                "{reason}"
            );
            assert!(!reason.contains("no AOT program is registered"), "{reason}");
        },
    );
}

#[test]
fn a_program_with_a_recording_entry_point_installs_its_workers() {
    static RECORDING: AotProgram =
        AotProgram::stamped([8; 32], AotProgram::CODEGEN_STAMP, halt).with_recorder(halt_too);

    in_own_process(
        "a_program_with_a_recording_entry_point_installs_its_workers",
        || {
            assert_eq!(register(&RECORDING), Ok(()));
            assert!(is_aot_factory_registered());
            assert!(is_aot_replay_factory_registered());
        },
    );
}

/// The first registration alone decides whether AOT replay workers exist, so the same ELF with
/// and without a recording entry point are two programs, in either order.
#[test]
fn the_same_elf_with_a_recording_entry_point_after_one_without_is_refused() {
    static PLAIN: AotProgram = AotProgram::stamped([10; 32], AotProgram::CODEGEN_STAMP, halt);
    static RECORDING: AotProgram =
        AotProgram::stamped([10; 32], AotProgram::CODEGEN_STAMP, halt).with_recorder(halt_too);

    in_own_process(
        "the_same_elf_with_a_recording_entry_point_after_one_without_is_refused",
        || {
            assert_eq!(register(&PLAIN), Ok(()));
            let refused = register(&RECORDING).expect_err("the recording program is refused");
            assert_eq!(
                refused,
                AotError::Conflict {
                    registered: [10; 32],
                    requested: [10; 32],
                }
            );
            assert!(
                refused.to_string().contains("recording entry point"),
                "{refused}"
            );
            assert!(!is_aot_replay_factory_registered());
            assert_eq!(register(&PLAIN), Ok(()));
        },
    );
}

#[test]
fn the_same_elf_without_a_recording_entry_point_after_one_with_is_refused() {
    static RECORDING: AotProgram =
        AotProgram::stamped([11; 32], AotProgram::CODEGEN_STAMP, halt).with_recorder(halt_too);
    static PLAIN: AotProgram = AotProgram::stamped([11; 32], AotProgram::CODEGEN_STAMP, halt);

    in_own_process(
        "the_same_elf_without_a_recording_entry_point_after_one_with_is_refused",
        || {
            assert_eq!(register(&RECORDING), Ok(()));
            assert_eq!(
                register(&PLAIN),
                Err(AotError::Conflict {
                    registered: [11; 32],
                    requested: [11; 32],
                })
            );
            assert!(is_aot_replay_factory_registered());
            assert_eq!(register(&RECORDING), Ok(()));
        },
    );
}
