//! `register`, the checked way into the VM's AOT slot. The slot is process-wide and is never
//! emptied, so each case runs alone in a child process: this test binary, re-run for that one test.

use std::{process::Command, sync::Arc};

use pico_aot_runtime::{register, AotEmulatorCore, AotError, AotProgram};
use pico_vm::{
    compiler::riscv::program::Program,
    emulator::{
        aot::{
            is_aot_factory_registered, is_aot_replay_factory_registered, register_aot_factory,
            register_aot_replay_factory, AotReplayEmulator, AotSnapshotEmulator,
        },
        opts::EmulatorOpts,
        riscv::{public_values::RecordFinalPvsState, state::RiscvEmulationState},
    },
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

#[test]
fn a_foreign_replay_factory_is_refused_without_installing_a_snapshot_factory() {
    static GENERATED: AotProgram = AotProgram::stamped([6; 32], AotProgram::CODEGEN_STAMP, halt);

    in_own_process(
        "a_foreign_replay_factory_is_refused_without_installing_a_snapshot_factory",
        || {
            assert!(!is_aot_factory_registered());
            assert!(!is_aot_replay_factory_registered());
            assert!(register_aot_replay_factory(foreign_replay_factory));

            assert_eq!(register(&GENERATED), Err(AotError::ForeignFactory));
            assert!(
                !is_aot_factory_registered(),
                "a refused registration must leave the snapshot factory unset"
            );
            assert_eq!(register(&GENERATED), Err(AotError::ForeignFactory));
        },
    );
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
