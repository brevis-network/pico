//! `register`, the checked way into the VM's AOT slot. The slot is process-wide and is never
//! emptied, so each case runs alone in a child process: this test binary, re-run for that one test.

use std::{process::Command, sync::Arc};

use pico_aot_runtime::{
    register, register_snapshot_aot_factory, AotEmulatorCore, AotError, AotProgram,
};
use pico_vm::{
    compiler::riscv::program::Program,
    emulator::{
        aot::{is_aot_factory_registered, register_aot_factory, AotSnapshotEmulator},
        opts::EmulatorOpts,
        riscv::public_values::RecordFinalPvsState,
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

/// The bootstrap stub is refused, and the refusal installs nothing: a real program registers after
/// it.
#[test]
fn the_stub_is_refused_and_installs_nothing() {
    static GENERATED: AotProgram = AotProgram::new([3; 32], halt);

    in_own_process("the_stub_is_refused_and_installs_nothing", || {
        assert!(AotProgram::STUB.is_stub());
        assert!(!GENERATED.is_stub());

        assert_eq!(register(&AotProgram::STUB), Err(AotError::Stub));
        assert!(!is_aot_factory_registered());

        assert_eq!(register(&GENERATED), Ok(()));
    });
}

/// `register` keys a program by its ELF digest: the same digest registers again, and a different
/// one is refused.
#[test]
fn the_same_program_registers_again_and_a_different_one_is_refused() {
    static FIRST: AotProgram = AotProgram::new([1; 32], halt);
    // The same ELF behind another static and another entry point: the digest decides, not the
    // pointer.
    static FIRST_AGAIN: AotProgram = AotProgram::new([1; 32], halt_too);
    static SECOND: AotProgram = AotProgram::new([2; 32], halt);

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
/// process's AOT slot then holds a program of unknown ELF. `register` learns of it from its own
/// install failing, which is also how it learns of a direct install that races it.
#[test]
fn a_factory_installed_around_register_is_refused() {
    static GENERATED: AotProgram = AotProgram::new([4; 32], halt);

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

/// The unchecked entry point both lines' callers use installs a working factory, after which the
/// checked one refuses: the program behind that factory has no digest to compare.
#[test]
fn a_legacy_registration_installs_the_factory_and_register_then_refuses() {
    static GENERATED: AotProgram = AotProgram::new([6; 32], halt);

    in_own_process(
        "a_legacy_registration_installs_the_factory_and_register_then_refuses",
        || {
            register_snapshot_aot_factory(halt);

            assert!(is_aot_factory_registered());
            assert_eq!(register(&GENERATED), Err(AotError::ForeignFactory));
        },
    );
}
