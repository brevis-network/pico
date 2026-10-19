//! The logger `cargo pico` installs, in a test process of its own: a process sets it once.

use tracing::{enabled, Level};

/// The Plonky3 crates are instrumented at debug level on the proving path, so a blanket `debug`
/// that reached them would flood stderr and slow the run.
#[test]
fn a_blanket_debug_leaves_the_instrumented_plonky3_crates_off() {
    std::env::set_var("RUST_LOG", "debug");
    std::env::remove_var("RUST_LOGGER");
    pico_sdk::init_logger();

    assert!(enabled!(target: "pico_vm", Level::DEBUG), "logging is off");
    // `enabled!` takes each target as a constant, so the list is spelled out here and held to the
    // SDK's: a target added there fails the comparison until it is added here.
    macro_rules! assert_off {
        ($($target:literal),+) => {
            assert_eq!([$($target),+], pico_sdk::SILENCED_LOG_TARGETS);
            $(assert!(!enabled!(target: $target, Level::ERROR), $target);)+
        };
    }
    assert_off!(
        "p3_keccak_air",
        "p3_fri",
        "p3_dft",
        "p3_matrix",
        "p3_merkle_tree",
        "p3_field",
        "p3_challenger"
    );
}
