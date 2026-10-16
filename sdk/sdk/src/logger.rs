use std::sync::Once;

use tracing::Level;
use tracing_forest::{
    printer::{MakeStderr, PrettyPrinter},
    ForestLayer,
};
use tracing_subscriber::{
    filter::filter_fn, fmt::format::FmtSpan, layer::SubscriberExt, util::SubscriberInitExt,
    EnvFilter, Layer, Registry,
};

/// Instrumented at debug level on the proving path, so a blanket `RUST_LOG=debug` would otherwise
/// flood the output and slow the run. `pico_vm::machine::logger::setup_logger` silences the same.
pub const SILENCED: [&str; 7] = [
    "p3_keccak_air",
    "p3_fri",
    "p3_dft",
    "p3_matrix",
    "p3_merkle_tree",
    "p3_field",
    "p3_challenger",
];

static INIT: Once = Once::new();

/// Log to stderr, filtered by `RUST_LOG` and off without it, so stdout holds only what the program
/// prints. `RUST_LOGGER=forest` prints the spans as a tree with their INFO events, `forest-all`
/// with every event, and `flat`, the default, one line per event and per closed span.
///
/// Only the first call does anything, and a subscriber the program installed first is kept.
pub fn init_logger() {
    INIT.call_once(|| {
        let mut filter =
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("off"));
        for target in SILENCED {
            filter = filter.add_directive(format!("{target}=off").parse().expect("a directive"));
        }
        let forest = || ForestLayer::from(PrettyPrinter::new().writer(MakeStderr));
        let flat = |filter: EnvFilter| {
            tracing_subscriber::fmt()
                .compact()
                .with_ansi(false)
                .with_target(false)
                .with_span_events(FmtSpan::CLOSE)
                .with_env_filter(filter)
                .with_writer(std::io::stderr)
                .finish()
                .try_init()
        };
        // The one failure is a subscriber already installed, which the program chose over this.
        let _ = match std::env::var("RUST_LOGGER").as_deref() {
            Ok("forest") => Registry::default()
                .with(filter)
                .with(forest().with_filter(filter_fn(|metadata| {
                    metadata.is_span() || *metadata.level() == Level::INFO
                })))
                .try_init(),
            Ok("forest-all") => Registry::default().with(filter).with(forest()).try_init(),
            Ok("flat") | Err(_) => flat(filter),
            Ok(other) => {
                eprintln!(
                    "warning: RUST_LOGGER={other} is none of `flat`, `forest` and `forest-all`; \
                     logging flat"
                );
                flat(filter)
            }
        };
    });
}
