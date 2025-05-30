//! Logger setup

use std::sync::Once;
use tracing::Level;
use tracing_forest::ForestLayer;
use tracing_subscriber::{
    filter::filter_fn, fmt::format::FmtSpan, layer::SubscriberExt, util::SubscriberInitExt,
    EnvFilter, Layer, Registry,
};

static INIT: Once = Once::new();

/// A simple logger.
///
/// Set the `RUST_LOG` environment variable to be set to `info` or `debug`.
pub fn setup_logger() {
    INIT.call_once(|| {
        let default_filter = "off";
        let env_filter = EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new(default_filter))
            .add_directive("p3_keccak_air=off".parse().unwrap())
            .add_directive("p3_fri=off".parse().unwrap())
            .add_directive("p3_dft=off".parse().unwrap())
            .add_directive("p3_matrix=off".parse().unwrap())
            .add_directive("p3_merkle_tree=off".parse().unwrap())
            .add_directive("p3_field=off".parse().unwrap())
            .add_directive("p3_challenger=off".parse().unwrap());

        // if the RUST_LOGGER environment variable is set, use it to determine which logger to
        // configure (tracing_forest or tracing_subscriber)
        // otherwise, default to 'forest'
        let logger_type = std::env::var("RUST_LOGGER").unwrap_or_else(|_| "flat".to_string());
        match logger_type.as_str() {
            "forest" => {
                Registry::default()
                    .with(env_filter)
                    .with(ForestLayer::default().with_filter(filter_fn(|metadata| {
                        metadata.is_span() || metadata.level() == &Level::INFO
                    })))
                    .init();
            }
            "forest-all" => {
                Registry::default()
                    .with(env_filter)
                    .with(ForestLayer::default())
                    .init();
            }
            "flat" => {
                tracing_subscriber::fmt::Subscriber::builder()
                    .compact()
                    .with_file(false)
                    .with_target(false)
                    .with_thread_names(false)
                    .with_env_filter(env_filter)
                    .with_span_events(FmtSpan::CLOSE)
                    .finish()
                    .init();
            }
            _ => {
                panic!("Invalid logger type: {}", logger_type);
            }
        }
    });
}
