use pico_aot_dispatch::run_aot;
use pico_aot_runtime::register_snapshot_aot_factory;

pub fn register() {
    register_snapshot_aot_factory(run_aot);
}
