//! Built against one guest's generated crates; `perf/aot/record_parity.sh` builds and runs it.

#[test]
fn the_aot_snapshot_thread_gives_the_interpreters_records() {
    aot_record_parity::check_generated_guest();
}
