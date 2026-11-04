//! The positive control for the AOT replay workers: needs no generated code, so
//! `perf/aot/record_parity.sh` runs it once against the committed stub.

#[test]
fn the_stub_code_in_the_replay_workers_interprets_every_chunk_and_matches_the_interpreter() {
    aot_record_parity::check_stub_replay();
}
