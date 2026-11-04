//! The positive control for the AOT core's own records: needs no generated code, so
//! `perf/aot/record_parity.sh` runs it once against the committed stub.

#[test]
fn the_stub_code_interprets_every_chunk_and_writes_the_interpreters_records() {
    aot_record_parity::check_stub_code();
}
