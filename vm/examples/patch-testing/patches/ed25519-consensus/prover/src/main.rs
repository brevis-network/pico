use common::run_proof;

fn main() {
    // The guest asserts its own result and commits nothing.
    run_proof!([ED_ADD, ED_DECOMPRESS], commits = b"");
}
