//! The pipeline's replay workers writing through a sink that keeps the execution history alone,
//! against the serial interpreter over the same guests.

// Only the guests and their runs: the comparison in there is between two emulation paths.
#[allow(dead_code)]
#[path = "common/record_parity.rs"]
mod record_parity;
#[path = "common/replay_parity.rs"]
mod replay_parity;

#[test]
fn fib() {
    replay_parity::check("fib");
}

#[test]
fn ed25519() {
    replay_parity::check("ed25519");
}

#[test]
fn poseidon2() {
    replay_parity::check("poseidon2");
}

#[test]
fn aggregator() {
    replay_parity::check("aggregator");
}

#[test]
fn bls12381_fp() {
    replay_parity::check("bls12381-fp");
}

#[test]
fn sha2() {
    replay_parity::check("sha2");
}

#[test]
fn sha3() {
    replay_parity::check("sha3");
}

#[test]
fn tiny_keccak() {
    replay_parity::check("tiny-keccak");
}

#[test]
fn k256() {
    replay_parity::check("k256");
}

#[test]
fn bn254_fp() {
    replay_parity::check("bn254-fp");
}

#[test]
fn bls12381_ws() {
    replay_parity::check("bls12381-ws");
}

#[test]
fn bn254_ws() {
    replay_parity::check("bn254-ws");
}
