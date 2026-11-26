fn main() {
    tonic_build::compile_protos("proto/prover_server.proto").unwrap();
    tonic_build::compile_protos("proto/scheduler.proto").unwrap();
}
