fn main() {
    tonic_build::compile_protos("proto/coordinator.proto").unwrap();
    tonic_build::compile_protos("proto/prover_server.proto").unwrap();
    tonic_build::compile_protos("proto/proving_network.proto").unwrap();
    tonic_build::compile_protos("proto/final_proof.proto").unwrap();
    tonic_build::compile_protos("proto/orchestrator.proto").unwrap();
    tonic_build::compile_protos("proto/proof.proto").unwrap();
    tonic_build::compile_protos("proto/aggregator.proto").unwrap();
    tonic_build::compile_protos("proto/subblock.proto").unwrap();
    tonic_build::compile_protos("proto/proof_transfer.proto").unwrap();
    tonic_build::compile_protos("proto/scheduler.proto").unwrap();
}
