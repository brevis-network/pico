use alloy_sol_types::SolType;
use fibonacci_lib::{fibonacci, load_elf, PublicValuesStruct};
use pico_sdk::{client::DefaultProverClient, init_logger};
use std::path::PathBuf;

fn main() {
    // Initialize logger
    init_logger();

    let fast = std::env::args().any(|arg| arg == "--fast");

    // Load the ELF file
    let elf_path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../app/elf/riscv32im-pico-zkvm-elf");
    let elf = load_elf(elf_path.to_str().expect("ELF path is not valid UTF-8"));

    println!("elf length: {}", elf.len());

    // Initialize the prover client
    let client = DefaultProverClient::new(&elf);

    // Set up input and generate proof
    let n = 100u32;
    let mut stdin_builder = client.new_stdin_builder();
    stdin_builder.write(&n);

    if fast {
        // RISCV-only proving path.
        let riscv_proof = client
            .prove_fast(stdin_builder)
            .expect("Failed to generate fast proof");

        let public_buffer = riscv_proof.pv_stream.clone().unwrap();
        let public_values = PublicValuesStruct::abi_decode(&public_buffer, true).unwrap();

        // Verify the public values
        verify_public_values(n, &public_values);
        return;
    }

    // Generate proof
    let (riscv_proof, embed_proof) = client
        .prove(stdin_builder)
        .expect("Failed to generate proof");

    // Optional: cryptographically verify both phases.
    client
        .verify(&(riscv_proof.clone(), embed_proof.clone()))
        .expect("Failed to verify proof");

    // Write constraints + witness + proof/vk artifacts used by the Gnark onchain wrapper.
    let out_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("./pico_out");
    std::fs::create_dir_all(&out_dir).expect("Failed to create output directory");
    client
        .write_onchain_data(&out_dir, &riscv_proof, &embed_proof)
        .expect("Failed to write onchain data");

    // Decodes public values from the proof's public value stream.
    let public_buffer = riscv_proof.pv_stream.clone().unwrap();
    let public_values = PublicValuesStruct::abi_decode(&public_buffer, true).unwrap();

    // Verify the public values
    verify_public_values(n, &public_values);
}

/// Verifies that the computed Fibonacci values match the public values.
fn verify_public_values(n: u32, public_values: &PublicValuesStruct) {
    println!(
        "Public value n: {:?}, a: {:?}, b: {:?}",
        public_values.n, public_values.a, public_values.b
    );

    // Compute Fibonacci values locally
    let (result_a, result_b) = fibonacci(0, 1, n);

    // Assert that the computed values match the public values
    assert_eq!(result_a, public_values.a, "Mismatch in value 'a'");
    assert_eq!(result_b, public_values.b, "Mismatch in value 'b'");
}
