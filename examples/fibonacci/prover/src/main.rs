use alloy_sol_types::SolType;
use fibonacci_lib::{fibonacci, load_elf, PublicValuesStruct};
use pico_sdk::{client::SDKProverClient, init_logger};

fn main() {
    // Initialize logger
    init_logger();

    // Load the ELF file
    let elf = load_elf("./elf/riscv32im-pico-zkvm-elf");

    println!("elf length: {}", elf.len());

    // Initialize the prover client
    let client = SDKProverClient::new(&elf, false);
    let stdin_builder = client.get_stdin_builder(); // Shared instance

    // Set up input and generate proof
    let n = 100u32;
    stdin_builder.borrow_mut().write(&n);

    // Generate proof
    let proof = client.prove_fast().expect("Failed to generate proof");

    // Decodes public values from the proof's public value stream.
    let public_buffer = proof.pv_stream.unwrap();
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
