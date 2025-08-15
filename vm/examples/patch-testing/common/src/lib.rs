pub use pico_sdk;
use std::fs;

/// Loads an ELF file from the given path.
pub fn load_elf(path: &str) -> Vec<u8> {
    fs::read(path).unwrap_or_else(|err| {
        panic!("Failed to load ELF file from {}: {}", path, err);
    })
}

/// A macro to run the prover.
/// The first argument is the ELF file path produced by the app.
/// Any subsequent arguments are optional inputs.
#[macro_export]
macro_rules! run_proof {
    ( $elf_path:expr $(, $input:expr )* $(,)? ) => {{
        // Initialize logger
        $crate::pico_sdk::init_logger();

        // Load the ELF file
        let elf = $crate::load_elf($elf_path);

        // Initialize the prover client
        let client = $crate::pico_sdk::client::DefaultProverClient::new(&elf);

        // Write any provided inputs to the stdin builder.
        let mut stdin_builder = client.new_stdin_builder();
        $(
            stdin_builder.write(&$input);
        )*

        // Generate proof
        client.prove_fast(stdin_builder).expect("Failed to generate proof");
    }};
}
