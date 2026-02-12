//! Shared library for reth AOT example.
//!
//! Provides helpers for loading the reth ELF binary and block input data.

use anyhow::{Context, Result};
use pico_vm::{
    compiler::riscv::program::Program, configs::config::StarkGenericConfig,
    emulator::stdin::EmulatorStdin,
};
use std::{
    fs,
    path::{Path, PathBuf},
};

/// Default block numbers available for testing
pub const AVAILABLE_BLOCKS: &[u32] = &[
    17106222, 18884864, 20528709, 22059900, 22515566, 22528700, 22745330,
];

/// Default block for testing (smallest input file for faster execution)
pub const DEFAULT_BLOCK: u32 = 18884864;

/// Resolves a path relative to the workspace root.
/// The workspace root is 3 levels up from this crate's manifest directory.
fn workspace_relative_path(relative_path: &str) -> PathBuf {
    // Try relative to current working directory first (for backward compatibility)
    let cwd_path = Path::new(relative_path);
    if cwd_path.exists() {
        return cwd_path.to_path_buf();
    }

    // Otherwise, resolve relative to workspace root
    // This crate is at examples/reth/lib/, so workspace root is 3 levels up
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let workspace_root = Path::new(manifest_dir)
        .parent() // examples/reth/
        .and_then(|p| p.parent()) // examples/
        .and_then(|p| p.parent()) // workspace root
        .unwrap_or_else(|| Path::new("."));

    workspace_root.join(relative_path)
}

/// Returns the path to the reth ELF binary.
pub fn reth_elf_path() -> PathBuf {
    workspace_relative_path("perf/bench_data/reth-elf")
}

/// Returns the path to the block input file for a given block number.
pub fn block_input_path(block_number: u32) -> PathBuf {
    workspace_relative_path(&format!("perf/bench_data/reth-{}.bin", block_number))
}

/// Loads the reth ELF binary from the default location.
pub fn load_reth_elf() -> Result<Vec<u8>> {
    let path = reth_elf_path();
    load_elf(&path)
}

/// Loads an ELF binary from the specified path.
pub fn load_elf(path: &Path) -> Result<Vec<u8>> {
    fs::read(path).with_context(|| format!("Failed to load ELF file from {}", path.display()))
}

/// Loads the block input data for a given block number.
pub fn load_block_input(block_number: u32) -> Result<Vec<u8>> {
    let path = block_input_path(block_number);
    fs::read(&path).with_context(|| format!("Failed to load block input from {}", path.display()))
}

/// Checks if a block input file exists.
pub fn block_input_exists(block_number: u32) -> bool {
    block_input_path(block_number).exists()
}

/// Parses block number from command line args or uses default.
/// Usage: program [block_number]
pub fn parse_block_arg() -> u32 {
    std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_BLOCK)
}

/// Validates that the block number is available and prints helpful message if not.
pub fn validate_block(block_number: u32) -> Result<()> {
    if !block_input_exists(block_number) {
        anyhow::bail!(
            "Block {} input file not found.\nAvailable blocks: {:?}\nExpected path: {}",
            block_number,
            AVAILABLE_BLOCKS,
            block_input_path(block_number).display()
        );
    }
    Ok(())
}

/// Creates an EmulatorStdin from input bytes, following the pattern from perf/src/common/bench_program.rs.
/// This is the correct way to load reth block inputs (raw bytes, not serialized EmulatorStdinBuilder).
#[allow(clippy::type_complexity)]
pub fn create_stdin<SC: StarkGenericConfig>(
    input_bytes: &[u8],
) -> Result<EmulatorStdin<Program, Vec<u8>>> {
    let mut stdin_builder = EmulatorStdin::<Program, Vec<u8>>::new_builder::<SC>();
    stdin_builder.write_slice(input_bytes);
    let (stdin, _deferred_proof) = stdin_builder.finalize();
    Ok(stdin)
}
