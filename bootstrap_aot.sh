#!/bin/bash
set -e

AOT_GEN_DIR="aot-generated"
LIB_RS="$AOT_GEN_DIR/src/lib.rs"
STUB_SENTINEL="$AOT_GEN_DIR/.aot-bootstrap-stub"

runtime_dep_line() {
  if [ -n "${PICO_AOT_RUNTIME_SPEC:-}" ]; then
    printf 'pico-aot-runtime = { %s }\n' "$PICO_AOT_RUNTIME_SPEC"
  else
    printf 'pico-aot-runtime = { path = "../aot-runtime" }\n'
  fi
}

write_bootstrap_stub() {
  mkdir -p "$AOT_GEN_DIR/src"

  cat >"$AOT_GEN_DIR/Cargo.toml" <<CARGO_TOML
[package]
name = "pico-aot-dispatch"
version = "0.1.0"
edition = "2021"

[dependencies]
$(runtime_dep_line)

[features]
bigint-rug = ["pico-aot-runtime/bigint-rug"]
mmap-memory = ["pico-aot-runtime/mmap-memory"]

[lib]
path = "src/lib.rs"
CARGO_TOML

  cat >"$LIB_RS" <<'LIB_RS'
//! Bootstrap stub for `pico-aot-dispatch`, replaced wholesale when the AOT code is generated from
//! a guest's ELF (`cargo pico aot`, or `generate_crates <elf> aot-generated`).
//!
//! It exports what a generated crate exports, so dependents build before any code is generated.
//! Its [`AOT`] is [`AotProgram::STUB`], which has no compiled code and which
//! `pico_aot_runtime::register` refuses.

pub use pico_aot_runtime::AotEmulatorCore;
use pico_aot_runtime::AotProgram;

pub static AOT: AotProgram = AotProgram::STUB;

/// Interprets every block: the stub has no compiled code.
pub fn run_aot(emu: &mut AotEmulatorCore) -> Result<(), String> {
    AOT.run(emu)
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_stub_exports_the_stub_program() {
        assert!(super::AOT.is_stub());
    }
}
LIB_RS

  # Sentinel marks this as a stub that bootstrap owns, safe to overwrite.
  # `generate_crates` wipes the whole directory, so the sentinel disappears
  # automatically when real code lands.
  : >"$STUB_SENTINEL"
}

if [ -f "$AOT_GEN_DIR/Cargo.toml" ]; then
  if [ -f "$STUB_SENTINEL" ]; then
    echo "Updating AOT bootstrap stub at $AOT_GEN_DIR"
    write_bootstrap_stub
    echo "✓ Bootstrap stub refreshed at $AOT_GEN_DIR"
  else
    echo "✓ AOT dispatch crate already exists at $AOT_GEN_DIR (generated output, skipping)"
  fi
  exit 0
fi

echo "Creating AOT bootstrap stub..."
write_bootstrap_stub

echo "✓ Bootstrap stub created at $AOT_GEN_DIR"
echo ""
echo "To generate AOT code from an ELF binary:"
echo "  cargo run -r -p pico-aot-codegen --bin generate_crates -- <elf_path> $AOT_GEN_DIR"
