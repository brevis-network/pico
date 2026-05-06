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
// Bootstrap stub - will be replaced by generate_crates
pub use pico_aot_runtime::AotEmulatorCore;
use pico_aot_runtime::NextStep;

pub fn run_aot(emu: &mut AotEmulatorCore) -> Result<(), String> {
    let mut next = if emu.pc == 0 {
        NextStep::Halt
    } else {
        NextStep::Dynamic(emu.pc)
    };

    loop {
        if emu.should_yield() {
            break;
        }
        match next {
            NextStep::Direct(func) => {
                next = func(emu)?;
            }
            NextStep::Dynamic(pc) => {
                emu.pc = pc;
                next = emu.interpret_from_current_pc()?;
            }
            NextStep::Halt => break,
        }
    }

    Ok(())
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
