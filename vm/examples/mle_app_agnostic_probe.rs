//! App-agnosticism probe: the convert VK must depend only on the proof SHAPE, not on the guest
//! program's CONTENT. Concretely, perturbing the RISC-V program-table commitment (pure
//! application identity — the only app value in the protocol vk) at a FIXED layout must leave
//! the convert verifying key byte-identical.
//!
//! This holds because the program commit is witnessed into the convert circuit, never baked as
//! a program constant (see `AirStructure::app_preprocessed`); if it were baked, a different
//! commit would yield a different program and hence a different VK — which is exactly what this
//! probe would catch as a regression.
//!
//! Usage:
//!   cargo run --release -p pico-vm --example mle_app_agnostic_probe -- --elf fib --n 10 --field kb

use std::sync::Arc;

use p3_field::PrimeCharacteristicRing;
use pico_mle_core::config::recursion_params_with_100_bits_security;
use pico_vm::{
    compiler::riscv::compiler::{Compiler, SourceType},
    configs::stark_config::KoalaBearPoseidon2,
    emulator::opts::EmulatorOpts,
    machine::logger::setup_logger,
    mle::machine::{
        convert::ConvertMachine,
        exe::RiscvVmVk,
        riscv::{self, air_id, Kb},
    },
};
use tracing::info;

#[path = "common/parse_args.rs"]
mod parse_args;

fn main() {
    setup_logger();
    let (elf, stdin, args) = parse_args::parse_args::<KoalaBearPoseidon2>();
    assert_eq!(args.field, "kb", "kb-only");

    let compiler = Compiler::new(SourceType::RISCV, elf).expect("failed to parse ELF");
    let program = compiler.compile();
    let records = riscv::emulate_with_opts(program.clone(), &stdin, EmulatorOpts::default())
        .expect("emulation failed")
        .records;
    let bundle = riscv::prove_riscv(
        program.clone(),
        &records,
        riscv::log_stacked_height_from_env(),
        true,
    )
    .expect("riscv prove");
    let (riscv_vk, proofs) = bundle.into_parts();
    info!("riscv proved: {} chunk(s)", proofs.len());
    // The vm-vk only feeds witness generation (never keygen), so the honest one is fine for
    // both machines — this probe compares KEYGEN outputs only.
    let vm_vk = RiscvVmVk::from_program_and_vk(&program, &riscv_vk);

    // Convert VK under the honest RISC-V vk.
    let convert_a = ConvertMachine::new(
        riscv_vk.clone(),
        vm_vk.clone(),
        &proofs,
        recursion_params_with_100_bits_security(),
        true, // whitelist mode: the default production circuit shape
    )
    .expect("convert machine");
    let vk_a = convert_a.pks[0].3.pre_hash;

    // Same shape, DIFFERENT program content: clone the RISC-V vk and perturb ONLY the program
    // table's preprocessed commitment (the application identity). Geometry/DAG/params unchanged.
    let mut perturbed = (*riscv_vk).clone();
    perturbed.inner.per_air[air_id::PROGRAM]
        .preprocessed_data
        .as_mut()
        .expect("program table has preprocessed data")
        .commit[0] += Kb::ONE;
    // pre_hash is recomputed from inner below only for logging; the convert build reads the
    // per-air commit directly.
    let convert_b = ConvertMachine::new(
        Arc::new(perturbed),
        vm_vk,
        &proofs,
        recursion_params_with_100_bits_security(),
        true,
    )
    .expect("convert machine");
    let vk_b = convert_b.pks[0].3.pre_hash;

    info!("convert VK (honest program)   = {:?}", vk_a);
    info!("convert VK (perturbed program) = {:?}", vk_b);
    assert_eq!(
        vk_a, vk_b,
        "APP-AGNOSTICISM VIOLATED: convert VK changed when the program commitment changed at \
         fixed shape — the program is still baked into the convert circuit"
    );
    info!("APP-AGNOSTIC ✓ — convert VK is invariant to the program commitment at fixed shape");
}
