//! `estimate_cost`: per-AIR rows from an emulation, split into the three components.

use pico_vm::mle::machine::riscv::air_name;

use super::fixture::{small_builder, N, POSEIDON2_ELF, SMALL_CHUNK, SMALL_LOG_STACKED_HEIGHT};
use crate::{CostComponent, Prover, Stdin};

#[test]
fn fib_costs_the_instruction_set_and_the_system_tables() {
    let builder = small_builder().chunk_size(SMALL_CHUNK);
    let cost = builder.estimate_cost(Stdin::from(&N)).expect("estimate");
    let execution = builder.execute_chunked(Stdin::from(&N)).expect("execute");
    assert_eq!(cost.cycles, execution.cycles);
    assert!(cost.records > 1, "{} record(s)", cost.records);

    let rows = |name: &str| cost.chips.iter().find(|c| c.name == name).map(|c| c.rows);
    // The byte table is full in every record, the program table one row per instruction in each.
    assert_eq!(rows("Byte"), Some(cost.records as u64 * (1 << 17)));
    assert!(rows("Cpu").is_some_and(|n| n > 0));

    assert!(cost.cells(CostComponent::Rv64) > 0);
    assert!(cost.cells(CostComponent::System) > 0);
    assert_eq!(
        cost.total_cells(),
        [
            CostComponent::Rv64,
            CostComponent::Precompile,
            CostComponent::System
        ]
        .map(|c| cost.cells(c))
        .iter()
        .sum::<u64>()
    );
    for chip in &cost.chips {
        assert!(chip.width > 0, "{}: zero width", chip.name);
        assert_ne!(
            chip.component,
            CostComponent::Precompile,
            "fib calls no precompile, yet {} has {} rows",
            chip.name,
            chip.rows
        );
    }
}

#[test]
fn every_air_has_its_component() {
    use CostComponent::{Precompile, Rv64, System};
    let expected = [
        ("Add", Rv64),
        ("Sub", Rv64),
        ("Mul", Rv64),
        ("Bitwise", Rv64),
        ("LessThan", Rv64),
        ("ShiftLeft", Rv64),
        ("ShiftRight", Rv64),
        ("DivRem", Rv64),
        ("Addw", Rv64),
        ("Subw", Rv64),
        ("Cpu", Rv64),
        ("MemoryLocal", System),
        ("MemoryReadWrite", Rv64),
        ("SyscallRiscv", Precompile),
        ("Byte", System),
        ("Program", System),
        ("MemoryInitialize", System),
        ("MemoryFinalize", System),
        ("Global", System),
        ("KeccakPermute", Precompile),
        ("ShaExtend", Precompile),
        ("ShaExtendControl", Precompile),
        ("ShaCompress", Precompile),
        ("ShaCompressControl", Precompile),
        ("Uint256MulMod", Precompile),
        ("Secp256k1AddAssign", Precompile),
        ("Secp256k1DoubleAssign", Precompile),
        ("Secp256k1Decompress", Precompile),
        ("Secp256r1AddAssign", Precompile),
        ("Secp256r1DoubleAssign", Precompile),
        ("Secp256r1Decompress", Precompile),
        ("Bn254AddAssign", Precompile),
        ("Bn254DoubleAssign", Precompile),
        ("Bls12381AddAssign", Precompile),
        ("Bls12381DoubleAssign", Precompile),
        ("Bls12381Decompress", Precompile),
        ("Bn254FpOp", Precompile),
        ("Bn254Fp2AddSub", Precompile),
        ("Bn254Fp2Mul", Precompile),
        ("Bls381FpOp", Precompile),
        ("Bls381Fp2AddSub", Precompile),
        ("Bls381Fp2Mul", Precompile),
        ("Secp256k1FpOp", Precompile),
        ("SyscallPrecompile", Precompile),
        ("Ecall", Rv64),
        ("KeccakControl", Precompile),
        ("Poseidon2Permute", Precompile),
        ("EdAddAssign", Precompile),
        ("EdDecompress", Precompile),
        ("MemoryUnaligned", Rv64),
        ("KeccakTables", Precompile),
        ("Bls12381G2AddAssign", Precompile),
        ("Bls12381G2DoubleAssign", Precompile),
        ("Blake2bControl", Precompile),
        ("Blake2bRound", Precompile),
    ];
    let actual: Vec<_> = (0..)
        .map_while(|id| Some((air_name(id)?, CostComponent::of_air(id))))
        .collect();
    assert_eq!(actual, expected);
}

#[test]
fn a_precompile_guest_costs_its_precompile() {
    let cost = Prover::builder(POSEIDON2_ELF)
        .log_stacked_height(SMALL_LOG_STACKED_HEIGHT)
        .estimate_cost(Stdin::from(&1u32))
        .expect("estimate");
    let permute = cost
        .chips
        .iter()
        .find(|c| c.name == "Poseidon2Permute")
        .expect("the Poseidon2 precompile is filled");
    assert_eq!(permute.component, CostComponent::Precompile);
    assert!(permute.rows > 0);
    assert!(cost.cells(CostComponent::Precompile) >= permute.cells());
}
