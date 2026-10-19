// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Pico verifier interface
/// @notice Verifies a Pico proof that a RISC-V program ran and committed some output. The program
/// is named by its verification key hash, the output by the bytes the guest committed.
interface IPicoVerifier {
    /// @notice Reverts unless `proof` proves that the program `riscvVkey` names committed
    /// `publicValues`.
    /// @param riscvVkey The program's verification key hash in whitelist mode: the program id
    /// `cargo pico prove --evm` prints, and `inputs.json`'s `riscvVKey`.
    /// @param publicValues The bytes the guest committed.
    /// @param proof The Groth16 proof (8 words), its Pedersen commitment (2) and the commitment's
    /// proof of knowledge (2): `inputs.json`'s `proof`.
    function verifyPicoProof(bytes32 riscvVkey, bytes calldata publicValues, uint256[12] calldata proof) external view;
}
