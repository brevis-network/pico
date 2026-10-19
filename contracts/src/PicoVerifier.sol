// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IPicoVerifier} from "./IPicoVerifier.sol";

/// @notice The contract gnark exports for a Groth16 setup of the wrap circuit
/// (`Groth16Verifier.sol`, contract `Verifier`), as PicoVerifier calls it. It reverts on a proof
/// that does not verify.
interface IGroth16Verifier {
    function verifyProof(
        uint256[8] calldata proof,
        uint256[2] calldata commitments,
        uint256[2] calldata commitmentPok,
        uint256[2] calldata input
    ) external view;
}

/// @title Pico verifier
/// @notice Checks Pico proofs with the Groth16 verifier of one setup of the wrap circuit. That
/// circuit bakes in the recursion whitelist root, so the proofs it accepts are those made under
/// that whitelist; a new whitelist or wrap circuit needs a new setup, and a PicoVerifier for it.
/// @dev The Groth16 verifier is a separate contract, so this one carries nothing that depends on
/// a setup's keys.
contract PicoVerifier is IPicoVerifier {
    /// @notice The Groth16 verifier this contract checks proofs with.
    IGroth16Verifier public immutable groth16;

    constructor(IGroth16Verifier _groth16) {
        groth16 = _groth16;
    }

    /// @notice The wrap circuit's second public input: the SHA-256 of the committed bytes, with
    /// its top three bits cleared so that it fits one BN254 scalar.
    function hashPublicValues(bytes calldata publicValues) public pure returns (bytes32) {
        return sha256(publicValues) & bytes32(uint256((1 << 253) - 1));
    }

    /// @inheritdoc IPicoVerifier
    function verifyPicoProof(bytes32 riscvVkey, bytes calldata publicValues, uint256[12] calldata proof) external view {
        uint256[8] memory groth16Proof;
        for (uint256 i = 0; i < 8; i++) {
            groth16Proof[i] = proof[i];
        }
        groth16.verifyProof(
            groth16Proof,
            [proof[8], proof[9]],
            [proof[10], proof[11]],
            [uint256(riscvVkey), uint256(hashPublicValues(publicValues))]
        );
    }
}
