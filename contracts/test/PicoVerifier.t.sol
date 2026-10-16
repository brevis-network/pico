// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IGroth16Verifier, PicoVerifier} from "../src/PicoVerifier.sol";
import {Verifier} from "./dev/Groth16Verifier.sol";

/// The cheatcodes the fixtures are read with, declared here rather than taken from forge-std so the
/// project has nothing to install.
interface Vm {
    function readFile(string calldata path) external view returns (string memory);
    function parseJsonBytes32(string calldata json, string calldata key) external pure returns (bytes32);
    function parseJsonBytes(string calldata json, string calldata key) external pure returns (bytes memory);
    function parseJsonBytes32Array(string calldata json, string calldata key) external pure returns (bytes32[] memory);
}

/// PicoVerifier over the dev Groth16 verifier in `test/dev`, against proofs `cargo pico prove --evm`
/// made with the same keys (`test/fixtures`, its `inputs.json` as written). Three programs, one
/// verifier: the wrap circuit is the same for every program, and only its public inputs differ.
contract PicoVerifierTest {
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    /// The Groth16 verification cost is fixed by the circuit's two public inputs and one
    /// commitment, not by the program: a bound catches a verifier or wrapper that grew.
    uint256 internal constant MAX_VERIFY_GAS = 350_000;

    PicoVerifier internal pico;

    struct Fixture {
        bytes32 riscvVkey;
        bytes publicValues;
        bytes32 committedValuesDigest;
        uint256[12] proof;
    }

    function setUp() public {
        pico = new PicoVerifier(IGroth16Verifier(address(new Verifier())));
    }

    function fixture(string memory name) internal view returns (Fixture memory f) {
        string memory json = vm.readFile(string.concat("test/fixtures/", name, ".json"));
        f.riscvVkey = vm.parseJsonBytes32(json, ".riscvVKey");
        f.publicValues = vm.parseJsonBytes(json, ".publicValues");
        f.committedValuesDigest = vm.parseJsonBytes32(json, ".committedValuesDigest");
        bytes32[] memory words = vm.parseJsonBytes32Array(json, ".proof");
        require(words.length == 12, "a proof is twelve words");
        for (uint256 i = 0; i < 12; i++) {
            f.proof[i] = uint256(words[i]);
        }
    }

    function verifies(string memory name) internal view {
        Fixture memory f = fixture(name);
        require(
            pico.hashPublicValues(f.publicValues) == f.committedValuesDigest,
            "the contract's digest of the public values is not the circuit's"
        );
        uint256 before = gasleft();
        pico.verifyPicoProof(f.riscvVkey, f.publicValues, f.proof);
        require(before - gasleft() < MAX_VERIFY_GAS, "verifying costs more than it should");
    }

    function test_fib_verifies() public view {
        verifies("fib");
        // The public values are the guest's output: fib commits (n, F(n), F(n+1)) as three words.
        (uint256 n, uint256 a, uint256 b) = abi.decode(fixture("fib").publicValues, (uint256, uint256, uint256));
        require(n == 10 && a == 55 && b == 89, "not fib(10)'s output");
    }

    function test_poseidon2_verifies() public view {
        verifies("poseidon2");
    }

    function test_ed25519_verifies() public view {
        verifies("ed25519");
    }

    function test_changed_public_values_are_refused() public view {
        Fixture memory f = fixture("fib");
        f.publicValues[f.publicValues.length - 1] ^= 0x01;
        expectProofInvalid(f);
    }

    function test_changed_vkey_is_refused() public view {
        Fixture memory f = fixture("fib");
        f.riscvVkey ^= bytes32(uint256(1));
        expectProofInvalid(f);
    }

    /// One program's proof does not verify as another's.
    function test_another_programs_vkey_is_refused() public view {
        Fixture memory f = fixture("fib");
        f.riscvVkey = fixture("poseidon2").riscvVkey;
        expectProofInvalid(f);
    }

    function test_changed_proof_is_refused() public view {
        Fixture memory f = fixture("fib");
        f.proof[0] ^= 1;
        expectRevert(f);
    }

    function test_changed_commitment_is_refused() public view {
        Fixture memory f = fixture("fib");
        f.proof[8] ^= 1;
        expectRevert(f);
    }

    function expectProofInvalid(Fixture memory f) internal view {
        try pico.verifyPicoProof(f.riscvVkey, f.publicValues, f.proof) {
            revert("a changed proof verified");
        } catch (bytes memory reason) {
            require(
                keccak256(reason) == keccak256(abi.encodeWithSelector(Verifier.ProofInvalid.selector)),
                "reverted, but not with ProofInvalid()"
            );
        }
    }

    function expectRevert(Fixture memory f) internal view {
        try pico.verifyPicoProof(f.riscvVkey, f.publicValues, f.proof) {
            revert("a changed proof verified");
        } catch {}
    }
}
