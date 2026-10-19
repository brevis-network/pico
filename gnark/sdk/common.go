package sdk

import (
	"fmt"
	"github.com/brevis-network/pico/gnark/utils"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	bn254cs "github.com/consensys/gnark/constraint/bn254"
	"golang.org/x/crypto/sha3"
	"os"
)

// The keys and circuit KoalaBearSetup makes. KoalaBearProve reads its own into fresh objects.
var (
	Pk  = groth16.NewProvingKey(ecc.BN254)
	Vk  = groth16.NewVerifyingKey(ecc.BN254)
	Ccs = new(bn254cs.R1CS)
)

type PicoGroth16Proof struct {
	VkeyHash              string
	CommittedValuesDigest string
	Proof                 string // hex
}

func ExportSolidify() error {
	// Decode into a FRESH key, never the package-level Vk. gnark's VerifyingKey.readFrom
	// appends to CommitmentKeys rather than resetting it, so decoding into a Vk that Setup
	// already populated yields len(CommitmentKeys) == 2 against a serialized count of 1 and
	// fails with "invalid number of commitment keys". That is invisible on a circuit with no
	// Pedersen commitment and unavoidable on one with a commitment, i.e. on every circuit
	// built with the log-derivative range checker.
	exportVk := groth16.NewVerifyingKey(ecc.BN254)
	err := utils.ReadVerifyingKey(os.Getenv("VK_PATH"), exportVk)
	if err != nil {
		return fmt.Errorf("failed to read verifiing key: %v", err)
	}

	f, err := os.Create(os.Getenv("SOLIDITY_PATH"))
	defer f.Close()
	if err != nil {
		return fmt.Errorf("fail to solidify file: %v", err)
	}

	err = exportVk.ExportSolidity(f)
	if err != nil {
		return fmt.Errorf("fail to export solidity: %v", err)
	}
	return nil
}

// Prove proves the witness, verifies the proof against vk, and writes it to PROOF_PATH in the
// layout GetAggOnChainProof documents. A proof that does not verify is never written.
func Prove(ccs *bn254cs.R1CS, pk groth16.ProvingKey, vk groth16.VerifyingKey, fullWitness, pubWitness witness.Witness) error {
	pf, err := groth16.Prove(ccs, pk, fullWitness, backend.WithProverHashToFieldFunction(sha3.NewLegacyKeccak256()))
	if err != nil {
		return fmt.Errorf("failed to prove: %v", err)
	}

	err = groth16.Verify(pf, vk, pubWitness, backend.WithVerifierHashToFieldFunction(sha3.NewLegacyKeccak256()))
	if err != nil {
		return fmt.Errorf("failed to verify proof: %v", err)
	}

	res, err := utils.GetAggOnChainProof(pf, pubWitness)
	if err != nil {
		return fmt.Errorf("failed to get OnChainProof: %v\n", err)
	}

	err = os.WriteFile(os.Getenv("PROOF_PATH"), []byte(res), 0644)
	if err != nil {
		return fmt.Errorf("failed to write res, err: %v", err)
	}
	fmt.Println("proof written successfully")
	return nil
}
