package sdk

import (
	"fmt"
	"github.com/brevis-network/pico/gnark/utils"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	groth16_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/backend/witness"
	bn254cs "github.com/consensys/gnark/constraint/bn254"
	"golang.org/x/crypto/sha3"
	"io/ioutil"
	"os"
	"sync"
)

var (
	Pk  = groth16.NewProvingKey(ecc.BN254)
	Vk  = groth16.NewVerifyingKey(ecc.BN254)
	Ccs = new(bn254cs.R1CS)

	loadLock sync.WaitGroup
)

type PicoGroth16Proof struct {
	VkeyHash              string
	CommittedValuesDigest string
	Proof                 string // hex
}

func ExportSolidify() error {
	err := utils.ReadVerifyingKey(os.Getenv("VK_PATH"), Vk)
	if err != nil {
		return fmt.Errorf("failed to read verifying key: %v", err)
	}

	f, err := os.Create(os.Getenv("SOLIDITY_PATH"))
	defer f.Close()
	if err != nil {
		return fmt.Errorf("failed to solidify file: %v", err)
	}

	err = Vk.ExportSolidity(f)
	if err != nil {
		return fmt.Errorf("failed to export solidity: %v", err)
	}
	return nil
}

func Prove(fullWitness, pubWitness witness.Witness) error {
	pf, err := groth16.Prove(Ccs, Pk, fullWitness, backend.WithProverHashToFieldFunction(sha3.NewLegacyKeccak256()))
	if err != nil {
		return fmt.Errorf("failed to prove: %v", err)
	}

	err = groth16.Verify(pf, Vk, pubWitness, backend.WithVerifierHashToFieldFunction(sha3.NewLegacyKeccak256()))
	if err != nil {
		return fmt.Errorf("failed to verify proof: %v", err)
	}

	res, err := utils.GetAggOnChainProof(pf, pubWitness)
	if err != nil {
		return fmt.Errorf("failed to get OnChainProof: %v\n", err)
	}

	err = ioutil.WriteFile(os.Getenv("PROOF_PATH"), []byte(res), 0644)
	if err != nil {
		return fmt.Errorf("failed to write res, err: %v", err)
	}
	fmt.Println("proof written successfully")

	bn254Proof := pf.(*groth16_bn254.Proof)
	fmt.Printf("bn254Proof Commitments: %v \n", bn254Proof.Commitments)
	fmt.Printf("bn254Proof CommitmentPok: %v \n", bn254Proof.CommitmentPok)
	return nil
}
