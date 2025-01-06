package main

import (
	"encoding/json"
	"fmt"
	"github.com/brevis-network/brevis-vm/gnark/utils"
	"github.com/brevis-network/brevis-vm/gnark/vm_verifier"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"
	"golang.org/x/crypto/sha3"
	"os"
)

// demo test
func main() {
	pk := groth16.NewProvingKey(ecc.BN254)
	vk := groth16.NewVerifyingKey(ecc.BN254)

	err := os.Setenv("GROTH16", "1")
	if err != nil {
		panic(err)
	}

	err = utils.ReadProvingKey("./vm_pk", pk)
	if err != nil {
		fmt.Printf("load pk failed: %v \n", err)
		return
	}

	err = utils.ReadVerifyingKey("./vm_vk", vk)
	if err != nil {
		fmt.Printf("load vk failed: %v \n", err)
		return
	}

	data, err := os.ReadFile("./groth16_witness.json")
	if err != nil {
		fmt.Printf("load WITNESS_JSON failed: %v \n", err)
		return
	}

	var inputs vm_verifier.WitnessInput
	err = json.Unmarshal(data, &inputs)
	if err != nil {
		fmt.Printf("unmarshal WITNESS_JSON_JSON failed: %v \n", err)
		return
	}
	assigment := vm_verifier.NewCircuit(inputs)
	circuit := vm_verifier.NewCircuit(inputs)

	err = test.IsSolved(circuit, assigment, ecc.BN254.ScalarField())
	if err != nil {
		fmt.Printf("solve failed: %v \n", err)
		return
	}

	fullWitness, err := frontend.NewWitness(assigment, ecc.BN254.ScalarField())
	if err != nil {
		fmt.Printf("load witmess failed: %v \n", err)
		return
	}
	pubWitness, err := fullWitness.Public()
	if err != nil {
		fmt.Printf("load pub witmess failed: %v \n", err)
		return
	}
	fmt.Printf("fullWitness: %v \n", pubWitness)

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		fmt.Printf("compile failed: %v \n", err)
		return
	}
	fmt.Printf("ccs: %d \n", ccs.GetNbConstraints())

	pf, err := groth16.Prove(ccs, pk, fullWitness, backend.WithProverHashToFieldFunction(sha3.NewLegacyKeccak256()))
	if err != nil {
		fmt.Printf("prove failed: %v \n", err)
		return
	}

	err = groth16.Verify(pf, vk, pubWitness, backend.WithVerifierHashToFieldFunction(sha3.NewLegacyKeccak256()))
	if err != nil {
		fmt.Printf("verify failed: %v \n", err)
	}
}
