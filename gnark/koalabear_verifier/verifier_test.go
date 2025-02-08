package vm_verifier

import (
	"encoding/json"
	"fmt"
	"github.com/brevis-network/brevis-vm/gnark/utils"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/logger"
	"github.com/consensys/gnark/test"
	"github.com/rs/zerolog"
	"golang.org/x/crypto/sha3"
	"log"
	"os"
	"testing"
)

func TestSolveVerifierCircuit(t *testing.T) {
	logger.Set(zerolog.New(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: "15:04:05"}).With().Timestamp().Logger())
	assert := test.NewAssert(t)

	os.Setenv("WITNESS_JSON", "./groth16_witness.json")
	os.Setenv("CONSTRAINTS_JSON", "./constraints.json")
	os.Setenv("GROTH16", "1")

	doSolve(assert)
	fmt.Printf("done koala bear verify \n")
}

func TestSetupVerifierCircuit(t *testing.T) {
	logger.Set(zerolog.New(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: "15:04:05"}).With().Timestamp().Logger())
	assert := test.NewAssert(t)

	os.Setenv("WITNESS_JSON", "./groth16_witness.json")
	os.Setenv("CONSTRAINTS_JSON", "./constraints.json")
	os.Setenv("GROTH16", "1")

	circuit, assigment := doSolve(assert)

	doSetUp(assert, circuit, assigment)
}

func doSolve(assert *test.Assert) (circuit *Circuit, assigment *Circuit) {
	data, err := os.ReadFile("./groth16_witness.json")
	assert.NoError(err)

	// Deserialize the JSON data into a slice of Instruction structs
	var inputs WitnessInput
	err = json.Unmarshal(data, &inputs)
	assert.NoError(err)
	assigment = NewCircuit(inputs)
	circuit = NewCircuit(inputs)

	err = test.IsSolved(circuit, assigment, ecc.BN254.ScalarField())
	assert.NoError(err)
	fmt.Println("solve done")

	return circuit, assigment
}

func doSetUp(assert *test.Assert, circuit *Circuit, assigment *Circuit) {
	fullWitness, err := frontend.NewWitness(assigment, ecc.BN254.ScalarField())
	assert.NoError(err)
	pubWitness, err := fullWitness.Public()
	assert.NoError(err)
	fmt.Printf("fullWitness: %v \n", pubWitness)

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
	assert.NoError(err)
	fmt.Printf("ccs: %d \n", ccs.GetNbConstraints())

	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		log.Fatalln(err)
	}

	pf, err := groth16.Prove(ccs, pk, fullWitness, backend.WithProverHashToFieldFunction(sha3.NewLegacyKeccak256()))
	assert.NoError(err)

	err = groth16.Verify(pf, vk, pubWitness, backend.WithVerifierHashToFieldFunction(sha3.NewLegacyKeccak256()))
	assert.NoError(err)

	err = utils.WriteProvingKey("vm_pk", pk)
	assert.NoError(err)

	err = utils.WriteVerifyingKey("vm_vk", vk)
	assert.NoError(err)
}
