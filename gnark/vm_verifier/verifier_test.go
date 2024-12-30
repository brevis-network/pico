package vm_verifier

import (
	"encoding/json"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/logger"
	"github.com/consensys/gnark/test"
	"github.com/rs/zerolog"
	"os"
	"testing"
)

func TestVerifierCircuit(t *testing.T) {
	logger.Set(zerolog.New(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: "15:04:05"}).With().Timestamp().Logger())
	assert := test.NewAssert(t)

	os.Setenv("WITNESS_JSON", "./groth16_witness.json")
	os.Setenv("CONSTRAINTS_JSON", "./constraints.json")
	os.Setenv("GROTH16", "1")

	data, err := os.ReadFile("./groth16_witness.json")
	assert.NoError(err)

	// Deserialize the JSON data into a slice of Instruction structs
	var inputs WitnessInput
	err = json.Unmarshal(data, &inputs)
	assert.NoError(err)

	assignment := NewCircuit(inputs)
	circuit := NewCircuit(inputs)

	err = test.IsSolved(&circuit, &assignment, ecc.BN254.ScalarField())
	assert.NoError(err)

	fmt.Println("done")

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	assert.NoError(err)
	fmt.Printf("ccs: %d \n", ccs.GetNbConstraints())
}
