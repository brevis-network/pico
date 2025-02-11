package poseidon2

import (
	"github.com/brevis-network/pico/gnark/babybear"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/logger"
	"github.com/consensys/gnark/test"
	"github.com/rs/zerolog"
	"os"
	"testing"
)

type TestPoseidon2BabyBearCircuit struct {
	Input, ExpectedOutput [BABYBEAR_WIDTH]babybear.Variable `gnark:",public"`
}

func (circuit *TestPoseidon2BabyBearCircuit) Define(api frontend.API) error {
	poseidon2Chip := NewBabyBearChip(api)

	input := [BABYBEAR_WIDTH]babybear.Variable{}
	for i := 0; i < BABYBEAR_WIDTH; i++ {
		input[i] = circuit.Input[i]
	}
	poseidon2Chip.PermuteMut(&input)

	for i := 0; i < BABYBEAR_WIDTH; i++ {
		poseidon2Chip.fieldApi.AssertIsEqualF(circuit.ExpectedOutput[i], input[i])
	}
	return nil
}

func TestPoseidon2BabyBear(t *testing.T) {
	logger.Set(zerolog.New(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: "15:04:05"}).With().Timestamp().Logger())
	assert := test.NewAssert(t)

	var circuit, witness *TestPoseidon2BabyBearCircuit

	input := [BABYBEAR_WIDTH]babybear.Variable{
		babybear.NewFConst("0"),
		babybear.NewFConst("0"),
		babybear.NewFConst("0"),
		babybear.NewFConst("0"),
		babybear.NewFConst("0"),
		babybear.NewFConst("0"),
		babybear.NewFConst("0"),
		babybear.NewFConst("0"),
		babybear.NewFConst("0"),
		babybear.NewFConst("0"),
		babybear.NewFConst("0"),
		babybear.NewFConst("0"),
		babybear.NewFConst("0"),
		babybear.NewFConst("0"),
		babybear.NewFConst("0"),
		babybear.NewFConst("0"),
	}

	//[618910652, 1488604963, 659088560, 1999029727, 1121255343, 20724378, 956965955, 1084245564,
	//751155763, 1075356210, 1159054104, 47710013, 179166241, 42705162, 1517988227, 1481867517]
	expected_output := [BABYBEAR_WIDTH]babybear.Variable{
		babybear.NewFConst("618910652"),
		babybear.NewFConst("1488604963"),
		babybear.NewFConst("659088560"),
		babybear.NewFConst("1999029727"),
		babybear.NewFConst("1121255343"),
		babybear.NewFConst("20724378"),
		babybear.NewFConst("956965955"),
		babybear.NewFConst("1084245564"),
		babybear.NewFConst("751155763"),
		babybear.NewFConst("1075356210"),
		babybear.NewFConst("1159054104"),
		babybear.NewFConst("47710013"),
		babybear.NewFConst("179166241"),
		babybear.NewFConst("42705162"),
		babybear.NewFConst("1517988227"),
		babybear.NewFConst("1481867517"),
	}

	circuit = &TestPoseidon2BabyBearCircuit{Input: input, ExpectedOutput: expected_output}
	witness = &TestPoseidon2BabyBearCircuit{Input: input, ExpectedOutput: expected_output}

	err := test.IsSolved(circuit, witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}
